"""업그레이드 영향 분석(stage 4)의 근거 문서 수집. AI를 부르지 않는다.

라이브러리 하나의 버전 범위(from → to)에 해당하는 릴리스 노트·마이그레이션 가이드를 모은다. 어디서 찾을지는
세 경로를 차례로 본다.

  1) 규칙 파일(release_note_sources.json) — groupId로 공식 문서 URL을 직접 지정한다. Spring Boot의 breaking
     change는 GitHub Releases가 아니라 위키의 Release Notes·Migration Guide에 있어서, 자동 경로만으로는 가장
     중요한 문서를 놓친다.
  2) 1)에서 문서를 못 찾았을 때만: Maven Central POM의 <scm> → GitHub/GitLab Releases, 없으면 저장소의 CHANGELOG 파일
     (1)을 찾았는데 패치 노트까지 더하면 버그 수정 목록이 근거 대부분을 차지해 비용만 커진다 — collect 주석 참고)
  3) POM의 <issueManagement>가 JIRA면 해당 버전들에서 해결된 이슈 목록 — 앞 경로에서 아무것도 못 찾았을 때만.
     "무엇이 깨지나"가 잘 드러나지 않는 근거라 자바가 신뢰도를 낮춘다(UpgradeImpactService.adjustConfidence).

모델이 아는 지식으로 채우지 않기 위해, 여기서 못 찾으면 AI를 부르지 않고 "근거 없음"으로 끝낸다.
일시 오류(GitHub 호출 한도, 네트워크)는 errors로 따로 올려서 "근거 없음"과 구분한다 — 전자는 다음 배치에서 다시 시도한다.
"""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests

RULES_FILE = Path(__file__).resolve().parent / "release_note_sources.json"
MAVEN_CENTRAL = "https://repo1.maven.org/maven2"
GITHUB_API = "https://api.github.com"
TIMEOUT = 20
USER_AGENT = "cve-monitoring-impact-collector"

# 한 업그레이드에 AI로 넘기는 근거의 총 글자 수 상한(대략 3~4만 토큰). 넘치면 오래된 문서부터 빼고 note에 남긴다 —
# 잘린 줄 모르고 분석하면 "breaking change 없음"이 근거 부족 때문인지 알 수 없다.
MAX_TOTAL_CHARS = 120_000
# 문서 하나의 상한. 처음엔 4만 자였는데 Tomcat 10.0→10.1 changelog(범위만 잘라도 6만 자)가 잘리면서, 라인이 바뀌는
# 업그레이드에서 가장 중요한 x.y.0 절(문서 맨 끝)이 빠졌다. 총량 상한 안에서 한 문서가 대부분을 써도 되게 둔다.
MAX_DOC_CHARS = 80_000
# GitHub Releases는 한 페이지 100개. 오래된 릴리스를 찾아 너무 깊이 내려가지 않는다.
MAX_RELEASE_PAGES = 3
# 부모 POM을 따라 올라가며 <scm>/<issueManagement>를 찾는 최대 깊이.
MAX_PARENT_DEPTH = 4
# 버전이 올라가지 않는 한 시도해 볼 다음 마이너 수(메이저가 바뀌는 업그레이드에서 중간 라인을 모를 때). 없는 페이지는 404로 끝난다.
CROSS_MAJOR_MINOR_PROBE = 10

CHANGELOG_FILES = ["CHANGELOG.md", "CHANGES.md", "RELEASE-NOTES.md", "RELEASE_NOTES.md", "changelog.md", "CHANGELOG.adoc"]
FINAL_QUALIFIERS = {"", "final", "release", "ga"}


class TransientFetchError(Exception):
    """다시 시도하면 될 수 있는 실패(호출 한도, 네트워크, 5xx)."""


@dataclass
class ReleaseDocument:
    kind: str  # GITHUB_RELEASE / GITLAB_RELEASE / CHANGELOG / JIRA / OFFICIAL_DOC (자바 UpgradeImpactService.SOURCE_KINDS)
    url: str   # 사람이 열어볼 수 있는 주소. AI가 breaking change의 출처로 이 값을 그대로 인용한다.
    title: str
    text: str


@dataclass
class CollectionResult:
    documents: list[ReleaseDocument] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 버전 비교 — 자바 쪽 ComparableVersion과 똑같지는 않지만, 릴리스 노트 범위를 고르는 데는 이 정도로 충분하다.
# ---------------------------------------------------------------------------

_VERSION_IN_TEXT = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+)+)(?:[.-]?([A-Za-z]+)\.?(\d*))?(?![\w])")


def parse_version(text: str) -> Optional[tuple[tuple[int, ...], str]]:
    """문자열 안의 첫 버전을 (숫자 튜플, 소문자 접미사)로. "v3.2.1" → ((3,2,1), ""), "4.1.118.Final" → ((4,1,118), "final")."""
    match = _VERSION_IN_TEXT.search(text or "")
    if not match:
        return None
    numbers = tuple(int(p) for p in match.group(1).split("."))
    return numbers, (match.group(2) or "").lower()


def is_final(version: tuple[tuple[int, ...], str]) -> bool:
    return version[1] in FINAL_QUALIFIERS


def is_relevant_release(version: tuple[tuple[int, ...], str], from_version: tuple[int, ...],
                        to_version: tuple[int, ...]) -> bool:
    """정식 버전이면 범위만 본다. 마일스톤·RC는 원칙적으로 빼지만, 라인이 바뀌는 업그레이드의 새 라인 x.y.0 사전 릴리스는
    넣는다 — Tomcat 10.1처럼 breaking change가 10.1.0-M1~M17 노트에만 있고 10.1.0 정식 노트에는 없는 경우가 있다."""
    numbers = version[0]
    if is_final(version):
        return in_upgrade_range(numbers, from_version, to_version)
    padded = _pad(numbers)
    return (padded[2:] == (0,) * (len(padded) - 2)
            and line_of(numbers) != line_of(from_version)
            and line_of(from_version) < line_of(numbers) <= line_of(to_version))


def _pad(numbers: tuple[int, ...], size: int = 3) -> tuple[int, ...]:
    return numbers + (0,) * (size - len(numbers)) if len(numbers) < size else numbers


def line_of(numbers: tuple[int, ...]) -> tuple[int, int]:
    padded = _pad(numbers)
    return padded[0], padded[1]


def in_upgrade_range(version: tuple[int, ...], from_version: tuple[int, ...], to_version: tuple[int, ...]) -> bool:
    """from 초과 ~ to 이하이면서, 옛 라인의 뒤늦은 패치는 뺀다.

    3.1.5 → 3.2.12로 올릴 때 3.1.6~3.1.12(옛 3.1 라인의 백포트 패치)는 이 업그레이드가 지나가는 길이 아니다 — 넣으면
    같은 수정이 두 번 보이고 근거만 길어진다. 같은 라인 안의 업그레이드(패치)면 라인 조건 없이 범위만 본다.
    """
    v, f, t = _pad(version), _pad(from_version), _pad(to_version)
    if not (f < v <= t):
        return False
    if line_of(f) == line_of(t):
        return True
    return line_of(v) > line_of(f)


def lines_between(from_version: tuple[int, ...], to_version: tuple[int, ...]) -> list[str]:
    """from 라인 초과 ~ to 라인 이하의 "메이저.마이너" 목록. 메이저가 바뀌면 중간 라인을 모르므로 몇 개를 짐작해 넣는다
    (없는 라인의 문서는 404로 걸러진다)."""
    f_major, f_minor = line_of(from_version)
    t_major, t_minor = line_of(to_version)
    if (f_major, f_minor) >= (t_major, t_minor):
        return []
    if f_major == t_major:
        return [f"{t_major}.{m}" for m in range(f_minor + 1, t_minor + 1)]
    lines = [f"{f_major}.{m}" for m in range(f_minor + 1, f_minor + 1 + CROSS_MAJOR_MINOR_PROBE)]
    for major in range(f_major + 1, t_major):
        lines += [f"{major}.{m}" for m in range(CROSS_MAJOR_MINOR_PROBE)]
    lines += [f"{t_major}.{m}" for m in range(t_minor + 1)]
    return lines


# ---------------------------------------------------------------------------
# 텍스트 가공
# ---------------------------------------------------------------------------

class _HtmlToText(HTMLParser):
    """HTML에서 본문 텍스트만. 제목 태그는 "# "를 붙여 slice_by_version_headings가 절 구분으로 쓸 수 있게 한다.

    container_id를 주면 그 id를 가진 요소 안의 텍스트만 모은다. GitHub 위키 페이지는 1MB 가까운 HTML 대부분이
    메뉴·사이드바라, 본문(#wiki-body)만 골라내지 않으면 근거 총량 상한을 메뉴 텍스트가 채운다.
    """

    _BLOCK = {"p", "div", "li", "tr", "br", "ul", "ol", "table", "section", "pre"}
    _HEADINGS = {"h1", "h2", "h3", "h4", "h5"}
    _SKIP = {"script", "style", "nav", "header", "footer"}
    _VOID = {"br", "img", "input", "meta", "hr", "link", "area", "base", "col", "embed", "source", "track", "wbr"}

    def __init__(self, container_id: Optional[str] = None):
        super().__init__()
        self._parts: list[str] = []
        self._skip_depth = 0
        self._container_id = container_id
        # container_id가 없으면 문서 전체가 대상이다. 있으면 그 요소에 들어간 뒤의 태그 깊이를 센다(0이 되면 나온 것).
        self._container_depth = None if container_id else 1

    def handle_starttag(self, tag, attrs):
        if self._container_depth is None:
            if dict(attrs).get("id") == self._container_id and tag not in self._VOID:
                self._container_depth = 1
            return
        if self._container_id and tag not in self._VOID:
            self._container_depth += 1
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag in self._HEADINGS:
            self._parts.append("\n# ")
        elif tag in self._BLOCK:
            self._parts.append("\n")
        if tag == "li":
            self._parts.append("- ")

    def handle_endtag(self, tag):
        if self._container_depth is None:
            return
        if self._container_id and tag not in self._VOID:
            self._container_depth -= 1
            if self._container_depth == 0:
                self._container_depth = None
                self._container_id = "(already read)"  # 본문은 한 번만 읽는다 — 같은 id가 또 나와도 다시 들어가지 않는다
                return
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in self._HEADINGS or tag in self._BLOCK:
            self._parts.append("\n")

    def handle_data(self, data):
        if self._container_depth is not None and not self._skip_depth:
            self._parts.append(data)

    def text(self) -> str:
        joined = "".join(self._parts)
        lines = [re.sub(r"[ \t]+", " ", line).strip() for line in joined.splitlines()]
        return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def html_to_text(html: str, container_id: Optional[str] = None) -> str:
    parser = _HtmlToText(container_id)
    parser.feed(html)
    return parser.text()


_HEADING = re.compile(r"^\s*(#{1,6}\s|={1,6}\s|v?\d+\.\d+|[A-Za-z][\w .-]{0,40}\s+v?\d+\.\d+)")


def slice_by_version_headings(text: str, from_version: tuple[int, ...], to_version: tuple[int, ...]) -> Optional[str]:
    """CHANGELOG·changelog 페이지처럼 여러 버전이 한 문서에 있을 때, 범위 안 버전의 절만 이어 붙인다.

    절 = 버전이 적힌 제목 줄부터 다음 제목 줄 전까지. 목록 항목("- Bump foo to 1.2.3")은 제목이 아니다. 오름차순·내림차순
    문서 모두 같은 방식으로 처리된다. 범위 안 절이 하나도 없으면 None — 문서 전체를 넘기지 않는다(엉뚱한 버전이 근거가 된다).
    """
    lines = text.splitlines()
    headings: list[tuple[int, tuple[tuple[int, ...], str]]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if len(stripped) > 150 or stripped.startswith(("-", "*", "+")) or not _HEADING.match(stripped):
            continue
        version = parse_version(stripped)
        # 버전이 없는 제목("### Bug Fixes", Tomcat의 "Catalina")은 절 안의 소제목이라 경계로 삼지 않는다 — 경계로 삼으면
        # 버전 절이 첫 소제목에서 끊겨 본문이 통째로 빠진다. 버전이 있는 제목은 모두 경계이고, 넣을지는 is_relevant_release가 정한다.
        if version is None:
            continue
        headings.append((index, version))

    # 새 라인의 x.y.0 절(마일스톤·RC 포함)을 앞에 둔다. 라인이 바뀌는 업그레이드의 breaking change는 거의 여기 있는데,
    # 최신순 문서에서는 맨 끝이라 길이 상한(_cap)에 걸리면 먼저 잘려 나갔다. 나머지 패치 절은 문서 순서 그대로 뒤에 붙인다.
    line_start_sections, other_sections = [], []
    for position, (start, version) in enumerate(headings):
        if not is_relevant_release(version, from_version, to_version):
            continue
        end = headings[position + 1][0] if position + 1 < len(headings) else len(lines)
        section = "\n".join(lines[start:end]).strip()
        padded = _pad(version[0])
        is_line_start = padded[2] == 0 and line_of(version[0]) != line_of(from_version)
        (line_start_sections if is_line_start else other_sections).append(section)
    sections = line_start_sections + other_sections
    return "\n\n".join(sections) if sections else None


def _cap(text: str, limit: int, label: str, notes: list[str]) -> str:
    if len(text) <= limit:
        return text
    notes.append(f"{label}: 길이 {len(text)}자 중 앞 {limit}자만 근거로 넘김")
    return text[:limit] + "\n\n(이하 생략 — 문서가 길어 잘렸다)"


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class _Http:
    def __init__(self, session: Optional[requests.Session] = None):
        self._session = session or requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT})
        self._github_token = os.environ.get("GITHUB_TOKEN", "")

    def get(self, url: str, *, github_api: bool = False, params: Optional[dict] = None) -> Optional[requests.Response]:
        """404면 None. 일시 오류는 TransientFetchError. 그 밖의 4xx는 "그 출처엔 없다"로 보고 None."""
        headers = {}
        if github_api:
            headers["Accept"] = "application/vnd.github+json"
            if self._github_token:
                headers["Authorization"] = f"Bearer {self._github_token}"
        try:
            response = self._session.get(url, headers=headers, params=params, timeout=TIMEOUT)
        except requests.RequestException as e:
            raise TransientFetchError(f"{url}: {e.__class__.__name__}") from e

        if response.status_code == 404:
            return None
        if response.status_code == 429 or response.status_code >= 500 or (
                github_api and response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0"):
            raise TransientFetchError(f"{url}: HTTP {response.status_code}"
                                      + (" (GitHub 호출 한도 초과 — GITHUB_TOKEN을 설정하면 늘어난다)"
                                         if github_api and response.status_code in (403, 429) else ""))
        if response.status_code >= 400:
            return None
        return response


# ---------------------------------------------------------------------------
# 출처별 수집
# ---------------------------------------------------------------------------

def _load_rules() -> list[dict]:
    if not RULES_FILE.is_file():
        return []
    return json.loads(RULES_FILE.read_text(encoding="utf-8"))["rules"]


def _collect_from_rules(http: _Http, coordinate: str, from_v: tuple[int, ...], to_v: tuple[int, ...],
                        result: CollectionResult) -> None:
    for rule in _load_rules():
        if not coordinate.startswith(rule["match"]):
            continue
        for line in lines_between(from_v, to_v):
            for source in rule["sources"]:
                fetch_url = source["fetch"].format(line=line)
                view_url = source.get("view", source["fetch"]).format(line=line)
                response = http.get(fetch_url)
                if response is None:
                    continue
                text = html_to_text(response.text, source.get("container_id")) if source.get("html") else response.text
                if source.get("slice"):
                    text = slice_by_version_headings(text, from_v, to_v)
                    if not text:
                        continue
                result.documents.append(ReleaseDocument(
                    rule.get("kind", "OFFICIAL_DOC"), view_url, source.get("title", "{line}").format(line=line),
                    _cap(text.strip(), MAX_DOC_CHARS, view_url, result.notes)))


def _pom_url(group_id: str, artifact_id: str, version: str) -> str:
    return f"{MAVEN_CENTRAL}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.pom"


def _find_text(root: ET.Element, path: str) -> Optional[str]:
    element = root.find(path, {"m": "http://maven.apache.org/POM/4.0.0"})
    if element is None:
        element = root.find(path.replace("m:", ""))  # 네임스페이스 선언이 없는 POM
    return element.text.strip() if element is not None and element.text else None


def find_project_links(http: _Http, group_id: str, artifact_id: str, version: str) -> tuple[Optional[str], Optional[str]]:
    """(scm URL, JIRA URL). 모듈 POM엔 대개 없고 부모 POM에서 물려받으므로, 없으면 <parent>를 따라 올라간다.
    받은 원문 POM을 읽으므로(유효 POM이 아님) 부모의 값이 그대로 나온다 — Maven이 상속 시 붙이는 모듈 경로는 없다."""
    scm_url = jira_url = None
    coords: Optional[tuple[str, str, str]] = (group_id, artifact_id, version)
    for _ in range(MAX_PARENT_DEPTH + 1):
        if coords is None or (scm_url and jira_url):
            break
        response = http.get(_pom_url(*coords))
        if response is None:
            break
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError:
            break
        scm_url = scm_url or _find_text(root, "m:scm/m:url") or _find_text(root, "m:scm/m:connection")
        if not jira_url:
            system = (_find_text(root, "m:issueManagement/m:system") or "").lower()
            url = _find_text(root, "m:issueManagement/m:url")
            if url and ("jira" in system or "/browse/" in url or "/jira/" in url):
                jira_url = url
        parent_group = _find_text(root, "m:parent/m:groupId")
        parent_artifact = _find_text(root, "m:parent/m:artifactId")
        parent_version = _find_text(root, "m:parent/m:version")
        coords = (parent_group, parent_artifact, parent_version) if parent_group and parent_artifact and parent_version else None
    if scm_url and "${" in scm_url:
        scm_url = None  # 치환할 수 없는 표현식이 남은 URL로는 저장소를 특정할 수 없다
    return scm_url, jira_url


_GITHUB_REPO = re.compile(r"github\.com[:/]+([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?]|$)")
_GITLAB_REPO = re.compile(r"gitlab\.com[:/]+([\w./-]+?)(?:\.git)?(?:[#?]|$)")


def parse_github_repo(scm_url: str) -> Optional[tuple[str, str]]:
    match = _GITHUB_REPO.search(scm_url or "")
    return (match.group(1), match.group(2)) if match else None


def _collect_github_releases(http: _Http, owner: str, repo: str, from_v, to_v, result: CollectionResult) -> bool:
    found = []
    for page in range(1, MAX_RELEASE_PAGES + 1):
        response = http.get(f"{GITHUB_API}/repos/{owner}/{repo}/releases", github_api=True,
                            params={"per_page": 100, "page": page})
        if response is None:
            break
        releases = response.json()
        if not releases:
            break
        oldest_on_page = None
        for release in releases:
            version = parse_version(release.get("tag_name") or release.get("name") or "")
            if version is None:
                continue
            oldest_on_page = version[0] if oldest_on_page is None else min(oldest_on_page, version[0])
            if release.get("draft"):
                continue
            if is_relevant_release(version, from_v, to_v) and (release.get("body") or "").strip():
                if release.get("html_url") not in {r.get("html_url") for _, r in found}:
                    found.append((version[0], release))
        if oldest_on_page is not None and _pad(oldest_on_page) <= _pad(from_v):
            break  # 이 페이지에서 이미 from 이하까지 내려왔다
        if len(releases) < 100:
            break  # 마지막 페이지다 — 다음 페이지를 부르면 빈 목록에 호출 한도만 쓴다(토큰 없으면 IP당 시간당 60회)
    # 최신 릴리스가 앞에 오게 한다 — 총량 상한에 걸리면 오래된 것부터 빠진다(_fit_budget).
    for _, release in sorted(found, key=lambda item: _pad(item[0]), reverse=True):
        result.documents.append(ReleaseDocument(
            "GITHUB_RELEASE", release["html_url"], release.get("name") or release["tag_name"],
            _cap(release["body"].strip(), MAX_DOC_CHARS, release["html_url"], result.notes)))
    return bool(found)


def _collect_changelog(http: _Http, owner: str, repo: str, from_v, to_v, result: CollectionResult) -> bool:
    """Releases에 본문이 없는 저장소용. raw.githubusercontent.com은 API가 아니라서 호출 한도에 안 걸린다."""
    for name in CHANGELOG_FILES:
        response = http.get(f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{name}")
        if response is None:
            continue
        sliced = slice_by_version_headings(response.text, from_v, to_v)
        if sliced:
            url = f"https://github.com/{owner}/{repo}/blob/HEAD/{name}"
            result.documents.append(ReleaseDocument("CHANGELOG", url, name, _cap(sliced, MAX_DOC_CHARS, url, result.notes)))
            return True
    return False


def _collect_gitlab_releases(http: _Http, project_path: str, from_v, to_v, result: CollectionResult) -> bool:
    response = http.get(f"https://gitlab.com/api/v4/projects/{quote(project_path, safe='')}/releases",
                        params={"per_page": 100})
    if response is None:
        return False
    found = False
    for release in response.json():
        version = parse_version(release.get("tag_name") or "")
        if version and is_relevant_release(version, from_v, to_v) and (release.get("description") or "").strip():
            url = release.get("_links", {}).get("self") or f"https://gitlab.com/{project_path}/-/releases/{release['tag_name']}"
            result.documents.append(ReleaseDocument("GITLAB_RELEASE", url, release.get("name") or release["tag_name"],
                                                    _cap(release["description"].strip(), MAX_DOC_CHARS, url, result.notes)))
            found = True
    return found


def _collect_jira(http: _Http, jira_url: str, from_v, to_v, result: CollectionResult) -> bool:
    match = re.match(r"(https?://.+?)/(?:jira/)?browse/([A-Z][A-Z0-9_]+)", jira_url)
    if not match:
        return False
    base, key = match.group(1), match.group(2)
    if "/jira/browse/" in jira_url:
        base += "/jira"
    response = http.get(f"{base}/rest/api/2/project/{key}/versions")
    if response is None:
        return False
    names = []
    for item in response.json():
        version = parse_version(item.get("name", ""))
        if item.get("released") and version and is_relevant_release(version, from_v, to_v):
            names.append(item["name"])
    if not names:
        return False
    jql = f'project = {key} AND fixVersion in ({", ".join(json.dumps(n) for n in names)}) ORDER BY fixVersion DESC'
    response = http.get(f"{base}/rest/api/2/search", params={"jql": jql, "fields": "summary,issuetype,fixVersions",
                                                             "maxResults": 300})
    if response is None:
        return False
    issues = response.json().get("issues", [])
    if not issues:
        return False
    lines = [f"[{issue['fields']['issuetype']['name']}] {issue['key']} {issue['fields']['summary']}" for issue in issues]
    url = f"{base}/issues/?jql={quote(jql)}"
    result.documents.append(ReleaseDocument("JIRA", url, f"{key} {names[-1]}~{names[0]} 해결 이슈 {len(issues)}건",
                                            _cap("\n".join(lines), MAX_DOC_CHARS, url, result.notes)))
    return True


def _fit_budget(result: CollectionResult) -> None:
    """총량 상한을 넘으면 뒤쪽 문서부터 뺀다. 규칙 파일 문서(마이그레이션 가이드)가 앞, 릴리스는 최신순이라 오래된 것부터 빠진다."""
    total, kept = 0, []
    for document in result.documents:
        if total + len(document.text) > MAX_TOTAL_CHARS:
            continue
        kept.append(document)
        total += len(document.text)
    dropped = len(result.documents) - len(kept)
    if dropped:
        result.notes.append(f"근거 총량 상한({MAX_TOTAL_CHARS}자)을 넘어 문서 {dropped}건을 빼고 분석함")
    result.documents = kept


def collect(coordinate: str, from_version: str, to_version: str,
            session: Optional[requests.Session] = None) -> CollectionResult:
    result = CollectionResult()
    from_parsed, to_parsed = parse_version(from_version), parse_version(to_version)
    if not from_parsed or not to_parsed or ":" not in coordinate:
        result.notes.append(f"버전을 해석할 수 없음: {from_version} → {to_version}")
        return result
    from_v, to_v = from_parsed[0], to_parsed[0]
    group_id, artifact_id = coordinate.split(":", 1)
    http = _Http(session)

    # 출처 하나가 일시 오류로 실패해도 나머지 출처는 계속 본다. 실패는 errors로 올려 "근거 없음"과 구분한다.
    def attempt(label: str, fn) -> bool:
        try:
            return fn()
        except TransientFetchError as e:
            result.errors.append(f"{label}: {e}")
            return False

    attempt("규칙 파일", lambda: _collect_from_rules(http, coordinate, from_v, to_v, result) or False)

    # 규칙 파일의 공식 문서(릴리스 노트·마이그레이션 가이드)를 찾았으면 저장소 릴리스 노트는 읽지 않는다. 실측(Spring Boot
    # 3.1.5→3.2.12)에서 GitHub의 3.2.1~3.2.12 패치 노트 12건이 대부분 버그 수정 목록이었는데, 그게 근거 총량(12만 자)을 채워
    # 입력 토큰의 3/4을 차지했다. breaking change는 공식 문서에 모여 있으므로 빼도 잃는 게 적다 — 대신 패치 노트의
    # "Noteworthy"(동반 라이브러리 버전 변경 알림 등)는 못 보므로, 그 사실을 AI와 사람에게 메모로 알린다.
    if result.documents:
        result.notes.append("공식 문서를 찾아 저장소의 개별 릴리스 노트(패치 노트)는 읽지 않음")
        _fit_budget(result)
        return result

    links: tuple[Optional[str], Optional[str]] = (None, None)

    def load_links() -> bool:
        nonlocal links
        links = find_project_links(http, group_id, artifact_id, to_version)
        return True

    attempt("Maven Central POM", load_links)
    scm_url, jira_url = links

    github = parse_github_repo(scm_url or "")
    if github:
        if not attempt("GitHub Releases", lambda: _collect_github_releases(http, *github, from_v, to_v, result)):
            attempt("CHANGELOG", lambda: _collect_changelog(http, *github, from_v, to_v, result))
    elif scm_url and _GITLAB_REPO.search(scm_url):
        project_path = _GITLAB_REPO.search(scm_url).group(1)
        attempt("GitLab Releases", lambda: _collect_gitlab_releases(http, project_path, from_v, to_v, result))

    if not result.documents and jira_url:
        attempt("JIRA", lambda: _collect_jira(http, jira_url, from_v, to_v, result))

    if not result.documents and not result.errors:
        result.notes.append("근거 문서를 찾지 못함 — scm: " + (scm_url or "없음") + ", JIRA: " + (jira_url or "없음"))
    _fit_budget(result)
    return result
