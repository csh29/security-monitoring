"""CVE 취약점 판단 AI 어시스턴트.

두 단계로 동작한다.
  stage 1) 자바 백엔드(/api/ai/**)에서 아직 AI 판단이 없는 취약점을 읽어와서, 이 의존성 버전이
           실제로 해당 CVE에 취약한지 / 어떤 버전으로 올려야 하는지 판단하고 저장한다. 첫 건은
           혼자 먼저 보내 프롬프트 캐시를 예열한 뒤, 나머지는 ASSESS_MAX_WORKERS개씩 병렬로 처리한다.
  stage 2) stage 1에서 "취약함"으로 확정된 CVE들을, 앱(pom.xml) 단위로 모아서
           한 번에 취합 판단시켜 pom.xml 수정안(diff가 작은 전략 선택 포함)을 만들고 저장한다.
"""

from __future__ import annotations

import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Optional

import anthropic
import requests

from prompt_rules import ASSESS_SYSTEM, FIX_PLAN_SYSTEM, load_prompt

MODEL = "claude-sonnet-5"

# stage 1(CVE 판단)을 병렬로 돌릴 워커 수. 너무 높으면 두 가지 문제가 생긴다:
#   1) 프롬프트 캐시가 아직 안 만들어진 상태에서 여러 요청이 동시에 도착하면 각자 따로
#      캐시를 써버려서(cache_creation 중복) 캐싱 이득이 줄어든다.
#   2) Anthropic API의 분당 요청/토큰 제한(rate limit)에 걸릴 수 있다.
# 그래서 첫 건은 반드시 혼자 먼저 보내서 캐시를 예열한 뒤, 나머지만 이 워커 수로 병렬 처리한다.
ASSESS_MAX_WORKERS = 5

# 자바 백엔드 접속 정보. SecurityConfig에서 /api/ai/**는 세션 로그인 없이
# X-Internal-Token 헤더만으로 인증하므로, application.properties의
# ai.internal.token과 반드시 같은 값을 CVE_MONITOR_AI_TOKEN에 넣어줘야 한다.
BASE_URL = os.environ.get("CVE_MONITOR_BASE_URL", "http://localhost:8080")
AI_TOKEN = os.environ.get("CVE_MONITOR_AI_TOKEN", "")

# Structured Outputs 스키마. output_config.format 으로 넘기면 응답이 이 스키마를
# 만족하는 JSON 텍스트임이 보장되므로 코드펜스를 벗겨낼 필요가 없다.
ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "is_vulnerable": {"type": "boolean"},
        # 수정 버전을 모르면 null 이어야 하므로 nullable 로 둔다.
        "fixed_version": {"type": ["string", "null"]},
        "reasoning": {"type": "string"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["is_vulnerable", "fixed_version", "reasoning", "confidence"],
    "additionalProperties": False,
}

FIX_PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "strategy": {
            "type": "string",
            "enum": ["PARENT_UPGRADE", "PROPERTY_OVERRIDE", "MIXED"],
        },
        "pom_xml": {"type": "string"},
        "unresolved_cves": {"type": "string"},
        "reasoning": {"type": "string"},
    },
    "required": ["strategy", "pom_xml", "unresolved_cves", "reasoning"],
    "additionalProperties": False,
}

# pom.xml 전문을 그대로 받아야 해서 출력이 길다. 8192로는 큰 pom에서 잘린다.
ASSESS_MAX_TOKENS = 4096
FIX_PLAN_MAX_TOKENS = 32000

# output_config.effort를 안 넘기면 claude-sonnet-5는 기본 "high"로 돈다. CVE 판단은 정해진
# 스키마 안에서 고르는 분류 작업이라 medium으로 충분하다고 보고 낮춘다 — fix-plan(다중 CVE를
# 취합해서 pom.xml 전체를 다시 써야 하는 더 복잡한 작업)은 그대로 기본값(high)을 쓴다.
ASSESS_EFFORT = "medium"


@dataclass
class DependencyContext:
    """백엔드 VulnerabilityInfo와 대응되는 입력 정보."""

    id: int
    cve_id: str
    description: str
    severity: Optional[str]
    group_id: str
    artifact_id: str
    version: str
    brought_in_by: Optional[str] = None
    # OSV가 알려주는 수정 버전 후보(쉼표 구분). 있으면 설명을 다시 해석해서 유추할 필요가 없다.
    known_fixed_versions: Optional[str] = None

    @staticmethod
    def from_json(data: dict) -> "DependencyContext":
        return DependencyContext(
            id=data["id"],
            cve_id=data["cveId"],
            description=data.get("description") or "",
            severity=data.get("severity"),
            group_id=data.get("groupId") or "",
            artifact_id=data.get("artifactId") or "",
            version=data.get("version") or "",
            brought_in_by=data.get("broughtInBy"),
            known_fixed_versions=data.get("knownFixedVersions"),
        )


@dataclass
class VulnAssessment:
    """AI 판단 결과."""

    is_vulnerable: bool
    fixed_version: Optional[str]
    reasoning: str
    confidence: str  # "high" | "medium" | "low"


@dataclass
class CveFinding:
    """stage 1에서 이미 '취약함'으로 확정된 CVE 하나 (fix-plan 입력용)."""

    cve_id: str
    group_id: str
    artifact_id: str
    installed_version: str
    ai_fixed_version: Optional[str]
    ai_confidence: Optional[str]
    brought_in_by: Optional[str]  # 이 아티팩트를 끌고 들어온 최상위 직접 의존성. 직접 의존성 자신이면 스스로를 가리킴.
    # 최상위 직접 의존성부터 이 아티팩트까지의 전체 조상 체인("A -> B -> C" 형태로 이미 조인됨).
    # 직접 의존성이면 None. 자바에서 dependency:tree를 파싱해 미리 계산한 값이라, reasoning의
    # "경로:" 줄은 이 값을 그대로 인용하기만 하면 된다 — dependency:tree를 다시 훑어 재구성하지 않는다.
    dependency_path: Optional[str] = None

    @staticmethod
    def from_json(data: dict) -> "CveFinding":
        return CveFinding(
            cve_id=data["cveId"],
            group_id=data.get("groupId") or "",
            artifact_id=data.get("artifactId") or "",
            installed_version=data.get("installedVersion") or "",
            ai_fixed_version=data.get("aiFixedVersion"),
            ai_confidence=data.get("aiConfidence"),
            brought_in_by=data.get("broughtInBy"),
            dependency_path=data.get("dependencyPath"),
        )


@dataclass
class AppFixPlanTarget:
    """fix-plan 배치가 앱 하나를 처리하는 데 필요한 입력."""

    app_id: int
    system_name: str
    pom_xml: str
    dependency_tree: str
    cve_findings: list[CveFinding]

    @staticmethod
    def from_json(data: dict) -> "AppFixPlanTarget":
        return AppFixPlanTarget(
            app_id=data["appId"],
            system_name=data.get("systemName") or "",
            pom_xml=data.get("pomXml") or "",
            dependency_tree=data.get("dependencyTree") or "",
            cve_findings=[CveFinding.from_json(item) for item in data.get("cveFindings", [])],
        )


@dataclass
class FixPlan:
    """AI가 취합 판단해서 만든 pom.xml 수정안."""

    strategy: str  # "PARENT_UPGRADE" | "PROPERTY_OVERRIDE" | "MIXED"
    pom_xml: str
    unresolved_cves: str
    reasoning: str


def _reject_if_truncated(response, max_tokens: int) -> None:
    """max_tokens에서 잘린 응답은 저장하면 안 된다.

    특히 fix-plan은 pom.xml 전문이 오기 때문에, 잘린 걸 그대로 저장하면
    깨진 XML이 수정안으로 남는다. 파싱이 우연히 통과하는 경우도 있어
    stop_reason을 직접 확인한다.
    """
    if response.stop_reason == "max_tokens":
        raise ValueError(
            f"응답이 max_tokens({max_tokens})에서 잘렸습니다. "
            "내용이 불완전하므로 저장하지 않습니다."
        )


def _shorten_description(description: str, max_len: int = 240) -> str:
    """OSV 수정 버전 후보가 있어 설명 프로즈를 다시 해석할 필요가 없을 때, 컴포넌트 동일성
    확인용으로 앞부분만 남긴다. 문장 단위로 max_len 안에 들어가는 만큼 이어붙인다 — 첫 문장만
    자르면 "Netty is a network framework." 처럼 실제 영향 버전 정보가 없는 상투적 문장만
    남는 경우가 있어서, 예산이 허락하는 한 다음 문장까지 포함시킨다."""
    if len(description) <= max_len:
        return description

    result = ""
    for sentence in description.split(". "):
        candidate = result + sentence + ". "
        if len(candidate) > max_len:
            if not result:  # 첫 문장 자체가 너무 길면 강제로 자른다.
                return sentence[:max_len].rstrip() + "..."
            break
        result = candidate
    return result.rstrip()


def _strip_code_fence(raw_text: str) -> str:
    """코드펜스 제거. Structured Outputs를 쓰므로 지금은 안전망 역할만 한다."""
    text = raw_text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    return fenced.group(1) if fenced else text


def _extract_text(response) -> str:
    """확장 사고(thinking)가 켜지면 content[0]이 ThinkingBlock이라 텍스트 블록을 직접 찾아야 한다."""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            return block.text
    raise ValueError("Claude 응답에 텍스트 블록이 없습니다.")


@dataclass
class TokenUsageTracker:
    """호출별 토큰 사용량을 누적한다. 캐시가 실제로 적중하는지, 어떤 건이 유난히
    토큰을 많이 쓰는지 디버깅할 때 쓴다. stage 1을 병렬로 돌리므로 여러 스레드가
    동시에 record()를 호출할 수 있어 락으로 보호한다."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def record(self, label: str, usage) -> None:
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0) or 0
        with self._lock:
            self.input_tokens += usage.input_tokens
            self.output_tokens += usage.output_tokens
            self.cache_read_tokens += cache_read
            self.cache_creation_tokens += cache_creation
        print(f"  [tokens] {label}: input={usage.input_tokens} output={usage.output_tokens} "
              f"cache_read={cache_read} cache_creation={cache_creation}")

    def summary(self) -> str:
        return (f"input={self.input_tokens} output={self.output_tokens} "
                f"cache_read={self.cache_read_tokens} cache_creation={self.cache_creation_tokens}")


class CveMonitorClient:
    """자바 백엔드의 /api/ai/** 와 통신하는 클라이언트."""

    def __init__(self, base_url: str = BASE_URL, token: str = AI_TOKEN):
        if not token:
            raise ValueError("CVE_MONITOR_AI_TOKEN 환경변수가 비어 있습니다.")
        self._base_url = base_url.rstrip("/")
        self._headers = {"X-Internal-Token": token}

    def fetch_pending_vulnerabilities(self) -> list[DependencyContext]:
        response = requests.get(
            f"{self._base_url}/api/ai/vulnerabilities/pending",
            headers=self._headers,
            timeout=30,
        )
        response.raise_for_status()
        return [DependencyContext.from_json(item) for item in response.json()]

    def submit_assessment(self, vulnerability_id: int, assessment: VulnAssessment) -> None:
        response = requests.post(
            f"{self._base_url}/api/ai/vulnerabilities/{vulnerability_id}/assessment",
            headers=self._headers,
            json={
                "vulnerable": assessment.is_vulnerable,
                "fixedVersion": assessment.fixed_version,
                "reasoning": assessment.reasoning,
                "confidence": assessment.confidence,
            },
            timeout=30,
        )
        response.raise_for_status()

    def fetch_pending_fix_plans(self) -> list[AppFixPlanTarget]:
        response = requests.get(
            f"{self._base_url}/api/ai/fix-plans/pending",
            headers=self._headers,
            timeout=30,
        )
        response.raise_for_status()
        return [AppFixPlanTarget.from_json(item) for item in response.json()]

    def submit_fix_plan(self, app_id: int, plan: FixPlan) -> None:
        response = requests.post(
            f"{self._base_url}/api/ai/apps/{app_id}/fix-plan",
            headers=self._headers,
            json={
                "strategy": plan.strategy,
                "pomXml": plan.pom_xml,
                "unresolvedCves": plan.unresolved_cves,
                "reasoning": plan.reasoning,
            },
            timeout=60,
        )
        response.raise_for_status()


class VulnAssessorClient:
    def __init__(self, api_key: Optional[str] = None, model: str = MODEL):
        self._client = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self._model = model
        self.usage = TokenUsageTracker()

    def assess(self, ctx: DependencyContext) -> VulnAssessment:
        response = self._client.messages.create(
            model=self._model,
            # 확장 사고가 붙으면 답이 나오기 전에 토큰을 다 쓸 수 있어 여유 있게 잡는다.
            max_tokens=ASSESS_MAX_TOKENS,
            # 판정 룰은 prompts/assess.system.md 에 있다. CVE 건마다 같은 내용이
            # 반복되므로 캐시를 붙여 둔다(두 번째 요청부터 입력 토큰 값이 1/10).
            system=[{
                "type": "text",
                "text": load_prompt(ASSESS_SYSTEM),
                "cache_control": {"type": "ephemeral"},
            }],
            # CVE 판단은 정해진 스키마 안에서 취약 여부/버전을 고르는 분류에 가까운 작업이라
            # (Claude API 가이드 기준 effort 미설정 시 기본값은 high) high까지는 필요 없다.
            # medium으로 낮춰서 품질 손해 없이 thinking/output 토큰을 아낀다.
            output_config={
                "format": {"type": "json_schema", "schema": ASSESSMENT_SCHEMA},
                "effort": ASSESS_EFFORT,
            },
            messages=[{"role": "user", "content": self._build_prompt(ctx)}],
        )
        self.usage.record(ctx.cve_id, response.usage)
        _reject_if_truncated(response, ASSESS_MAX_TOKENS)
        return self._parse_response(_extract_text(response))

    def _build_prompt(self, ctx: DependencyContext) -> str:
        # 판정 룰은 전부 시스템 프롬프트(prompts/)로 갔다. 여기는 데이터만 담는다.
        # OSV 수정 버전 후보가 있으면 assess.system.md 규칙상 설명 프로즈를 다시 해석할 필요가
        # 없으므로(컴포넌트 동일성 확인 용도로만 쓰면 됨), 첫 문장만 남겨 입력 토큰을 아낀다.
        description = _shorten_description(ctx.description) if ctx.known_fixed_versions else ctx.description
        return f"""- CVE ID: {ctx.cve_id}
- 설명: {description}
- 의존성: {ctx.group_id}:{ctx.artifact_id}:{ctx.version}
- OSV 수정 버전 후보: {ctx.known_fixed_versions or "(없음)"}
"""

    def _parse_response(self, raw_text: str) -> VulnAssessment:
        data = json.loads(_strip_code_fence(raw_text))
        return VulnAssessment(
            is_vulnerable=data["is_vulnerable"],
            fixed_version=data.get("fixed_version"),
            reasoning=data.get("reasoning", ""),
            confidence=data.get("confidence", "low"),
        )


class FixPlanGeneratorClient:
    """stage 2: 앱 하나의 CVE 전체를 취합해서 pom.xml 수정안을 만든다."""

    def __init__(self, api_key: Optional[str] = None, model: str = MODEL):
        self._client = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self._model = model
        self.usage = TokenUsageTracker()

    def generate(self, target: AppFixPlanTarget) -> FixPlan:
        # 출력이 길어서 큰 max_tokens가 필요하고, 큰 max_tokens는 비스트리밍에서
        # HTTP 타임아웃에 걸릴 수 있어 스트리밍으로 받는다.
        with self._client.messages.stream(
            model=self._model,
            max_tokens=FIX_PLAN_MAX_TOKENS,
            system=[{
                "type": "text",
                "text": load_prompt(FIX_PLAN_SYSTEM),
                "cache_control": {"type": "ephemeral"},
            }],
            output_config={
                "format": {"type": "json_schema", "schema": FIX_PLAN_SCHEMA},
            },
            messages=[{"role": "user", "content": self._build_prompt(target)}],
        ) as stream:
            response = stream.get_final_message()

        self.usage.record(target.system_name, response.usage)
        _reject_if_truncated(response, FIX_PLAN_MAX_TOKENS)
        return self._parse_response(_extract_text(response))

    @staticmethod
    def _build_findings_text(cve_findings: list["CveFinding"]) -> str:
        """같은 아티팩트(groupId:artifactId:설치버전)에 CVE가 여러 개 걸리면(예: netty 계열
        하나에 8개) 경로처럼 CVE마다 똑같이 반복되는 필드를 매번 다시 안 쓰고, 아티팩트당
        블록 하나로 묶어서 CVE별로 다른 값(권장 버전/신뢰도)만 나열한다. dependency_path가
        이미 brought_in_by를 포함하는 전체 체인이라 brought_in_by는 따로 반복하지 않는다."""
        groups: dict[tuple, list["CveFinding"]] = {}
        for f in cve_findings:
            key = (f.group_id, f.artifact_id, f.installed_version, f.dependency_path)
            groups.setdefault(key, []).append(f)

        blocks = []
        for (group_id, artifact_id, installed_version, dependency_path), findings in groups.items():
            cve_list = ", ".join(
                f"{f.cve_id}(권장 {f.ai_fixed_version}, 신뢰도 {f.ai_confidence})" for f in findings
            )
            blocks.append(
                f"■ {group_id}:{artifact_id}  현재 {installed_version}\n"
                f"  경로: {dependency_path or '직접 의존성'}\n"
                f"  CVE: {cve_list}"
            )
        return "\n".join(blocks)

    def _build_prompt(self, target: AppFixPlanTarget) -> str:
        findings_text = self._build_findings_text(target.cve_findings)

        return f"""[대상 프로젝트] {target.system_name}

[pom.xml]
{target.pom_xml}

[dependency:tree]
{target.dependency_tree}

[취약점 목록] (아티팩트당 하나의 블록. 같은 아티팩트에 CVE가 여러 개면 CVE 줄에 전부 나열됨)
{findings_text}

각 블록의 "경로:"는 dependency:tree를 이미 파싱해서 계산해둔, 최상위 직접 의존성부터 이
아티팩트까지의 전체 조상 체인이다. reasoning의 "경로:" 줄에는 이 값을 그대로 인용하라 —
dependency:tree 텍스트를 다시 눈으로 훑어서 경로를 재구성하지 마라. 이름이 비슷한 형제 노드
(예: spring-security-config vs spring-security-web)를 혼동해서 잘못된 경로를 적는 실수를 막기
위한 값이다. "직접 의존성"이면 pom.xml에 직접 선언된 것이라 경로가 따로 없다는 뜻이다.

한 아티팩트에 CVE가 여러 개 걸려 있으면, 그중 "권장 최소 버전"이 가장 높은 값이 그 아티팩트의
목표 버전이다(권장 최소 버전이 null인 CVE는 목표 버전 산정에 쓰지 마라).
"""

    def _parse_response(self, raw_text: str) -> FixPlan:
        data = json.loads(_strip_code_fence(raw_text))
        return FixPlan(
            strategy=data.get("strategy", "MIXED"),
            pom_xml=data.get("pom_xml", ""),
            unresolved_cves=data.get("unresolved_cves", ""),
            reasoning=data.get("reasoning", ""),
        )


def _assess_one(ai_client: "VulnAssessorClient", backend: "CveMonitorClient",
                 ctx: DependencyContext) -> tuple[DependencyContext, Optional[VulnAssessment], Optional[Exception]]:
    """CVE 하나를 판단하고 저장한다. 병렬 실행 시 스레드에서 그대로 호출되므로
    예외를 여기서 잡아 (ctx, 결과, 에러) 형태로 돌려준다 — 한 건 실패가 나머지를 막지 않도록."""
    try:
        assessment = ai_client.assess(ctx)
        backend.submit_assessment(ctx.id, assessment)
        return ctx, assessment, None
    except Exception as e:
        return ctx, None, e


def main() -> None:
    backend = CveMonitorClient()

    # stage 1: CVE 하나씩 개별 판단. 시스템 프롬프트가 CVE 건마다 동일해서 프롬프트
    # 캐시를 쓰는데, 처음부터 여러 건을 동시에 보내면 캐시가 만들어지기 전에 여러
    # 요청이 동시에 도착해 각자 따로 캐시를 써버릴 수 있다(cache_creation 중복).
    # 그래서 첫 건은 혼자 먼저 보내 캐시를 예열한 뒤, 나머지만 병렬로 처리한다.
    ai_client = VulnAssessorClient()
    pending = backend.fetch_pending_vulnerabilities()
    print(f"판단할 취약점 {len(pending)}건")

    skipped_cves: list[tuple[str, str]] = []

    def handle_result(ctx: DependencyContext, assessment: Optional[VulnAssessment], err: Optional[Exception]) -> None:
        if err is not None:
            # 한 건 실패했다고 나머지 CVE 판단까지 통째로 포기하지 않는다.
            skipped_cves.append((ctx.cve_id, str(err)))
            print(f"[{ctx.cve_id}] 판단 실패, 건너뜀: {err}")
        else:
            print(f"[{ctx.cve_id}] vulnerable={assessment.is_vulnerable} "
                  f"fixed_version={assessment.fixed_version} confidence={assessment.confidence}")

    if pending:
        first_ctx, rest = pending[0], pending[1:]
        handle_result(*_assess_one(ai_client, backend, first_ctx))

        if rest:
            with ThreadPoolExecutor(max_workers=ASSESS_MAX_WORKERS) as executor:
                futures = [executor.submit(_assess_one, ai_client, backend, ctx) for ctx in rest]
                for future in as_completed(futures):
                    handle_result(*future.result())

    # stage 2: 앱 단위로 취합해서 pom.xml 수정안 생성
    fix_plan_client = FixPlanGeneratorClient()
    fix_plan_targets = backend.fetch_pending_fix_plans()
    print(f"fix-plan 생성할 앱 {len(fix_plan_targets)}건")

    skipped_apps: list[tuple[str, str]] = []
    for target in fix_plan_targets:
        try:
            plan = fix_plan_client.generate(target)
            backend.submit_fix_plan(target.app_id, plan)
            print(f"[{target.system_name}] strategy={plan.strategy} "
                  f"unresolved={'있음' if plan.unresolved_cves else '없음'}")
        except Exception as e:
            skipped_apps.append((target.system_name, str(e)))
            print(f"[{target.system_name}] fix-plan 생성 실패, 건너뜀: {e}")

    # 한 화면 가득 스크롤한 로그 사이에서 실패 건만 놓치지 않도록 끝에 다시 요약해서 보여준다.
    print()
    print("=== 요약 ===")
    print(f"CVE 판단: 성공 {len(pending) - len(skipped_cves)}건 / 건너뜀 {len(skipped_cves)}건")
    for cve_id, reason in skipped_cves:
        print(f"  - {cve_id}: {reason}")
    print(f"fix-plan 생성: 성공 {len(fix_plan_targets) - len(skipped_apps)}건 / 건너뜀 {len(skipped_apps)}건")
    for system_name, reason in skipped_apps:
        print(f"  - {system_name}: {reason}")

    print()
    print("=== 토큰 사용량 ===")
    print(f"CVE 판단: {ai_client.usage.summary()}")
    print(f"fix-plan: {fix_plan_client.usage.summary()}")
    total_input = ai_client.usage.input_tokens + fix_plan_client.usage.input_tokens
    total_output = ai_client.usage.output_tokens + fix_plan_client.usage.output_tokens
    total_cache_read = ai_client.usage.cache_read_tokens + fix_plan_client.usage.cache_read_tokens
    total_cache_creation = ai_client.usage.cache_creation_tokens + fix_plan_client.usage.cache_creation_tokens
    print(f"합계: input={total_input} output={total_output} "
          f"cache_read={total_cache_read} cache_creation={total_cache_creation}")


if __name__ == "__main__":
    main()
