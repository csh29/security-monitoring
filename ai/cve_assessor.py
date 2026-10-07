"""라이브러리 취약점(CVE) AI 단계 — 스캔한 의존성의 CVE 판단·조치안·설명 요약·업그레이드 영향 분석.

네 단계로 동작한다.
  stage 1) 자바 백엔드(/api/ai/**)에서 아직 AI 판단이 없는 취약점을 읽어와서, 이 의존성 버전이
           실제로 해당 CVE에 취약한지 / 어떤 버전으로 올려야 하는지 판단하고 저장한다. 첫 건은
           혼자 먼저 보내 프롬프트 캐시를 예열한 뒤, 나머지는 ASSESS_MAX_WORKERS개씩 병렬로 처리한다.
  stage 2) stage 1에서 "취약함"으로 확정된 CVE들을, 앱(pom.xml) 단위로 모아서
           한 번에 취합 판단시켜 pom.xml 수정안(diff가 작은 전략 선택 포함)을 만들고 저장한다.
  stage 3) 등급·판정과 무관하게, 아직 요약이 없거나 NVD가 설명을 바꾼 CVE의 영어 설명을 한국어 2~3문장으로
           요약해서 저장한다(CVE ID당 한 번, SUMMARY_BATCH_SIZE건씩 묶어 한 요청으로). 판단이 아니라 화면에서
           읽기 위한 것이라 싼 모델(SUMMARY_MODEL)을 쓴다.
  stage 4) fix-plan이 제안한 마이너·메이저 업그레이드마다 릴리스 노트를 모아(release_notes.py, AI 없음) 그 근거만으로
           breaking change·필요 조치·테스트 영역을 정리해 저장한다. (좌표, from, to) 단위라 여러 앱이 같은 업그레이드를
           하면 한 번만 분석한다. 근거를 못 찾으면 AI를 부르지 않는다.

보통은 진입점(vuln_assessor.py)이 시큐어코딩 단계와 함께 돌린다. 이 단계만 돌리려면 `py cve_assessor.py`.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

import anthropic

from ai_common import (MODEL, BackendClient, BatchReport, TokenUsageTracker, _extract_text, _reject_if_truncated,
                       _strip_code_fence, _system_prompt, print_reports, run_batch)
from prompt_rules import ASSESS_SYSTEM, FIX_PLAN_SYSTEM, IMPACT_SYSTEM, SUMMARIZE_SYSTEM, load_prompt
from release_notes import CollectionResult, ReleaseDocument, collect as collect_release_notes

# stage 3(설명 요약)은 버전 범위를 추론하는 게 아니라 영어 문장 몇 줄을 한국어로 줄이는 일이라 Haiku로 충분하다.
# 판단용 MODEL과 같이 쓰면 등급 제한 없이 모든 CVE에 도는 단계라 비용이 그만큼 커진다.
SUMMARY_MODEL = "claude-haiku-4-5"
# 한 요청에 묶는 CVE 수. 건마다 따로 보내면 요약 규칙(시스템 프롬프트, 약 500토큰)이 건수만큼 반복돼
# 입력의 60% 이상을 차지했다(104건에 입력 8만 토큰). 캐시 최소 길이보다 짧아 캐시로도 못 줄인다.
# 너무 크게 묶으면 한 요청 실패에 그만큼 같이 실패하고(다음 배치에서 다시 대기가 되긴 한다) 출력이 길어진다.
SUMMARY_BATCH_SIZE = 10
# 건당 요약 출력이 100~220토큰(실측)이라 10건 + JSON 껍데기로 넉넉히 잡는다. 잘리면(_reject_if_truncated)
# 그 묶음은 저장하지 않는다 — JSON이 중간에 끊겨 일부만 파싱되는 상황을 만들지 않기 위해서다.
SUMMARY_MAX_TOKENS = 8192
SUMMARY_MAX_WORKERS = 5

# stage 1(CVE 판단)을 병렬로 돌릴 워커 수. 너무 높으면 두 가지 문제가 생긴다:
#   1) 프롬프트 캐시가 아직 안 만들어진 상태에서 여러 요청이 동시에 도착하면 각자 따로
#      캐시를 써버려서(cache_creation 중복) 캐싱 이득이 줄어든다.
#   2) Anthropic API의 분당 요청/토큰 제한(rate limit)에 걸릴 수 있다.
# 그래서 첫 건은 반드시 혼자 먼저 보내서 캐시를 예열한 뒤, 나머지만 이 워커 수로 병렬 처리한다.
ASSESS_MAX_WORKERS = 5

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

SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {
        "summaries": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string"},
                    "summary": {"type": "string"},
                },
                "required": ["cve_id", "summary"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summaries"],
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
        # pom.xml에서 바꾼 버전 값 목록. 업그레이드 영향 분석이 reasoning 문장을 다시 해석하지 않고 이걸 입력으로
        # 쓴다. 점프 폭(패치/마이너/메이저)은 자바가 계산하므로 여기서 받지 않는다. via 값은 자바
        # FixPlanService.CHANGE_VIA와 같아야 한다.
        "changes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "coordinate": {"type": "string"},
                    "property_name": {"type": "string"},
                    "from_version": {"type": "string"},
                    "to_version": {"type": "string"},
                    "via": {"type": "string", "enum": ["PARENT", "BOM", "PROPERTY", "DIRECT"]},
                },
                "required": ["coordinate", "property_name", "from_version", "to_version", "via"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["strategy", "pom_xml", "unresolved_cves", "reasoning", "changes"],
    "additionalProperties": False,
}

IMPACT_SCHEMA = {
    "type": "object",
    "properties": {
        "risk": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "breaking_changes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "source_url": {"type": "string"},
                    # 이 변경이 가리키는 클래스·패키지·설정 키 이름. 서버가 앱의 import·설정 키와 대조한다(CodeUsageMatcher) —
                    # 코드 목록을 AI로 보내지 않고 이름만 받아 서버 안에서 맞춰 보기 위함이다.
                    "symbols": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["summary", "source_url", "symbols"],
                "additionalProperties": False,
            },
        },
        "required_actions": {"type": "array", "items": {"type": "string"}},
        "test_focus": {"type": "array", "items": {"type": "string"}},
        "note": {"type": "string"},
    },
    "required": ["risk", "confidence", "breaking_changes", "required_actions", "test_focus", "note"],
    "additionalProperties": False,
}

# 근거(최대 약 3~4만 토큰)를 읽고 목록 몇 개를 내는 일이라 출력 자체는 짧지만, adaptive thinking이 같은 한도를 쓴다.
IMPACT_MAX_TOKENS = 32000

ASSESS_MAX_TOKENS = 4096

# fix-plan은 pom.xml 전문 + reasoning을 그대로 받아야 해서 출력이 길다. 게다가 claude-sonnet-5는
# thinking 파라미터를 안 넘겨도 adaptive thinking이 켜진 채로 돌고(effort 기본 high), thinking
# 토큰도 max_tokens 한도를 같이 쓴다. 그래서 같은 앱이라도 thinking 양에 따라 출력이 9천~3만 토큰으로
# 들쭉날쭉했고, 32000에서는 CRM_BACK이 실제로 잘렸다(_reject_if_truncated가 저장을 막음).
# 스트리밍으로 받으니 큰 값이어도 HTTP 타임아웃 걱정이 없고, 모델 출력 상한(128K) 안이다.
# 한도는 상한일 뿐 실제로 쓴 만큼만 과금된다.
FIX_PLAN_MAX_TOKENS = 64000

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
    # NVD의 구조화된 영향 버전 범위(cpeMatch)와 설치 버전을 자바가 직접 비교한 결과.
    # None이면 NVD가 구조화된 범위를 안 줬거나 파싱 불가라 판단 불가라는 뜻 — 이때만
    # description 프로즈를 근거로 판단한다. True/False면 그 자체가 최종 근거다.
    nvd_range_vulnerable: Optional[bool] = None
    nvd_matched_range: Optional[str] = None

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
            nvd_range_vulnerable=data.get("nvdRangeVulnerable"),
            nvd_matched_range=data.get("nvdMatchedRange"),
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
    # [{coordinate, property_name, from_version, to_version, via}] — FIX_PLAN_SCHEMA의 changes 그대로
    changes: list[dict]


@dataclass
class CveSummaryTarget:
    """요약할 CVE 하나. description_hash는 자바가 준 값을 그대로 되돌려준다(어느 설명을 요약했는지의 기준)."""

    cve_id: str
    description: str
    description_hash: str

    @staticmethod
    def from_json(data: dict) -> "CveSummaryTarget":
        return CveSummaryTarget(
            cve_id=data["cveId"],
            description=data["description"],
            description_hash=data["descriptionHash"],
        )


class CveBackendClient(BackendClient):
    """라이브러리 취약점 단계가 부르는 /api/ai/** 호출."""

    def fetch_pending_vulnerabilities(self) -> list[DependencyContext]:
        return [DependencyContext.from_json(item) for item in self._get("/api/ai/vulnerabilities/pending")]

    def submit_assessment(self, vulnerability_id: int, assessment: VulnAssessment) -> None:
        self._post(f"/api/ai/vulnerabilities/{vulnerability_id}/assessment", {
            "vulnerable": assessment.is_vulnerable,
            "fixedVersion": assessment.fixed_version,
            "reasoning": assessment.reasoning,
            "confidence": assessment.confidence,
        })

    def fetch_pending_fix_plans(self) -> list[AppFixPlanTarget]:
        return [AppFixPlanTarget.from_json(item) for item in self._get("/api/ai/fix-plans/pending")]

    def submit_fix_plan(self, app_id: int, plan: FixPlan) -> None:
        self._post(f"/api/ai/apps/{app_id}/fix-plan", {
            "strategy": plan.strategy,
            "pomXml": plan.pom_xml,
            "unresolvedCves": plan.unresolved_cves,
            "reasoning": plan.reasoning,
            "changes": [
                {
                    "coordinate": c["coordinate"],
                    "propertyName": c.get("property_name") or None,
                    "fromVersion": c["from_version"],
                    "toVersion": c["to_version"],
                    "via": c["via"],
                }
                for c in plan.changes
            ],
        }, timeout=60)

    def fetch_pending_impacts(self) -> list["UpgradeImpactTarget"]:
        return [UpgradeImpactTarget.from_json(item) for item in self._get("/api/ai/impacts/pending")]

    def submit_impact(self, target: "UpgradeImpactTarget", status: str, documents: list[ReleaseDocument],
                      note: str, analysis: Optional["UpgradeImpact"] = None) -> None:
        self._post("/api/ai/impacts", {
            "coordinate": target.coordinate,
            "fromVersion": target.from_version,
            "toVersion": target.to_version,
            "status": status,
            "risk": analysis.risk if analysis else None,
            "confidence": analysis.confidence if analysis else None,
            "breakingChanges": [{"summary": c["summary"], "sourceUrl": c["source_url"],
                                 "symbols": c.get("symbols", [])}
                                for c in analysis.breaking_changes] if analysis else [],
            "requiredActions": analysis.required_actions if analysis else [],
            "testFocus": analysis.test_focus if analysis else [],
            "sources": [{"kind": d.kind, "url": d.url} for d in documents],
            "note": note,
        })

    def fetch_pending_summaries(self) -> list[CveSummaryTarget]:
        return [CveSummaryTarget.from_json(item) for item in self._get("/api/ai/summaries/pending")]

    def submit_summary(self, target: CveSummaryTarget, summary: str) -> None:
        self._post("/api/ai/summaries", {
            "cveId": target.cve_id,
            "summary": summary,
            "descriptionHash": target.description_hash,
        })


class VulnAssessorClient:
    def __init__(self, api_key: Optional[str] = None, model: str = MODEL, use_cache: bool = False):
        self._client = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self._model = model
        self._use_cache = use_cache
        self.usage = TokenUsageTracker()

    def assess(self, ctx: DependencyContext) -> VulnAssessment:
        response = self._client.messages.create(
            model=self._model,
            # 확장 사고가 붙으면 답이 나오기 전에 토큰을 다 쓸 수 있어 여유 있게 잡는다.
            max_tokens=ASSESS_MAX_TOKENS,
            # 판정 룰은 prompts/assess.system.md 에 있다. CVE 건마다 같은 내용이라, 판단할 CVE가
            # 2건 이상인 배치에서만 캐시를 붙인다(두 번째 요청부터 입력 토큰 값이 1/10).
            system=_system_prompt(load_prompt(ASSESS_SYSTEM), self._use_cache),
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
        #
        # description은 절대 축약하지 않는다 — 예전엔 OSV 후보가 있으면 "컴포넌트 동일성 확인용"
        # 이라고 보고 240자로 잘랐는데, 실측해보니 여러 CVE에서 "Affected versions:" 목록이
        # 뒷부분에 나와서 그 전에 잘려나갔다. is_vulnerable 판단(범위 안/밖)에 description이
        # 실제로 필요한 경우가 많아 이제 항상 전문을 보낸다.
        # nvd_range_vulnerable은 NVD의 configurations가 있으면 그 결과, 없으면 OSV의 구조화 범위
        # (affected[].ranges)로 자바가 대신 확인한 결과다 — 어느 쪽이든 이미 결정론적으로 나온
        # 값이라 여기까지 내려온다는 건 둘 다 구조화 데이터가 없었다는 뜻이다.
        if ctx.nvd_range_vulnerable is None:
            nvd_line = "- 구조화 범위 판정(NVD/OSV): 판단 불가(구조화된 영향 범위 데이터 없음) — 아래 설명을 근거로 직접 판단할 것"
        else:
            verdict = "영향 범위 안(취약)" if ctx.nvd_range_vulnerable else "영향 범위 밖(취약 아님)"
            range_detail = f", 매치된 범위: {ctx.nvd_matched_range}" if ctx.nvd_matched_range else ""
            nvd_line = f"- 구조화 범위 판정(NVD/OSV): {verdict}{range_detail} — 이 값이 최종 근거이니 설명과 다르게 보여도 이 값을 따를 것"
        return f"""- CVE ID: {ctx.cve_id}
- 설명: {ctx.description}
- 의존성: {ctx.group_id}:{ctx.artifact_id}:{ctx.version}
- OSV 수정 버전 후보: {ctx.known_fixed_versions or "(없음)"}
{nvd_line}
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

    def __init__(self, api_key: Optional[str] = None, model: str = MODEL, use_cache: bool = False):
        self._client = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self._model = model
        self._use_cache = use_cache
        self.usage = TokenUsageTracker()

    def generate(self, target: AppFixPlanTarget) -> FixPlan:
        # 출력이 길어서 큰 max_tokens가 필요하고, 큰 max_tokens는 비스트리밍에서
        # HTTP 타임아웃에 걸릴 수 있어 스트리밍으로 받는다.
        with self._client.messages.stream(
            model=self._model,
            max_tokens=FIX_PLAN_MAX_TOKENS,
            # 앱이 2건 이상인 배치에서만 캐시를 붙인다. 앱 하나의 생성이 5분(캐시 수명, 요청 시작 기준)을
            # 넘기면 다음 앱은 어차피 못 읽지만, 그 경우 손해는 쓰기 할증 한 번뿐이다.
            system=_system_prompt(load_prompt(FIX_PLAN_SYSTEM), self._use_cache),
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
            changes=data.get("changes", []),
        )


@dataclass
class UpgradeImpactTarget:
    """영향 분석할 업그레이드 한 건(자바 UpgradeImpactTarget)."""

    coordinate: str
    from_version: str
    to_version: str
    jump: str  # MINOR | MAJOR

    @staticmethod
    def from_json(data: dict) -> "UpgradeImpactTarget":
        return UpgradeImpactTarget(
            coordinate=data["coordinate"],
            from_version=data["fromVersion"],
            to_version=data["toVersion"],
            jump=data.get("jump") or "",
        )


@dataclass
class UpgradeImpact:
    risk: str
    confidence: str
    breaking_changes: list[dict]  # [{summary, source_url, symbols}]
    required_actions: list[str]
    test_focus: list[str]
    note: str
    dropped_count: int = 0  # 출처가 근거 문서에 없어서 버린 breaking change 수


class UpgradeImpactAnalyzerClient:
    """stage 4: 모아 온 릴리스 노트만 근거로 업그레이드 한 건의 영향을 정리한다."""

    def __init__(self, api_key: Optional[str] = None, model: str = MODEL, use_cache: bool = False):
        self._client = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self._model = model
        self._use_cache = use_cache
        self.usage = TokenUsageTracker()

    def analyze(self, target: UpgradeImpactTarget, collected: CollectionResult) -> UpgradeImpact:
        # 근거가 수만 토큰이라 비스트리밍이면 HTTP 타임아웃에 걸릴 수 있다(fix-plan과 같은 이유).
        with self._client.messages.stream(
            model=self._model,
            max_tokens=IMPACT_MAX_TOKENS,
            system=_system_prompt(load_prompt(IMPACT_SYSTEM), self._use_cache),
            output_config={"format": {"type": "json_schema", "schema": IMPACT_SCHEMA}},
            messages=[{"role": "user", "content": self._build_prompt(target, collected)}],
        ) as stream:
            response = stream.get_final_message()

        self.usage.record(f"{target.coordinate} {target.from_version}→{target.to_version}", response.usage)
        _reject_if_truncated(response, IMPACT_MAX_TOKENS)
        return self._parse_response(_extract_text(response), {d.url for d in collected.documents})

    @staticmethod
    def _build_prompt(target: UpgradeImpactTarget, collected: CollectionResult) -> str:
        # 문서마다 제목 줄에 URL을 붙인다 — 모델이 breaking change의 출처로 이 값을 그대로 복사한다.
        documents = "\n\n".join(
            f"### [문서 {i}] {d.title}\nURL: {d.url}\n종류: {d.kind}\n\n{d.text}"
            for i, d in enumerate(collected.documents, start=1)
        )
        notes = "\n".join(f"- {n}" for n in collected.notes + collected.errors) or "- 없음"
        return f"""[업그레이드]
- 라이브러리: {target.coordinate}
- 현재 → 목표: {target.from_version} → {target.to_version} ({target.jump})

[수집 메모]
{notes}

[근거 문서]
{documents}
"""

    @staticmethod
    def _parse_response(raw_text: str, source_urls: set[str]) -> UpgradeImpact:
        data = json.loads(_strip_code_fence(raw_text))
        # 근거 문서에 없는 URL을 출처로 단 항목은 모델이 지어냈을 수 있어 버린다(자바도 한 번 더 거른다).
        requested = data.get("breaking_changes", [])
        changes = [c for c in requested if c.get("summary", "").strip() and c.get("source_url") in source_urls]
        return UpgradeImpact(
            risk=data["risk"],
            confidence=data["confidence"],
            breaking_changes=changes,
            required_actions=data.get("required_actions", []),
            test_focus=data.get("test_focus", []),
            note=data.get("note", ""),
            dropped_count=len(requested) - len(changes),
        )


def _analyze_impact(analyzer: UpgradeImpactAnalyzerClient, backend: "CveBackendClient",
                    target: UpgradeImpactTarget) -> str:
    """업그레이드 한 건을 수집 → (근거가 있으면) 분석 → 저장하고, 저장한 상태를 한 줄로 돌려준다.
    AI 호출이나 저장이 실패하면 예외를 그대로 올린다 — 저장하지 않았으니 다음 배치에서 다시 대기로 잡힌다."""
    collected = collect_release_notes(target.coordinate, target.from_version, target.to_version)
    notes = collected.notes + collected.errors
    if not collected.documents:
        # 일시 오류가 있었으면 "근거 없음"으로 굳히지 않고 FETCH_FAILED로 남겨 다음 배치에서 다시 시도한다.
        status = "FETCH_FAILED" if collected.errors else "NO_SOURCE"
        backend.submit_impact(target, status, [], "\n".join(notes))
        return status

    analysis = analyzer.analyze(target, collected)
    if analysis.dropped_count:
        notes.append(f"출처가 근거 문서에 없는 breaking change {analysis.dropped_count}건을 버림")
    if analysis.note:
        notes.insert(0, analysis.note)
    backend.submit_impact(target, "ANALYZED", collected.documents, "\n".join(notes), analysis)
    return (f"ANALYZED risk={analysis.risk} confidence={analysis.confidence} "
            f"breaking={len(analysis.breaking_changes)} 근거={len(collected.documents)}건")


class DescriptionSummarizerClient:
    """stage 3: NVD 영어 설명을 한국어 2~3문장으로 요약한다.

    Haiku 4.5에는 effort(output_config.effort)를 넘기면 오류가 나고, thinking은 안 넘기면 꺼진 채로 돈다 —
    요약에는 둘 다 필요 없어서 넘기지 않는다. 여러 건을 묶어 보내므로 결과를 CVE별로 되돌려 나눌 수 있게
    Structured Outputs(SUMMARY_SCHEMA)로 받는다. 시스템 프롬프트가 짧아 캐시 최소 길이에 못 미치므로 캐시는 붙이지 않는다.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = SUMMARY_MODEL):
        self._client = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self._model = model
        self.usage = TokenUsageTracker()

    def summarize_batch(self, targets: list[CveSummaryTarget]) -> dict[str, str]:
        """여러 CVE를 한 요청으로 요약해 {cve_id: 요약}을 돌려준다. 응답에서 빠진 CVE는 결과에 없다(호출부가 실패로 센다)."""
        response = self._client.messages.create(
            model=self._model,
            max_tokens=SUMMARY_MAX_TOKENS,
            system=load_prompt(SUMMARIZE_SYSTEM),
            output_config={"format": {"type": "json_schema", "schema": SUMMARY_SCHEMA}},
            messages=[{"role": "user", "content": self._build_prompt(targets)}],
        )
        self.usage.record(f"{targets[0].cve_id} 외 {len(targets) - 1}건", response.usage)
        _reject_if_truncated(response, SUMMARY_MAX_TOKENS)

        requested = {t.cve_id for t in targets}
        summaries: dict[str, str] = {}
        for item in json.loads(_strip_code_fence(_extract_text(response)))["summaries"]:
            cve_id, summary = item["cve_id"].strip(), item["summary"].strip()
            # 요청하지 않은 ID(모델이 번호를 잘못 옮긴 경우)는 버린다 — 엉뚱한 CVE에 요약이 붙으면 안 된다.
            if cve_id in requested and summary:
                summaries[cve_id] = summary
        return summaries

    @staticmethod
    def _build_prompt(targets: list[CveSummaryTarget]) -> str:
        # 설명 사이 경계가 흐려지면 요약이 옆 CVE와 섞이므로 CVE마다 제목 줄로 구분한다.
        return "\n\n".join(f"### {t.cve_id}\n{t.description}" for t in targets)


def _summarize_group(summarizer: "DescriptionSummarizerClient", backend: "CveBackendClient",
                     group: list[CveSummaryTarget]) -> list[tuple[CveSummaryTarget, Optional[Exception]]]:
    """묶음 하나를 요약하고 CVE별로 저장한다. _assess_one과 같은 이유로 예외를 잡아서 돌려준다.
    요청 자체가 실패하면 묶음 전체가, 응답에서 빠졌거나 저장이 실패한 CVE는 그 건만 실패로 남는다 —
    실패한 건은 요약이 없으니 다음 배치에서 다시 대기로 잡힌다."""
    try:
        summaries = summarizer.summarize_batch(group)
    except Exception as e:
        return [(t, e) for t in group]

    results: list[tuple[CveSummaryTarget, Optional[Exception]]] = []
    for target in group:
        try:
            if target.cve_id not in summaries:
                raise ValueError("응답에 이 CVE의 요약이 없습니다.")
            backend.submit_summary(target, summaries[target.cve_id])
            results.append((target, None))
        except Exception as e:
            results.append((target, e))
    return results


def _assess_one(ai_client: "VulnAssessorClient", backend: "CveBackendClient",
                 ctx: DependencyContext) -> tuple[DependencyContext, Optional[VulnAssessment], Optional[Exception]]:
    """CVE 하나를 판단하고 저장한다. 병렬 실행 시 스레드에서 그대로 호출되므로
    예외를 여기서 잡아 (ctx, 결과, 에러) 형태로 돌려준다 — 한 건 실패가 나머지를 막지 않도록."""
    try:
        assessment = ai_client.assess(ctx)
        backend.submit_assessment(ctx.id, assessment)
        return ctx, assessment, None
    except Exception as e:
        return ctx, None, e


def run(backend: CveBackendClient) -> BatchReport:
    """stage 1~4를 차례로 돌리고 요약을 돌려준다. 한 단계가 일부 실패해도 다음 단계는 그대로 진행한다."""
    # stage 1: CVE 하나씩 개별 판단. 시스템 프롬프트가 CVE 건마다 동일해서 2건 이상이면 프롬프트
    # 캐시를 쓰는데, 처음부터 여러 건을 동시에 보내면 캐시가 만들어지기 전에 여러
    # 요청이 동시에 도착해 각자 따로 캐시를 써버릴 수 있다(cache_creation 중복).
    # 그래서 첫 건은 혼자 먼저 보내 캐시를 예열한 뒤, 나머지만 병렬로 처리한다.
    pending = backend.fetch_pending_vulnerabilities()
    ai_client = VulnAssessorClient(use_cache=len(pending) > 1)
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
    fix_plan_targets = backend.fetch_pending_fix_plans()
    fix_plan_client = FixPlanGeneratorClient(use_cache=len(fix_plan_targets) > 1)
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

    # stage 3: 설명 요약. 앞 단계와 무관한 작업이라 앞 단계가 일부 실패했어도 그대로 진행한다.
    summary_targets = backend.fetch_pending_summaries()
    summarizer = DescriptionSummarizerClient()
    print(f"설명 요약할 CVE {len(summary_targets)}건")

    skipped_summaries: list[tuple[str, str]] = []
    if summary_targets:
        groups = [summary_targets[i:i + SUMMARY_BATCH_SIZE]
                  for i in range(0, len(summary_targets), SUMMARY_BATCH_SIZE)]
        with ThreadPoolExecutor(max_workers=SUMMARY_MAX_WORKERS) as executor:
            futures = [executor.submit(_summarize_group, summarizer, backend, g) for g in groups]
            for future in as_completed(futures):
                for target, err in future.result():
                    if err is not None:
                        skipped_summaries.append((target.cve_id, str(err)))
                        print(f"[{target.cve_id}] 요약 실패, 건너뜀: {err}")

    # stage 4: 업그레이드 영향 분석. stage 2(fix-plan)가 만든 변경 목록이 입력이라 그 뒤에 돈다. 외부 문서를 받느라
    # 건마다 수 초씩 걸리지만, GitHub 호출 한도(토큰 없으면 IP당 시간당 60회)를 나눠 쓰므로 병렬로 돌리지 않는다.
    impact_targets = backend.fetch_pending_impacts()
    impact_client = UpgradeImpactAnalyzerClient(use_cache=len(impact_targets) > 1)
    print(f"영향 분석할 업그레이드 {len(impact_targets)}건")

    skipped_impacts: list[tuple[str, str]] = []
    impact_counts: dict[str, int] = {}
    for target in impact_targets:
        label = f"{target.coordinate} {target.from_version}→{target.to_version}"
        try:
            result = _analyze_impact(impact_client, backend, target)
            status = result.split()[0]
            impact_counts[status] = impact_counts.get(status, 0) + 1
            print(f"[{label}] {result}")
        except Exception as e:
            skipped_impacts.append((label, str(e)))
            print(f"[{label}] 영향 분석 실패, 건너뜀: {e}")

    report = BatchReport()
    report.summary.append(f"CVE 판단: 성공 {len(pending) - len(skipped_cves)}건 / 건너뜀 {len(skipped_cves)}건")
    report.summary += [f"  - {cve_id}: {reason}" for cve_id, reason in skipped_cves]
    report.summary.append(f"fix-plan 생성: 성공 {len(fix_plan_targets) - len(skipped_apps)}건 / 건너뜀 {len(skipped_apps)}건")
    report.summary += [f"  - {system_name}: {reason}" for system_name, reason in skipped_apps]
    report.summary.append(f"설명 요약: 성공 {len(summary_targets) - len(skipped_summaries)}건 / 건너뜀 {len(skipped_summaries)}건")
    report.summary += [f"  - {cve_id}: {reason}" for cve_id, reason in skipped_summaries]
    # NO_SOURCE는 사람이 직접 봐야 하는 건이라 성공과 따로 센다.
    report.summary.append(f"영향 분석: {impact_counts or '없음'} / 건너뜀 {len(skipped_impacts)}건")
    report.summary += [f"  - {label}: {reason}" for label, reason in skipped_impacts]
    report.usages += [("CVE 판단", MODEL, ai_client.usage), ("fix-plan", MODEL, fix_plan_client.usage),
                      ("설명 요약", SUMMARY_MODEL, summarizer.usage), ("영향 분석", MODEL, impact_client.usage)]
    return report


def main() -> None:
    print_reports([run(CveBackendClient())])


if __name__ == "__main__":
    run_batch(main, "라이브러리 취약점")
