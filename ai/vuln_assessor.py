"""CVE 취약점 판단 AI 어시스턴트.

두 단계로 동작한다.
  stage 1) 자바 백엔드(/api/ai/**)에서 아직 AI 판단이 없는 취약점을 하나씩 읽어와서,
           이 의존성 버전이 실제로 해당 CVE에 취약한지 / 어떤 버전으로 올려야 하는지 판단하고 저장한다.
  stage 2) stage 1에서 "취약함"으로 확정된 CVE들을, 앱(pom.xml) 단위로 모아서
           한 번에 취합 판단시켜 pom.xml 수정안(diff가 작은 전략 선택 포함)을 만들고 저장한다.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Optional

import anthropic
import requests

from prompt_rules import ASSESS_SYSTEM, FIX_PLAN_SYSTEM, load_prompt

MODEL = "claude-sonnet-5"

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

    @staticmethod
    def from_json(data: dict) -> "CveFinding":
        return CveFinding(
            cve_id=data["cveId"],
            group_id=data.get("groupId") or "",
            artifact_id=data.get("artifactId") or "",
            installed_version=data.get("installedVersion") or "",
            ai_fixed_version=data.get("aiFixedVersion"),
            ai_confidence=data.get("aiConfidence"),
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
    토큰을 많이 쓰는지 디버깅할 때 쓴다."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0

    def record(self, label: str, usage) -> None:
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0) or 0
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
            output_config={
                "format": {"type": "json_schema", "schema": ASSESSMENT_SCHEMA},
            },
            messages=[{"role": "user", "content": self._build_prompt(ctx)}],
        )
        self.usage.record(ctx.cve_id, response.usage)
        _reject_if_truncated(response, ASSESS_MAX_TOKENS)
        return self._parse_response(_extract_text(response))

    def _build_prompt(self, ctx: DependencyContext) -> str:
        # 판정 룰은 전부 시스템 프롬프트(prompts/)로 갔다. 여기는 데이터만 담는다.
        return f"""- CVE ID: {ctx.cve_id}
- 심각도: {ctx.severity}
- 설명: {ctx.description}
- 의존성: {ctx.group_id}:{ctx.artifact_id}:{ctx.version}
- 최상위 원인 의존성(직접 의존성): {ctx.brought_in_by}
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

    def _build_prompt(self, target: AppFixPlanTarget) -> str:
        findings_text = "\n".join(
            f"- {f.cve_id} / {f.group_id}:{f.artifact_id} / 현재 {f.installed_version} "
            f"/ 권장 최소 {f.ai_fixed_version} (신뢰도 {f.ai_confidence})"
            for f in target.cve_findings
        )

        return f"""[대상 프로젝트] {target.system_name}

[pom.xml]
{target.pom_xml}

[dependency:tree]
{target.dependency_tree}

[취약점 목록] (CVE ID / groupId:artifactId / 현재 버전 / 권장 최소 버전 / 신뢰도)
{findings_text}
"""

    def _parse_response(self, raw_text: str) -> FixPlan:
        data = json.loads(_strip_code_fence(raw_text))
        return FixPlan(
            strategy=data.get("strategy", "MIXED"),
            pom_xml=data.get("pom_xml", ""),
            unresolved_cves=data.get("unresolved_cves", ""),
            reasoning=data.get("reasoning", ""),
        )


def main() -> None:
    backend = CveMonitorClient()

    # stage 1: CVE 하나씩 개별 판단
    ai_client = VulnAssessorClient()
    pending = backend.fetch_pending_vulnerabilities()
    print(f"판단할 취약점 {len(pending)}건")

    skipped_cves: list[tuple[str, str]] = []
    for ctx in pending:
        try:
            assessment = ai_client.assess(ctx)
            backend.submit_assessment(ctx.id, assessment)
            print(f"[{ctx.cve_id}] vulnerable={assessment.is_vulnerable} "
                  f"fixed_version={assessment.fixed_version} confidence={assessment.confidence}")
        except Exception as e:
            # 한 건 실패했다고 나머지 CVE 판단까지 통째로 포기하지 않는다.
            skipped_cves.append((ctx.cve_id, str(e)))
            print(f"[{ctx.cve_id}] 판단 실패, 건너뜀: {e}")

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
