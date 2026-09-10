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

MODEL = "claude-sonnet-5"

# 자바 백엔드 접속 정보. SecurityConfig에서 /api/ai/**는 세션 로그인 없이
# X-Internal-Token 헤더만으로 인증하므로, application.properties의
# ai.internal.token과 반드시 같은 값을 CVE_MONITOR_AI_TOKEN에 넣어줘야 한다.
BASE_URL = os.environ.get("CVE_MONITOR_BASE_URL", "http://localhost:8080")
AI_TOKEN = os.environ.get("CVE_MONITOR_AI_TOKEN", "")


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


def _strip_code_fence(raw_text: str) -> str:
    """지시해도 ```json ... ``` 코드펜스로 감싸서 답하는 경우가 있어 벗겨낸다."""
    text = raw_text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    return fenced.group(1) if fenced else text


def _extract_text(response) -> str:
    """확장 사고(thinking)가 켜지면 content[0]이 ThinkingBlock이라 텍스트 블록을 직접 찾아야 한다."""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            return block.text
    raise ValueError("Claude 응답에 텍스트 블록이 없습니다.")


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

    def assess(self, ctx: DependencyContext) -> VulnAssessment:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            messages=[{"role": "user", "content": self._build_prompt(ctx)}],
        )
        return self._parse_response(_extract_text(response))

    def _build_prompt(self, ctx: DependencyContext) -> str:
        # TODO: 근거 자료(NVD/OSV 상세, changelog 등) 추가, few-shot 예시 보강
        return f"""다음 오픈소스 의존성이 아래 CVE에 실제로 취약한지 판단해줘.

- CVE ID: {ctx.cve_id}
- 심각도: {ctx.severity}
- 설명: {ctx.description}
- 의존성: {ctx.group_id}:{ctx.artifact_id}:{ctx.version}
- 최상위 원인 의존성(직접 의존성): {ctx.brought_in_by}

반드시 아래 JSON 스키마 형식으로만 답해. 다른 텍스트는 출력하지 마.
{{
  "is_vulnerable": true|false,
  "fixed_version": "취약점이 수정된 최소 버전 (모르면 null)",
  "reasoning": "판단 근거를 한국어로 간단히",
  "confidence": "high|medium|low"
}}
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

    def generate(self, target: AppFixPlanTarget) -> FixPlan:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=8192,
            messages=[{"role": "user", "content": self._build_prompt(target)}],
        )
        return self._parse_response(_extract_text(response))

    def _build_prompt(self, target: AppFixPlanTarget) -> str:
        findings_text = "\n".join(
            f"- {f.cve_id} / {f.group_id}:{f.artifact_id} / 현재 {f.installed_version} "
            f"/ 권장 최소 {f.ai_fixed_version} (신뢰도 {f.ai_confidence})"
            for f in target.cve_findings
        )

        return f"""다음은 "{target.system_name}" 프로젝트의 pom.xml이고, 그 아래는 mvn dependency:tree 결과다.
그 아래는 이 프로젝트에서 실제로 취약하다고 이미 확인된 CVE 목록이다(컴포넌트별 권장 최소 버전 포함).

[pom.xml]
{target.pom_xml}

[dependency:tree]
{target.dependency_tree}

[취약점 목록] (CVE ID / groupId:artifactId / 현재 버전 / 권장 최소 버전)
{findings_text}

요청사항:
1. 같은 아티팩트에 CVE가 여러 개 걸려 있으면, 그 아티팩트의 권장 최소 버전 중 가장 높은 걸 최종 목표 버전으로 잡아라.
2. 이 프로젝트가 Spring Boot 등 parent BOM을 쓰고 있다면, parent 버전 업그레이드로 자연스럽게 해결되는지,
   아니면 <netty.version> 같은 개별 property override가 필요한지 판단하고, 더 안전하고 diff가 작은 쪽을 선택해라.
3. 선택한 전략을 반영한 pom.xml 전체를 출력해라.
4. 버전을 올려도 해결이 안 되는 CVE가 있으면(예: 코드/설정 변경이 필요한 경우) 별도로 표시해라.

반드시 아래 JSON 스키마 형식으로만 답해. 다른 텍스트는 출력하지 마.
{{
  "strategy": "PARENT_UPGRADE|PROPERTY_OVERRIDE|MIXED",
  "pom_xml": "수정이 반영된 pom.xml 전체 내용",
  "unresolved_cves": "버전 업그레이드만으론 해결 안 되는 CVE와 이유 (없으면 빈 문자열)",
  "reasoning": "판단 근거를 한국어로 간단히"
}}
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

    for ctx in pending:
        assessment = ai_client.assess(ctx)
        backend.submit_assessment(ctx.id, assessment)
        print(f"[{ctx.cve_id}] vulnerable={assessment.is_vulnerable} "
              f"fixed_version={assessment.fixed_version} confidence={assessment.confidence}")

    # stage 2: 앱 단위로 취합해서 pom.xml 수정안 생성
    fix_plan_client = FixPlanGeneratorClient()
    fix_plan_targets = backend.fetch_pending_fix_plans()
    print(f"fix-plan 생성할 앱 {len(fix_plan_targets)}건")

    for target in fix_plan_targets:
        plan = fix_plan_client.generate(target)
        backend.submit_fix_plan(target.app_id, plan)
        print(f"[{target.system_name}] strategy={plan.strategy} "
              f"unresolved={'있음' if plan.unresolved_cves else '없음'}")


if __name__ == "__main__":
    main()
