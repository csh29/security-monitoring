"""CVE 취약점 판단 AI 어시스턴트.

자바 백엔드(/api/ai/**)에서 아직 AI 판단이 없는 취약점 목록을 읽어온 뒤,
AI에게 다음 두 가지를 판단시키고 그 결과를 다시 백엔드에 저장한다.
  1) 이 의존성 버전이 실제로 해당 CVE에 취약한지 (is_vulnerable)
  2) 취약하다면 어떤 버전으로 올려야 하는지 (fixed_version)
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
        return self._parse_response(response.content[0].text)

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
        # 지시해도 ```json ... ``` 코드펜스로 감싸서 답하는 경우가 있어 벗겨낸 뒤 파싱한다.
        text = raw_text.strip()
        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if fenced:
            text = fenced.group(1)

        data = json.loads(text)
        return VulnAssessment(
            is_vulnerable=data["is_vulnerable"],
            fixed_version=data.get("fixed_version"),
            reasoning=data.get("reasoning", ""),
            confidence=data.get("confidence", "low"),
        )


def main() -> None:
    backend = CveMonitorClient()
    ai_client = VulnAssessorClient()

    pending = backend.fetch_pending_vulnerabilities()
    print(f"판단할 취약점 {len(pending)}건")

    for ctx in pending:
        assessment = ai_client.assess(ctx)
        backend.submit_assessment(ctx.id, assessment)
        print(f"[{ctx.cve_id}] vulnerable={assessment.is_vulnerable} "
              f"fixed_version={assessment.fixed_version} confidence={assessment.confidence}")


if __name__ == "__main__":
    main()
