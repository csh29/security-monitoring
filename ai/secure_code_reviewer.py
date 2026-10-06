"""시큐어코딩 점검 AI 단계 — 코드 점검(Semgrep 행안부 규칙) 탐지가 진짜 취약한지 판별한다.

결정론(연계 추적)으로 못 정한 높은 등급 탐지만(비밀값 규칙 제외 — 대상은 자바 SecureCodeAiReviewService가 정한다), 걸린 줄을 감싼
메서드를 보고 VULNERABLE/NOT_VULNERABLE/UNCERTAIN을 판별해 저장한다. 라이브러리 취약점 단계(cve_assessor.py)와 무관하다.
판별은 화면 참고용이고 처리여부는 사람이 정한다. 코드는 자바가 비밀값을 가린 뒤 넘겨준다.

보통은 진입점(vuln_assessor.py)이 라이브러리 단계와 함께 돌린다. 이 단계만 돌리려면 `py secure_code_reviewer.py`.
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
from prompt_rules import SECURE_CODE_REVIEW_SYSTEM, load_prompt

SECURE_CODE_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        # 값은 자바 SecureCodeAiReviewService.VERDICTS와 같아야 한다.
        "verdict": {"type": "string", "enum": ["VULNERABLE", "NOT_VULNERABLE", "UNCERTAIN"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reasoning"],
    "additionalProperties": False,
}

# 코드 최대 80줄을 읽고 몇 문장을 내는 일이지만, 값의 흐름을 따라가느라 adaptive thinking이 길어질 수 있어
# CVE 판단(4096)보다 넉넉히 잡는다. 잘리면 저장하지 않으므로(_reject_if_truncated) 다음 배치에서 다시 대기가 된다.
SECURE_CODE_REVIEW_MAX_TOKENS = 8192
# 정해진 세 값 중 하나를 고르는 분류라 CVE 판단과 같은 이유로 medium.
SECURE_CODE_REVIEW_EFFORT = "medium"

# 병렬 워커 수. 라이브러리 stage 1(ASSESS_MAX_WORKERS)과 같은 이유로 첫 건으로 캐시를 예열한 뒤 이 수만큼만 동시에 보낸다.
REVIEW_MAX_WORKERS = 5


@dataclass
class SecureCodeReviewTarget:
    """판별할 코드 점검 탐지 하나(자바 SecureCodeReviewTarget). input_hash는 자바가 준 값을 그대로 되돌려준다
    (어느 입력으로 판별했는지의 기준 — 그사이 재점검으로 코드가 바뀌면 다음 배치에서 다시 대기가 된다)."""

    id: int
    rule_id: str
    kisa_category: str
    kisa_name: str
    cwe: str
    severity: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    code: str
    code_start_line: int
    trace_label: Optional[str]
    trace_evidence: list[str]
    input_hash: str

    @staticmethod
    def from_json(data: dict) -> "SecureCodeReviewTarget":
        return SecureCodeReviewTarget(
            id=data["id"],
            rule_id=data.get("ruleId") or "",
            kisa_category=data.get("kisaCategory") or "",
            kisa_name=data.get("kisaName") or "",
            cwe=data.get("cwe") or "",
            severity=data.get("severity") or "",
            message=data.get("message") or "",
            file_path=data.get("filePath") or "",
            start_line=data.get("startLine") or 0,
            end_line=data.get("endLine") or 0,
            code=data.get("code") or "",
            code_start_line=data.get("codeStartLine") or 1,
            trace_label=data.get("traceLabel"),
            trace_evidence=data.get("traceEvidence") or [],
            input_hash=data["inputHash"],
        )


@dataclass
class SecureCodeReview:
    verdict: str  # "VULNERABLE" | "NOT_VULNERABLE" | "UNCERTAIN"
    confidence: str  # "high" | "medium" | "low"
    reasoning: str


class SecureCodeBackendClient(BackendClient):
    """시큐어코딩 단계가 부르는 /api/ai/** 호출."""

    def fetch_pending_secure_code_reviews(self) -> list[SecureCodeReviewTarget]:
        return [SecureCodeReviewTarget.from_json(item) for item in self._get("/api/ai/secure-code/pending")]

    def submit_secure_code_review(self, target: SecureCodeReviewTarget, review: SecureCodeReview) -> None:
        self._post(f"/api/ai/secure-code/{target.id}/review", {
            "verdict": review.verdict,
            "confidence": review.confidence,
            "reasoning": review.reasoning,
            "inputHash": target.input_hash,
        })


class SecureCodeReviewerClient:
    """stage 5: 코드 점검 탐지 하나를 코드 문맥과 함께 보고 진짜 취약한지 판별한다."""

    def __init__(self, api_key: Optional[str] = None, model: str = MODEL, use_cache: bool = False):
        self._client = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self._model = model
        self._use_cache = use_cache
        self.usage = TokenUsageTracker()

    def review(self, target: SecureCodeReviewTarget) -> SecureCodeReview:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=SECURE_CODE_REVIEW_MAX_TOKENS,
            # 판별 기준은 탐지마다 같은 내용이라 2건 이상이면 캐시를 붙인다(stage 1과 같은 방식).
            system=_system_prompt(load_prompt(SECURE_CODE_REVIEW_SYSTEM), self._use_cache),
            output_config={
                "format": {"type": "json_schema", "schema": SECURE_CODE_REVIEW_SCHEMA},
                "effort": SECURE_CODE_REVIEW_EFFORT,
            },
            messages=[{"role": "user", "content": self._build_prompt(target)}],
        )
        self.usage.record(f"{target.file_path}:{target.start_line}", response.usage)
        _reject_if_truncated(response, SECURE_CODE_REVIEW_MAX_TOKENS)
        data = json.loads(_strip_code_fence(_extract_text(response)))
        return SecureCodeReview(
            verdict=data["verdict"],
            confidence=data["confidence"],
            reasoning=data.get("reasoning", "").strip(),
        )

    @staticmethod
    def _build_prompt(target: SecureCodeReviewTarget) -> str:
        # 줄 번호를 붙이고 탐지된 줄에 >> 를 단다 — 모델이 reasoning에서 줄 번호로 근거를 대게 하고,
        # 메서드 안 어느 호출이 걸렸는지 헷갈리지 않게 한다.
        lines = []
        for offset, line in enumerate(target.code.split("\n")):
            no = target.code_start_line + offset
            mark = ">>" if target.start_line <= no <= max(target.start_line, target.end_line) else "  "
            lines.append(f"{mark} {no:5d} | {line}")
        code = "\n".join(lines)

        if target.trace_label:
            evidence = "\n".join(f"  - {step}" for step in target.trace_evidence) or "  - (근거 없음)"
            trace = f"\n[연계 추적]\n- 판정: {target.trace_label}\n- 따라간 경로:\n{evidence}\n"
        else:
            trace = ""

        return f"""[탐지]
- 규칙: {target.rule_id}
- 행안부 분류/항목: {target.kisa_category} / {target.kisa_name}
- CWE: {target.cwe}
- 등급: {target.severity}
- 규칙 설명: {target.message}
- 파일: {target.file_path} ({target.start_line}줄)
{trace}
[코드]
{code}
"""


def _review_one(reviewer: SecureCodeReviewerClient, backend: "SecureCodeBackendClient",
                target: SecureCodeReviewTarget) -> tuple[SecureCodeReviewTarget, Optional[SecureCodeReview], Optional[Exception]]:
    """탐지 하나를 판별하고 저장한다. _assess_one과 같은 이유로 예외를 잡아서 돌려준다 — 한 건 실패가 나머지를 막지 않도록.
    실패한 건은 판별이 저장되지 않았으니 다음 배치에서 다시 대기로 잡힌다."""
    try:
        review = reviewer.review(target)
        backend.submit_secure_code_review(target, review)
        return target, review, None
    except Exception as e:
        return target, None, e


def run(backend: SecureCodeBackendClient) -> BatchReport:
    """판별 대기를 가져와 판별·저장하고 요약을 돌려준다."""
    review_targets = backend.fetch_pending_secure_code_reviews()
    reviewer = SecureCodeReviewerClient(use_cache=len(review_targets) > 1)
    print(f"코드 점검 판별할 탐지 {len(review_targets)}건")

    skipped_reviews: list[tuple[str, str]] = []
    review_counts: dict[str, int] = {}

    def handle_review(target: SecureCodeReviewTarget, review: Optional[SecureCodeReview], err: Optional[Exception]) -> None:
        label = f"{target.file_path}:{target.start_line} {target.rule_id}"
        if err is not None:
            skipped_reviews.append((label, str(err)))
            print(f"[{label}] 판별 실패, 건너뜀: {err}")
        else:
            review_counts[review.verdict] = review_counts.get(review.verdict, 0) + 1
            print(f"[{label}] verdict={review.verdict} confidence={review.confidence}")

    if review_targets:
        handle_review(*_review_one(reviewer, backend, review_targets[0]))
        if len(review_targets) > 1:
            with ThreadPoolExecutor(max_workers=REVIEW_MAX_WORKERS) as executor:
                futures = [executor.submit(_review_one, reviewer, backend, t) for t in review_targets[1:]]
                for future in as_completed(futures):
                    handle_review(*future.result())

    report = BatchReport()
    report.summary.append(f"코드 점검 판별: {review_counts or '없음'} / 건너뜀 {len(skipped_reviews)}건")
    report.summary += [f"  - {label}: {reason}" for label, reason in skipped_reviews]
    report.usages.append(("코드 점검 판별", MODEL, reviewer.usage))
    return report


def main() -> None:
    print_reports([run(SecureCodeBackendClient())])


if __name__ == "__main__":
    run_batch(main)
