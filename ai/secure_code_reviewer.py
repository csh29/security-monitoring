"""시큐어코딩 점검 AI 단계 — 코드 점검 탐지(대상은 자바 SecureCodeAiReviewService가 정함)를 감싼 메서드와 함께 보고
VULNERABLE/NOT_VULNERABLE/UNCERTAIN을 판별해 저장한다. 판별은 참고용이고 처리여부는 사람이 정한다.
보통은 서버가 `vuln_assessor.py securecode`로 띄우고, 직접 돌리려면 `py secure_code_reviewer.py`(같은 실행 잠금을 잡는다).
"""

from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

import anthropic
import requests

from ai_common import (MODEL, BackendClient, BatchReport, TokenUsageTracker, _extract_text, _reject_if_truncated,
                       _strip_code_fence, _system_prompt, print_reports, run_batch, stage_lock)
from prompt_rules import SECURE_CODE_REVIEW_SYSTEM, load_prompt

SECURE_CODE_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        # 값은 자바 SecureCodeAiReviewService.VERDICTS와 같아야 한다.
        "verdict": {"type": "string", "enum": ["VULNERABLE", "NOT_VULNERABLE", "UNCERTAIN"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        # 한 문단 이유는 무엇을 해야 하는지가 묻혀서, 사람이 읽기 쉽게 항목으로 나눠 받는다.
        "summary": {"type": "string"},
        "reasoning": {"type": "string"},
        "attack": {"type": "string"},
        "fix": {"type": "string"},
    },
    "required": ["verdict", "confidence", "summary", "reasoning", "attack", "fix"],
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
    """판별할 코드 점검 탐지 하나(자바 SecureCodeReviewTarget). input_hash는 어느 입력으로 판별했는지의 기준이라
    자바가 준 값을 그대로 되돌려준다."""

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
    # 탐지 메서드와 함께 보는 다른 메서드들(자바 AiRelatedCode — path, startLine, code, reason). .java만, 비밀값은 자바가 가렸다.
    related_code: list[dict] = field(default_factory=list)
    # 같은 출처의 다른 지점(자바 SameOriginMember). 같은 원인을 두 번 묻지 않게 이 건과 한 번에 판별하고 결과를 함께 보낸다.
    same_origin: list[dict] = field(default_factory=list)
    # 이 앱(시스템)의 구조 사실(자바 SecureCodeSystemContext — 인터셉터·필터·세션 덮어쓰기·로그인 정보 이름). 코드가 아니라 이름과 근거 한 줄.
    system_context: list[str] = field(default_factory=list)

    def same_origin_refs(self) -> list[dict]:
        return [{"id": m["id"], "inputHash": m["inputHash"]} for m in self.same_origin]

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
            related_code=data.get("relatedCode") or [],
            same_origin=data.get("sameOrigin") or [],
            system_context=data.get("systemContext") or [],
        )


@dataclass
class SecureCodeReview:
    verdict: str  # "VULNERABLE" | "NOT_VULNERABLE" | "UNCERTAIN"
    confidence: str  # "high" | "medium" | "low"
    summary: str  # 결론 한 문장
    reasoning: str  # 근거 — 줄 번호를 단 글머리
    attack: str  # 예상 공격. 취약하지 않으면 ""
    fix: str  # 조치 방법. 취약하지 않으면 ""


class SecureCodeBackendClient(BackendClient):
    """시큐어코딩 단계가 부르는 /api/ai/** 호출."""

    def fetch_pending_secure_code_reviews(self) -> list[SecureCodeReviewTarget]:
        """판별 대기. 서버가 점검 뒤 띄운 배치는 그 앱만(SECURITY_MONITOR_APP_ID), 건수 상한은 서버가 정한다(ai.securecode.max-per-run)."""
        app_id = os.environ.get("SECURITY_MONITOR_APP_ID")
        params = {"appId": app_id} if app_id else None
        return [SecureCodeReviewTarget.from_json(item) for item in self._get("/api/ai/secure-code/pending", params)]

    def report_secure_code_failure(self, target: SecureCodeReviewTarget, reason: str) -> None:
        """같은 입력으로 다시 해도 실패할 판별을 알린다 — 서버가 세어 상한에 닿으면 대기에서 뺀다(배치마다 재과금하지 않게)."""
        self._post(f"/api/ai/secure-code/{target.id}/failure", {
            "inputHash": target.input_hash, "reason": reason[:500], "sameOrigin": target.same_origin_refs()})

    def submit_secure_code_review(self, target: SecureCodeReviewTarget, review: SecureCodeReview) -> None:
        self._post(f"/api/ai/secure-code/{target.id}/review", {
            "verdict": review.verdict,
            "confidence": review.confidence,
            "summary": review.summary,
            "reasoning": review.reasoning,
            "attack": review.attack,
            "fix": review.fix,
            "sameOrigin": target.same_origin_refs(),
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
            summary=data.get("summary", "").strip(),
            reasoning=data.get("reasoning", "").strip(),
            attack=data.get("attack", "").strip(),
            fix=data.get("fix", "").strip(),
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

        related = ""
        for item in target.related_code:
            body = "\n".join(f"   {item.get('startLine', 1) + i:5d} | {line}"
                             for i, line in enumerate((item.get("code") or "").split("\n")))
            related += f"\n--- {item.get('path')} ({item.get('reason')})\n{body}\n"
        related = f"\n[관련 코드]{related}" if related else ""

        system = "\n".join(f"- {line}" for line in target.system_context)
        system = f"\n[시스템 구조]\n{system}\n" if system else ""

        same = ""
        for member in target.same_origin:
            head = f"\n--- {member.get('filePath')}:{member.get('startLine')} ({member.get('ruleId')})"
            sink = f"\n    위험 호출: {member.get('sink')}" if member.get("sink") else ""
            body = ""
            if member.get("code"):
                start = member.get("codeStartLine") or 1
                body = "\n" + "\n".join(
                    f"{'>>' if start + i == member.get('startLine') else '  '} {start + i:5d} | {line}"
                    for i, line in enumerate(member["code"].split("\n")))
            same += head + sink + body + "\n"
        same = f"\n[같은 출처의 다른 지점]{same}" if same else ""

        return f"""[탐지]
- 규칙: {target.rule_id}
- 행안부 분류/항목: {target.kisa_category} / {target.kisa_name}
- CWE: {target.cwe}
- 등급: {target.severity}
- 규칙 설명: {target.message}
- 파일: {target.file_path} ({target.start_line}줄)
{system}{trace}
[코드]
{code}
{related}{same}"""


# 연속으로 이만큼 실패하면 배치를 멈춘다 — 원인이 건마다가 아니라 공통(모델·서버·네트워크)일 가능성이 높고, 계속 보내면 과금만 쌓인다.
MAX_CONSECUTIVE_FAILURES = 5


def classify_failure(err: Exception) -> str:
    """판별 실패의 종류.
    - "fatal": 다른 건도 똑같이 실패한다(API 키·권한·모델 없음·잔액 부족, 백엔드 토큰 오류) — 배치를 멈춘다.
    - "transient": 잠시 뒤 다시 하면 될 수 있다(요청 한도·연결·서버 오류) — 실패로 세지 않는다(다음 배치가 다시 가져간다).
    - "content": 같은 입력으로 다시 해도 실패할 것(응답 잘림·형식 오류·서버가 저장 거절) — 서버에 알려 센다."""
    if isinstance(err, (anthropic.AuthenticationError, anthropic.PermissionDeniedError, anthropic.NotFoundError)):
        return "fatal"
    if isinstance(err, anthropic.BadRequestError) and "credit balance" in str(err).lower():
        return "fatal"
    if isinstance(err, (anthropic.RateLimitError, anthropic.APIConnectionError, anthropic.InternalServerError,
                        requests.ConnectionError, requests.Timeout)):
        return "transient"
    if isinstance(err, requests.HTTPError) and err.response is not None:
        status = err.response.status_code
        if status == 401:
            return "fatal"
        if status >= 500:
            return "transient"
    return "content"


def _review_one(reviewer: SecureCodeReviewerClient, backend: "SecureCodeBackendClient",
                target: SecureCodeReviewTarget,
                stop: threading.Event) -> tuple[SecureCodeReviewTarget, Optional[SecureCodeReview], Optional[Exception]]:
    """탐지 하나를 판별하고 저장한다. 한 건 실패가 나머지를 막지 않도록 예외를 잡아서 돌려주고, 배치가 멈췄으면 보내지 않는다."""
    if stop.is_set():
        return target, None, None
    try:
        review = reviewer.review(target)
        backend.submit_secure_code_review(target, review)
        return target, review, None
    except Exception as e:
        return target, None, e


def run(backend: SecureCodeBackendClient, reviewer: Optional[SecureCodeReviewerClient] = None) -> BatchReport:
    """판별 대기를 가져와 판별·저장하고 요약을 돌려준다."""
    review_targets = backend.fetch_pending_secure_code_reviews()
    # reviewer는 테스트가 가짜를 넣을 때만 받는다(실제 API를 부르지 않고 중단 규칙을 확인).
    reviewer = reviewer or SecureCodeReviewerClient(use_cache=len(review_targets) > 1)
    print(f"코드 점검 판별할 탐지 {len(review_targets)}건")

    skipped_reviews: list[tuple[str, str]] = []
    review_counts: dict[str, int] = {}
    stop = threading.Event()
    stop_reason: list[str] = []
    consecutive_failures = 0

    def handle_review(target: SecureCodeReviewTarget, review: Optional[SecureCodeReview], err: Optional[Exception]) -> None:
        nonlocal consecutive_failures
        label = f"{target.file_path}:{target.start_line} {target.rule_id}"
        if target.same_origin:
            label += f" (+같은 출처 {len(target.same_origin)}건)"
        if review is None and err is None:
            return  # 배치가 멈춰 보내지 않은 건 — 대기로 남는다
        if err is None:
            consecutive_failures = 0
            review_counts[review.verdict] = review_counts.get(review.verdict, 0) + 1
            print(f"[{label}] verdict={review.verdict} confidence={review.confidence}")
            return
        kind = classify_failure(err)
        consecutive_failures += 1
        skipped_reviews.append((label, f"[{kind}] {err}"))
        print(f"[{label}] 판별 실패({kind}), 건너뜀: {err}")
        if kind == "content":
            try:
                backend.report_secure_code_failure(target, f"{type(err).__name__}: {err}")
            except Exception as report_err:  # 실패 보고가 실패해도 배치는 계속 — 다음 배치에서 다시 센다
                print(f"[{label}] 실패 보고 실패: {report_err}")
        if kind == "fatal" and not stop.is_set():
            stop_reason.append(f"더 보내도 같은 오류라 멈춤: {type(err).__name__}: {err}")
            stop.set()
        elif consecutive_failures >= MAX_CONSECUTIVE_FAILURES and not stop.is_set():
            stop_reason.append(f"연속 {consecutive_failures}건 실패로 멈춤(마지막: {type(err).__name__})")
            stop.set()

    if review_targets:
        handle_review(*_review_one(reviewer, backend, review_targets[0], stop))
        if len(review_targets) > 1 and not stop.is_set():
            with ThreadPoolExecutor(max_workers=REVIEW_MAX_WORKERS) as executor:
                futures = [executor.submit(_review_one, reviewer, backend, t, stop) for t in review_targets[1:]]
                for future in as_completed(futures):
                    if future.cancelled():
                        continue
                    handle_review(*future.result())
                    if stop.is_set():
                        for pending in futures:
                            pending.cancel()  # 아직 시작 안 한 건은 보내지 않는다(시작한 건은 stop을 보고 바로 돌아온다)

    report = BatchReport()
    if stop_reason:
        print(f"!! 코드 점검 판별 중단: {stop_reason[0]}")
        report.summary.append(f"코드 점검 판별 중단: {stop_reason[0]} — 남은 건은 대기로 남는다")
    report.summary.append(f"코드 점검 판별: {review_counts or '없음'} / 건너뜀 {len(skipped_reviews)}건")
    report.summary += [f"  - {label}: {reason}" for label, reason in skipped_reviews]
    report.usages.append(("코드 점검 판별", MODEL, reviewer.usage))
    return report


def main() -> None:
    with stage_lock("securecode") as acquired:
        if not acquired:
            print("시큐어코딩: 이미 실행 중인 배치가 있어 건너뜁니다.")
            return
        print_reports([run(SecureCodeBackendClient())])


if __name__ == "__main__":
    run_batch(main, "시큐어코딩")
