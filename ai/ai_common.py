"""AI 배치 공통 — 모델, 자바 백엔드 접속, Claude 응답 처리, 토큰 집계, 배치 로그 형식.

라이브러리 취약점(cve_assessor.py)과 시큐어코딩 점검(secure_code_reviewer.py)이 함께 쓴다. 기능별 판단 로직은 두지 않는다.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

import requests

MODEL = "claude-sonnet-5"

# 자바 백엔드 접속 정보. SecurityConfig에서 /api/ai/**는 세션 로그인 없이
# X-Internal-Token 헤더만으로 인증하므로, application.properties의
# ai.internal.token과 반드시 같은 값을 SECURITY_MONITOR_AI_TOKEN에 넣어줘야 한다.
BASE_URL = os.environ.get("SECURITY_MONITOR_BASE_URL", "http://localhost:8080")
AI_TOKEN = os.environ.get("SECURITY_MONITOR_AI_TOKEN", "")


class BackendClient:
    """자바 백엔드의 /api/ai/** 와 통신하는 클라이언트의 공통 부분. 기능별 호출은 각 모듈이 상속해서 둔다."""

    def __init__(self, base_url: str = BASE_URL, token: str = AI_TOKEN):
        if not token:
            raise ValueError("SECURITY_MONITOR_AI_TOKEN 환경변수가 비어 있습니다.")
        self._base_url = base_url.rstrip("/")
        self._headers = {"X-Internal-Token": token}

    def _get(self, path: str):
        response = requests.get(f"{self._base_url}{path}", headers=self._headers, timeout=30)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: dict, timeout: int = 30) -> None:
        response = requests.post(f"{self._base_url}{path}", headers=self._headers, json=body, timeout=timeout)
        response.raise_for_status()


def _system_prompt(text: str, use_cache: bool) -> list[dict]:
    """시스템 프롬프트 블록. 같은 시스템 프롬프트로 이번 배치에서 요청이 2번 이상 갈 때만 캐시를 붙인다.

    캐시 쓰기는 입력 단가의 1.25배, 읽기는 0.1배라 5분 안에 두 번 이상 읽혀야 이득이다. 실제 운영에선
    자바가 결정론적으로 먼저 판정해서 CVE 판단은 거의 0건이고 fix-plan도 스캔 한 번에 앱 1건이라,
    무조건 붙여 두면 읽히지 않는 캐시 쓰기 할증(0.25배)만 매번 냈다(ai-assessor.log에서 cache_read=0 확인).
    """
    block = {"type": "text", "text": text}
    if use_cache:
        block["cache_control"] = {"type": "ephemeral"}
    return [block]


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


@dataclass
class BatchReport:
    """한 기능(라이브러리 취약점 / 시큐어코딩)이 배치 끝에 남기는 요약. 진입점(vuln_assessor.py)이 모아서 찍는다.

    summary: "=== 요약 ===" 아래에 찍을 줄(실패 건 포함)
    usages: (라벨, 모델, 사용량) — 모델이 MODEL과 같은 것만 합계에 더한다(단가가 달라서).
    """

    summary: list[str] = field(default_factory=list)
    usages: list[tuple[str, str, TokenUsageTracker]] = field(default_factory=list)


def print_reports(reports: list[BatchReport]) -> None:
    # 한 화면 가득 스크롤한 로그 사이에서 실패 건만 놓치지 않도록 끝에 다시 요약해서 보여준다.
    print()
    print("=== 요약 ===")
    for report in reports:
        for line in report.summary:
            print(line)

    print()
    print("=== 토큰 사용량 ===")
    same_model: list[TokenUsageTracker] = []
    for report in reports:
        for label, model, usage in report.usages:
            # 모델이 다른 단계(설명 요약의 Haiku)는 단가가 달라 합계에 섞지 않고 따로 본다.
            print(f"{label}: {usage.summary()}" if model == MODEL else f"{label}({model}): {usage.summary()}")
            if model == MODEL:
                same_model.append(usage)
    print(f"합계({MODEL}): input={sum(u.input_tokens for u in same_model)} "
          f"output={sum(u.output_tokens for u in same_model)} "
          f"cache_read={sum(u.cache_read_tokens for u in same_model)} "
          f"cache_creation={sum(u.cache_creation_tokens for u in same_model)}")


_LOG_LOCK = threading.Lock()


class _TimestampedStream:
    """줄마다 앞에 "[YYYY-MM-DD HH:MM:SS][traceId] "를 붙여 쓰는 stdout/stderr 대체.

    서버가 이 배치의 표준출력·표준에러를 ai-assessor.log 하나에 이어 붙이는데(AiAssessmentTriggerService),
    시각이 없으면 어느 호출이 오래 걸렸는지 볼 수 없고, 실행 구분이 빈 줄뿐이면 로그 중간의 줄이 어느 실행
    것인지 알 수 없었다. traceId는 실행마다 하나라 grep으로 한 실행만 골라낼 수 있다. print를 전부 바꾸지 않고
    스트림에서 붙이므로 예외 traceback 줄에도 같이 붙는다. 빈 줄은 구분용이라 아무것도 붙이지 않는다.

    print는 본문과 줄바꿈을 따로 write하므로, 병렬로 도는 스레드끼리 한 줄이 섞이지 않게 스레드별로 한 줄을
    다 모은 뒤 락을 잡고 한 번에 쓴다.
    """

    def __init__(self, stream, trace_id: str):
        self._stream = stream
        self._trace_id = trace_id
        self._local = threading.local()

    def write(self, text: str) -> int:
        *lines, rest = (getattr(self._local, "pending", "") + text).split("\n")
        self._local.pending = rest
        if lines:
            prefix = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][{self._trace_id}] "
            out = "".join(f"{prefix}{line}\n" if line.strip() else "\n" for line in lines)
            with _LOG_LOCK:
                self._stream.write(out)
                self._stream.flush()
        return len(text)

    def flush(self) -> None:
        self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


def run_batch(main: Callable[[], None], label: str = "") -> None:
    """배치 로그 형식(시각·traceId·시작/종료 줄)을 씌워 main을 돌리고 종료 코드로 끝낸다. 각 모듈을 단독 실행할 때도 같은 형식을 쓴다.
    label은 시작 줄에 붙일 기능 이름(라이브러리 취약점 / 시큐어코딩) — 어느 배치의 로그인지 첫 줄에서 보이게."""
    # 서버가 띄우면 SECURITY_MONITOR_TRACE_ID를 넘기고 서버 로그의 "배치 실행 시작" 줄에도 같은 값을 찍는다 — 두 로그를
    # 이 값으로 서로 찾아간다. 사람이 직접 돌리면 없으므로 여기서 만든다.
    trace_id = os.environ.get("SECURITY_MONITOR_TRACE_ID") or uuid.uuid4().hex[:8]
    sys.stdout = _TimestampedStream(sys.stdout, trace_id)
    sys.stderr = _TimestampedStream(sys.stderr, trace_id)
    print(f"===== AI 배치 시작({label}) =====" if label else "===== AI 배치 시작 =====")
    exit_code = 0
    try:
        main()
    except Exception:
        # 인터프리터가 종료하면서 찍게 두면 아래 구분용 빈 줄보다 traceback이 뒤에 붙는다 — 직접 찍고 종료 코드를 지킨다
        # (서버가 종료 코드로 성공/실패를 기록한다: AiAssessmentTriggerService.lastExitCode).
        traceback.print_exc()
        exit_code = 1
    print(f"===== AI 배치 종료(exit={exit_code}) =====")
    # 같은 로그 파일에 실행이 계속 이어 붙으므로, 실행 끝마다 빈 줄을 하나 더 넣어 다음 실행과 구분한다.
    print()
    sys.exit(exit_code)
