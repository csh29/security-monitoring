"""코드 점검 AI 판별 배치의 안전장치 — 실패 분류·중단·실패 보고·실행 잠금. 실제 API·서버를 부르지 않는다.

ai/ 폴더에서: py -m unittest test_secure_code_reviewer
"""

import os
import unittest
from unittest import mock

import anthropic
import httpx
import requests

import ai_common
import secure_code_reviewer as scr


def _api_error(cls, status: int, message: str = "error"):
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls(message, response=httpx.Response(status, request=request), body=None)


def _http_error(status: int) -> requests.HTTPError:
    response = requests.Response()
    response.status_code = status
    return requests.HTTPError(f"{status}", response=response)


def _target(i: int) -> scr.SecureCodeReviewTarget:
    return scr.SecureCodeReviewTarget(
        id=i, rule_id="kisa-path-traversal-dynamic-path", kisa_category="입력", kisa_name="경로 조작", cwe="CWE-22",
        severity="HIGH", message="m", file_path=f"A{i}.java", start_line=1, end_line=1, code="x", code_start_line=1,
        trace_label=None, trace_evidence=[], input_hash=f"h{i}")


class FakeBackend:
    def __init__(self, targets):
        self.targets = targets
        self.saved = []
        self.failures = []

    def fetch_pending_secure_code_reviews(self):
        return self.targets

    def submit_secure_code_review(self, target, review):
        self.saved.append(target.id)

    def report_secure_code_failure(self, target, reason):
        self.failures.append((target.id, reason))


class FakeReviewer:
    """id별로 낼 결과(예외 또는 None=성공)를 정해 둔다."""

    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.called = []
        self.usage = ai_common.TokenUsageTracker()

    def review(self, target):
        self.called.append(target.id)
        outcome = self.outcomes.get(target.id)
        if isinstance(outcome, Exception):
            raise outcome
        return scr.SecureCodeReview("VULNERABLE", "high", "요약", "- 근거", "공격", "조치")


class ClassifyFailureTest(unittest.TestCase):

    def test_키_권한_모델_잔액_오류는_배치를_멈춘다(self):
        self.assertEqual("fatal", scr.classify_failure(_api_error(anthropic.AuthenticationError, 401)))
        self.assertEqual("fatal", scr.classify_failure(_api_error(anthropic.PermissionDeniedError, 403)))
        self.assertEqual("fatal", scr.classify_failure(_api_error(anthropic.NotFoundError, 404)))
        self.assertEqual("fatal", scr.classify_failure(
            _api_error(anthropic.BadRequestError, 400, "Your credit balance is too low")))
        self.assertEqual("fatal", scr.classify_failure(_http_error(401)))  # 백엔드 내부 토큰 오류

    def test_요청_한도_연결_서버_오류는_세지_않는다(self):
        self.assertEqual("transient", scr.classify_failure(_api_error(anthropic.RateLimitError, 429)))
        self.assertEqual("transient", scr.classify_failure(_api_error(anthropic.InternalServerError, 500)))
        self.assertEqual("transient", scr.classify_failure(requests.ConnectionError("down")))
        self.assertEqual("transient", scr.classify_failure(_http_error(503)))

    def test_응답_잘림_형식_오류_저장_거절은_서버에_알린다(self):
        self.assertEqual("content", scr.classify_failure(ValueError("max_tokens에서 잘렸습니다")))
        self.assertEqual("content", scr.classify_failure(KeyError("verdict")))
        self.assertEqual("content", scr.classify_failure(_http_error(400)))  # 취약인데 공격·조치 없음 등


class RunStopTest(unittest.TestCase):

    def test_치명_오류가_나면_남은_건을_보내지_않는다(self):
        targets = [_target(i) for i in range(1, 21)]
        backend = FakeBackend(targets)
        reviewer = FakeReviewer({1: _api_error(anthropic.AuthenticationError, 401)})

        report = scr.run(backend, reviewer)

        self.assertEqual([1], reviewer.called)  # 첫 건(캐시 예열)에서 멈춰 나머지는 보내지 않는다
        self.assertEqual([], backend.failures)  # 키 오류는 탐지 탓이 아니라 세지 않는다
        self.assertTrue(any("중단" in line for line in report.summary))

    def test_내용_실패는_서버에_알리고_계속한다(self):
        targets = [_target(i) for i in range(1, 4)]
        backend = FakeBackend(targets)
        reviewer = FakeReviewer({2: _http_error(400)})

        scr.run(backend, reviewer)

        self.assertEqual([2], [f[0] for f in backend.failures])
        self.assertEqual([1, 3], sorted(backend.saved))

    def test_연속으로_실패하면_멈춘다(self):
        targets = [_target(i) for i in range(1, 51)]
        backend = FakeBackend(targets)
        reviewer = FakeReviewer({i: ValueError("잘림") for i in range(1, 51)})

        report = scr.run(backend, reviewer)

        # 멈추기 전에 이미 워커가 집어 간 건은 더 갈 수 있지만(가짜는 즉시 끝나 실제보다 많다) 50건 전부를 보내지는 않는다.
        self.assertLess(len(reviewer.called), len(targets))
        self.assertTrue(any("연속" in line for line in report.summary))


class StageLockTest(unittest.TestCase):

    def test_같은_기능은_한_번만_잡히고_PID를_남긴다(self):
        name = "unittest"
        pid_path = os.path.join(os.path.dirname(os.path.abspath(ai_common.__file__)), f".batch-{name}.pid")
        with ai_common.stage_lock(name) as first:
            self.assertTrue(first)
            with open(pid_path, encoding="ascii") as f:
                self.assertEqual(str(os.getpid()), f.read())
            with ai_common.stage_lock(name) as second:
                self.assertFalse(second)
        self.assertFalse(os.path.exists(pid_path))  # 끝나면 PID 파일을 지운다
        with ai_common.stage_lock(name) as again:
            self.assertTrue(again)
        os.remove(pid_path.replace(".pid", ".lock"))


class FetchPendingTest(unittest.TestCase):

    def test_서버가_띄운_배치는_그_앱의_대기만_가져온다(self):
        backend = scr.SecureCodeBackendClient(token="t")
        with mock.patch.dict(os.environ, {"SECURITY_MONITOR_APP_ID": "3"}), \
                mock.patch.object(backend, "_get", return_value=[]) as get:
            backend.fetch_pending_secure_code_reviews()
        get.assert_called_once_with("/api/ai/secure-code/pending", {"appId": "3"})


class SameOriginTest(unittest.TestCase):

    def test_같은_출처_지점을_결과와_실패_보고에_함께_싣는다(self):
        target = scr.SecureCodeReviewTarget.from_json({
            "id": 1, "inputHash": "h1", "code": "x", "codeStartLine": 1, "startLine": 1, "filePath": "A.java",
            "sameOrigin": [{"id": 2, "inputHash": "h2", "filePath": "B.java", "startLine": 88, "ruleId": "r",
                            "sink": "B.java:88 new File(path)", "code": "a\nb", "codeStartLine": 87}]})
        backend = scr.SecureCodeBackendClient(token="t")
        review = scr.SecureCodeReview("VULNERABLE", "high", "요약", "- 근거", "공격", "조치")
        with mock.patch.object(backend, "_post") as post:
            backend.submit_secure_code_review(target, review)
            backend.report_secure_code_failure(target, "잘림")
        self.assertEqual([{"id": 2, "inputHash": "h2"}], post.call_args_list[0].args[1]["sameOrigin"])
        self.assertEqual([{"id": 2, "inputHash": "h2"}], post.call_args_list[1].args[1]["sameOrigin"])
        prompt = scr.SecureCodeReviewerClient._build_prompt(target)
        self.assertIn("[같은 출처의 다른 지점]", prompt)
        self.assertIn("B.java:88", prompt)


class SystemContextTest(unittest.TestCase):

    def test_시스템_구조를_프롬프트에_싣고_없으면_구역도_없다(self):
        target = scr.SecureCodeReviewTarget.from_json({
            "id": 1, "inputHash": "h1", "code": "x", "codeStartLine": 1, "startLine": 1, "filePath": "A.java",
            "systemContext": ["인터셉터: TokenInterceptor — WebConfig.java addInterceptor(TokenInterceptor)"]})
        prompt = scr.SecureCodeReviewerClient._build_prompt(target)
        self.assertIn("[시스템 구조]\n- 인터셉터: TokenInterceptor", prompt)

        bare = scr.SecureCodeReviewTarget.from_json({"id": 2, "inputHash": "h2", "code": "x", "startLine": 1})
        self.assertNotIn("[시스템 구조]", scr.SecureCodeReviewerClient._build_prompt(bare))


if __name__ == "__main__":
    unittest.main()
