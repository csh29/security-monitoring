"""AI 배치 진입점 — 서버(AiAssessmentTriggerService, 설정 ai.assessor.script)가 띄우는 스크립트.

두 기능의 AI 단계를 차례로 돌리고 요약·토큰 사용량을 한 번에 찍는다. 기능별 내용은 각 모듈에 있다.
  - cve_assessor.py         라이브러리 취약점(CVE): 판단(stage 1) → fix-plan(2) → 설명 요약(3) → 업그레이드 영향 분석(4)
  - secure_code_reviewer.py 시큐어코딩 점검: 코드 점검 탐지 판별(stage 5)
  - ai_common.py            모델·백엔드 접속·응답 처리·토큰 집계·배치 로그 형식

한 기능의 단계가 통째로 실패해도(예외) 다른 기능은 돈다 — 둘은 서로 무관하다. 대기열에서 뺀 게 없으니 실패한 쪽은 다음 배치에서 다시 대기가 된다.
한 기능만 돌리려면 그 모듈을 직접 실행한다(`py cve_assessor.py`, `py secure_code_reviewer.py`).
"""

from __future__ import annotations

import traceback

import cve_assessor
import secure_code_reviewer
from ai_common import BatchReport, print_reports, run_batch


def main() -> None:
    reports: list[BatchReport] = []
    failed: list[str] = []
    for name, run_stage in (("라이브러리 취약점", lambda: cve_assessor.run(cve_assessor.CveBackendClient())),
                            ("시큐어코딩", lambda: secure_code_reviewer.run(secure_code_reviewer.SecureCodeBackendClient()))):
        try:
            reports.append(run_stage())
        except Exception:
            traceback.print_exc()
            failed.append(name)
            reports.append(BatchReport(summary=[f"{name}: 단계 실행 중 오류로 중단 — 위 traceback 참고"]))
    print_reports(reports)
    if failed:
        # 종료 코드로 서버가 실패를 기록한다(AiAssessmentTriggerService.lastExitCode).
        raise RuntimeError(f"AI 단계 실패: {', '.join(failed)}")


if __name__ == "__main__":
    run_batch(main)
