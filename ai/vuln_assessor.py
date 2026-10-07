"""AI 배치 진입점 — 서버(AiAssessmentTriggerService, 설정 ai.assessor.script)가 띄우는 스크립트.

    py -u vuln_assessor.py cve          라이브러리 취약점만(서버가 라이브러리 스캔 뒤에 띄운다)
    py -u vuln_assessor.py securecode   시큐어코딩만(서버가 코드 점검 뒤에 띄운다)
    py -u vuln_assessor.py              둘 다(사람이 직접 돌릴 때)

기능별 내용은 각 모듈에 있다.
  - cve_assessor.py         라이브러리 취약점(CVE): 판단(stage 1) → fix-plan(2) → 설명 요약(3) → 업그레이드 영향 분석(4)
  - secure_code_reviewer.py 시큐어코딩 점검: 코드 점검 탐지 판별(stage 5)
  - ai_common.py            모델·백엔드 접속·응답 처리·토큰 집계·배치 로그 형식

서버는 기능을 골라 띄운다 — 예전엔 코드 점검 뒤에도 전체를 돌려서, 할 일 없는 CVE 단계의 로그·요약(CVE 판단 0건, fix-plan …)이
시큐어코딩 로그에 섞였다. 둘을 같이 돌릴 때도 한 기능이 통째로 실패하면(예외) 다른 기능은 돈다 — 둘은 서로 무관하고,
대기열에서 뺀 게 없으니 실패한 쪽은 다음 배치에서 다시 대기가 된다.
"""

from __future__ import annotations

import sys
import traceback
from typing import Callable

import cve_assessor
import secure_code_reviewer
from ai_common import BatchReport, print_reports, run_batch

# 인자 이름 → (로그에 쓸 기능 이름, 실행). 인자 이름은 서버 AiAssessmentTriggerService.BatchKind.arg와 같아야 한다.
STAGES: dict[str, tuple[str, Callable[[], BatchReport]]] = {
    "cve": ("라이브러리 취약점", lambda: cve_assessor.run(cve_assessor.CveBackendClient())),
    "securecode": ("시큐어코딩", lambda: secure_code_reviewer.run(secure_code_reviewer.SecureCodeBackendClient())),
}


def selected_stages(argv: list[str]) -> list[str]:
    """실행할 기능 인자 이름들. 인자가 없으면 전부, 모르는 인자면 오류(조용히 아무것도 안 돌리지 않게)."""
    if len(argv) <= 1:
        return list(STAGES)
    unknown = [a for a in argv[1:] if a not in STAGES]
    if unknown:
        raise SystemExit(f"알 수 없는 기능: {', '.join(unknown)} (가능: {', '.join(STAGES)})")
    return argv[1:]


def main(names: list[str]) -> None:
    reports: list[BatchReport] = []
    failed: list[str] = []
    for name in names:
        label, run_stage = STAGES[name]
        try:
            reports.append(run_stage())
        except Exception:
            traceback.print_exc()
            failed.append(label)
            reports.append(BatchReport(summary=[f"{label}: 단계 실행 중 오류로 중단 — 위 traceback 참고"]))
    print_reports(reports)
    if failed:
        # 종료 코드로 서버가 실패를 기록한다(AiAssessmentTriggerService).
        raise RuntimeError(f"AI 단계 실패: {', '.join(failed)}")


if __name__ == "__main__":
    names = selected_stages(sys.argv)
    run_batch(lambda: main(names), " · ".join(STAGES[n][0] for n in names))
