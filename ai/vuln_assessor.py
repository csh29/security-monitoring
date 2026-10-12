"""AI 배치 진입점 — 서버가 기능을 골라 띄운다(cve_assessor.py, secure_code_reviewer.py). 한 기능이 실패해도 다른 기능은 돈다.

    py -u vuln_assessor.py [cve|securecode]   인자가 없으면 둘 다
"""

from __future__ import annotations

import sys
import traceback
from typing import Callable

import cve_assessor
import secure_code_reviewer
from ai_common import BatchReport, print_reports, run_batch, stage_lock

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
            with stage_lock(name) as acquired:
                if not acquired:
                    # 같은 기능이 이미 돌고 있으면 같은 대기를 두 번 판별하지 않게 건너뛴다.
                    print(f"{label}: 이미 실행 중인 배치가 있어 건너뜁니다.")
                    reports.append(BatchReport(summary=[f"{label}: 이미 실행 중인 배치가 있어 건너뜀"]))
                    continue
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
