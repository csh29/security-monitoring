"""코드 점검 규칙(rules/*.yml) 회귀 테스트를 규칙 파일마다 하나씩 순서대로 돌린다.

`semgrep --test .`는 규칙 여러 개를 동시에 돌리면서 ~/.semgrep/settings.yml을 같이 써서, Windows에서는
PermissionError로 일부 규칙이 테스트에서 조용히 빠지거나 전체가 죽는다(이 PC에서 실제로 그랬다). 하나씩 돌리면 나지 않는다.

사용: securecode 폴더에서 `py test_rules.py` (semgrep이 PATH에 없으면 파이썬 Scripts 폴더에서 찾는다).
규칙 파일과 이름이 같은 예제(sql-injection.java, sql-injection.xml …)를 그 규칙의 테스트 대상으로 쓴다.
"""
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent / "rules"


def semgrep_command() -> str:
    found = shutil.which("semgrep")
    if found:
        return found
    for name in ("semgrep.exe", "semgrep"):
        candidate = Path(sysconfig.get_path("scripts")) / name
        if candidate.is_file():
            return str(candidate)
    sys.exit("semgrep을 찾지 못했습니다. py -m pip install -r requirements.txt")


def main() -> int:
    # Windows 콘솔 기본 인코딩(cp949)으로는 규칙 메시지의 일부 문자가 깨진다.
    sys.stdout.reconfigure(encoding="utf-8")
    semgrep = semgrep_command()
    env = dict(os.environ, PYTHONUTF8="1")
    failed = []
    rules = sorted(RULES_DIR.glob("*.yml"))
    for rule in rules:
        targets = sorted(p for p in RULES_DIR.glob(rule.stem + ".*") if p.suffix not in (".yml", ".yaml"))
        if not targets:
            print(f"[예제 없음] {rule.name}")
            failed.append(rule.name)
            continue
        # --test는 대상을 하나만 받는다 — 예제 파일(.java, .xml …)마다 따로 돌린다.
        problems = []
        for target in targets:
            result = subprocess.run(
                [semgrep, "--test", "--metrics=off", "--config", str(rule), str(target)],
                cwd=RULES_DIR, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
            output = result.stdout + result.stderr
            if result.returncode != 0 or "All tests passed" not in output:
                problems.append(f"  {target.name}\n{output.strip()}")
        if problems:
            print(f"[실패] {rule.name}\n" + "\n".join(problems) + "\n")
            failed.append(rule.name)
        else:
            print(f"[통과] {rule.name} ({', '.join(t.name for t in targets)})")
    print(f"\n{len(rules) - len(failed)}/{len(rules)} 규칙 파일 통과")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
