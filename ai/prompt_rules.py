"""prompts/ 아래 md 룰 파일을 읽어서 시스템 프롬프트 문자열로 만들어 준다.

`{{include: rules/xxx.md}}` 한 줄을 그 파일 내용으로 치환한다. 룰을 성격별로
나눠 두고 여러 프롬프트에서 재사용하기 위한 것이다.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"

_INCLUDE = re.compile(r"^[ \t]*\{\{include:\s*(?P<path>[^}\s]+)\s*\}\}[ \t]*$", re.MULTILINE)
_MAX_DEPTH = 5


def _render(rel_path: str, depth: int) -> str:
    if depth > _MAX_DEPTH:
        raise RecursionError(f"프롬프트 include 중첩이 너무 깊습니다: {rel_path}")

    path = (PROMPT_DIR / rel_path).resolve()
    # 디렉터리 밖으로 나가는 include를 막는다.
    if not path.is_relative_to(PROMPT_DIR):
        raise ValueError(f"prompts/ 밖의 파일은 include할 수 없습니다: {rel_path}")
    if not path.is_file():
        raise FileNotFoundError(f"프롬프트 파일이 없습니다: {path}")

    text = path.read_text(encoding="utf-8")
    return _INCLUDE.sub(lambda m: _render(m.group("path"), depth + 1).strip(), text)


@lru_cache(maxsize=None)
def load_prompt(rel_path: str) -> str:
    """prompts/<rel_path> 를 읽고 include를 모두 펼친 문자열을 돌려준다."""
    return _render(rel_path, 0).strip()


ASSESS_SYSTEM = "assess.system.md"
FIX_PLAN_SYSTEM = "fix_plan.system.md"
SUMMARIZE_SYSTEM = "summarize.system.md"
IMPACT_SYSTEM = "impact.system.md"
SECURE_CODE_REVIEW_SYSTEM = "secure_code_review.system.md"
