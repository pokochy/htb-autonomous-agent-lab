"""공용 유틸리티."""

from __future__ import annotations

import shlex


def binary_of(command: str, strip_path: bool = False) -> str:
    """
    명령에서 실제 바이너리 토큰을 추출(선행 환경변수 할당 NAME=VALUE 는 건너뜀).
    strip_path=True 면 경로를 제거한 basename 반환.
    """
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    for t in toks:
        if "=" in t and not t.startswith("-"):
            continue
        return t.rsplit("/", 1)[-1] if strip_path else t
    return ""
