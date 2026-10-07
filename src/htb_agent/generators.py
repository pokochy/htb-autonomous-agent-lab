"""
generators — 익스플로잇 루프의 후보 생성원
===========================================

`exploit_loop.ExploitLoop` 에 주입하는 `Generator`(= `loop -> list[Candidate]`)
들을 만든다. 설계 원칙은 **기존 오픈소스 도구를 골라 돌린다**는 것 하나다 —
익스플로잇을 새로 짜지 않고 Kali 에 이미 있는 것(searchsploit·msfconsole·
nuclei·hydra·netexec·impacket·evil-winrm 등)을 호출한다.

지금 두 생성원:
  - `make_llm_generator`  — LLM 이 단계·관측·죽은 가설을 보고 '어떤 도구를
    어떻게 돌릴지'를 expected 와 함께 제안한다. Hard 머신의 본 엔진.
  - `make_flag_generator` — 자격증명이나 셸 Foothold 가 생기면, 기존 도구로
    user.txt/root.txt 를 읽는 결정적(deterministic) 후보. LLM 없이도 동작.

둘 다 매 라운드 `loop.ledger` 를 읽어 **이미 죽은 가설·획득한 Foothold** 를
반영한다. 같은 시도 반복을 막고, Foothold 가 생기면 다음 수가 바뀐다.
"""

from __future__ import annotations

from typing import Callable

from .attempt import Candidate
from .creds import CredentialVault
from .tiering import tier_for
from .verify import is_capability

# loop 타입은 런타임 임포트(순환 방지). Generator 시그니처만 맞춘다.
Generator = Callable[[object], list[Candidate]]


def make_llm_generator(llm_router, base_context: dict, target: str,
                       phase: str, max_items: int = 5) -> Generator:
    """LLM 후보 생성원. 매 호출 ledger 피드백을 컨텍스트에 얹는다."""
    def gen(loop) -> list[Candidate]:
        ctx = dict(base_context)
        footholds = loop.ledger.footholds()
        if footholds:
            ctx["footholds"] = footholds
        dead = [f"{label}: {why}" for label, why in loop.ledger.dead_hypotheses()]
        if dead:
            ctx["dead"] = dead[-8:]          # 죽은 가설을 되먹여 반복 차단
        # 막힐수록(라운드↑) 더 센 티어. floor 는 라우터 기본 티어.
        rnd = max(0, getattr(loop.result, "rounds", 1) - 1)
        tier = tier_for(phase, round_idx=rnd, floor=llm_router.default_tier)
        try:
            return llm_router.suggest_candidates(ctx, target, phase, tier=tier,
                                                 max_items=max_items)
        except Exception as e:               # 백엔드 오류가 루프를 깨지 않는다
            loop.audit.event("llm_generator_error", error=str(e))
            return []
    return gen


# ── 플래그 캡처 (결정적) ──────────────────────────────────────────
# OS 별로 '내용을 아는 위치'를 기존 도구로 읽는다. 와일드카드로 사용자 홈을 훑되
# 읽기 전용(파괴 없음). expected 는 flag:user / flag:root.
_LINUX_FLAGS = [
    ("cat /home/*/user.txt 2>/dev/null", "user"),
    ("cat /root/root.txt 2>/dev/null", "root"),
]
_WINDOWS_FLAGS = [
    ("type C:\\Users\\*\\Desktop\\user.txt", "user"),
    ("type C:\\Users\\Administrator\\Desktop\\root.txt", "root"),
]
# 자격증명이 있을 때 — netexec 로 원격 실행(기존 도구). {user}/{pass} 는 볼트가 채운다.
_CRED_FLAGS_WIN = [
    ('netexec smb {t} -u {user} -p {pass} -x "type C:\\Users\\*\\Desktop\\user.txt"', "user"),
]
_CRED_FLAGS_NIX = [
    ("sshpass -p {pass} ssh {user}@{t} 'cat /home/*/user.txt /root/root.txt 2>/dev/null'", "user"),
]


def make_flag_generator(vault: CredentialVault | None, target: str,
                        os_class: str = "", phase: str = "privesc") -> Generator:
    """Foothold/자격증명이 생기면 기존 도구로 플래그를 읽는 후보.

    아무 근거도 없으면(셸 없음·자격증명 없음) 빈 목록 → 루프는 다른 생성원으로.
    """
    is_win = "windows" in (os_class or "").lower()
    local = _WINDOWS_FLAGS if is_win else _LINUX_FLAGS
    cred_tmpls = _CRED_FLAGS_WIN if is_win else _CRED_FLAGS_NIX

    def gen(loop) -> list[Candidate]:
        out: list[Candidate] = []
        # '능력' Foothold 만 — verified:(확인된 사실)로는 대상 셸이 없다.
        have_shell = any(is_capability(f) for f in loop.ledger.footholds())

        # 1) 셸 Foothold 가 있으면 그 셸로 직접 읽는다
        if have_shell:
            for cmd, kind in local:
                out.append(_flag_cand(cmd, kind, phase))

        # 2) 자격증명이 있으면 기존 원격도구로 읽는다 (볼트가 {user}/{pass} 채움)
        if vault is not None and vault.creds:
            for tmpl, kind in cred_tmpls:
                for cmd, runnable in vault.expand(tmpl, target):
                    if runnable:
                        out.append(_flag_cand(cmd, kind, phase))
        return out
    return gen


def _flag_cand(cmd: str, kind: str, phase: str) -> Candidate:
    return Candidate(surface=f"{phase}:flag", summary=f"flag:{kind} 읽기",
                     commands=[cmd], expected=f"flag:{kind}", source="kb",
                     est_seconds=20)
