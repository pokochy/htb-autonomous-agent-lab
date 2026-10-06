"""
tiering — 난이도별 모델 차등 선택 (룰 [2-5])
=============================================

작업 난이도에 따라 저렴/로컬 모델과 고성능/외부 API 를 갈라 쓴다. 목적은
**API 토큰 소모 억제**다 — 일상적인 열거는 로컬·저렴 모델이 처리하고, 어려운
추론(침투·권한상승)과 막혔을 때만 외부 API 로 올린다.

두 조각으로 나뉜다. 둘은 독립이다:
  - `tier_for(phase, round_idx)` — **무엇이 어려운가**를 정한다(정책).
  - `HybridProvider`            — **어려우면 어디로 보내는가**를 정한다(배선).

단일 프로바이더(claude 만, ollama 만)에서도 `tier_for` 는 그대로 쓸모가 있다.
Claude 한 곳이라도 열거는 haiku, 권한상승은 opus 로 갈라져 비용이 준다.
"""

from __future__ import annotations

from .llm.base import LLMProvider, LLMResponse, Tier

_ORDER = (Tier.CHEAP, Tier.STANDARD, Tier.STRONG)

# phase 별 기본 난이도. 열거/정찰은 일상(저렴·로컬), 침투·권한상승·측면이동은
# 추론 부담이 커 한 단계 위에서 시작한다.
_PHASE_BASE = {
    "recon": Tier.CHEAP,
    "enum": Tier.CHEAP,
    "access": Tier.STANDARD,
    "privesc": Tier.STANDARD,
    "lateral": Tier.STANDARD,
}


def _rank(t: Tier) -> int:
    return _ORDER.index(t)


def tier_for(phase: str, round_idx: int = 0, floor: Tier = Tier.CHEAP) -> Tier:
    """(단계, 막힌 정도) → 티어.

    같은 단계를 라운드가 거듭될수록(= 저렴한 모델이 못 풀고 있을수록) 한 단계씩
    올린다. 이게 '난이도별' 의 난이도 신호다 — 안 풀리면 더 센 모델.
    `floor` 는 하한(사용자가 `--llm-tier strong` 으로 전부 강제하는 경우).
    """
    base = _PHASE_BASE.get(phase, Tier.STANDARD)
    level = max(_rank(base), _rank(floor)) + max(round_idx, 0)
    return _ORDER[min(level, len(_ORDER) - 1)]


class HybridProvider(LLMProvider):
    """로컬 기본 + 어려운 호출만 외부 API 로 승격 — 토큰 절감의 실제 배선.

    `external_from` 이상의 티어는 외부로, 그 미만은 로컬로 보낸다. 선택된 쪽이
    실패하면(네트워크·미설치 등) 나머지 한쪽으로 폴백한다 — 한쪽이 None 이어도
    동작한다. 반환되는 `LLMResponse.model` 은 실제 응답한 프로바이더의 모델명이라
    비용 집계가 자동으로 맞는다.
    """

    name = "hybrid"

    def __init__(self, local: LLMProvider | None, external: LLMProvider | None,
                 external_from: Tier = Tier.STRONG):
        if local is None and external is None:
            raise ValueError("hybrid: local·external 둘 다 None")
        self.local = local
        self.external = external
        self.external_from = external_from

    @property
    def models(self) -> dict:  # type: ignore[override]
        # 비용/표시는 실제 응답의 model 로 처리한다. 여기선 참고용 병합만.
        merged: dict = {}
        if self.local:
            merged.update(self.local.models)
        if self.external:
            merged.update(self.external.models)
        return merged

    def available(self) -> tuple[bool, str]:
        avail = []
        for label, p in (("local", self.local), ("external", self.external)):
            if p is None:
                continue
            ok, _why = p.available()
            if ok:
                avail.append(f"{label}={p.name}")
        if avail:
            return True, "hybrid(" + ", ".join(avail) + ")"
        return False, "hybrid: 로컬·외부 모두 사용 불가"

    def _route(self, tier: Tier) -> list[LLMProvider]:
        """티어 → 시도 순서(1순위 먼저). None 은 제외."""
        if _rank(tier) >= _rank(self.external_from):
            order = (self.external, self.local)      # 어려움 → 외부 우선
        else:
            order = (self.local, self.external)      # 일상 → 로컬 우선
        return [p for p in order if p is not None]

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        providers = self._route(tier)
        last_err: Exception | None = None
        for p in providers:
            try:
                return p.complete(system, user, tier, max_tokens)
            except Exception as e:                   # 선택된 쪽 실패 → 폴백
                last_err = e
        raise RuntimeError(f"hybrid: 모든 프로바이더 실패 — {last_err}")
