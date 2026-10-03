"""
LLM 가격·비용 추정 (per 1M 토큰, USD)
======================================

Anthropic 1st-party API 요율(claude-api 스킬 기준, 2026-09 캐시). 로컬(Ollama)은
무과금(0). 가격은 변할 수 있으므로 참고용 추정이며, 정확한 청구는 콘솔을 확인.
"""

from __future__ import annotations

# {model: (input, output, cache_read)} — $/1M 토큰
PRICES: dict[str, tuple[float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-opus-5": (5.00, 25.00, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-sonnet-5": (2.00, 10.00, 0.20),
    "claude-haiku-4-5": (1.00, 5.00, 0.10),
    "claude-fable-5-1": (10.00, 50.00, 1.00),
}

CACHE_WRITE_MULT = 1.25   # 캐시 생성은 입력가의 1.25배(통상)


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int,
                  cache_read_tokens: int = 0, cache_creation_tokens: int = 0) -> float:
    """토큰 사용량으로 비용(USD) 추정. 미등록 모델(로컬 등)은 0."""
    price = PRICES.get(model)
    if not price:
        return 0.0
    pin, pout, pcache = price
    non_cached_in = max(0, prompt_tokens - cache_read_tokens - cache_creation_tokens)
    cost = (non_cached_in * pin
            + cache_read_tokens * pcache
            + cache_creation_tokens * pin * CACHE_WRITE_MULT
            + completion_tokens * pout) / 1_000_000
    return round(cost, 6)
