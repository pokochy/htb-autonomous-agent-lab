"""Claude API 백엔드. anthropic SDK + ANTHROPIC_API_KEY 필요(지연 임포트)."""
from __future__ import annotations

import os
from .base import LLMProvider, LLMResponse, Tier


class ClaudeProvider(LLMProvider):
    name = "claude"
    # 티어별 모델 — 비용/성능 균형
    models = {
        Tier.CHEAP: "claude-haiku-4-5",
        Tier.STANDARD: "claude-sonnet-5-5",
        Tier.STRONG: "claude-opus-5-5",
    }

    def available(self) -> tuple[bool, str]:
        import importlib.util
        if importlib.util.find_spec("anthropic") is None:
            return False, "anthropic SDK 미설치 (pip install anthropic)"
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY 환경변수 미설정"
        return True, "ok"

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        import anthropic
        client = anthropic.Anthropic()
        model = self.model_for(tier)
        # 큰 시스템 프롬프트는 prefix 캐시 대상(ephemeral) — 반복 호출서 토큰 절감.
        system_blocks = [{"type": "text", "text": system,
                          "cache_control": {"type": "ephemeral"}}]
        msg = client.messages.create(
            model=model, max_tokens=max_tokens, system=system_blocks,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(getattr(b, "text", "") for b in msg.content
                       if getattr(b, "type", "") == "text")
        usage = getattr(msg, "usage", None)
        return LLMResponse(
            text, model,
            prompt_tokens=getattr(usage, "input_tokens", 0) or 0,
            completion_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        )
