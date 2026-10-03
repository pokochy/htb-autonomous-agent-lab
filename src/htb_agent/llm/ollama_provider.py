"""로컬 Ollama 백엔드 — 오프라인·무과금. 표준 라이브러리만 사용."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from .base import LLMProvider, LLMResponse, Tier


class OllamaProvider(LLMProvider):
    name = "ollama"
    models = {
        Tier.CHEAP: "llama3.1:8b",
        Tier.STANDARD: "llama3.1:8b",
        Tier.STRONG: "llama3.1:70b",
    }

    def __init__(self, host: str | None = None, models: dict | None = None):
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        if models:
            self.models = {**self.models, **models}

    def available(self) -> tuple[bool, str]:
        try:
            with urllib.request.urlopen(self.host + "/api/tags", timeout=3) as r:
                r.read()
            return True, "ok"
        except (urllib.error.URLError, OSError) as e:
            return False, f"Ollama 연결 실패({self.host}): {e}"

    def complete(self, system: str, user: str,
                 tier: Tier = Tier.STANDARD, max_tokens: int = 1024) -> LLMResponse:
        model = self.model_for(tier)
        payload = json.dumps({
            "model": model, "system": system, "prompt": user,
            "stream": False, "options": {"num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(self.host + "/api/generate", data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as r:
            data = json.loads(r.read())
        return LLMResponse(data.get("response", ""), model)
