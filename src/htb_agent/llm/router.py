"""
LLM Router — 관측·지식을 받아 다음 명령 후보를 추론
====================================================

압축된 관측(OS·포트·서비스)과 지식베이스 제안을 컨텍스트로 LLM 에 넘겨,
'다음에 시도할 명령 후보'를 받는다. 토큰 절감을 위해 원문이 아닌 요약만 넣는다.

반환된 명령은 '후보'일 뿐이다 — 실행 전 반드시 검증→범위→승인 3관문을 거친다.
"""

from __future__ import annotations

import re
from .base import LLMProvider, Tier
from .pricing import estimate_cost


SYSTEM_PROMPT = """\
당신은 권한이 확인된 Hack The Box 훈련용 머신을 대상으로 하는 침투 테스트
보조자다. 주어진 '관측 결과'에만 근거해 다음에 실행할 '열거(enumeration)/탐색'
명령 후보를 제안한다.

규칙(엄수):
- 특정 머신의 공개 라이트업/워크스루를 인용하지 말고, 주어진 관측에서 추론하라.
- 대상은 제공된 타겟 IP 하나뿐이다. 다른 호스트/인터넷 대상 금지.
- 출력은 '명령만' 한 줄에 하나씩. 설명/서론/마크다운/번호매기기 금지.
- 파괴적 명령(rm -rf, mkfs, dd of=/dev/... 등) 금지.
- 크리덴셜이 필요한 명령은 {user}/{pass}/{domain} 플레이스홀더를 그대로 두라.
- 표준 도구(nmap, ffuf, gobuster, netexec, enum4linux-ng, smbclient,
  ldapsearch, curl 등)를 우선 사용하라.
- 최대 {max_items}개까지만.
"""


class LLMRouter:
    def __init__(self, provider: LLMProvider,
                 default_tier: Tier = Tier.STANDARD, max_items: int = 5):
        self.provider = provider
        self.default_tier = default_tier
        self.max_items = max_items
        # 누적 사용량/비용 집계
        self.calls = 0
        self.total_prompt = 0
        self.total_completion = 0
        self.total_cache_read = 0
        self.total_cost = 0.0

    def cost_summary(self) -> str:
        return (f"LLM 호출 {self.calls}회, 입력 {self.total_prompt} "
                f"(캐시읽기 {self.total_cache_read}) / 출력 {self.total_completion} 토큰, "
                f"추정 비용 ${self.total_cost:.4f}")

    def suggest_commands(self, context: dict, target: str,
                         tier: Tier | None = None,
                         max_items: int | None = None) -> list[str]:
        limit = max_items or self.max_items
        # 주의: SYSTEM_PROMPT 에 리터럴 {user}/{pass} 가 있어 .format() 금지.
        system = SYSTEM_PROMPT.replace("{max_items}", str(limit))
        user = self._user_prompt(context, target)
        resp = self.provider.complete(system, user, tier or self.default_tier)
        self.calls += 1
        self.total_prompt += resp.prompt_tokens
        self.total_completion += resp.completion_tokens
        self.total_cache_read += resp.cache_read_tokens
        self.total_cost += estimate_cost(resp.model, resp.prompt_tokens,
                                         resp.completion_tokens,
                                         resp.cache_read_tokens,
                                         resp.cache_creation_tokens)
        return self._parse(resp.text, target, limit)

    @staticmethod
    def _user_prompt(context: dict, target: str) -> str:
        lines = [f"타겟: {target}"]
        if context.get("phase"):
            lines.append(f"현재 모의해킹 단계: {context['phase']} — 이 단계에 맞는 명령만 제안하라.")
        if context.get("profile"):
            lines.append(f"OS 판정:\n{context['profile']}")
        if context.get("open_ports"):
            lines.append("열린 포트/서비스:\n  " + "\n  ".join(context["open_ports"]))
        if context.get("findings"):
            lines.append("지금까지 관측(명령 → 결과):\n  " + "\n  ".join(context["findings"]))
        if context.get("kb"):
            lines.append("참고(지식베이스 제안):\n  " + "\n  ".join(context["kb"]))
        if context.get("notes"):
            lines.append("참고(사용자 노트):\n  " + "\n  ".join(context["notes"]))
        lines.append("\n위 관측에 근거해 다음 열거 명령을 제안하라(명령만, 한 줄에 하나).")
        return "\n\n".join(lines)

    @staticmethod
    def _parse(text: str, target: str, limit: int) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for raw in text.splitlines():
            line = raw.strip().strip("`").strip()
            if not line or line.startswith("#") or line.startswith("```"):
                continue
            line = re.sub(r"^\d+[\.\)]\s*", "", line)   # 번호 제거
            line = re.sub(r"^[-*]\s*", "", line)         # 불릿 제거
            line = line.replace("{t}", target)
            # 남은 플레이스홀더(크리덴셜 등)가 있으면 자동실행 후보에서 제외
            if "{" in line and "}" in line:
                continue
            if len(line) > 300 or not re.search(r"[A-Za-z]", line):
                continue
            if line in seen:
                continue
            seen.add(line)
            out.append(line)
            if len(out) >= limit:
                break
        return out
