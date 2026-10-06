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
from ..attempt import Candidate, CandidateError
from ..util import binary_of


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


# 익스플로잇 루프용 — 기존 도구를 '골라 돌리는' 후보를 받는다. 익스플로잇을
# 새로 짜지 말고 Kali 에 이미 있는 것(searchsploit·msfconsole·nuclei·hydra·
# netexec·impacket·certipy 등)을 호출하게 한다. 각 후보는 성공 판정 기준을
# 기계가 읽을 수 있는 형식으로 '함께' 선언해야 한다.
CANDIDATE_PROMPT = """\
당신은 권한이 확인된 Hack The Box 머신을 공략하는 OSCP 수준 침투 테스터다.
현재 단계는 '{phase}'다. 주어진 관측에 근거해, **이미 설치된 기존 도구**를
호출해 이 단계를 진전시킬 실행 후보를 제안하라. 익스플로잇을 새로 작성하지 말고
기존 도구(searchsploit·msfconsole·nuclei·hydra·netexec·impacket·certipy·
evil-winrm 등)를 고른다.

각 후보를 **정확히 한 줄**, 다음 형식으로:
    CMD <실행할 명령> ||| <expected>

<expected> 는 성공 시 '증거로 확인될 것'이며 다음 셋 중 하나다:
    shell:<라벨>                 명령이 셸/명령실행을 획득 (예: shell:www)
    probe:<확인명령>::<기대표식>   결과를 독립 명령으로 재확인 (예: probe:id::uid=)
    flag:user   또는   flag:root  플래그 파일을 읽는 경우

규칙(엄수):
- 대상은 제공된 타겟 하나뿐. 다른 호스트/인터넷 금지.
- 파괴적·비가역 명령(rm -rf, 서비스 중지, 계정 잠금, 파일 덮어쓰기) 금지.
- 자격증명이 필요하면 {user}/{pass}/{domain} 플레이스홀더를 그대로 두라.
- 특정 머신의 공개 라이트업을 인용하지 말고 관측에서 추론하라.
- expected 를 못 정하는 후보는 제안하지 마라. 설명·마크다운·번호 금지.
- 최대 {max_items}개.
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

    def suggest_candidates(self, context: dict, target: str, phase: str,
                           tier: Tier | None = None,
                           max_items: int | None = None) -> list[Candidate]:
        """익스플로잇 루프용 후보. 명령 + 성공판정(expected)을 함께 받는다.

        반환된 Candidate 는 '후보'일 뿐 — 루프의 Gate(검증→범위→승인)를 거쳐야
        실행된다. expected 규약을 못 지킨 줄은 조용히 버린다(루프가 검증 불가한
        후보를 거르는 것과 같은 규율)."""
        limit = max_items or self.max_items
        system = (CANDIDATE_PROMPT
                  .replace("{phase}", phase)
                  .replace("{max_items}", str(limit)))
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
        return self._parse_candidates(resp.text, target, phase, limit)

    @staticmethod
    def _parse_candidates(text: str, target: str, phase: str,
                          limit: int) -> list[Candidate]:
        out: list[Candidate] = []
        seen: set[str] = set()
        for raw in text.splitlines():
            line = raw.strip().strip("`").strip()
            if not line or "|||" not in line:
                continue
            line = re.sub(r"^\s*CMD\s*[:\-]?\s*", "", line, flags=re.I)
            cmd_part, _, exp_part = line.partition("|||")
            cmd = cmd_part.strip().replace("{t}", target)
            expected = exp_part.strip()
            if not cmd or not expected or cmd in seen:
                continue
            from ..exploit_loop import parse_expectation
            if parse_expectation(expected) is None:    # 규약 밖 expected 는 버린다
                continue
            # 크리덴셜 플레이스홀더가 남은 명령은 루프 쪽(creds.expand)에서 채운다.
            seen.add(cmd)
            surface = f"{phase}:{binary_of(cmd) or 'cmd'}"
            try:
                out.append(Candidate(surface=surface, summary=cmd[:80],
                                     commands=[cmd], expected=expected,
                                     source="llm"))
            except CandidateError:
                continue          # expected 미선언 등 — 검증 불가 후보는 버린다
            if len(out) >= limit:
                break
        return out

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
        if context.get("cve"):
            lines.append("탐지된 취약점(서비스→CVE→기존도구):\n  " + "\n  ".join(context["cve"]))
        if context.get("creds"):
            lines.append("확보한 자격증명:\n  " + "\n  ".join(context["creds"]))
        if context.get("footholds"):
            lines.append("획득한 접근(Foothold):\n  " + "\n  ".join(context["footholds"]))
        if context.get("dead"):
            lines.append("이미 실패한 가설(반복 금지):\n  " + "\n  ".join(context["dead"]))
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
