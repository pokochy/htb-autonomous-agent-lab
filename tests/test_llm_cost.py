# 실행: htb-agent 디렉토리에서  python3 tests/test_llm_cost.py
import sys
sys.path.insert(0, "src")
from htb_agent.llm.pricing import estimate_cost
from htb_agent.llm.base import LLMResponse
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 가격 추정 ===")
# Opus 5.5: in $4, out $20 /1M. 1M in + 1M out = 4 + 20 = 24
check("opus 5.5 기본", abs(estimate_cost("claude-opus-5-5", 1_000_000, 1_000_000) - 24.0) < 1e-6)
# Sonnet 5.5: in $2 out $10 → 0.5M in + 0.2M out = 1.0 + 2.0 = 3.0
check("sonnet 5.5", abs(estimate_cost("claude-sonnet-5-5", 500_000, 200_000) - 3.0) < 1e-6)
# 캐시 읽기는 저렴($0.20) → 비용 감소
full = estimate_cost("claude-opus-5-5", 1_000_000, 0)
cached = estimate_cost("claude-opus-5-5", 1_000_000, 0, cache_read_tokens=900_000)
check("캐시 읽기로 비용 감소", cached < full)
check("미등록 모델(로컬)은 0", estimate_cost("llama3.1:8b", 1_000_000, 1_000_000) == 0.0)

print("\n=== 라우터 누적 집계 ===")
# usage 가 담긴 LLMResponse 를 반환하는 FakeProvider
def responder(system, user, tier):
    return LLMResponse(text="nmap -sV {t}", model="claude-sonnet-5-5",
                       prompt_tokens=1000, completion_tokens=100,
                       cache_read_tokens=500)
r = LLMRouter(FakeProvider(responder))
r.suggest_commands({}, "10.129.1.5")
r.suggest_commands({}, "10.129.1.5")
check("호출 2회 집계", r.calls == 2)
check("입력 토큰 누적", r.total_prompt == 2000)
check("캐시 읽기 누적", r.total_cache_read == 1000)
check("비용 > 0", r.total_cost > 0)
check("cost_summary 문자열", "추정 비용" in r.cost_summary() and "LLM 호출 2회" in r.cost_summary())

print("\n=== 캐시 미사용 provider(문자열 반환) 안전 ===")
r2 = LLMRouter(FakeProvider("nmap -sV {t}"))
r2.suggest_commands({}, "10.129.1.5")
check("usage 없는 응답도 집계 안전", r2.calls == 1 and r2.total_cost == 0.0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
