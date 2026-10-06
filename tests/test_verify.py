# 실행: htb-agent 디렉토리에서  python3 tests/test_verify.py
import sys
sys.path.insert(0, "src")
from htb_agent.verify import shell, confirms, flag, Evidence
from htb_agent.attempt import Attempt
from htb_agent.tools.runner import FakeRunner, RunOutput

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== shell: 토큰 왕복 ===")
# 정상 셸 — echo 가 토큰을 돌려준다
r = FakeRunner(lambda c: c.split()[-1] if c.startswith("echo ") else "")
ev = shell(r)
check("토큰 반환 → confirmed", ev.verdict == "confirmed" and ev.foothold == "shell")
check("확인에 쓴 명령 기록", ev.probe_command.startswith("echo "))

# 매 호출 다른 토큰 (재생공격·캐시된 출력 방지)
t1 = shell(r).probe_command
t2 = shell(r).probe_command
check("토큰은 매번 새로 생성", t1 != t2)

# 명령을 그대로 에코만 하는 채널 — 토큰이 '출력'이 아니라 '명령'에 있을 뿐
echo_only = FakeRunner(lambda c: c)
check("명령 에코만 하는 채널 → refuted", shell(echo_only).verdict == "refuted")

# 프롬프트처럼 보이는 배너 — 모양으로 속지 않는다
banner = FakeRunner(lambda c: "root@target:~# ")
ev = shell(banner)
check("프롬프트 배너 → refuted", ev.verdict == "refuted")
check("refuted 에 근거 있음", bool(ev.because.strip()))

print("=== shell: 모르면 inconclusive ===")
check("미설치/실행실패 → inconclusive",
      shell(FakeRunner(lambda c: RunOutput(c, error="'sh' 미설치"))).verdict == "inconclusive")
check("타임아웃 → inconclusive",
      shell(FakeRunner(lambda c: RunOutput(c, timed_out=True))).verdict == "inconclusive")

print("=== confirms: 일반 증거 ===")
# 내용을 아는 파일을 읽어 일치 확인
fr = FakeRunner(lambda c: "root:x:0:0:root:/root:/bin/bash" if "passwd" in c else "")
ev = confirms(fr, "cat /etc/passwd", "root:x:0:0")
check("파일 내용 일치 → confirmed", ev.verdict == "confirmed")
check("foothold 기본값 채워짐", bool(ev.foothold))
check("표식 없음 → refuted", confirms(fr, "cat /etc/shadow", "root:$6$").verdict == "refuted")
check("must_contain 미지정 → inconclusive",
      confirms(fr, "whoami", "").verdict == "inconclusive")
check("probe 실패 → inconclusive",
      confirms(FakeRunner(lambda c: RunOutput(c, error="boom")),
               "id", "uid=0").verdict == "inconclusive")

# 명령줄에만 표식이 있는 경우를 성공으로 오인하지 않는다
check("명령 에코는 증거가 아님",
      confirms(FakeRunner(lambda c: c), "echo uid=0", "uid=0").verdict == "refuted")

print("=== flag: 형식 + 출처 ===")
ev = flag("cat /home/bob/user.txt", "a" * 32)
check("user 플래그 → confirmed", ev.verdict == "confirmed" and ev.foothold == "flag:user")
check("출처 경로를 근거에 기록", "user.txt" in ev.because)
check("TAG{} 형식 포착", flag("echo x", "HTB{p0wn3d}").verdict == "confirmed")
# 못 찾은 것은 반증이 아니다
check("플래그 없음 → inconclusive(= not refuted)",
      flag("cat /etc/hostname", "target").verdict == "inconclusive")
# 플래그 맥락이 아닌 해시는 플래그가 아니다
check("비플래그 맥락의 hex 무시",
      flag("hashid 5f4dcc3b5aa765d61d8327deb882cf99",
           "5f4dcc3b5aa765d61d8327deb882cf99").verdict == "inconclusive")

print("=== flag provenance (ctf-abacus) ===")
from htb_agent.verify import FLAG_GENUINE, FLAG_UNDEMONSTRATED
ev_u = flag("cat /home/bob/user.txt", "a" * 32, earned=False)
check("선행 익스플로잇 없음 → undemonstrated", ev_u.provenance == FLAG_UNDEMONSTRATED)
check("undemonstrated 근거 명시", "undemonstrated" in ev_u.because or "미증명" in ev_u.because)
ev_g = flag("cat /home/bob/user.txt", "a" * 32, earned=True)
check("선행 Foothold 있음 → genuine", ev_g.provenance == FLAG_GENUINE)
check("genuine 도 confirmed", ev_g.verdict == "confirmed")
check("기본값은 undemonstrated(보수적)", flag("x user.txt", "b" * 32).provenance == FLAG_UNDEMONSTRATED)

print("=== attempt.py 와의 접합 ===")
# confirmed 는 foothold 를 들고 와야 Attempt 가 강등하지 않는다
ev = shell(r)
a = Attempt(hid="h1", surface="http:80", commands=["x"], expected="shell",
            observed=ev.observed, verdict=ev.verdict, because=ev.because,
            foothold=ev.foothold)
check("confirmed 가 강등되지 않음", a.verdict == "confirmed" and not a.coerced)

# refuted 는 근거를 들고 와야 강등되지 않는다
ev = shell(banner)
a = Attempt(hid="h2", surface="http:80", commands=["x"], expected="shell",
            observed=ev.observed, verdict=ev.verdict, because=ev.because)
check("refuted 가 강등되지 않음", a.verdict == "refuted" and not a.coerced)

# inconclusive 는 그대로
ev = flag("cat /etc/hostname", "target")
a = Attempt(hid="h3", surface="http:80", commands=["x"], expected="flag",
            observed=ev.observed, verdict=ev.verdict, because=ev.because)
check("inconclusive 유지", a.verdict == "inconclusive")

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
