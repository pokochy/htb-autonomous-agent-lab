# 실행: htb-agent 디렉토리에서  python3 tests/test_creds.py
import sys
sys.path.insert(0, "src")
from htb_agent.creds import Credential, CredentialVault, fill
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== fill / 치환 ===")
c = Credential("admin", "p@ss", "corp.local")
cmd, ok = fill("evil-winrm -i {t} -u {user} -p {pass}", "10.129.1.5", c)
check("user/pass 치환 + 완전", cmd == "evil-winrm -i 10.129.1.5 -u admin -p p@ss" and ok)
cmd, ok = fill("netexec smb {t} -u {user} -p {pass} -d {domain}", "10.129.1.5", c)
check("domain 포함 완전", ok and "corp.local" in cmd)
cmd, ok = fill("x {t} {hash}", "10.129.1.5", Credential("u"))  # hash 없음
check("미충족 플레이스홀더 → 불완전", not ok)

print("\n=== CLI 파싱 ===")
v = CredentialVault.from_cli(["admin:secret", "svc:pw:corp.local", "guestonly"])
check("user:pass", v.creds[0].username == "admin" and v.creds[0].password == "secret")
check("user:pass:domain", v.creds[1].domain == "corp.local")
check("user만", v.creds[2].username == "guestonly" and v.creds[2].password is None)
check("label 비밀 마스킹", "****" in v.creds[0].label())

print("\n=== expand ===")
v = CredentialVault.from_cli(["admin:pw"])
check("플레이스홀더 없음 → runnable", v.expand("nmap {t}", "10.1.1.1") == [("nmap 10.1.1.1", True)])
exp = v.expand("evil-winrm -i {t} -u {user} -p {pass}", "10.1.1.1")
check("cred 로 채워 runnable", exp == [("evil-winrm -i 10.1.1.1 -u admin -p pw", True)])
empty = CredentialVault()
check("볼트 비면 not runnable", empty.expand("x {t} -u {user}", "10.1.1.1") == [("x 10.1.1.1 -u {user}", False)])

print("\n=== 오케스트레이터: 수동 제안 승격 ===")
AD = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.10"/><ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="5985"><state state="open"/><service name="winrm"/></port>
</ports><hostscript><script id="smb-os-discovery" output="OS: Windows Server 2019"/></hostscript>
</host></nmaprun>"""
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.10"); return g
def runner():
    return FakeRunner(lambda c: RunOutput(c, stdout=AD) if c.startswith("nmap") else RunOutput(c, stdout="ok"))

# 볼트 없음: WinRM 은 수동 제안에만
rep = Orchestrator(guard(), runner(), KnowledgeBase.load(), auto_approve_in_scope,
                   is_tool_available=lambda b: True).run()
check("볼트 없으면 evil-winrm 수동", any("evil-winrm" in s for s in rep.manual_suggestions)
      and all("evil-winrm" not in f.command for f in rep.enum_findings))

# 볼트 있음: WinRM 이 실행 후보로 승격 → 실행됨
v = CredentialVault.from_cli(["administrator:Passw0rd"])
rep = Orchestrator(guard(), runner(), KnowledgeBase.load(), auto_approve_in_scope,
                   vault=v, is_tool_available=lambda b: True).run()
check("볼트 있으면 evil-winrm 실행 승격",
      any("evil-winrm" in f.command and f.ran for f in rep.enum_findings))
check("승격 명령에 자격증명 치환", any("administrator" in f.command for f in rep.enum_findings))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
