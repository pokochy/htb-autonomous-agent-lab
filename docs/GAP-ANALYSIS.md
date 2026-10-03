# 격차 분석 — 참고 구현 → 무개입 자동화

기준일 2026-10-03. 대회 종료 2026-10-23 21:00 (**20일**), 히든문제 공개 10-21.
인원 2명. 설계 목표 난이도는 **Hard 가정**(Active Machine 은 난이도 혼재이나,
Hard 를 기준으로 잡아 손해 볼 것이 없다).

출처 구분: 〔확인〕 = 이 저장소에서 실행·측정함 / 〔추정〕 = 코드 근거 기반 판단.

---

## 1. 출발점 (`HyungJinKwon/Blog_Custom_Skin` @ `claude/zen-goldberg-yma7t2`)

〔확인〕 Kali(WSL, Python 3.13.12)에서 `python3 tests/run_all.py` → **22 스위트
359 passed, 0 failed**. src 4,439줄 / tests 1,614줄. CI 워크플로 존재.

재사용 가치가 높아 **이 저장소의 출발점으로 그대로 가져왔다**(재작성 아님):

| 계층 | 모듈 | 상태 |
|---|---|---|
| 안전 | `scope_guard` · `command_validator` · `approval` | 유지 — 대상 범위 강제는 그대로 필요 |
| 관측 | `observation/{parsers,web,smb,ad,net,summarize,compressor}` | 유지 — 파서 품질 양호 |
| 운영 | `state`(중단/재개) · `audit`(JSONL) · `creds` · `config` | 유지 — 재분석 루프의 기반 |
| 산출 | `writeup` (htb / tistory 13섹션) | 유지 — 대회 제출물 |
| 도구 | `tools/registry` + `scripts/install_tools.sh` | 유지 — 59개 도구 등록 |

---

## 2. 구멍 (대회 요구 = VPN·IP 만 주면 플래그까지)

### G1. 익스플로잇 실행이 설계상 제외 — **부분 해결 (이번 커밋)**

〔확인〕 `src/htb_agent/vuln.py:11` 주석: *"매칭 결과는 '탐지 + 수동 제안
(searchsploit 등)'으로만 제시한다"*. CVE 를 찾아도 `searchsploit ...` **문자열을
출력**하고 끝난다. `user.txt` 는 `--cred` 로 사람이 자격증명을 넣어줘야 도달한다.

〔확인〕 하드코딩 CVE 는 7건 — vsftpd 2.3.4 / Apache 2.4.49 / Samba
is_known_pipename / Heartbleed / EternalBlue / OpenSSH 유저열거. 전형적인 Easy
레퍼토리이며 Hard 에는 거의 쓰이지 않는다.

→ 탐지와 실행 사이의 단계(선택 → 준비 → 실행 → 검증 → 가설 전환)가 통째로
없었다. `verify.py` + `exploit_loop.py` 로 그 단계를 채웠다.

〔확인〕 `tests/test_verify.py` 22 + `tests/test_exploit_loop.py` 41 passed.
전체 **26 스위트 458 passed, 0 failed**.

- `verify.py` — 증거 기반 판정. **익스플로잇 자신의 출력으로 `confirmed` 를
  낼 수 있는 경로는 플래그 하나뿐**이고, 나머지는 전부 독립 probe 를 거친다.
  셸은 난수 토큰 왕복으로만 인정한다(프롬프트 모양 금지).
- `exploit_loop.py` — ①~⑥. `expected` 를 기계가 읽는 규약
  (`shell:` / `probe:…::…` / `flag:`)으로 고정해, **검증 불가능한 후보는
  실행 전에 탈락**시킨다. 전제조건 미충족은 원장에 남기지 않고 보류 과제로
  돌린다(반증 아님). 후보 생성원은 주입식이라 KB/CVE/LLM 기여를 따로 잴 수 있다.

구현 중 실제로 잡은 결함 2건 — 기록해 둔다:
- **범위 봉쇄를 승인자가 뒤집을 수 있었다.** `inspect_command` 는 범위 밖을
  `needs_confirmation` 으로 돌려줄 뿐 예외를 던지지 않는다. 승인자가 주입식인
  무개입 루프에서는 느슨한 승인자 하나로 봉쇄가 뚫린다. → `Gate` 가 범위를
  **승인자보다 먼저** 막는다. 승인자는 더 조이는 것만 가능하다.
- **같은 후보가 한 라운드에 두 번 실행됐다.** 생성원과 재시도 큐에서 동시에
  올라와 `inconclusive` 재시도 상한이 절반 속도로 타버렸다. → 라운드 내 hid 중복 제거.

→ **남은 일**: `orchestrator.py` 배선. 지금 루프는 **실제 런에서 돌지 않는다** —
`access`·`privesc` phase 는 여전히 열거만 하고, `vuln.py` 도 아직 종착점이다.
후보 생성원(KB 규칙 / CVE / LLM)도 아직 하나도 안 붙었다.

### G2. 지속 셸·세션 부재 — **해결됨 (이번 커밋)**

〔확인〕 `tools/runner.py` 의 `SubprocessRunner` 는 one-shot
`subprocess.run(shell=False, timeout=120)`. 결과: `cd`·환경변수 소실, 파이프·
리다이렉트·`&&`·`$()` 전부 불가, pty 없어 `nc`·`ssh`·`evil-winrm`·`gdb` 상호작용
불가, 120초 넘는 `nmap -p-`·크래킹·퍼징 전부 중단.

→ `tools/session.py` `ShellSession` 추가. `Runner` 프로토콜을 만족해
**orchestrator 무수정 교체**. `--runner session` 이 기본값이고, pexpect/pty 가
없으면 oneshot 으로 자동 강하.

〔확인〕 `tests/test_session.py` **28 passed**. 전체 **23 스위트 387 passed, 0 failed**.
측정으로 확인한 동작: `cd`/env 유지, 파이프·리다이렉트·`&&`·명령치환, 종료코드
회수, 타임아웃→Ctrl-C→재동기화 후 세션 재사용, 백그라운드 작업(긴 스캔 중 다른
명령 동시 진행), 대화형 stdin 전달, 셸 사망 시 자동 교체.

구현 중 실제로 잡은 결함 2건 — 기록해 둔다:
- **Ctrl-C 가 터미널 입력 큐를 함께 비운다.** 미리 큐에 넣어둔 종료 마커가
  유실돼 타임아웃 복구가 영구 실패했다. → 복구 시 **새 마커로** 재동기화.
- **`exit` 한 줄로 지속 셸이 죽는다.** 무개입 운용에서는 런 전체 손실.
  → EOF 시 셸 자동 교체(`respawns` 카운트), 단 작업디렉토리·환경변수가
  초기화된 사실을 호출측에 **숨기지 않고 보고**.

### G3. 지식베이스가 사실상 빈 상태 — 미해결

〔확인〕 `knowledge/rules/` 1개(9줄) · `notes/` 1개(2줄) · `vulns/` 1개(10줄).
오케스트레이터는 "phase KB 규칙 + LLM"으로 도는데 KB 기여가 0 → **사실상 LLM 단독**.

→ `docs/KNOWLEDGE-LAYERS.md` 의 L2·L3 를 채우는 것이 비용 대비 효과가 가장 크다.

### G4. 권한상승 열거 수단 없음 — 미해결

〔확인〕 src 전체에 `linpeas`/`winpeas`/`pspy` 참조 **0건**. `privesc` phase 는
존재하지만 거기서 돌릴 도구가 등록돼 있지 않다. Hard 는 privesc 가 본론이다.

### G5. 승인 게이트가 기본 전제 — 부분 해결

〔확인〕 `--auto` 는 scope 기반 자동승인이라 범위 내에서는 사람 없이 돈다.
남은 문제는 승인이 아니라 **판단 루프**: 실패했을 때 가설을 바꾸고 다음 수를
고르는 주체가 없다. G1 과 같은 작업.

### G6. Writeup 미참조가 "원칙" 문장뿐 — 미해결, 대회 필수

〔확인〕 `docs/ARCHITECTURE.md` 5절 "외부 검색 없음"이 전부. 대회 규칙은 1등이
**어떤 조치를 취했는지 발표에서 설명**할 것을 요구한다. 증빙 가능한 메커니즘이
필요하다. → `docs/NO-WRITEUP-POLICY.md` 에 설계만 작성, 구현 미완.

---

## 3. 우선순위 (2명 20일)

| 순위 | 항목 | 근거 |
|---|---|---|
| 1 | **G1** 익스플로잇 실행 루프 | 이게 없으면 Hard 는 0문제. 작업량 최대 |
| 2 | **G4** privesc 열거 + G3 KB 채우기 | Hard 의 실제 병목. 둘이 같은 작업 |
| 3 | **G6** 미참조 증빙 | 대회 필수 제출물. 작업량 작음 → 빨리 끝내 둘 것 |
| 4 | 평가 하네스 | 아래 참조 |

### 평가 하네스를 먼저 만들 것

속도가 평가 기준인데 **측정 수단이 없다**. 같은 모델·같은 시간 예산에서
기준선(`--runner oneshot` + LLM 단독)을 먼저 재고, 거기에 지식 계층 → 세션 →
익스플로잇 루프를 하나씩 얹어 각 단계의 기여를 분리 측정해야 한다. 그러지 않으면
무엇이 도움이 됐는지 알 수 없고, 발표에서 설명할 근거도 없다.

측정 항목: 플래그 도달률 · user.txt/root.txt 까지 경과시간 · 토큰·비용 ·
사람 개입 횟수(목표 0) · 막힌 지점 분류.

### 미검증으로 남은 것 — 과장하지 않기 위해 명시

- 실제 HTB 머신 대상 실행을 **한 번도 하지 않았다**. VPN 미연결(`tun0` 없음).
- `ShellSession` 은 로컬 Kali 셸에서만 검증했다. 리버스 셸·`evil-winrm` 경유
  중첩 세션은 미검증.
- 백그라운드 `bg_kill` 은 자식 프로세스까지 확실히 정리하지 않는다
  (`session.py` 의 `ponytail:` 주석 참조).
- 히든문제(10-21)가 어떤 성격인지 모른다. 그 전까지의 측정은 전부 대리지표다.
