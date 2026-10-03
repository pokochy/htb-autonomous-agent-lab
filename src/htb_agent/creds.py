"""
Credential Vault — 자격증명 저장·재사용
=========================================

발견/제공된 자격증명을 저장하고, 지식베이스 제안 템플릿의 {user}/{pass}/{domain}/
{hash} 플레이스홀더를 채워 '수동 제안 → 자동 실행 후보'로 승격시킨다(승인 하).
침투 후 확보한 계정을 AD 단계로 이어가는 연결고리.

⚠️ 자격증명은 민감정보다. 상태 저장(state/)은 .gitignore 처리되며, 로컬
권한 확인된 HTB 훈련 용도에 한정한다. LLM 프롬프트에는 기본적으로 넣지 않는다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_LEFT = re.compile(r"\{[a-zA-Z_]+\}")
# 플레이스홀더 → Credential 속성
_FIELD = {"user": "username", "pass": "password", "domain": "domain",
          "hash": "nt_hash", "nthash": "nt_hash"}


@dataclass
class Credential:
    username: str
    password: str | None = None
    domain: str | None = None
    nt_hash: str | None = None
    source: str = "user"

    def to_dict(self) -> dict:
        return {"username": self.username, "password": self.password,
                "domain": self.domain, "nt_hash": self.nt_hash, "source": self.source}

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        return cls(username=d.get("username", ""), password=d.get("password"),
                   domain=d.get("domain"), nt_hash=d.get("nt_hash"),
                   source=d.get("source", "user"))

    def label(self) -> str:
        dom = f"{self.domain}/" if self.domain else ""
        secret = "****" if (self.password or self.nt_hash) else "(no-secret)"
        return f"{dom}{self.username}:{secret}"


def fill(template: str, target: str, cred: Credential) -> tuple[str, bool]:
    """템플릿의 {t} + 자격증명 플레이스홀더를 채운다. (cmd, 완전치환?) 반환."""
    cmd = template.replace("{t}", target)
    for ph, attr in _FIELD.items():
        val = getattr(cred, attr, None)
        if val:
            cmd = cmd.replace("{" + ph + "}", val)
    return cmd, (_LEFT.search(cmd) is None)


class CredentialVault:
    def __init__(self, creds: list[Credential] | None = None):
        self.creds = creds if creds is not None else []

    def add(self, cred: Credential) -> None:
        # 중복(동일 user/pass/domain) 제거
        key = (cred.username, cred.password, cred.domain, cred.nt_hash)
        if key not in {(c.username, c.password, c.domain, c.nt_hash) for c in self.creds}:
            self.creds.append(cred)

    @classmethod
    def from_cli(cls, items: list[str] | None) -> "CredentialVault":
        """'user:pass' 또는 'user:pass:domain' 또는 'user' 형식 파싱."""
        vault = cls()
        for item in items or []:
            parts = item.split(":")
            username = parts[0]
            password = parts[1] if len(parts) > 1 and parts[1] != "" else None
            domain = parts[2] if len(parts) > 2 and parts[2] != "" else None
            if username:
                vault.add(Credential(username=username, password=password,
                                     domain=domain, source="cli"))
        return vault

    @classmethod
    def load_file(cls, path: str) -> "CredentialVault":
        vault = cls()
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return vault
        for d in (data if isinstance(data, list) else [data]):
            if isinstance(d, dict) and d.get("username"):
                vault.add(Credential.from_dict(d))
        return vault

    def expand(self, template: str, target: str,
               max_creds: int = 3) -> list[tuple[str, bool]]:
        """
        템플릿을 (명령, 실행가능여부) 목록으로 확장.
        - 자격증명 플레이스홀더가 없으면 → [(cmd, True)]
        - 있고 볼트에 자격증명이 있으면 → 채워진 명령들(runnable=True)
        - 있고 볼트가 비면 → [(원본, False)] (수동 제안으로 남김)
        """
        base = template.replace("{t}", target)
        if _LEFT.search(base) is None:
            return [(base, True)]
        if not self.creds:
            return [(base, False)]
        out: list[tuple[str, bool]] = []
        seen: set[str] = set()
        for cred in self.creds[:max_creds]:
            cmd, filled = fill(template, target, cred)
            if filled and cmd not in seen:
                seen.add(cmd)
                out.append((cmd, True))
        return out or [(base, False)]

    def to_list(self) -> list[dict]:
        return [c.to_dict() for c in self.creds]
