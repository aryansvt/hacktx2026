"""settings from env vars. every value has a safe local default."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"


def _int(env: dict, name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    return int(raw) if raw else default


def _float(env: dict, name: str, default: float) -> float:
    raw = env.get(name, "").strip()
    return float(raw) if raw else default


@dataclass
class Settings:
    ssh_host: str = "0.0.0.0"
    ssh_port: int = 2222
    # the fake website listens on ssh_host too
    http_port: int = 8080
    state_dir: Path = Path("state")
    logins_path: Path = DATA / "logins.json"
    guest_user: str = ""
    guest_password: str = ""
    team_user: str = ""
    team_password: str = ""
    team_ips: frozenset[str] = field(default_factory=frozenset)
    # limits
    max_connections: int = 200
    max_sessions_per_conn: int = 10
    login_timeout: float = 60
    idle_timeout: float = 300
    hard_timeout: float = 1800
    # where the sender posts events. empty url or token turns the sender off
    core_url: str = ""
    ingest_token: str = ""
    # llm fallback for installed commands the engine doesn't model. no key turns it off
    llm_provider: str = "anthropic"
    anthropic_api_key: str = ""
    llm_hourly_cap: int = 200

    @property
    def llm_log_path(self) -> Path:
        return self.state_dir / "llm.jsonl"

    @property
    def spool_path(self) -> Path:
        return self.state_dir / "spool.jsonl"

    @property
    def cursor_path(self) -> Path:
        return self.state_dir / "spool.cursor"

    @property
    def dead_letter_path(self) -> Path:
        return self.state_dir / "dead_letter.jsonl"

    @property
    def host_key_dir(self) -> Path:
        return self.state_dir / "host_keys"

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Settings":
        env = os.environ if env is None else env
        ips = frozenset(ip.strip() for ip in env.get("TEAM_IPS", "").split(",") if ip.strip())
        return cls(
            ssh_host=env.get("TRAP_SSH_HOST", "0.0.0.0"),
            ssh_port=_int(env, "TRAP_SSH_PORT", 2222),
            http_port=_int(env, "TRAP_HTTP_PORT", 8080),
            state_dir=Path(env.get("TRAP_STATE_DIR") or "state"),
            logins_path=Path(env.get("TRAP_LOGINS_PATH") or DATA / "logins.json"),
            guest_user=env.get("GUEST_SSH_USER", ""),
            guest_password=env.get("GUEST_SSH_PASSWORD", ""),
            team_user=env.get("TEAM_SSH_USER", ""),
            team_password=env.get("TEAM_SSH_PASSWORD", ""),
            team_ips=ips,
            max_connections=_int(env, "TRAP_MAX_CONNECTIONS", 200),
            max_sessions_per_conn=_int(env, "TRAP_MAX_SESSIONS_PER_CONN", 10),
            login_timeout=_float(env, "TRAP_LOGIN_TIMEOUT", 60),
            idle_timeout=_float(env, "TRAP_IDLE_TIMEOUT", 300),
            hard_timeout=_float(env, "TRAP_HARD_TIMEOUT", 1800),
            core_url=env.get("CORE_URL", "").strip().rstrip("/"),
            ingest_token=env.get("INGEST_TOKEN", "").strip(),
            llm_provider=env.get("LLM_PROVIDER", "").strip().lower() or "anthropic",
            anthropic_api_key=env.get("ANTHROPIC_API_KEY", "").strip(),
            llm_hourly_cap=_int(env, "LLM_HOURLY_CAP", 200),
        )
