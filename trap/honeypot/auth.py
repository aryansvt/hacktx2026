"""login policy. passwords are compared here and dropped, never stored or logged."""

from __future__ import annotations

import hmac
import json
from pathlib import Path

from .config import Settings


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8", "replace"), b.encode("utf-8", "replace"))


class Auth:
    def __init__(
        self,
        pairs: list[tuple[str, str]],
        guest: tuple[str, str] | None = None,
        team: tuple[str, str] | None = None,
        team_ips: frozenset[str] = frozenset(),
    ):
        self._pairs = list(pairs)
        # a demo login only counts when both user and password are set
        self._guest = guest if guest and all(guest) else None
        self._team = team if team and all(team) else None
        self.team_ips = team_ips

    @classmethod
    def load(cls, settings: Settings) -> "Auth":
        return cls(
            load_pairs(settings.logins_path),
            guest=(settings.guest_user, settings.guest_password),
            team=(settings.team_user, settings.team_password),
            team_ips=settings.team_ips,
        )

    def check(self, username: str, password: str) -> str | None:
        """return the login's source (team, guest, wild) or None if rejected."""
        if self._team and _same(username, self._team[0]) and _same(password, self._team[1]):
            return "team"
        if self._guest and _same(username, self._guest[0]) and _same(password, self._guest[1]):
            return "guest"
        ok = False
        for user, pw in self._pairs:
            # no early exit so timing doesn't hint at which pair matched
            ok |= _same(username, user) & _same(password, pw)
        return "wild" if ok else None

    def source_for(self, ip: str, login_source: str | None) -> str:
        """team ips win over anything a login says."""
        if ip in self.team_ips:
            return "team"
        return login_source or "wild"


def load_pairs(path: Path) -> list[tuple[str, str]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [(str(u), str(p)) for u, p in data["allow"]]
