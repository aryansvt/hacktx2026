import socket
from pathlib import Path

import pytest

from honeypot.vfs import BaseFS, Overlay

DATA = Path(__file__).resolve().parent.parent / "honeypot" / "data"


@pytest.fixture(scope="session")
def base() -> BaseFS:
    return BaseFS.load(DATA / "fs_base.json")


@pytest.fixture
def fs(base) -> Overlay:
    return Overlay(base)


def block_network(monkeypatch) -> None:
    """any outbound connection attempt fails the test."""

    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket.socket, "connect_ex", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)


@pytest.fixture
def no_network(monkeypatch):
    block_network(monkeypatch)


@pytest.fixture
async def no_network_async(monkeypatch):
    """same, for async tests. patched after the loop exists, since windows builds it with a socketpair."""
    block_network(monkeypatch)


@pytest.fixture(scope="session")
def engine():
    from honeypot.shell.engine import Engine

    return Engine()


@pytest.fixture
def sh(engine, base):
    """run lines in one fresh root session. sh.state exposes the session."""
    state = engine.new_state("root", tty=False, base=base)

    def run(line: str) -> str:
        return engine.run(state, line).out

    run.state = state
    run.engine = engine
    return run
