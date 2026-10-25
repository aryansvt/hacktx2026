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


@pytest.fixture
def no_network(monkeypatch):
    """any outbound connection attempt fails the test."""

    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket.socket, "connect_ex", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
