import pytest

from brain.__main__ import main


async def test_refuses_to_start_without_salt(monkeypatch):
    monkeypatch.setenv("IP_HASH_SALT", "")
    with pytest.raises(SystemExit):
        await main()
