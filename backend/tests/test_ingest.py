import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

from .conftest import EXAMPLES, TOKEN, load_example

AUTH = {"Authorization": f"Bearer {TOKEN}"}
VALID = sorted(p.name for p in (EXAMPLES / "valid").glob("raw_event.*.json"))
INVALID = sorted(p.name for p in (EXAMPLES / "invalid").glob("raw_event.*.json"))


def valid_batch():
    return [load_example(f"valid/{name}") for name in VALID]


def test_valid_batch_lands_in_raw_stream(app, sync_redis):
    batch = valid_batch()
    with TestClient(app) as client:
        resp = client.post("/ingest", json=batch, headers=AUTH)
    assert resp.status_code == 202
    assert resp.json() == {"accepted": len(batch)}
    entries = sync_redis.xrange("raw")
    assert [json.loads(fields["data"]) for _, fields in entries] == batch


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong"},
        {"Authorization": TOKEN},
        {"Authorization": f"Basic {TOKEN}"},
    ],
)
def test_bad_auth_is_rejected(app, sync_redis, headers):
    with TestClient(app) as client:
        resp = client.post("/ingest", json=valid_batch(), headers=headers)
    assert resp.status_code == 401
    assert sync_redis.xlen("raw") == 0


def test_empty_token_disables_ingest(settings, redis, store):
    app = create_app(replace(settings, ingest_token=""), redis=redis, store=store)
    with TestClient(app) as client:
        resp = client.post("/ingest", json=valid_batch(), headers={"Authorization": "Bearer "})
    assert resp.status_code == 401


@pytest.mark.parametrize("name", INVALID)
def test_invalid_examples_reject_the_whole_batch(app, sync_redis, name):
    bad = load_example(f"invalid/{name}")
    with TestClient(app) as client:
        resp = client.post("/ingest", json=[*valid_batch(), bad], headers=AUTH)
    assert resp.status_code == 422
    invalid = resp.json()["detail"]["invalid"]
    assert [i["index"] for i in invalid] == [len(VALID)]
    assert sync_redis.xlen("raw") == 0


def test_errors_do_not_echo_input(app):
    bad = load_example("invalid/raw_event.password_in_detail.json")
    with TestClient(app) as client:
        resp = client.post("/ingest", json=[bad], headers=AUTH)
    assert resp.status_code == 422
    assert '"input"' not in resp.text
    for value in bad["detail"].values():
        if isinstance(value, str) and len(value) > 4:
            assert value not in resp.text


@pytest.mark.parametrize("body", ["not json", "{}", "[]", '{"a": 1}'])
def test_body_must_be_a_non_empty_array(app, body):
    with TestClient(app) as client:
        resp = client.post("/ingest", content=body, headers={**AUTH, "content-type": "application/json"})
    assert resp.status_code == 422


def test_batch_size_cap(settings, redis, store):
    app = create_app(replace(settings, ingest_max_batch=2), redis=redis, store=store)
    with TestClient(app) as client:
        resp = client.post("/ingest", json=valid_batch()[:3], headers=AUTH)
    assert resp.status_code == 413


def test_rate_limit(settings, redis, store):
    app = create_app(replace(settings, ingest_rate_per_sec=0.01, ingest_burst=2), redis=redis, store=store)
    batch = valid_batch()[:1]
    with TestClient(app) as client:
        codes = [client.post("/ingest", json=batch, headers=AUTH).status_code for _ in range(3)]
        limited = client.post("/ingest", json=batch, headers=AUTH)
    assert codes == [202, 202, 429]
    assert int(limited.headers["Retry-After"]) >= 1


def test_rate_limit_applies_before_auth(settings, redis, store):
    # token guessing burns the same budget
    app = create_app(replace(settings, ingest_rate_per_sec=0.01, ingest_burst=1), redis=redis, store=store)
    with TestClient(app) as client:
        first = client.post("/ingest", json=[], headers={"Authorization": "Bearer nope"})
        second = client.post("/ingest", json=[], headers={"Authorization": "Bearer nope"})
    assert (first.status_code, second.status_code) == (401, 429)
