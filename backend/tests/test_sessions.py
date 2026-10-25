from datetime import datetime, timedelta, timezone

import pytest
from hacktx_contracts import SessionSummary

from app.sessions import apply_event, fmt_ts, next_status, parse_ts, to_summary

from .conftest import make_event

T0 = datetime(2026, 10, 24, 18, 0, 0, tzinfo=timezone.utc)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def fold(events):
    row = None
    for e in events:
        row = apply_event(row, e)
    return row


@pytest.mark.parametrize(
    "current,event,expected",
    [
        ("approaching", "login_fail", "at_gate"),
        ("approaching", "login_success", "inside"),
        ("at_gate", "login_fail", "at_gate"),
        ("at_gate", "login_success", "inside"),
        ("inside", "login_fail", "inside"),
        ("inside", "command", "inside"),
        ("approaching", "session_end", "ended"),
        ("inside", "session_end", "ended"),
        ("ended", "login_success", "ended"),
        ("ended", "login_fail", "ended"),
        ("approaching", "classified", "approaching"),
    ],
)
def test_next_status(current, event, expected):
    assert next_status(current, event) == expected


def test_full_lifecycle():
    row = fold(
        [
            make_event("session_start", ts=at(0), kind="unknown"),
            make_event("login_fail", ts=at(1)),
            make_event("login_fail", ts=at(2)),
            make_event("login_success", ts=at(3)),
            make_event("command", ts=at(4)),
            make_event("command", ts=at(5)),
            make_event("story", ts=at(6), detail={"story": "the troll got in"}),
            make_event("session_end", ts=at(7), detail={"duration_s": 7, "command_count": 2}),
        ]
    )
    assert row["status"] == "ended"
    assert row["login_fails"] == 2
    assert row["command_count"] == 2
    assert row["breached"] is True
    assert row["story"] == "the troll got in"
    assert row["started_at"] == at(0)
    assert row["ended_at"] == at(7)
    assert row["attacker"]["kind"] == "bot"


def test_status_steps_through_the_gate():
    row = apply_event(None, make_event("session_start", ts=at(0)))
    assert row["status"] == "approaching"
    row = apply_event(row, make_event("login_fail", ts=at(1)))
    assert row["status"] == "at_gate"
    row = apply_event(row, make_event("login_success", ts=at(2)))
    assert row["status"] == "inside"
    row = apply_event(row, make_event("session_end", ts=at(3)))
    assert row["status"] == "ended"


def test_out_of_order_events_do_not_regress():
    row = fold(
        [
            make_event("session_start", ts=at(0), kind="unknown"),
            make_event("classified", ts=at(5), kind="human"),
            make_event("login_success", ts=at(3), kind="unknown"),
            make_event("login_fail", ts=at(2), kind="unknown"),
        ]
    )
    assert row["status"] == "inside"
    assert row["login_fails"] == 1
    # older events don't overwrite the newer classification
    assert row["attacker"]["kind"] == "human"
    assert row["last_seen"] == at(5)


def test_session_created_by_first_event_of_any_type():
    row = apply_event(None, make_event("command", ts=at(10)))
    assert row["status"] == "approaching"
    assert row["command_count"] == 1
    row = apply_event(row, make_event("session_start", ts=at(1)))
    assert row["started_at"] == at(1)


def test_session_end_keeps_the_higher_command_count():
    row = fold([make_event("command", ts=at(1)), make_event("command", ts=at(2))])
    row = apply_event(row, make_event("session_end", ts=at(3), detail={"duration_s": 3, "command_count": 1}))
    assert row["command_count"] == 2
    row = apply_event(None, make_event("session_end", ts=at(3), detail={"duration_s": 3, "command_count": 9}))
    assert row["command_count"] == 9


def test_apply_event_does_not_mutate():
    row = apply_event(None, make_event("session_start", ts=at(0)))
    snapshot = dict(row)
    apply_event(row, make_event("login_fail", ts=at(1)))
    assert row == snapshot


def test_summary_matches_contract():
    row = fold([make_event("session_start", ts=at(0)), make_event("session_end", ts=at(1))])
    summary = to_summary(row)
    SessionSummary.model_validate(summary)
    assert summary["started_at"] == "2026-10-24T18:00:00.000Z"
    assert summary["ended_at"] == "2026-10-24T18:00:01.000Z"


def test_timestamp_round_trip():
    assert fmt_ts(parse_ts("2026-10-24T18:03:11.250Z")) == "2026-10-24T18:03:11.250Z"
    assert parse_ts("2026-10-24T18:03:11Z") == datetime(2026, 10, 24, 18, 3, 11, tzinfo=timezone.utc)
