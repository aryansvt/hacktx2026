"""list the commands the trap's rules engine sends to the llm most often.

the trap writes one json line per llm-route command to $TRAP_STATE_DIR/llm.jsonl
(rotated to llm.jsonl.1 at 8 MiB). the top of this list is what to model next.

    python scripts/llm_misses.py trap/state/llm.jsonl
    python scripts/llm_misses.py trap/state/llm.jsonl trap/state/llm.jsonl.1 --by command --top 50

on the trap box, from the repo:
    docker compose -f infra/trap/docker-compose.yml exec -T trap cat /state/llm.jsonl | python3 scripts/llm_misses.py -
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, TextIO


@dataclass
class Row:
    key: str
    count: int = 0
    outcomes: Counter = field(default_factory=Counter)
    # latency only counts real llm calls, not cache hits or instant fallbacks
    llm_ms: list[int] = field(default_factory=list)

    @property
    def avg_ms(self) -> int | None:
        return round(sum(self.llm_ms) / len(self.llm_ms)) if self.llm_ms else None


LLM_OUTCOMES = {"ok", "timeout", "invalid", "error", "rejected"}


def read(lines: Iterable[str]) -> list[dict]:
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and "outcome" in rec:
            out.append(rec)
    return out


def summarize(records: list[dict], by: str = "name") -> list[Row]:
    rows: dict[str, Row] = {}
    for rec in records:
        key = str(rec.get(by) or rec.get("command") or "?")
        row = rows.setdefault(key, Row(key))
        row.count += 1
        row.outcomes[rec["outcome"]] += 1
        if rec["outcome"] in LLM_OUTCOMES and isinstance(rec.get("latency_ms"), int):
            row.llm_ms.append(rec["latency_ms"])
    return sorted(rows.values(), key=lambda r: (-r.count, r.key))


def render(rows: list[Row], top: int, out: TextIO) -> None:
    total = sum(r.count for r in rows)
    out.write(f"{total} llm-route commands, {len(rows)} distinct\n\n")
    out.write(f"{'count':>6}  {'avg ms':>6}  {'outcomes':<36}  command\n")
    for r in rows[:top]:
        outcomes = " ".join(f"{k} {v}" for k, v in r.outcomes.most_common())
        avg = "-" if r.avg_ms is None else str(r.avg_ms)
        out.write(f"{r.count:>6}  {avg:>6}  {outcomes:<36}  {r.key}\n")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", default=["trap/state/llm.jsonl"], help="llm.jsonl files, or - for stdin")
    ap.add_argument("--by", choices=["name", "command"], default="name", help="group by program name or full command")
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args(argv)
    records: list[dict] = []
    for path in args.paths:
        if path == "-":
            records += read(sys.stdin)
            continue
        try:
            with open(path, encoding="utf-8") as f:
                records += read(f)
        except FileNotFoundError:
            sys.exit(f"no such file: {path}")
    render(summarize(records, args.by), args.top, sys.stdout)


if __name__ == "__main__":
    main()
