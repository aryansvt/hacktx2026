"""make one real call to the trap's llm fallback model and print the latency and result.

it builds the same prompt the trap would for `git status` in /var/www/html,
through the same client (pinned to api.anthropic.com), so the numbers match
what attackers get. each --repeat is one small haiku call.

inside the trap container (the image has the honeypot package, not scripts/,
so pipe the file in):
    docker compose -f infra/trap/docker-compose.yml exec -T trap python - < scripts/llm_probe.py
    docker compose -f infra/trap/docker-compose.yml exec -T trap python - --mode schema --repeat 3 < scripts/llm_probe.py

locally, with the trap package installed:
    ANTHROPIC_API_KEY=... python scripts/llm_probe.py
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time

from honeypot.llm import fallback, prompt
from honeypot.shell.engine import Engine, load_system

COMMAND = "git status"
CWD = "/var/www/html"


def build_prompts(command: str) -> tuple[str, str]:
    state = Engine().new_state("root", tty=False)
    state.cwd = CWD
    state.history += [f"cd {CWD}", command]
    return prompt.system_prompt(load_system()), prompt.user_prompt(state, command, command.split(), None)


async def probe(provider, repeat: int, command: str, out=None) -> int:
    out = out or sys.stdout
    system, user = build_prompts(command)
    limit = int(fallback.TIMEOUT * 1000)
    try:
        out.write(f"warm-up (GET /v1/models): {await provider.warm()} ms\n")
    except Exception as e:
        out.write(f"warm-up failed: {e!r}\n")
    status = 0
    for n in range(1, repeat + 1):
        t0 = time.perf_counter()
        try:
            reply = await provider.complete(system, [{"role": "user", "content": user}], prompt.SCHEMA)
        except Exception as e:
            out.write(f"call {n}: failed after {int((time.perf_counter() - t0) * 1000)} ms: {e!r}\n")
            status = 2
            continue
        wall = int((time.perf_counter() - t0) * 1000)
        verdict = "ok" if wall <= limit else f"SLOWER than the {limit} ms timeout"
        out.write(f"call {n}: {reply.ms} ms ({verdict}), stop={reply.stop}, "
                  f"tokens in={reply.input_tokens} out={reply.output_tokens}\n")
        try:
            answer = fallback.parse_answer(reply.text)
            how = "parsed"
        except fallback.Invalid as e:
            answer = fallback.salvage(reply.text) if reply.stop == "max_tokens" else None
            how = "salvaged from a cut-off reply" if answer else f"NOT parseable ({e}), the trap would send a repair request"
        out.write(f"  json: {how}\n")
        if answer is None:
            out.write("  raw reply:\n" + "".join(f"    {line}\n" for line in reply.text.splitlines()))
            status = status or 1
            continue
        out.write(f"  $ {command}\n" + "".join(f"    {line}\n" for line in answer.stdout.splitlines()))
        if answer.changes:
            out.write("  fs_changes: " + json.dumps([list(c[:2]) for c in answer.changes]) + "\n")
    return status


def main(argv: list[str] | None = None, provider=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["plain", "schema"], default="plain",
                    help="plain asks for json in the prompt (what the trap uses), schema sends the json schema")
    ap.add_argument("--repeat", type=int, default=1, help="calls to make, 1 to 5")
    ap.add_argument("--command", default=COMMAND)
    args = ap.parse_args(argv)
    repeat = max(1, min(args.repeat, 5))
    if provider is None:
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not key:
            print("ANTHROPIC_API_KEY is not set", file=sys.stderr)
            return 2
        from honeypot.llm.anthropic_client import AnthropicProvider

        provider = AnthropicProvider(key, structured=args.mode == "schema")
    print(f"model {getattr(provider, 'model', '?')}, mode {args.mode}, timeout {fallback.TIMEOUT:g} s")

    async def run() -> int:
        try:
            return await probe(provider, repeat, args.command)
        finally:
            await provider.close()

    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
