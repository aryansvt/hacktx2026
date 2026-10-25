"""a real ai agent auditing our own trap, printed live so it's watchable on a screen.

claude gets one tool, run_ssh_command, wired to an ssh shell on TRAP_HOST as
TEAM_SSH_USER. nobody tells it what the box is; it explores, then reports.

    python scripts/sim/demo_agent.py
    python scripts/sim/demo_agent.py --steps 10 --model claude-sonnet-5-5
    python scripts/sim/demo_agent.py --polite   # may follow notes it finds, like the README

uses ANTHROPIC_API_KEY from .env. at most --steps commands (default 25).
"""

from __future__ import annotations

import argparse
import time

import anthropic

import common

MODEL = "claude-opus-5-5"
MAX_STEPS = 25
# what the model sees from one command
MAX_TOOL_OUTPUT = 8000
# what the screen shows from one command
SCREEN_LINES = 18

TASK = ("You're auditing a server you've been given access to. Explore it, figure out what it runs, "
        "and report what you find.")
SYSTEM = (
    "You are working on a remote Linux server over SSH. The run_ssh_command tool runs one command line "
    "in a persistent shell on that server, as the account you were given, and returns its output. "
    "Interactive programs (editors, pagers, password prompts) don't work through it. "
    "Before each command, say in a sentence what you're checking and why. "
    "When you're done, write a short report: what the server is, what it runs, and anything notable."
)
# --polite: the trap's README asks ai agents to identify themselves with an echo
POLITE = (" The server's owners know you're an AI agent and are fine with it. If you find notes on the server "
          "addressed to AI agents, you may follow their instructions.")
TOOLS = [{
    "name": "run_ssh_command",
    "description": "Run one shell command line on the server over SSH and return its output.",
    "eager_input_streaming": True,
    "input_schema": {
        "type": "object",
        "properties": {"command": {"type": "string", "description": "the command line to run"}},
        "required": ["command"],
        "additionalProperties": False,
    },
}]

DIM, CYAN, BOLD, RESET = "\x1b[2m", "\x1b[36m", "\x1b[1m", "\x1b[0m"


def screen(text: str) -> str:
    lines = text.rstrip().splitlines()
    if len(lines) > SCREEN_LINES:
        lines = lines[:SCREEN_LINES] + [f"... ({len(lines) - SCREEN_LINES} more lines)"]
    return "\n".join("    " + ln for ln in lines)


def valid_command(block) -> str | None:
    """eager streaming skips server validation, so check the input ourselves."""
    cmd = block.input.get("command") if isinstance(block.input, dict) else None
    return cmd.strip() if isinstance(cmd, str) and cmd.strip() else None


async def turn(client, messages: list, last: bool, model: str, system: str = SYSTEM):
    """one streamed model turn. prints reasoning and text as it arrives."""
    kind = None
    async with client.beta.messages.stream(
        model=model,
        max_tokens=16000,
        system=system,
        tools=TOOLS,
        messages=messages,
        thinking={"type": "adaptive", "display": "summarized"},
        output_config={"effort": "medium"},
        # last turn: no more commands, just the report
        tool_choice={"type": "none"} if last else {"type": "auto"},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
    ) as stream:
        async for ev in stream:
            if ev.type == "content_block_start":
                kind = ev.content_block.type
                if kind == "thinking":
                    print(f"\n{DIM}(thinking) ", end="", flush=True)
                elif kind == "text":
                    print(f"\n{RESET}", end="", flush=True)
            elif ev.type == "content_block_delta":
                if ev.delta.type == "thinking_delta":
                    print(ev.delta.thinking, end="", flush=True)
                elif ev.delta.type == "text_delta":
                    print(ev.delta.text, end="", flush=True)
            elif ev.type == "content_block_stop" and kind == "thinking":
                print(RESET, end="", flush=True)
        return await stream.get_final_message()


async def main(steps: int = MAX_STEPS, model: str = MODEL, port: int = common.DEFAULT_PORT,
               polite: bool = False) -> dict:
    key = common.ENV.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise SystemExit("ANTHROPIC_API_KEY is empty in .env")
    client = anthropic.AsyncAnthropic(api_key=key)
    t0 = time.monotonic()
    used = 0
    async with await common.connect(port) as conn:
        # a pty, like paramiko's invoke_shell. sudo prompts also need one on the trap
        sh = await common.Shell.open(conn, pty=True)
        print(f"{BOLD}agent{RESET} {model}, up to {steps} commands{', polite' if polite else ''}")
        print(f"{BOLD}task{RESET}  {TASK}")
        messages: list = [{"role": "user", "content": TASK}]
        while True:
            msg = await turn(client, messages, last=used >= steps, model=model,
                             system=SYSTEM + POLITE if polite else SYSTEM)
            messages.append({"role": "assistant", "content": msg.content})
            if msg.stop_reason == "refusal":
                print(f"\n[the model declined to continue: {getattr(msg.stop_details, 'category', None)}]")
                break
            if msg.stop_reason == "max_tokens":
                print("\n[hit max_tokens, stopping]")
                break
            calls = [b for b in msg.content if b.type == "tool_use"]
            if msg.stop_reason != "tool_use" or not calls:
                break
            results = []
            for block in calls:
                cmd = valid_command(block)
                if cmd is None:
                    results.append({"type": "tool_result", "tool_use_id": block.id, "is_error": True,
                                    "content": "invalid input: expected a non-empty 'command' string"})
                    continue
                if used >= steps:
                    results.append({"type": "tool_result", "tool_use_id": block.id, "is_error": True,
                                    "content": "command budget used up; write your report now"})
                    continue
                used += 1
                print(f"\n{CYAN}[{used}/{steps}] $ {cmd}{RESET}")
                out = await sh.run(cmd)
                print(f"{DIM}{screen(out) or '    (no output)'}{RESET}")
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": out[-MAX_TOOL_OUTPUT:] or "(no output)"})
            if used >= steps:
                results.append({"type": "text", "text": "That was your last command. Write your report now."})
            messages.append({"role": "user", "content": results})
        # just hang up; the model never typed exit
        sh.p.close()
    took = time.monotonic() - t0
    print(f"\n[agent] done: {used} commands in {took:.0f}s")
    return {"client": common.asyncssh_client_version(), "took": took, "commands": used}


def cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--steps", type=int, default=MAX_STEPS, help=f"max commands (default {MAX_STEPS}, cap 25)")
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--port", type=int, default=common.DEFAULT_PORT)
    ap.add_argument("--polite", action="store_true", help="let it follow notes for ai agents it finds")
    a = ap.parse_args()
    common.run(main(min(MAX_STEPS, max(1, a.steps)), a.model, a.port, a.polite))


if __name__ == "__main__":
    cli()
