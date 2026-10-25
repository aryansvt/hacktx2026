"""llm fallback for installed commands the rules engine doesn't model.

the engine stays synchronous. a line runs with a hook that answers unknown
commands from this line's answers or the cache, and notes the rest as misses.
if there were misses, the line is rolled back, the misses go to the llm
together, and the line runs again with the answers. answers carry fs_changes,
which land in the session overlay so later commands see them.

anything that goes wrong (timeout, caps, breaker, bad json, output that
contradicts the fs) ends in a plain "command not found", and that command
stays not found for the rest of the session.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import shlex
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..events import now_ts
from ..shell.engine import Engine, Result, ShellState
from ..vfs import FsError, norm
from . import prompt
from .provider import LLMError, LLMTimeout, Provider, Reply

log = logging.getLogger("honeypot.llm")

TIMEOUT = 6.0
# warm the api connection when it's been idle this long
KEEP_WARM = 120.0
SESSION_CAP = 30
BREAKER_FAILURES = 5
BREAKER_WINDOW = 60.0
BREAKER_COOLDOWN = 60.0
CACHE_SIZE = 2000
# each round can find new unknown commands; the last round never asks
MAX_ROUNDS = 3
MAX_STDOUT = 16_000
MAX_CHANGES = 10
MAX_CONTENT = 64_000
LOG_ROTATE_BYTES = 8 << 20
NO_WRITE = ("/proc", "/sys", "/dev", "/run")

SECRETS = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bsk-ant-[A-Za-z0-9_-]{8,}"
    r"|\bsk-[A-Za-z0-9]{32,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{30,}"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|\$(?:1|5|6|y|2[aby])\$[^\s:]{8,}"
)

Key = tuple[str, str, str, str]


class Invalid(Exception):
    """reply isn't the json we asked for."""


class Rejected(Exception):
    """reply is json but we won't use it."""


class Blocked(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Answer:
    stdout: str
    changes: tuple[tuple[str, str, str], ...] = ()


@dataclass
class Resolved:
    answer: Answer | None
    outcome: str
    ms: int
    calls: list[dict] = field(default_factory=list)


@dataclass
class Miss:
    key: Key
    command: str
    cwd: str
    user_prompt: str


@dataclass
class LLMSession:
    session_id: str
    calls: int = 0
    # command names that fell back once and stay "not found"
    missing: set[str] = field(default_factory=set)


_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")
_STDOUT_START = re.compile(r'^\s*\{\s*"stdout"\s*:\s*"')


def _load(text: str):
    """the first json object in the reply, tolerating code fences and chatter around it."""
    if not isinstance(text, str):
        raise Invalid("not text")
    body = _FENCE.sub("", text.strip())
    start = body.find("{")
    if start < 0:
        raise Invalid("no json object")
    try:
        return json.JSONDecoder().raw_decode(body, start)[0]
    except json.JSONDecodeError as e:
        raise Invalid(f"not json: {e}") from e


def salvage(text: str) -> Answer | None:
    """a reply cut off by max_tokens: keep the stdout that made it, drop any fs changes."""
    rest = _FENCE.sub("", text.strip())
    m = _STDOUT_START.match(rest)
    if not m:
        return None
    raw, i = [], m.end()
    while i < len(rest):
        c = rest[i]
        if c == '"':
            break
        if c == "\\":
            if i + 1 >= len(rest):
                break
            raw.append(rest[i : i + 2])
            i += 2
            continue
        raw.append(c)
        i += 1
    try:
        stdout = json.loads('"' + "".join(raw) + '"')
    except json.JSONDecodeError:
        # a \u escape cut in half; drop it
        stdout = json.loads('"' + re.sub(r"\\u[0-9a-fA-F]{0,3}$", "", "".join(raw)) + '"')
    # the last line is probably half a line
    stdout = stdout.rsplit("\n", 1)[0] if "\n" in stdout else stdout
    return Answer(stdout[:MAX_STDOUT])


def parse_answer(text: str) -> Answer:
    data = _load(text)
    if not isinstance(data, dict) or not isinstance(data.get("stdout"), str):
        raise Invalid("missing stdout")
    raw = data.get("fs_changes", [])
    if not isinstance(raw, list) or len(raw) > MAX_CHANGES:
        raise Invalid("bad fs_changes")
    changes = []
    for c in raw:
        if not isinstance(c, dict):
            raise Invalid("bad change")
        op, path, content = c.get("op"), c.get("path"), c.get("content", "")
        if op not in ("write", "mkdir", "delete") or not isinstance(path, str) or not path.startswith("/"):
            raise Invalid("bad change")
        if not isinstance(content, str) or len(content) > MAX_CONTENT:
            raise Invalid("bad content")
        changes.append((op, norm(path), content if op == "write" else ""))
    return Answer(data["stdout"][:MAX_STDOUT], tuple(changes))


def screen(answer: Answer) -> None:
    """refuse anything that looks like a real secret, whatever the prompt said."""
    for text in [answer.stdout] + [c[2] for c in answer.changes]:
        if SECRETS.search(text):
            raise Rejected("looks like a secret")


def contradicts(answer: Answer, state: ShellState, argv: list[str]) -> bool:
    """claims a path the session can see is missing."""
    for a in argv[1:]:
        if a.startswith("-") or not a:
            continue
        if f"{a}: No such file or directory" in answer.stdout and state.fs.exists(norm(a, state.cwd)):
            return True
    return False


def apply(answer: Answer, state: ShellState, argv: list[str]) -> Result | None:
    """the answer as a result, with its fs changes applied. None if it contradicts the fs."""
    if contradicts(answer, state, argv):
        return None
    snap = state.fs.snapshot()
    try:
        for op, path, content in answer.changes:
            if path == "/" or any(path == p or path.startswith(p + "/") for p in NO_WRITE):
                raise FsError("EACCES", path)
            if op == "write":
                state.fs.write(path, content, state.user)
            elif op == "mkdir":
                if not state.fs.is_dir(path):
                    state.fs.mkdir(path, state.user)
            else:
                state.fs.remove(path, state.user, recursive=True, dir_ok=True)
    except FsError:
        state.fs.restore(snap)
        return None
    out = answer.stdout
    if out and not out.endswith("\n"):
        out += "\n"
    return Result(out=out)


def not_found(name: str) -> Result:
    return Result(err=f"{name}: command not found\n", code=127)


def command_text(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


def cache_key(state: ShellState, argv: list[str], stdin: str | None) -> Key:
    digest = hashlib.sha256(stdin.encode("utf-8", "replace")).hexdigest()[:16] if stdin else ""
    return command_text(argv), state.cwd, state.user, digest


class Breaker:
    """after BREAKER_FAILURES failures inside BREAKER_WINDOW, stay open for BREAKER_COOLDOWN."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.failures: deque[float] = deque()
        self.until = 0.0

    @property
    def open(self) -> bool:
        return self.clock() < self.until

    def failure(self) -> None:
        now = self.clock()
        self.failures.append(now)
        while self.failures and self.failures[0] <= now - BREAKER_WINDOW:
            self.failures.popleft()
        if len(self.failures) >= BREAKER_FAILURES:
            self.until = now + BREAKER_COOLDOWN
            self.failures.clear()
            log.warning("llm breaker open for %ds", BREAKER_COOLDOWN)


class HourlyCap:
    def __init__(self, cap: int, clock: Callable[[], float] = time.time):
        self.cap = cap
        self.clock = clock
        self.hour = -1
        self.used = 0

    def _roll(self) -> None:
        hour = int(self.clock() // 3600)
        if hour != self.hour:
            self.hour, self.used = hour, 0

    @property
    def spent(self) -> bool:
        self._roll()
        return self.used >= self.cap

    def take(self) -> None:
        self._roll()
        self.used += 1


class CallLog:
    """one json line per command that went the llm route, for scripts/llm_misses.py."""

    def __init__(self, path: Path | None):
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: dict) -> None:
        api = f" api {'+'.join(str(ms) for ms in record['api_ms'])}ms" if record.get("api_ms") else ""
        log.info("llm %s %dms%s %s", record["outcome"], record["latency_ms"], api, record["command"][:200])
        if not self.path:
            return
        try:
            if self.path.exists() and self.path.stat().st_size > LOG_ROTATE_BYTES:
                self.path.replace(self.path.with_name(self.path.name + ".1"))
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, separators=(",", ":")) + "\n")
        except OSError:
            log.exception("could not write llm log")


class _Hook:
    """the engine's state.unknown for one run of one line."""

    def __init__(self, fb: "LLMFallback", sess: LLMSession, resolved: dict[Key, Resolved], ask: bool):
        self.fb, self.sess, self.resolved, self.ask = fb, sess, resolved, ask
        self.misses: dict[Key, Miss] = {}
        self.records: list[dict] = []
        self.kinds: set[str] = set()

    def _record(self, state: ShellState, argv: list[str], outcome: str, ms: int = 0, calls: list[dict] | None = None) -> None:
        record = {
            "ts": now_ts(),
            "session": self.sess.session_id,
            "name": argv[0],
            "command": command_text(argv)[:500],
            "cwd": state.cwd,
            "outcome": outcome,
            "latency_ms": ms,
        }
        if calls:
            # each real api call, so slow calls and repairs show up on their own
            record["api_ms"] = [c["ms"] for c in calls]
            record["stop"] = calls[-1]["stop"]
            record["output_tokens"] = sum(c["out"] for c in calls)
        self.records.append(record)

    def _fall_back(self, state: ShellState, argv: list[str], outcome: str, ms: int = 0, calls: list[dict] | None = None) -> Result:
        self._record(state, argv, outcome, ms, calls)
        self.sess.missing.add(argv[0])
        return not_found(argv[0])

    def __call__(self, state: ShellState, argv: list[str], stdin: str | None) -> Result:
        key = cache_key(state, argv, stdin)
        name = argv[0]
        done = self.resolved.get(key)
        if done is not None:
            if done.answer is None:
                return self._fall_back(state, argv, done.outcome, done.ms, done.calls)
            res = apply(done.answer, state, argv)
            if res is None:
                self.fb.cache.pop(key, None)
                return self._fall_back(state, argv, "rejected", done.ms, done.calls)
            self._record(state, argv, "ok", done.ms, done.calls)
            self.kinds.add("llm")
            return res
        if name in self.sess.missing:
            return self._fall_back(state, argv, "sticky")
        cached = self.fb.cache.get(key)
        if cached is not None:
            res = apply(cached, state, argv)
            if res is not None:
                self.fb.cache.move_to_end(key)
                self._record(state, argv, "cache")
                self.kinds.add("cache")
                return res
            self.fb.cache.pop(key, None)
        reason = self.fb.blocked(self.sess) or ("" if self.ask else "rounds")
        if reason:
            return self._fall_back(state, argv, reason)
        if key not in self.misses:
            text = command_text(argv)
            self.misses[key] = Miss(key, text, state.cwd, prompt.user_prompt(state, text, argv, stdin))
        # placeholder; this run gets rolled back
        return Result()

    @property
    def answered_by(self) -> str:
        return "llm" if "llm" in self.kinds else "cache" if "cache" in self.kinds else "engine"


class LLMFallback:
    def __init__(
        self,
        provider: Provider,
        system: dict,
        hourly_cap: int,
        log_path: Path | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ):
        self.provider = provider
        self.system_prompt = prompt.system_prompt(system)
        self.cap = HourlyCap(hourly_cap, wall)
        self.breaker = Breaker(clock)
        self.clock = clock
        self.cache: OrderedDict[Key, Answer] = OrderedDict()
        self.calls = CallLog(log_path)
        self.last_used = clock()
        self._warm_task: asyncio.Task | None = None

    def session(self, session_id: str) -> LLMSession:
        return LLMSession(session_id)

    async def close(self) -> None:
        if self._warm_task:
            self._warm_task.cancel()
            await asyncio.gather(self._warm_task, return_exceptions=True)
        await self.provider.close()

    def blocked(self, sess: LLMSession) -> str:
        if self.breaker.open:
            return "breaker"
        if sess.calls >= SESSION_CAP:
            return "session_cap"
        if self.cap.spent:
            return "hourly_cap"
        return ""

    def _charge(self, sess: LLMSession) -> None:
        reason = self.blocked(sess)
        if reason:
            raise Blocked(reason)
        sess.calls += 1
        self.cap.take()

    async def run(self, engine: Engine, state: ShellState, line: str, sess: LLMSession) -> tuple[Result, str]:
        resolved: dict[Key, Resolved] = {}
        for attempt in range(MAX_ROUNDS):
            hook = _Hook(self, sess, resolved, ask=attempt < MAX_ROUNDS - 1)
            snap = state.snapshot()
            state.unknown = hook
            try:
                res = engine.run(state, line)
            finally:
                state.unknown = None
            if not hook.misses:
                for record in hook.records:
                    self.calls.write(record)
                return res, hook.answered_by
            state.restore(snap)
            await asyncio.gather(*(self._resolve(m, sess, resolved) for m in hook.misses.values()))
        raise AssertionError("unreachable: the last round never asks")

    async def _resolve(self, miss: Miss, sess: LLMSession, resolved: dict[Key, Resolved]) -> None:
        t0 = self.clock()
        answer = None
        calls: list[dict] = []
        try:
            answer = await asyncio.wait_for(self._ask(miss, sess, calls), TIMEOUT)
            outcome = "ok"
        except (TimeoutError, LLMTimeout):
            outcome = "timeout"
            log.warning("llm timed out after %dms: %s", int((self.clock() - t0) * 1000), miss.command[:200])
            self.breaker.failure()
        except Blocked as e:
            outcome = e.reason
        except Rejected:
            outcome = "rejected"
        except Invalid:
            outcome = "invalid"
            self.breaker.failure()
        except LLMError:
            outcome = "error"
            self.breaker.failure()
        except Exception:
            log.exception("llm call crashed")
            outcome = "error"
            self.breaker.failure()
        ms = int((self.clock() - t0) * 1000)
        resolved[miss.key] = Resolved(answer, outcome, ms, calls)
        if answer is not None:
            self.cache[miss.key] = answer
            self.cache.move_to_end(miss.key)
            while len(self.cache) > CACHE_SIZE:
                self.cache.popitem(last=False)

    async def _call(self, messages: list[dict], sess: LLMSession, calls: list[dict]) -> Reply:
        self._charge(sess)
        self.last_used = self.clock()
        reply = await self.provider.complete(self.system_prompt, messages, prompt.SCHEMA)
        calls.append({"ms": reply.ms, "stop": reply.stop, "in": reply.input_tokens, "out": reply.output_tokens})
        log.info("llm call %dms stop=%s in=%d out=%d", reply.ms, reply.stop, reply.input_tokens, reply.output_tokens)
        return reply

    async def _ask(self, miss: Miss, sess: LLMSession, calls: list[dict]) -> Answer:
        messages = [{"role": "user", "content": miss.user_prompt}]
        reply = await self._call(messages, sess, calls)
        try:
            answer = parse_answer(reply.text)
        except Invalid:
            # cut off by max_tokens: another try would be cut off too, so keep what came
            cut = salvage(reply.text) if reply.stop == "max_tokens" else None
            if cut is not None:
                answer = cut
            else:
                # one repair attempt
                messages += [{"role": "assistant", "content": reply.text}, {"role": "user", "content": prompt.REPAIR}]
                answer = parse_answer((await self._call(messages, sess, calls)).text)
        screen(answer)
        return answer

    def start(self) -> None:
        """warm the connection now, and keep it warm while nobody is using it."""
        if self._warm_task is None:
            self._warm_task = asyncio.create_task(self._keep_warm())

    async def _keep_warm(self) -> None:
        first = True
        while True:
            if first or self.clock() - self.last_used >= KEEP_WARM:
                try:
                    ms = await self.provider.warm()
                    self.last_used = self.clock()
                    log.info("llm connection %s in %dms", "warmed" if first else "kept warm", ms)
                except Exception as e:
                    log.warning("llm warm-up failed: %s", e)
            first = False
            await asyncio.sleep(KEEP_WARM / 4)
