"""a small bash-like parser. it only produces data; nothing here runs anything.

two phases so expansions see earlier side effects (cd /tmp; echo $PWD):
  split_line(line)        -> [(connector, [raw command, ...]), ...]
  parse_command(raw, ctx) -> Command(argv, redirects, assigns)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

GLOB_CHARS = set("*?[")


class ParseError(Exception):
    pass


@dataclass
class Redirect:
    fd: int  # 0, 1, 2, or -1 for both (&>)
    op: str  # < > >> dup
    target: str  # path, or fd number as text for dup


@dataclass
class Command:
    argv: list[str] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)
    assigns: list[tuple[str, str]] = field(default_factory=list)


class Expander(Protocol):
    def var(self, name: str) -> str: ...
    def substitute(self, script: str) -> str: ...
    def home(self, user: str) -> str | None: ...
    def glob(self, pattern: str) -> list[str]: ...


def _skip_subst(line: str, i: int) -> int:
    """i points just past '$('. return index just past the matching ')'."""
    depth = 1
    quote = ""
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "\\":
            i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ParseError("unexpected EOF while looking for matching `)'")


def split_line(line: str) -> list[tuple[str, list[str]]]:
    """split on ; && || & and | at top level. first connector is ';'."""
    out: list[tuple[str, list[str]]] = []
    pipeline: list[str] = []
    buf: list[str] = []
    connector = ";"
    quote = ""
    i = 0

    def end_cmd() -> None:
        raw = "".join(buf).strip()
        buf.clear()
        if not raw:
            raise ParseError
        pipeline.append(raw)

    def end_pipeline(next_conn: str, tok: str) -> None:
        nonlocal connector
        try:
            end_cmd()
        except ParseError:
            raise ParseError(f"syntax error near unexpected token `{tok}'") from None
        out.append((connector, list(pipeline)))
        pipeline.clear()
        connector = next_conn

    while i < len(line):
        c = line[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < len(line):
                buf.append(line[i + 1])
                i += 1
            elif c == quote:
                quote = ""
            i += 1
            continue
        if c in "'\"`":
            quote = c
            buf.append(c)
        elif c == "\\" and i + 1 < len(line):
            buf.append(line[i : i + 2])
            i += 1
        elif c == "$" and line[i + 1 : i + 2] == "(":
            j = _skip_subst(line, i + 2)
            buf.append(line[i:j])
            i = j
            continue
        elif c == "#" and (not buf or buf[-1][-1:].isspace()):
            break
        elif c == ";":
            end_pipeline(";", ";")
        elif c == "&" and line[i + 1 : i + 2] == "&":
            end_pipeline("&&", "&&")
            i += 1
        elif c == "&" and line[i + 1 : i + 2] == ">":
            buf.append("&>")
            i += 1
        elif c == "&" and buf and buf[-1].endswith(">"):
            buf.append(c)  # 2>&1
        elif c == "&":
            end_pipeline("&", "&")
        elif c == "|" and line[i + 1 : i + 2] == "|":
            end_pipeline("||", "||")
            i += 1
        elif c == "|":
            try:
                end_cmd()
            except ParseError:
                raise ParseError("syntax error near unexpected token `|'") from None
        else:
            buf.append(c)
        i += 1

    if quote:
        q = {"'": "'", '"': '"', "`": "`"}[quote]
        raise ParseError(f"unexpected EOF while looking for matching `{q}'")
    raw = "".join(buf).strip()
    if raw:
        pipeline.append(raw)
    elif pipeline:
        raise ParseError("syntax error: unexpected end of file")
    if pipeline:
        out.append((connector, pipeline))
    elif connector in ("&&", "||"):
        raise ParseError("syntax error: unexpected end of file")
    return out


ESCAPES_DQ = set('$`"\\\n')


def _read_var(raw: str, i: int) -> tuple[str, int]:
    """i points just past '$'. returns (name, next index); empty name means literal $."""
    if i < len(raw) and raw[i] == "{":
        j = raw.find("}", i)
        if j < 0:
            raise ParseError("bad substitution")
        return raw[i + 1 : j], j + 1
    if i < len(raw) and raw[i] in "?$#!@*0123456789-":
        return raw[i], i + 1
    j = i
    while j < len(raw) and (raw[j].isalnum() or raw[j] == "_"):
        j += 1
    return raw[i:j], j


def tokenize(raw: str, ex: Expander) -> list[tuple[str, bool, bool]]:
    """returns (word, globbable, is_operator) tuples after quote removal and expansion."""
    words: list[tuple[str, bool, bool]] = []
    buf: list[str] = []
    started = False
    globbable = False
    i = 0
    n = len(raw)

    def flush() -> None:
        nonlocal started, globbable
        if started:
            words.append(("".join(buf), globbable, False))
        buf.clear()
        started = False
        globbable = False

    def expand_dollar(j: int) -> tuple[str, int]:
        if raw[j : j + 1] == "(":
            end = _skip_subst(raw, j + 1)
            return ex.substitute(raw[j + 1 : end - 1]), end
        name, k = _read_var(raw, j)
        if not name:
            return "$", j
        return ex.var(name), k

    while i < n:
        c = raw[i]
        if c.isspace():
            flush()
            i += 1
            continue
        # redirect operators, only at word start or after a bare fd digit
        if c in "<>" or (c == "&" and raw[i + 1 : i + 2] == ">"):
            fd_prefix = "".join(buf) if started and "".join(buf) in ("0", "1", "2") and not globbable else None
            if started and fd_prefix is None:
                flush()
            if fd_prefix is not None:
                buf.clear()
                started = False
            j = i
            if c == "&":
                op = "&>"
                j += 2
            elif raw[i : i + 2] == ">>":
                op = ">>"
                j += 2
            else:
                op = c
                j += 1
            if raw[j : j + 1] == "&" and op in (">", "<"):
                op += "&"
                j += 1
            words.append(((fd_prefix or "") + op, False, True))
            i = j
            continue
        started = True
        if c == "'":
            j = raw.find("'", i + 1)
            if j < 0:
                raise ParseError("unexpected EOF while looking for matching `''")
            buf.append(raw[i + 1 : j])
            i = j + 1
        elif c == '"':
            i += 1
            while i < n and raw[i] != '"':
                if raw[i] == "\\" and i + 1 < n and raw[i + 1] in ESCAPES_DQ:
                    buf.append(raw[i + 1])
                    i += 2
                elif raw[i] == "$":
                    val, i = expand_dollar(i + 1)
                    buf.append(val)
                elif raw[i] == "`":
                    j = raw.find("`", i + 1)
                    if j < 0:
                        raise ParseError("unexpected EOF while looking for matching ``'")
                    buf.append(ex.substitute(raw[i + 1 : j]))
                    i = j + 1
                else:
                    buf.append(raw[i])
                    i += 1
            if i >= n:
                raise ParseError("unexpected EOF while looking for matching `\"'")
            i += 1
        elif c == "\\":
            if i + 1 < n:
                buf.append(raw[i + 1])
            i += 2
        elif c == "$":
            val, i = expand_dollar(i + 1)
            # unquoted expansion splits on whitespace
            parts = val.split()
            if not parts:
                if not buf:
                    started = False
                continue
            if val[:1].isspace() and buf:
                flush()
                started = True
            buf.append(parts[0])
            for p in parts[1:]:
                flush()
                started = True
                buf.append(p)
            if val[-1:].isspace():
                flush()
        elif c == "`":
            j = raw.find("`", i + 1)
            if j < 0:
                raise ParseError("unexpected EOF while looking for matching ``'")
            parts = ex.substitute(raw[i + 1 : j]).split()
            i = j + 1
            if not parts:
                if not buf:
                    started = False
                continue
            buf.append(parts[0])
            for p in parts[1:]:
                flush()
                started = True
                buf.append(p)
        elif c == "~" and not buf:
            j = i + 1
            while j < n and not raw[j].isspace() and raw[j] not in "/'\"<>;":
                j += 1
            user = raw[i + 1 : j]
            h = ex.home(user)
            buf.append(h if h is not None else raw[i:j])
            i = j
        else:
            if c in GLOB_CHARS:
                globbable = True
            buf.append(c)
            i += 1
    flush()
    return words


def parse_command(raw: str, ex: Expander) -> Command:
    cmd = Command()
    tokens = tokenize(raw, ex)
    i = 0
    while i < len(tokens):
        word, globbable, is_op = tokens[i]
        if is_op:
            if i + 1 >= len(tokens) or tokens[i + 1][2]:
                raise ParseError("syntax error near unexpected token `newline'")
            target = tokens[i + 1][0]
            i += 2
            op = word.lstrip("012")
            fd_text = word[: len(word) - len(op)]
            if op == "&>":
                cmd.redirects.append(Redirect(-1, ">", target))
            elif op in (">&", "<&"):
                cmd.redirects.append(Redirect(int(fd_text or (1 if op == ">&" else 0)), "dup", target))
            else:
                default = 0 if op == "<" else 1
                cmd.redirects.append(Redirect(int(fd_text) if fd_text else default, op, target))
            continue
        if not cmd.argv and "=" in word and _is_assign(word):
            name, value = word.split("=", 1)
            cmd.assigns.append((name, value))
        elif globbable:
            matches = ex.glob(word)
            cmd.argv.extend(matches or [word])
        else:
            cmd.argv.append(word)
        i += 1
    return cmd


def _is_assign(word: str) -> bool:
    name = word.split("=", 1)[0]
    return bool(name) and (name[0].isalpha() or name[0] == "_") and all(ch.isalnum() or ch == "_" for ch in name)


def simple_expander(env: dict[str, str] | None = None, run: Callable[[str], str] | None = None) -> Expander:
    """expander for tests and tools that don't need a real session."""
    env = env or {}

    class _E:
        def var(self, name):
            return env.get(name, "")

        def substitute(self, script):
            return run(script) if run else ""

        def home(self, user):
            return env.get("HOME") if not user else f"/home/{user}"

        def glob(self, pattern):
            return []

    return _E()
