"""wget and curl, simulated as text only.

nothing here opens a socket or resolves a name. the url is only parsed, names
are looked up in the fake /etc/hosts or get a made-up documentation address,
and the progress text is formatted from that. every "download" is the same
small placeholder file in the session overlay. it's marked as a simulated
download, so running it gives "cannot execute binary file: Exec format error".
"""

from __future__ import annotations

import hashlib
import ipaddress
import posixpath
import time
from email.utils import formatdate
from urllib.parse import SplitResult, urlsplit

from ...vfs import FsError, Node
from ..engine import Ctx, Result, command
from ._util import now, parse_flags

PLACEHOLDER = "placeholder\n"
SIZE = len(PLACEHOLDER)
# rfc 5737 ranges, the same ones the seed uses for outside hosts
TEST_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")
PORTS = {"http": 80, "https": 443, "ftp": 21}
CURL_VALUE = "oXdHAumxebcwTrFE"
CURL_LONG = ("output", "request", "data", "data-raw", "data-binary", "data-urlencode", "header", "user-agent", "user",
             "max-time", "connect-timeout", "proxy", "referer", "cookie", "cookie-jar", "write-out", "upload-file",
             "range", "form", "retry", "cacert", "cert")
WGET_VALUE = "OPoaUtTe"
WGET_LONG = ("output-document", "directory-prefix", "output-file", "user-agent", "tries", "timeout", "header",
             "post-data", "user", "password", "execute")


def parse_url(raw: str) -> SplitResult | None:
    url = raw if "://" in raw else "http://" + raw
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018  raises on a bad port
    except ValueError:
        return None
    return parts


def resolve(ctx: Ctx, host: str) -> str:
    """the fake fs's /etc/hosts first, then a stable made-up address. never dns."""
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        pass
    try:
        hosts = ctx.fs.read("/etc/hosts", ctx.user)
    except FsError:
        hosts = ""
    for line in hosts.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) > 1 and host.lower() in (f.lower() for f in fields[1:]):
            return fields[0]
    digest = hashlib.sha256(host.lower().encode()).digest()
    return f"{TEST_NETS[digest[0] % 3]}{1 + digest[1] % 253}"


def remote_name(parts: SplitResult) -> str:
    return posixpath.basename(parts.path)


def save(ctx: Ctx, path: str) -> None:
    """drop the placeholder into the overlay. fake_size marks it as a simulated download."""
    node = Node("file", 0o644, owner=ctx.user, group=ctx.user, mtime=time.time(), content=PLACEHOLDER, fake_size=SIZE)
    ctx.fs.write_node(ctx.path(path), node, ctx.user)


def _discard(ctx: Ctx, path: str) -> bool:
    return ctx.path(path) in ("/dev/null", "/dev/zero")


def _free_name(ctx: Ctx, name: str) -> str:
    """wget never clobbers: index.html, then index.html.1, index.html.2 ..."""
    if not ctx.fs.exists(ctx.path(name)):
        return name
    n = 1
    while ctx.fs.exists(ctx.path(f"{name}.{n}")):
        n += 1
    return f"{name}.{n}"


# wget

def _wget_one(ctx: Ctx, raw: str, flags: dict) -> tuple[str, str, int]:
    """(stdout, stderr, status) for one url."""
    quiet = bool(flags.get("q") or flags.get("quiet"))
    parts = parse_url(raw)
    if parts is None or parts.scheme not in PORTS:
        scheme = parts.scheme if parts else raw.split("://")[0]
        return "", f"{raw}: Unsupported scheme ‘{scheme}’.\n", 1
    host = parts.hostname or ""
    if not host:
        return "", f"{parts.scheme}://: Invalid host name.\n", 1
    url = parts.geturl()
    out_doc = flags.get("O") or flags.get("output-document")
    to_stdout = out_doc == "-"
    if isinstance(out_doc, str) and out_doc:
        name = out_doc
    else:
        name = _free_name(ctx, posixpath.join(str(flags.get("P") or flags.get("directory-prefix") or ""), remote_name(parts) or "index.html"))
    ip = resolve(ctx, host)
    port = parts.port or PORTS[parts.scheme]
    ts = now().strftime("%Y-%m-%d %H:%M:%S")
    shown = "STDOUT" if to_stdout else name
    log = [f"--{ts}--  {url}"]
    if host == ip:
        log.append(f"Connecting to {ip}:{port}... connected.")
    else:
        log += [f"Resolving {host} ({host})... {ip}", f"Connecting to {host} ({host})|{ip}|:{port}... connected."]
    log += ["HTTP request sent, awaiting response... 200 OK", f"Length: {SIZE} [application/octet-stream]", f"Saving to: ‘{shown}’", ""]
    if not to_stdout:
        try:
            prefix = posixpath.dirname(name)
            if prefix and not ctx.fs.exists(ctx.path(prefix)):
                ctx.fs.mkdir(ctx.path(prefix), ctx.user, parents=True)
            if not _discard(ctx, name):
                save(ctx, name)
        except FsError as e:
            return "", ("" if quiet else "\n".join(log) + "\n") + f"{name}: {e.message}\n\nCannot write to ‘{name}’ ({e.message}).\n", 3
    bar = f"{posixpath.basename(shown)[:18]:<18} 100%[===================>]      {SIZE}  --.-KB/s    in 0s      "
    done = f"- written to stdout [{SIZE}/{SIZE}]" if to_stdout else f"- ‘{name}’ saved [{SIZE}/{SIZE}]"
    log += [bar, "", f"{ts} (1.17 MB/s) {done}", ""]
    return (PLACEHOLDER if to_stdout else ""), ("" if quiet else "\n".join(log) + "\n"), 0


@command("wget")
def wget(ctx: Ctx, args: list[str]) -> Result:
    flags, urls = parse_flags(args, with_value=WGET_VALUE, long_value=WGET_LONG)
    if flags.get("V") or flags.get("version"):
        return Result("GNU Wget 1.21.2 built on linux-gnu.\n")
    if not urls:
        return Result(err="wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n", code=1)
    outs, errs, code = [], [], 0
    if flags.get("b") or flags.get("background"):
        errs.append(f"Continuing in background, pid {ctx.state.pid + 7}.\nOutput will be written to ‘wget-log’.\n")
        flags["q"] = True
    for raw in urls:
        out, err, status = _wget_one(ctx, raw, flags)
        outs.append(out)
        errs.append(err)
        code = code or status
    return Result("".join(outs), "".join(errs), code)


# curl

def _write_out(fmt: str, ip: str, port: int, url: str) -> str:
    values = {"http_code": "200", "response_code": "200", "size_download": str(SIZE), "remote_ip": ip,
              "remote_port": str(port), "url_effective": url, "time_total": "0.063412", "content_type": "application/octet-stream"}
    for key, value in values.items():
        fmt = fmt.replace("%{" + key + "}", value)
    return fmt.replace("\\n", "\n").replace("\\t", "\t")


def _curl_one(ctx: Ctx, raw: str, flags: dict, output: str | None, use_remote: bool) -> tuple[str, str, int]:
    silent = bool(flags.get("s") or flags.get("silent"))
    show_err = bool(flags.get("S") or flags.get("show-error")) or not silent
    parts = parse_url(raw)
    if parts is None or not parts.hostname:
        return "", "curl: (3) URL using bad/illegal format or missing URL\n" if show_err else "", 3
    if parts.scheme not in PORTS:
        return "", f'curl: (1) Protocol "{parts.scheme}" not supported or disabled in libcurl\n' if show_err else "", 1
    host = parts.hostname
    ip = resolve(ctx, host)
    port = parts.port or PORTS[parts.scheme]
    url = parts.geturl()
    err = []
    if flags.get("v") or flags.get("verbose"):
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        method = flags.get("X") or flags.get("request") or ("HEAD" if flags.get("I") else "POST" if flags.get("d") or flags.get("data") else "GET")
        err.append(f"*   Trying {ip}:{port}...\n* Connected to {host} ({ip}) port {port} (#0)\n"
                   f"> {method} {path} HTTP/1.1\n> Host: {host}\n> User-Agent: curl/7.81.0\n> Accept: */*\n> \n"
                   f"< HTTP/1.1 200 OK\n< Server: nginx\n< Content-Type: application/octet-stream\n< Content-Length: {SIZE}\n< \n"
                   f"{{ [{SIZE} bytes data]\n* Connection #0 to host {host} left intact\n")
    if flags.get("I") or flags.get("head"):
        head = (f"HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: {formatdate(usegmt=True)}\r\nContent-Type: application/octet-stream\r\n"
                f"Content-Length: {SIZE}\r\nConnection: keep-alive\r\n\r\n")
        return head, "".join(err), 0
    target = output
    if use_remote:
        target = remote_name(parts)
        if not target:
            return "", "curl: Remote file name has no length!\ncurl: (23) Failure writing output to destination\n", 23
    body = ""
    if target and target != "-":
        if not silent:
            err.append("  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                       "                                 Dload  Upload   Total   Spent    Left  Speed\n"
                       f"100    {SIZE}  100    {SIZE}    0     0    187      0 --:--:-- --:--:-- --:--:--   190\n")
        if not _discard(ctx, target):
            try:
                save(ctx, target)
            except FsError as e:
                msg = f"Warning: Failed to create the file {target}: {e.message}\ncurl: (23) Failure writing output to destination\n"
                return "", "".join(err) + (msg if show_err else ""), 23
    else:
        body = PLACEHOLDER
    fmt = flags.get("w") or flags.get("write-out")
    if isinstance(fmt, str):
        body += _write_out(fmt, ip, port, url)
    return body, "".join(err), 0


@command("curl")
def curl(ctx: Ctx, args: list[str]) -> Result:
    flags, urls = parse_flags(args, with_value=CURL_VALUE, long_value=CURL_LONG)
    if flags.get("V") or flags.get("version"):
        return Result("curl 7.81.0 (x86_64-pc-linux-gnu) libcurl/7.81.0 OpenSSL/3.0.2 zlib/1.2.11\nRelease-Date: 2022-01-05\n")
    if not urls:
        return Result(err="curl: try 'curl --help' or 'curl --manual' for more information\n", code=2)
    output = flags.get("o") or flags.get("output")
    use_remote = bool(flags.get("O") or flags.get("remote-name"))
    outs, errs, code = [], [], 0
    for raw in urls:
        out, err, status = _curl_one(ctx, raw, flags, output if isinstance(output, str) else None, use_remote)
        outs.append(out)
        errs.append(err)
        code = code or status
    return Result("".join(outs), "".join(errs), code)
