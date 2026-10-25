"""netstat, ss, ip and ifconfig, formatted from system.json.

sockets follow the same rules as ps: a listener disappears when its process is
killed or its service is stopped. the only established connection is the
session's own ssh connection, from the same address w and who show.
"""

from __future__ import annotations

import ipaddress

from ..engine import Ctx, Result, command
from ._util import parse_flags, proc_cmd, stopped_pids

PORTS = {"22": "ssh", "53": "domain", "68": "bootpc", "80": "http", "5432": "postgresql", "6379": "redis"}
# what systemd-resolved answers for these
HOSTS = {"127.0.0.1": "localhost", "127.0.0.53": "_localdnsstub", "10.0.4.1": "_gateway"}
BACKLOG = {"sshd": 128, "nginx": 511}
MODIFY = ("add", "del", "delete", "change", "replace", "set", "flush", "append")


def _split(addr: str) -> tuple[str, str]:
    host, _, port = addr.rpartition(":")
    return host, port


def _sockets(ctx: Ctx, listening: bool, established: bool, tcp: bool, udp: bool) -> list[dict]:
    """rows of proto, local, peer, state, pid, comm, cmd."""
    rows = []
    if listening:
        gone = stopped_pids(ctx)
        for proto, local, comm, pid in ctx.system["listen"]:
            is_udp = proto.startswith("udp")
            if pid in gone or (is_udp and not udp) or (not is_udp and not tcp):
                continue
            v6 = proto.endswith("6")
            rows.append({"proto": proto, "local": local, "peer": ("[::]" if v6 else "0.0.0.0") + ":*",
                         "state": "UNCONN" if is_udp else "LISTEN", "pid": pid, "comm": comm, "cmd": proc_cmd(ctx, pid),
                         "sendq": 0 if is_udp else BACKLOG.get(comm, 4096)})
    if established and tcp:
        st = ctx.state
        tty = "pts/0" if st.tty else ""
        rows.append({"proto": "tcp", "local": f"{ctx.system['ip']}:22", "peer": f"{st.display_ip}:{st.display_port}",
                     "state": "ESTAB", "pid": st.pid - 9, "comm": "sshd",
                     "cmd": f"sshd: {st.user}@{tty}" if tty else f"sshd: {st.user}", "sendq": 0})
    return rows


def _which(flags: dict) -> tuple[bool, bool, bool, bool]:
    tcp, udp = bool(flags.get("t") or flags.get("tcp")), bool(flags.get("u") or flags.get("udp"))
    if not tcp and not udp:
        tcp = udp = True
    listening = bool(flags.get("l") or flags.get("listening") or flags.get("a") or flags.get("all"))
    established = not (flags.get("l") or flags.get("listening"))
    return listening, established, tcp, udp


def _name(addr: str, numeric: bool, resolve_hosts: bool) -> str:
    host, port = _split(addr)
    if not numeric:
        port = PORTS.get(port, port)
        if resolve_hosts:
            base, pct, dev = host.partition("%")
            host = HOSTS.get(base, base) + pct + dev
    return f"{host}:{port}"


# netstat

def _netstat_prog(row: dict) -> str:
    cmd = row["cmd"] or row["comm"]
    argv0 = cmd.split(" ")[0]
    # setproctitle names like "sshd: /usr/sbin/sshd" stay whole; otherwise argv[0]'s basename
    name = cmd if argv0.endswith(":") else argv0.rsplit("/", 1)[-1]
    return f"{row['pid']}/{name}"[:19].rstrip()


def _netstat_addr(addr: str, numeric: bool) -> str:
    host, port = _split(addr)
    # netstat never shows the %dev that ss does
    host, port = _split(_name(host.split("%")[0] + ":" + port, numeric, True))
    if numeric and host == "[::]":
        host = "::"
    return f"{host}:{port}"


def _routes(ctx: Ctx, numeric: bool) -> Result:
    out = ["Kernel IP routing table", "Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface"]
    for r in ctx.system["routes"]:
        if r["dst"] == "default":
            dst, mask = ("0.0.0.0" if numeric else "default"), "0.0.0.0"
        else:
            net = ipaddress.ip_network(r["dst"] if "/" in r["dst"] else r["dst"] + "/32")
            dst, mask = str(net.network_address), str(net.netmask)
        gw = r["gw"] or "0.0.0.0"
        if not numeric:
            gw = HOSTS.get(gw, gw) if r["gw"] else "0.0.0.0"
        flags = "U" + ("G" if r["gw"] else "") + ("H" if mask == "255.255.255.255" else "")
        out.append(f"{dst:<15} {gw:<15} {mask:<15} {flags:<5} {0:>5} {0:<6} {0:>5} {r['dev']}")
    return Result("\n".join(out) + "\n")


@command("netstat")
def netstat(ctx: Ctx, args: list[str]) -> Result:
    flags, _ = parse_flags(args)
    numeric = bool(flags.get("n") or flags.get("numeric"))
    if flags.get("r") or flags.get("route"):
        return _routes(ctx, numeric)
    listening, established, tcp, udp = _which(flags)
    show_pid = bool(flags.get("p") or flags.get("program"))
    rows = _sockets(ctx, listening, established, tcp, udp)
    title = ("servers and established" if flags.get("a") or flags.get("all")
             else "only servers" if listening else "w/o servers")
    head = "Proto Recv-Q Send-Q Local Address           Foreign Address         State      "
    lines = [f"Active Internet connections ({title})", head + (" PID/Program name    " if show_pid else "")]
    note = ""
    if show_pid and not ctx.state.is_root:
        note = ("(Not all processes could be identified, non-owned process info\n"
                " will not be shown, you would have to be root to see it all.)\n")
    for r in rows:
        state = {"LISTEN": "LISTEN", "ESTAB": "ESTABLISHED", "UNCONN": ""}[r["state"]]
        sendq = 36 if r["state"] == "ESTAB" else 0
        line = (f"{r['proto']:<5} {0:>6} {sendq:>6} {_netstat_addr(r['local'], numeric):<23} "
                f"{_netstat_addr(r['peer'], numeric):<23} {state:<11}")
        if show_pid:
            line += " " + (_netstat_prog(r) if ctx.state.is_root else "-")
        lines.append(line.rstrip() if not show_pid else line)
    return Result(note + "\n".join(lines) + "\n")


# ss

@command("ss")
def ss(ctx: Ctx, args: list[str]) -> Result:
    flags, _ = parse_flags(args)
    numeric = bool(flags.get("n") or flags.get("numeric"))
    listening, established, tcp, udp = _which(flags)
    rows = _sockets(ctx, listening, established, tcp, udp)
    show_pid = bool(flags.get("p") or flags.get("processes")) and ctx.state.is_root
    netid = tcp and udp
    table = []
    for i, r in enumerate(rows):
        lh, lp = _split(_name(r["local"], numeric, False))
        ph, pp = _split(r["peer"] if r["state"] != "ESTAB" else _name(r["peer"], numeric, False))
        proc = f'users:(("{r["comm"]}",pid={r["pid"]},fd={3 + i}))' if show_pid else ""
        table.append([r["proto"].rstrip("6"), r["state"], "0", str(r["sendq"]), lh, lp, ph, pp, proc])
    head = ["Netid", "State", "Recv-Q", "Send-Q", "Local Address", "Port", "Peer Address", "Port", "Process"]
    w = [max(len(row[i]) for row in table + [head]) for i in range(len(head))]
    out = []
    for row in [head] + table:
        cells = ([f"{row[0]:<{w[0]}}"] if netid else []) + [f"{row[1]:<{w[1]}}", f"{row[2]:<{w[2]}}", f"{row[3]:<{w[3]}}"]
        local = f"{row[4]:>{w[4]}}:{row[5]:<{w[5]}}"
        peer = f"{row[6]:>{w[6]}}:{row[7]:<{w[7]}}"
        out.append((" ".join(cells) + " " + local + " " + peer + " " + row[8]).rstrip())
    return Result("\n".join(out) + "\n")


# ip

def _iface_flags(i: dict) -> str:
    return ",".join(i["flags"])


def _iface_name(i: dict) -> str:
    return f"{i['name']}@if{i['peer']}" if "peer" in i else i["name"]


def _ip_link_lines(i: dict, mode: bool) -> list[str]:
    master = f" master {i['master']}" if "master" in i else ""
    qlen = f" qlen {i['qlen']}" if i["qlen"] else ""
    mode_text = " mode DEFAULT" if mode else ""
    lines = [f"{i['index']}: {_iface_name(i)}: <{_iface_flags(i)}> mtu {i['mtu']} qdisc {i['qdisc']}{master} "
             f"state {i['state']}{mode_text} group default{qlen}" + ("" if qlen else " ")]
    kind, brd = ("loopback", "00:00:00:00:00:00") if i["name"] == "lo" else ("ether", "ff:ff:ff:ff:ff:ff")
    netns = f" link-netnsid {i['netns']}" if "netns" in i else ""
    lines.append(f"    link/{kind} {i['mac']} brd {brd}{netns}")
    if "altname" in i:
        lines.append(f"    altname {i['altname']}")
    return lines


def _ip_addr(ctx: Ctx, ifaces: list[dict], family: str, brief: bool) -> str:
    out = []
    for i in ifaces:
        v4 = [] if family == "6" else i["inet"]
        v6 = [] if family == "4" else i["inet6"]
        if family and not v4 and not v6:
            continue
        if brief:
            addrs = [f"{a}/{p}" for a, p, _ in v4] + [f"{a}/{p}" for a, p, _ in v6]
            out.append(f"{_iface_name(i):<16} {i['state']:<14} {' '.join(addrs)} ".rstrip() + " ")
            continue
        lines = _ip_link_lines(i, False)
        if family:
            lines = lines[:1]
        for addr, prefix, scope in v4:
            net = ipaddress.ip_interface(f"{addr}/{prefix}").network
            metric = " metric 100" if i.get("dynamic") else ""
            brd = f" brd {net.broadcast_address}" if scope != "host" else ""
            dyn = " dynamic" if i.get("dynamic") else ""
            lines.append(f"    inet {addr}/{prefix}{metric}{brd} scope {scope}{dyn} {i['name']}")
            lft = "85841sec" if i.get("dynamic") else "forever"
            lines.append(f"       valid_lft {lft} preferred_lft {lft}")
        for addr, prefix, scope in v6:
            lines.append(f"    inet6 {addr}/{prefix} scope {scope} ")
            lines.append("       valid_lft forever preferred_lft forever")
        out += lines
    return "\n".join(out) + "\n" if out else ""


def _ip_route(ctx: Ctx) -> str:
    out = []
    for r in ctx.system["routes"]:
        parts = [r["dst"]]
        if r["gw"]:
            parts += ["via", r["gw"]]
        parts += ["dev", r["dev"], "proto", r["proto"]]
        if r["scope"]:
            parts += ["scope", r["scope"]]
        parts += ["src", r["src"]]
        if "metric" in r:
            parts += ["metric", str(r["metric"])]
        if r.get("linkdown"):
            parts.append("linkdown")
        out.append(" ".join(parts) + " ")
    return "\n".join(out) + "\n"


def _object(word: str) -> str:
    for full in ("address", "route", "link", "neighbour"):
        if word and full.startswith(word):
            return full
    if word == "addr":
        return "address"
    return ""


@command("ip")
def ip(ctx: Ctx, args: list[str]) -> Result:
    family, brief, rest = "", False, []
    for a in args:
        if a in ("-4", "-6"):
            family = a[1]
        elif a in ("-br", "-brief", "--brief"):
            brief = True
        elif a.startswith("-"):
            continue
        else:
            rest.append(a)
    if not rest:
        return Result(err="Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
                          "where  OBJECT := { address | link | route | neigh | ... }\n", code=255)
    obj = _object(rest[0])
    if not obj:
        return Result(err=f'Object "{rest[0]}" is unknown, try "ip help".\n', code=255)
    verb = rest[1] if len(rest) > 1 else "show"
    if verb in MODIFY:
        return Result(err="RTNETLINK answers: Operation not permitted\n", code=2)
    ifaces = ctx.system["interfaces"]
    if obj in ("address", "link"):
        names = [a for a in rest[2:] if a != "dev"]
        if names:
            ifaces = [i for i in ifaces if i["name"] == names[0]]
            if not ifaces:
                return Result(err=f'Device "{names[0]}" does not exist.\n', code=1)
        if obj == "address":
            return Result(_ip_addr(ctx, ifaces, family, brief))
        if brief:
            return Result("".join(f"{_iface_name(i):<16} {i['state']:<14} {i['mac']} <{_iface_flags(i)}> \n" for i in ifaces))
        return Result("".join("\n".join(_ip_link_lines(i, True)) + "\n" for i in ifaces))
    if obj == "route":
        if verb == "get":
            return Result(err="RTNETLINK answers: Network is unreachable\n", code=2)
        return Result(_ip_route(ctx))
    return Result(f"{ctx.system['gateway']} dev eth0 lladdr {ctx.system['gateway_mac']} REACHABLE \n")


# ifconfig

def _bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1000 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1000
    return f"{size:.1f} TB"


def _ifconfig_one(i: dict) -> str:
    bits = {"UP": 1, "BROADCAST": 2, "LOOPBACK": 8, "RUNNING": 64, "MULTICAST": 4096}
    names = [f for f in ("UP", "BROADCAST", "LOOPBACK", "MULTICAST") if f in i["flags"]]
    if "LOWER_UP" in i["flags"] and "NO-CARRIER" not in i["flags"]:
        names.append("RUNNING")
    names.sort(key=lambda f: ["UP", "BROADCAST", "LOOPBACK", "RUNNING", "MULTICAST"].index(f))
    value = sum(bits[f] for f in names)
    lines = [f"{i['name']}: flags={value}<{','.join(names)}>  mtu {i['mtu']}"]
    for addr, prefix, scope in i["inet"]:
        net = ipaddress.ip_interface(f"{addr}/{prefix}").network
        brd = f"  broadcast {net.broadcast_address}" if scope != "host" else ""
        lines.append(f"        inet {addr}  netmask {net.netmask}{brd}")
    for addr, prefix, scope in i["inet6"]:
        sid = {"link": "0x20<link>", "host": "0x10<host>"}.get(scope, "0x0<global>")
        lines.append(f"        inet6 {addr}  prefixlen {prefix}  scopeid {sid}")
    if i["name"] == "lo":
        lines.append(f"        loop  txqueuelen {i['qlen']}  (Local Loopback)")
    else:
        lines.append(f"        ether {i['mac']}  txqueuelen {i['qlen']}  (Ethernet)")
    (rxp, rxb), (txp, txb) = i["rx"], i["tx"]
    lines += [
        f"        RX packets {rxp}  bytes {rxb} ({_bytes(rxb)})",
        "        RX errors 0  dropped 0  overruns 0  frame 0",
        f"        TX packets {txp}  bytes {txb} ({_bytes(txb)})",
        "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0",
    ]
    return "\n".join(lines) + "\n\n"


@command("ifconfig")
def ifconfig(ctx: Ctx, args: list[str]) -> Result:
    names = [a for a in args if not a.startswith("-")]
    ifaces = sorted(ctx.system["interfaces"], key=lambda i: i["name"])
    if not names:
        return Result("".join(_ifconfig_one(i) for i in ifaces))
    match = [i for i in ifaces if i["name"] == names[0]]
    if not match:
        return Result(err=f"{names[0]}: error fetching interface information: Device not found\n", code=1)
    if len(names) > 1:
        if not ctx.state.is_root:
            return Result(err="SIOCSIFFLAGS: Operation not permitted\n", code=1)
        return Result()
    return Result(_ifconfig_one(match[0]))
