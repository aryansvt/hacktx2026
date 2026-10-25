"""read-only display commands. everything comes from system.json and has to agree
with ps, systemctl, df, w and each other."""

import re

import pytest


def pids_in(text):
    return {int(p) for p in re.findall(r"pid=(\d+)", text)} | {int(p) for p in re.findall(r"\s(\d+)/", text)}


def ps_pids(sh):
    return {int(line.split()[1]) for line in sh("ps aux").splitlines()[1:]}


# sockets

def test_every_listener_is_a_running_process(sh):
    ps = ps_pids(sh)
    for cmd in ("ss -tulpn", "netstat -tulpn"):
        found = pids_in(sh(cmd))
        assert found and found <= ps, cmd


def test_listener_pids_match_systemctl(sh):
    for svc, port in (("ssh", ":22 "), ("nginx", ":80 ")):
        main = int(re.search(r"Main PID: (\d+)", sh(f"systemctl status {svc}")).group(1))
        line = next(l for l in sh("ss -tlnp").splitlines() if port in l + " ")
        assert f"pid={main}," in line


def test_stopping_a_service_hides_it_everywhere(sh):
    sh("systemctl stop nginx")
    assert ":80 " not in sh("ss -tlnp") and ":80 " not in sh("netstat -tlnp")
    assert "nginx" not in sh("ps aux")
    sh("systemctl stop docker")
    assert "docker-proxy" not in sh("ps aux") and "5432" not in sh("ss -tln")
    sh("systemctl start nginx")
    assert ":80 " in sh("ss -tlnp") and "nginx: master" in sh("ps aux")


def test_netstat_formats(sh):
    out = sh("netstat -tlnp")
    assert out.startswith("Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address")
    assert re.search(r"^tcp\s+0\s+0 0\.0\.0\.0:22\s+0\.0\.0\.0:\*\s+LISTEN\s+812/sshd: /usr/sbin$", out, re.M)
    assert re.search(r"^tcp6\s+0\s+0 :::22\s+:::\*\s+LISTEN", out, re.M)
    assert "udp" not in out
    # names without -n, like systemd-resolved hands out
    named = sh("netstat -tl")
    assert "0.0.0.0:ssh" in named and "localhost:postgresql" in named and "_localdnsstub:domain" in named
    assert "%lo" not in out and "127.0.0.53:53 " in out


def test_own_connection_matches_w(sh):
    ip = sh("w").splitlines()[2].split()[2]
    assert ip == sh.state.display_ip
    assert re.search(rf"10\.0\.4\.17:22\s+{re.escape(ip)}:\d+\s+ESTABLISHED", sh("netstat -tn"))
    assert re.search(rf"ESTAB .*10\.0\.4\.17:22\s+{re.escape(ip)}:\d+", sh("ss -tn"))
    # sshd for the session is in ps under the same pid
    pid = re.search(r"(\d+)/sshd: root", sh("netstat -tnp")).group(1)
    assert re.search(rf"^root\s+{pid}\s.*sshd: root", sh("ps aux"), re.M)


def test_non_root_sees_no_processes(engine, base):
    state = engine.new_state("deploy", tty=False, base=base)
    netstat = engine.run(state, "netstat -tlnp").out
    assert "Not all processes could be identified" in netstat and "812/" not in netstat
    assert "users:" not in engine.run(state, "ss -tlnp").out


# interfaces and routes

def test_ip_and_ifconfig_agree_with_system(sh):
    system = sh.state.system
    ip_a = sh("ip a")
    assert f"inet {system['ip']}/24" in ip_a and f"link/ether {system['mac']}" in ip_a
    assert f"inet6 {system['ip6_link']}/64" in ip_a and f"inet {system['docker_ip']}/16" in ip_a
    eth0 = sh("ifconfig eth0")
    assert f"inet {system['ip']}  netmask 255.255.255.0  broadcast 10.0.4.255" in eth0
    assert f"ether {system['mac']}" in eth0 and eth0.startswith("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>")
    assert sh("ifconfig lo").startswith("lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536")
    # same interfaces, ifconfig sorted by name
    names_ip = re.findall(r"^\d+: ([^:@]+)", ip_a, re.M)
    names_if = re.findall(r"^(\S+): flags=", sh("ifconfig"), re.M)
    assert sorted(names_ip) == names_if


def test_ip_variants(sh):
    assert sh("ip -4 a show eth0").splitlines()[1].strip().startswith("inet 10.0.4.17/24")
    assert "inet " not in sh("ip -6 addr")
    assert sh("ip -br a").startswith("lo               UNKNOWN        127.0.0.1/8 ::1/128")
    assert "Device \"eth9\" does not exist." in sh("ip a show eth9 2>&1")
    assert "mode DEFAULT" in sh("ip link")
    assert 'Object "bogus" is unknown' in sh("ip bogus 2>&1")
    assert "Operation not permitted" in sh("ip addr add 10.9.9.9/24 dev eth0 2>&1")
    assert sh("ip neigh").startswith(f"{sh.state.system['gateway']} dev eth0 lladdr")
    assert "error fetching interface information" in sh("ifconfig eth7 2>&1")


def test_routes_agree(sh):
    gw = sh.state.system["gateway"]
    ip_r = sh("ip r")
    assert ip_r.startswith(f"default via {gw} dev eth0 proto dhcp src 10.0.4.17 metric 100 \n")
    assert "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown" in ip_r
    rn = sh("netstat -rn")
    assert re.search(rf"^0\.0\.0\.0\s+{re.escape(gw)}\s+0\.0\.0\.0\s+UG\s", rn, re.M)
    assert re.search(r"^default\s+_gateway\s", sh("netstat -r"), re.M)
    assert len(ip_r.splitlines()) == len(rn.splitlines()) - 2


# packages

def test_dpkg_and_apt_list_the_same_packages(sh):
    pkgs = {p[0]: p[1] for p in sh.state.system["packages"]}
    dpkg = {l.split()[1]: l.split()[2] for l in sh("dpkg -l").splitlines() if l.startswith("ii  ")}
    apt = {}
    for line in sh("apt list --installed 2>/dev/null").splitlines()[1:]:
        name, rest = line.split("/", 1)
        apt[name] = rest.split()[1]
    assert dpkg == pkgs == apt
    # every tool the shell has comes from an installed package
    for name in ("iproute2", "net-tools", "mount", "procps", "dpkg", "curl", "wget"):
        assert name in pkgs


def test_dpkg_queries(sh):
    assert sh("dpkg -l 'nginx*'").count("\nii  ") == 1
    assert "no packages found matching nmap" in sh("dpkg -l nmap 2>&1")
    assert "Status: install ok installed" in sh("dpkg -s curl")
    assert "is not installed and no information is available" in sh("dpkg -s nmap 2>&1")
    assert "need an action option" in sh("dpkg 2>&1")


def test_apt_get_install_hits_the_lock_held_by_a_real_process(sh):
    out = sh("apt-get install -y nmap 2>&1")
    assert sh.state.last_status == 100
    pid, name = re.search(r"Could not get lock /var/lib/dpkg/lock-frontend\. It is held by process (\d+) \((\S+)\)", out).groups()
    assert re.search(rf"^root\s+{pid}\s.*unattended-upgrade", sh("ps aux"), re.M)
    assert name == "unattended-upgr"
    assert "activating" in sh("systemctl list-units")
    assert "dpkg frontend lock was locked by another process with pid " + pid in sh("dpkg -i x.deb 2>&1")
    assert "Could not get lock" in sh("apt install curl 2>&1")


def test_lock_goes_away_with_its_service(sh):
    sh("systemctl stop apt-daily-upgrade")
    assert "unattended-upgrade" not in sh("ps aux")
    assert "curl is already the newest version (7.81.0-1ubuntu1.16)." in sh("apt-get install curl")
    assert "E: Unable to locate package nmap" in sh("apt-get install nmap 2>&1")
    assert "is not a Debian format archive" in sh("echo x > a.deb; dpkg -i a.deb 2>&1")


def test_apt_get_needs_root(engine, base):
    state = engine.new_state("deploy", tty=False, base=base)
    res = engine.run(state, "apt-get install nmap 2>&1")
    assert "are you root?" in res.out and res.code == 100
    assert "Unable to lock directory /var/lib/apt/lists/" in engine.run(state, "apt-get update 2>&1").out
    assert "requires superuser privilege" in engine.run(state, "dpkg -i x.deb 2>&1").out


def test_apt_get_update_cannot_reach_mirrors(sh):
    out = sh("apt-get update 2>&1")
    assert "Temporary failure resolving 'archive.ubuntu.com'" in out
    assert "W: Some index files failed to download." in out


def test_apt_warns_when_piped(sh):
    assert "WARNING: apt does not have a stable CLI interface" in sh("apt list --installed 2>&1 | grep WARNING")
    assert "WARNING" not in sh("apt list --installed 2>/dev/null")
    assert "nginx/jammy-updates,jammy-security,now 1.18.0-6ubuntu14.4 amd64 [installed]" in sh("apt list nginx")


# logins and mounts

def test_last_agrees_with_w_and_uptime(engine, base):
    state = engine.new_state("root", tty=True, base=base)
    out = engine.run(state, "last").out.splitlines()
    assert re.match(rf"^root\s+pts/0\s+{re.escape(state.display_ip)}\s+\w{{3}} \w{{3}} [ \d]\d \d\d:\d\d   still logged in$", out[0])
    reboot = next(l for l in out if l.startswith("reboot"))
    # boot_time is 2026-10-06 04:12, uptime counts from it
    assert "Tue Oct  6 04:12   still running" in reboot
    assert out[-1].startswith("wtmp begins ")
    assert engine.run(state, "last -n 2").out.count("\n") == 4
    assert all(l.startswith("deploy") for l in engine.run(state, "last deploy").out.splitlines()[:-2])


def test_exec_sessions_are_not_in_last(sh):
    assert "still logged in" not in sh("last")


def test_mount_agrees_with_df(sh):
    mounts = {(m[0], m[1], m[2]) for m in sh.state.system["mounts"]}
    for dev, kind, *_, mp in sh.state.system["disks"]:
        assert (dev, mp, kind) in mounts
    out = sh("mount")
    assert "/dev/vda1 on / type ext4 (rw,relatime,discard,errors=remount-ro)\n" in out
    assert sh("mount -t ext4") == "/dev/vda1 on / type ext4 (rw,relatime,discard,errors=remount-ro)\n"
    assert out.count(" type overlay ") == len(sh.state.system["containers"])


@pytest.mark.parametrize(
    "line,needle",
    [
        ("mount /dev/sdb1 /mnt", "special device /dev/sdb1 does not exist."),
        ("mount /mnt", "can't find in /etc/fstab."),
    ],
)
def test_mount_attempts_fail(sh, line, needle):
    assert needle in sh(line + " 2>&1")


def test_mount_needs_root(engine, base):
    state = engine.new_state("deploy", tty=False, base=base)
    assert "must be superuser to use mount." in engine.run(state, "mount /dev/vda1 /mnt 2>&1").out
