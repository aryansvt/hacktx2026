import re


def test_identity(sh):
    assert sh("whoami") == "root\n"
    assert sh("id") == "uid=0(root) gid=0(root) groups=0(root)\n"
    assert sh("id deploy").startswith("uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),")
    assert "no such user" in sh("id nobodyhere 2>&1")
    assert sh("hostname") == "qf-web-01\n"
    assert sh("uname") == "Linux\n"
    assert sh("uname -r") == "5.15.0-105-generic\n"
    assert sh("uname -a").startswith("Linux qf-web-01 5.15.0-105-generic #115-Ubuntu SMP")


def test_uptime_w_who(sh):
    assert re.match(r"^ \d\d:\d\d:\d\d up \d+ days, .*load average: \d\.\d\d, \d\.\d\d, \d\.\d\d\n$", sh("uptime"))
    w = sh("w")
    assert "USER     TTY      FROM" in w and "10.0.4.1" in w
    assert sh("who").startswith("root ")


def test_ps_matches_systemctl(sh):
    ps = sh("ps aux")
    assert ps.startswith("USER         PID %CPU %MEM")
    assert "nginx: master process" in ps and "ps aux" in ps
    status = sh("systemctl status nginx")
    pid = re.search(r"Main PID: (\d+)", status).group(1)
    assert re.search(rf"^root\s+{pid}\s", ps, re.M)
    assert "UID          PID    PPID" in sh("ps -ef")
    assert sh("ps").startswith("    PID TTY          TIME CMD\n")


def test_top_free_df(sh):
    assert sh("top -bn1").startswith("top - ")
    assert sh("free -m").splitlines()[1].split()[:2] == ["Mem:", "3921"]
    assert "Swap:" in sh("free -h")
    df = sh("df -h")
    assert df.startswith("Filesystem") and "/dev/vda1" in df and " /\n" in df


def test_cpu_info_agrees(sh):
    assert sh("nproc") == "2\n"
    assert sh("grep -c processor /proc/cpuinfo") == "2\n"
    assert "CPU(s):                   2" in sh("lscpu")


def test_systemctl(sh):
    assert "Unit mysql.service could not be found." in sh("systemctl status mysql 2>&1")
    assert sh.state.last_status == 4
    sh("systemctl stop nginx")
    assert "inactive (dead)" in sh("systemctl status nginx")
    assert sh("systemctl is-active nginx") == "inactive\n"
    sh("systemctl start nginx")
    assert sh("systemctl is-active nginx") == "active\n"
    assert "ssh.service" in sh("systemctl list-units --type=service")
    assert "[ + ]  nginx" in sh("service --status-all")
    assert "Active: active" in sh("service docker status")


def test_systemctl_needs_root(engine, base):
    state = engine.new_state("test", tty=False, base=base)
    assert "Interactive authentication required" in engine.run(state, "systemctl stop nginx 2>&1").out


def test_docker(sh):
    ps = sh("docker ps")
    assert ps.startswith("CONTAINER ID   IMAGE")
    for name in ("app-web-1", "app-db-1", "app-redis-1"):
        assert name in ps
    assert "postgres" in sh("docker images")
    assert "Docker version 24.0.7" in sh("docker --version")
    assert "server misbehaving" in sh("docker pull alpine 2>&1")


def test_docker_permission(engine, base):
    state = engine.new_state("test", tty=False, base=base)
    assert "permission denied" in engine.run(state, "docker ps 2>&1").out
    state = engine.new_state("deploy", tty=False, base=base)
    assert "app-web-1" in engine.run(state, "docker ps").out


def test_crontab(sh):
    assert "backup.sh" in sh("crontab -l")
    sh("echo '*/5 * * * * /tmp/job' | crontab -")
    assert sh("crontab -l") == "*/5 * * * * /tmp/job\n"
    sh("crontab -r")
    assert "no crontab for root" in sh("crontab -l 2>&1")


def test_env_export_history(sh):
    env = sh("env")
    assert "HOME=/root" in env and "USER=root" in env and "PATH=" in env
    sh("export FOO=bar")
    assert sh("echo $FOO") == "bar\n"
    assert sh("printenv FOO") == "bar\n"
    sh("unset FOO")
    assert sh("echo $FOO") == "\n"
    assert "docker compose up -d" in sh("history")
    sh("history -c")
    assert sh("history") == ""


def test_which_exit(sh):
    assert sh("which ls") == "/usr/sbin/ls\n" or sh("which ls") == "/usr/bin/ls\n"
    assert sh("which nope") == ""
    assert sh.state.last_status == 1
    sh("exit")
    assert sh.state.exit_requested
