def test_pwd_cd(sh):
    assert sh("pwd") == "/root\n"
    sh("cd /var/log")
    assert sh("pwd") == "/var/log\n"
    sh("cd ..; cd -")
    assert sh("pwd") == "/var/log\n"
    sh("cd")
    assert sh("pwd") == "/root\n"
    assert "No such file or directory" in sh("cd /nope 2>&1")
    assert "Not a directory" in sh("cd /etc/passwd 2>&1")


def test_ls(sh):
    out = sh("ls /")
    for name in ("etc", "home", "opt", "var", "usr", "tmp"):
        assert name + "\n" in out
    assert ".bashrc" not in sh("ls ~")
    assert ".bashrc" in sh("ls -a ~")
    long = sh("ls -la /opt/app")
    assert long.startswith("total ")
    assert "-rw-r----- 1 deploy deploy" in long and ".env" in long
    assert "bin -> usr/bin" in sh("ls -l /")
    assert "cannot access '/nope'" in sh("ls /nope")


def test_ls_columns_on_tty(engine, base):
    state = engine.new_state("root", tty=True, base=base)
    out = engine.run(state, "ls /").out
    assert len(out.splitlines()) < 10


def test_cat_head_tail(sh):
    assert sh("cat /etc/hostname") == "qf-web-01\n"
    assert sh("head -n 1 /etc/passwd") == "root:x:0:0:root:/root:/bin/bash\n"
    assert sh("head -3 /etc/passwd").count("\n") == 3
    assert sh("tail -n 1 /etc/hostname") == "qf-web-01\n"
    assert "No such file or directory" in sh("cat /nope")
    assert sh("cat -n /etc/hostname") == "     1\tqf-web-01\n"


def test_write_read_rm(sh):
    sh("mkdir -p /tmp/a/b && echo hello > /tmp/a/b/f")
    assert sh("cat /tmp/a/b/f") == "hello\n"
    sh("echo again >> /tmp/a/b/f")
    assert sh("cat /tmp/a/b/f") == "hello\nagain\n"
    sh("cp /tmp/a/b/f /tmp/g && mv /tmp/g /tmp/h")
    assert sh("cat /tmp/h") == "hello\nagain\n"
    assert "Is a directory" in sh("rm /tmp/a")
    sh("rm -rf /tmp/a")
    assert "No such file" in sh("ls /tmp/a")
    sh("touch /tmp/t")
    assert sh("ls /tmp/t") == "/tmp/t\n"


def test_rm_root_failsafe(sh):
    assert "dangerous" in sh("rm -rf /")
    assert sh("cat /etc/hostname") == "qf-web-01\n"


def test_chmod_and_scripts(sh):
    sh("echo 'echo from-script' > /tmp/s.sh")
    assert "Permission denied" in sh("/tmp/s.sh")
    sh("chmod +x /tmp/s.sh")
    assert sh("/tmp/s.sh") == "from-script\n"
    assert "-rwxr-xr-x" in sh("ls -l /tmp/s.sh")
    sh("chmod 600 /tmp/s.sh")
    assert "-rw-------" in sh("ls -l /tmp/s.sh")
    sh("chmod -R go= /opt/app")
    assert "drwx------" in sh("ls -ld /opt/app")


def test_binary_placeholder_fails_to_run(sh):
    assert "Exec format error" in sh("/usr/bin/nc")


def test_find_file_stat(sh):
    assert sh("find /opt/app -name '*.sh'") == "/opt/app/scripts/backup.sh\n"
    assert "/etc/nginx/nginx.conf" in sh("find /etc -type f -name nginx.conf")
    assert "Bourne-Again shell script" in sh("file /opt/app/scripts/backup.sh")
    assert "ELF 64-bit" in sh("file /usr/bin/ls")
    assert "Size:" in sh("stat /etc/passwd")


def test_redirects_and_pipes(sh):
    assert sh("cat /etc/passwd | grep root | head -n 1") == "root:x:0:0:root:/root:/bin/bash\n"
    assert sh("cat /nope 2>/dev/null") == ""
    assert "No such file" in sh("cat /nope 2>&1 | head -n 1")
    sh("echo one > /tmp/x; echo two >> /tmp/x")
    assert sh("wc -l < /tmp/x") == "2\n"
    assert sh("echo a && echo b || echo c") == "a\nb\n"
    assert sh("cat /nope 2>/dev/null || echo fallback") == "fallback\n"
    assert sh("echo $(cat /etc/hostname)-x") == "qf-web-01-x\n"
    sh("X=42")
    assert sh("echo $X") == "42\n"


def test_glob(sh):
    assert sh("echo /etc/*release") == "/etc/lsb-release /etc/os-release\n"
    assert sh("ls /opt/app/scripts/*.sh") == "/opt/app/scripts/backup.sh\n"


def test_permissions_as_user(engine, base):
    state = engine.new_state("deploy", tty=False, base=base)

    def run(line):
        return engine.run(state, line).out

    assert run("pwd") == "/home/deploy\n"
    assert "Permission denied" in run("cat /etc/shadow")
    assert "Permission denied" in run("ls /root")
    assert "Permission denied" in run("echo x > /etc/passwd")
    assert "qf_app" in run("cat /opt/app/.env")


def test_unknown_command(sh):
    assert sh("frobnicate --now") == "frobnicate: command not found\n"
    assert sh.state.last_status == 127


def test_base_untouched_between_sessions(engine, base):
    a = engine.new_state("root", tty=False, base=base)
    b = engine.new_state("root", tty=False, base=base)
    engine.run(a, "rm -rf /opt/app; echo x > /etc/hostname")
    assert engine.run(b, "cat /etc/hostname").out == "qf-web-01\n"
    assert ".env" in engine.run(b, "ls -a /opt/app").out
