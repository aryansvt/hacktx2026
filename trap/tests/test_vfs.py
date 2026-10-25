import copy
import importlib.util
import json
from pathlib import Path

import pytest

from honeypot import vfs
from honeypot.vfs import FsError, Overlay, norm

SEED = Path(__file__).resolve().parent.parent / "seed" / "build_seed.py"


def test_norm():
    assert norm("a/../b", "/root") == "/root/b"
    assert norm("//etc///passwd") == "/etc/passwd"
    assert norm("../../..", "/home/deploy") == "/"
    assert norm("./x/.", "/tmp") == "/tmp/x"


def test_seed_json_is_current(base):
    spec = importlib.util.spec_from_file_location("build_seed", SEED)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    data = SEED.parent.parent / "honeypot" / "data"
    assert json.loads((data / "fs_base.json").read_text()) == mod.build_fs()
    assert json.loads((data / "system.json").read_text()) == mod.build_system()


def test_seed_looks_like_ubuntu(fs):
    assert 'VERSION_ID="22.04"' in fs.read("/etc/os-release")
    assert fs.read("/etc/hostname") == "qf-web-01\n"
    assert fs.read("/etc/passwd").startswith("root:x:0:0:")
    assert "processor\t: 1" in fs.read("/proc/cpuinfo")


def test_canary_values_are_marked_fake(fs):
    env = fs.read("/opt/app/.env")
    secrets = [l.split("=", 1)[1] for l in env.splitlines()
               if "=" in l and any(k in l for k in ("PASSWORD", "SECRET", "KEY"))]
    assert secrets
    assert all("FAKE-CANARY" in s for s in secrets)


def test_symlinks(fs):
    assert fs.realpath("/bin/ls") == "/usr/bin/ls"
    assert fs.is_file("/bin/cat")
    assert fs.listdir("/etc/nginx/sites-enabled") == ["quillfern"]
    assert "server_name shop.quillfern.lan" in fs.read("/etc/nginx/sites-enabled/quillfern")


def test_write_is_copy_on_write(base):
    before = copy.deepcopy(base.nodes)
    a, b = Overlay(base), Overlay(base)
    a.write("/tmp/x.sh", "echo hi\n")
    a.write("/etc/hostname", "pwned\n")
    a.remove("/etc/passwd")
    assert a.read("/tmp/x.sh") == "echo hi\n"
    assert a.read("/etc/hostname") == "pwned\n"
    assert not a.exists("/etc/passwd")
    assert "passwd" not in a.listdir("/etc")
    # other session and base untouched
    assert b.read("/etc/hostname") == "qf-web-01\n"
    assert b.exists("/etc/passwd")
    assert not b.exists("/tmp/x.sh")
    assert base.nodes == before


def test_append_and_listing_merge(fs):
    fs.write("/tmp/a", "1\n")
    fs.write("/tmp/a", "2\n", append=True)
    assert fs.read("/tmp/a") == "1\n2\n"
    assert "a" in fs.listdir("/tmp")
    assert ".X11-unix" in fs.listdir("/tmp")


def test_mkdir_rm_recreate(fs):
    fs.mkdir("/tmp/d/e/f", parents=True)
    fs.write("/tmp/d/e/f/g", "x")
    with pytest.raises(FsError) as e:
        fs.remove("/tmp/d")
    assert e.value.code == "EISDIR"
    fs.remove("/tmp/d", recursive=True)
    assert not fs.exists("/tmp/d/e/f/g")
    fs.mkdir("/tmp/d")
    assert fs.listdir("/tmp/d") == []


def test_rm_base_dir_hides_children(fs):
    fs.remove("/opt/app", recursive=True)
    assert not fs.exists("/opt/app/.env")
    assert fs.listdir("/opt") == []
    fs.mkdir("/opt/app")
    assert fs.listdir("/opt/app") == []


def test_copy_and_move(fs):
    fs.copy("/etc/hostname", "/tmp")
    assert fs.read("/tmp/hostname") == "qf-web-01\n"
    fs.move("/tmp/hostname", "/tmp/h2")
    assert not fs.exists("/tmp/hostname") and fs.exists("/tmp/h2")
    fs.copy("/opt/app", "/tmp/app", recursive=True)
    assert "POSTGRES_PASSWORD" in fs.read("/tmp/app/.env")
    fs.move("/tmp/app", "/root/app2")
    assert fs.exists("/root/app2/scripts/backup.sh") and not fs.exists("/tmp/app")
    with pytest.raises(FsError):
        fs.copy("/opt", "/opt/app/x", recursive=True)


def test_permissions(fs):
    with pytest.raises(FsError) as e:
        fs.read("/etc/shadow", user="deploy")
    assert e.value.code == "EACCES"
    with pytest.raises(FsError):
        fs.listdir("/root", user="deploy")
    with pytest.raises(FsError):
        fs.read("/root/.bash_history", user="deploy")
    with pytest.raises(FsError):
        fs.write("/etc/passwd", "x", user="deploy")
    assert "qf_app" in fs.read("/opt/app/.env", user="deploy")
    fs.write("/tmp/mine", "x", user="deploy")
    assert fs.get("/tmp/mine").owner == "deploy"
    fs.read("/etc/shadow", user="root")


def test_chmod_chown(fs):
    fs.write("/tmp/x", "")
    fs.chmod("/tmp/x", 0o755)
    assert fs.get("/tmp/x").mode == 0o755
    fs.chown("/tmp/x", "deploy", None)
    assert fs.get("/tmp/x").owner == "deploy"


def test_link_loop(fs):
    fs._put("/tmp/l1", vfs.Node("link", 0o777, target="/tmp/l2"))
    fs._put("/tmp/l2", vfs.Node("link", 0o777, target="/tmp/l1"))
    assert fs.get("/tmp/l1") is None
    with pytest.raises(FsError) as e:
        fs.read("/tmp/l1")
    assert e.value.code == "ELOOP"


def test_caps(fs, monkeypatch):
    with pytest.raises(FsError) as e:
        fs.write("/tmp/big", "x" * (vfs.MAX_FILE_BYTES + 1))
    assert e.value.code == "ENOSPC"
    monkeypatch.setattr(vfs, "MAX_OVERLAY_ENTRIES", 3)
    for i in range(3):
        fs.write(f"/tmp/f{i}", "x")
    with pytest.raises(FsError):
        fs.write("/tmp/f9", "x")
    # rewriting an existing entry still works
    fs.write("/tmp/f0", "y")


def test_overlay_byte_cap(fs, monkeypatch):
    monkeypatch.setattr(vfs, "MAX_OVERLAY_BYTES", 10)
    fs.write("/tmp/a", "x" * 8)
    with pytest.raises(FsError):
        fs.write("/tmp/b", "x" * 5)
    fs.write("/tmp/a", "x" * 2)
    fs.write("/tmp/b", "x" * 5)
