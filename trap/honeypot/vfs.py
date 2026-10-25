"""virtual filesystem: a read-only base tree plus a copy-on-write overlay per session.

nothing here touches the real disk except loading the seed json once.
"""

from __future__ import annotations

import json
import posixpath
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_MTIME = "2026-09-14 10:22"

# per-session caps so an attacker can't eat our memory
MAX_FILE_BYTES = 1_000_000
MAX_OVERLAY_BYTES = 5_000_000
MAX_OVERLAY_ENTRIES = 2000
MAX_LINK_HOPS = 8


class FsError(Exception):
    """errno-style error. code is ENOENT, EACCES, EISDIR, ENOTDIR, EEXIST, ENOTEMPTY, ENOSPC, ELOOP."""

    MESSAGES = {
        "ENOENT": "No such file or directory",
        "EACCES": "Permission denied",
        "EISDIR": "Is a directory",
        "ENOTDIR": "Not a directory",
        "EEXIST": "File exists",
        "ENOTEMPTY": "Directory not empty",
        "ENOSPC": "No space left on device",
        "ELOOP": "Too many levels of symbolic links",
        "EINVAL": "Invalid argument",
    }

    def __init__(self, code: str, path: str = ""):
        super().__init__(f"{path}: {self.MESSAGES.get(code, code)}")
        self.code = code
        self.path = path

    @property
    def message(self) -> str:
        return self.MESSAGES.get(self.code, self.code)


@dataclass(frozen=True)
class Node:
    type: str  # dir | file | link
    mode: int
    owner: str = "root"
    group: str = "root"
    mtime: float = 0.0
    content: str = ""
    target: str = ""
    # shown size for simulated downloads, so we don't hold megabytes of filler
    fake_size: int | None = None

    @property
    def size(self) -> int:
        if self.fake_size is not None:
            return self.fake_size
        if self.type == "dir":
            return 4096
        if self.type == "link":
            return len(self.target)
        return len(self.content.encode())


def _parse_mtime(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    dt = datetime.strptime(value or DEFAULT_MTIME, "%Y-%m-%d %H:%M")
    return dt.replace(tzinfo=timezone.utc).timestamp()


def norm(path: str, cwd: str = "/") -> str:
    """lexical absolute path: joins cwd, collapses //, ., and .."""
    if not path.startswith("/"):
        path = posixpath.join(cwd, path)
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def _parent(path: str) -> str:
    return posixpath.dirname(path) or "/"


class BaseFS:
    """the seed tree, flattened to path -> node. never mutated after load."""

    def __init__(self, nodes: dict[str, Node]):
        self.nodes = nodes
        self.children: dict[str, set[str]] = {}
        for path in nodes:
            if path != "/":
                self.children.setdefault(_parent(path), set()).add(posixpath.basename(path))

    @classmethod
    def from_tree(cls, tree: dict) -> "BaseFS":
        nodes: dict[str, Node] = {}

        def walk(path: str, spec) -> None:
            if isinstance(spec, str):
                spec = {"type": "file", "content": spec}
            kind = spec.get("type") or ("dir" if "children" in spec else "link" if "target" in spec else "file")
            default_mode = {"dir": 0o755, "file": 0o644, "link": 0o777}[kind]
            nodes[path] = Node(
                type=kind,
                mode=int(spec["mode"], 8) if "mode" in spec else default_mode,
                owner=spec.get("owner", "root"),
                group=spec.get("group", spec.get("owner", "root")),
                mtime=_parse_mtime(spec.get("mtime")),
                content=spec.get("content", ""),
                target=spec.get("target", ""),
            )
            for name, child in spec.get("children", {}).items():
                walk(posixpath.join(path, name), child)

        walk("/", tree)
        return cls(nodes)

    @classmethod
    def load(cls, path: Path) -> "BaseFS":
        return cls.from_tree(json.loads(path.read_text(encoding="utf-8")))


class Overlay:
    """per-session view. writes land in self.entries; None marks a deleted path."""

    def __init__(self, base: BaseFS):
        self.base = base
        self.entries: dict[str, Node | None] = {}
        self.added: dict[str, set[str]] = {}
        self.bytes_used = 0

    def snapshot(self) -> tuple:
        """cheap copy of the overlay. nodes are frozen, so sharing them is fine."""
        return dict(self.entries), {k: set(v) for k, v in self.added.items()}, self.bytes_used

    def restore(self, snap: tuple) -> None:
        entries, added, used = snap
        self.entries, self.added, self.bytes_used = dict(entries), {k: set(v) for k, v in added.items()}, used

    # lookups

    def _raw(self, path: str) -> Node | None:
        if path in self.entries:
            return self.entries[path]
        return self.base.nodes.get(path)

    def realpath(self, path: str, follow_last: bool = True, _hops: int = 0) -> str:
        path = norm(path)
        if path == "/":
            return "/"
        parent = self.realpath(_parent(path), True, _hops)
        full = posixpath.join(parent, posixpath.basename(path))
        node = self._raw(full)
        if node is not None and node.type == "link" and follow_last:
            if _hops >= MAX_LINK_HOPS:
                raise FsError("ELOOP", path)
            return self.realpath(norm(node.target, parent), True, _hops + 1)
        return full

    def get(self, path: str, follow: bool = True) -> Node | None:
        try:
            return self._raw(self.realpath(path, follow))
        except FsError:
            return None

    def exists(self, path: str) -> bool:
        return self.get(path) is not None

    def is_dir(self, path: str) -> bool:
        node = self.get(path)
        return node is not None and node.type == "dir"

    def is_file(self, path: str) -> bool:
        node = self.get(path)
        return node is not None and node.type == "file"

    # permissions (owner and other bits only, root bypasses)

    @staticmethod
    def allowed(node: Node, user: str, bit: int) -> bool:
        if user == "root":
            return True
        shift = 6 if node.owner == user else 0
        return bool(node.mode & (bit << shift))

    def _check_traverse(self, real: str, user: str) -> None:
        cur = _parent(real)
        chain = []
        while True:
            chain.append(cur)
            if cur == "/":
                break
            cur = _parent(cur)
        for d in reversed(chain):
            node = self._raw(d)
            if node is not None and node.type == "dir" and not self.allowed(node, user, 0o1):
                raise FsError("EACCES", real)

    def stat(self, path: str, user: str = "root", follow: bool = True) -> Node:
        real = self.realpath(path, follow)
        self._check_traverse(real, user)
        node = self._raw(real)
        if node is None:
            raise FsError("ENOENT", path)
        return node

    def read(self, path: str, user: str = "root") -> str:
        node = self.stat(path, user)
        if node.type == "dir":
            raise FsError("EISDIR", path)
        if not self.allowed(node, user, 0o4):
            raise FsError("EACCES", path)
        return node.content

    def listdir(self, path: str, user: str = "root") -> list[str]:
        node = self.stat(path, user)
        if node.type != "dir":
            raise FsError("ENOTDIR", path)
        if not self.allowed(node, user, 0o4):
            raise FsError("EACCES", path)
        real = self.realpath(path)
        names = set(self.base.children.get(real, set())) | self.added.get(real, set())
        prefix = real.rstrip("/") + "/"
        return sorted(n for n in names if self._raw(prefix + n) is not None)

    def walk(self, path: str, user: str = "root"):
        """yield (abs path, node) for path and everything under it, skipping unreadable dirs."""
        real = self.realpath(path)
        node = self._raw(real)
        if node is None:
            return
        yield real, node
        if node.type == "dir":
            try:
                names = self.listdir(real, user)
            except FsError:
                return
            for name in names:
                yield from self.walk(posixpath.join(real, name), user)

    # writes

    def _put(self, path: str, node: Node | None) -> None:
        old = self.entries.get(path)
        old_bytes = len(old.content) if old is not None else 0
        new_bytes = len(node.content) if node is not None else 0
        if node is not None and new_bytes > MAX_FILE_BYTES:
            raise FsError("ENOSPC", path)
        if self.bytes_used - old_bytes + new_bytes > MAX_OVERLAY_BYTES:
            raise FsError("ENOSPC", path)
        if path not in self.entries and len(self.entries) >= MAX_OVERLAY_ENTRIES:
            raise FsError("ENOSPC", path)
        self.bytes_used += new_bytes - old_bytes
        self.entries[path] = node
        if node is not None and path != "/":
            self.added.setdefault(_parent(path), set()).add(posixpath.basename(path))

    def _writable_parent(self, real: str, user: str) -> None:
        parent = self._raw(_parent(real))
        if parent is None:
            raise FsError("ENOENT", real)
        if parent.type != "dir":
            raise FsError("ENOTDIR", real)
        self._check_traverse(real, user)
        if not self.allowed(parent, user, 0o2):
            raise FsError("EACCES", real)

    def write(self, path: str, content: str, user: str = "root", append: bool = False, mode: int = 0o644) -> None:
        real = self.realpath(path)
        node = self._raw(real)
        if node is not None:
            if node.type == "dir":
                raise FsError("EISDIR", path)
            if not self.allowed(node, user, 0o2):
                raise FsError("EACCES", path)
            new = replace(node, content=(node.content + content) if append else content, mtime=time.time(), fake_size=None)
        else:
            self._writable_parent(real, user)
            new = Node("file", mode, owner=user, group=user, mtime=time.time(), content=content)
        self._put(real, new)

    def touch(self, path: str, user: str = "root") -> None:
        real = self.realpath(path)
        node = self._raw(real)
        if node is None:
            self.write(path, "", user)
        else:
            self._put(real, replace(node, mtime=time.time()))

    def mkdir(self, path: str, user: str = "root", parents: bool = False) -> None:
        real = self.realpath(path)
        node = self._raw(real)
        if node is not None:
            if parents and node.type == "dir":
                return
            raise FsError("EEXIST", path)
        if parents and self._raw(_parent(real)) is None:
            self.mkdir(_parent(real), user, parents=True)
        self._writable_parent(real, user)
        self._put(real, Node("dir", 0o755, owner=user, group=user, mtime=time.time()))

    def remove(self, path: str, user: str = "root", recursive: bool = False, dir_ok: bool = False) -> None:
        real = self.realpath(path, follow_last=False)
        node = self._raw(real)
        if node is None:
            raise FsError("ENOENT", path)
        self._writable_parent(real, user)
        if node.type == "dir":
            children = self.listdir(real, user)
            if children and not recursive:
                raise FsError("ENOTEMPTY" if dir_ok else "EISDIR", path)
            if not recursive and not dir_ok:
                raise FsError("EISDIR", path)
            for name in children:
                self.remove(posixpath.join(real, name), user, recursive=True, dir_ok=True)
        self._put(real, None)

    def copy(self, src: str, dst: str, user: str = "root", recursive: bool = False) -> None:
        node = self.stat(src, user)
        real_dst = self.realpath(dst)
        target = self._raw(real_dst)
        if target is not None and target.type == "dir":
            real_dst = posixpath.join(real_dst, posixpath.basename(norm(src)))
        if node.type == "dir":
            if not recursive:
                raise FsError("EISDIR", src)
            if real_dst == self.realpath(src) or real_dst.startswith(self.realpath(src) + "/"):
                raise FsError("EINVAL", dst)
            if self._raw(real_dst) is None:
                self.mkdir(real_dst, user)
            for name in self.listdir(src, user):
                self.copy(posixpath.join(self.realpath(src), name), posixpath.join(real_dst, name), user, True)
            return
        if not self.allowed(node, user, 0o4):
            raise FsError("EACCES", src)
        self.write(real_dst, node.content, user, mode=node.mode)

    def move(self, src: str, dst: str, user: str = "root") -> None:
        node = self.stat(src, user, follow=False)
        real_src = self.realpath(src, follow_last=False)
        real_dst = self.realpath(dst)
        target = self._raw(real_dst)
        if target is not None and target.type == "dir":
            real_dst = posixpath.join(real_dst, posixpath.basename(real_src))
        if real_dst == real_src:
            return
        if node.type == "dir":
            if real_dst.startswith(real_src + "/"):
                raise FsError("EINVAL", dst)
            self.copy(real_src, real_dst, user, recursive=True)
            self.remove(real_src, user, recursive=True, dir_ok=True)
            return
        self._writable_parent(real_src, user)
        self._writable_parent(real_dst, user)
        self._put(real_dst, replace(node, mtime=time.time()))
        self._put(real_src, None)

    def symlink(self, target: str, path: str, user: str = "root") -> None:
        real = self.realpath(path, follow_last=False)
        if self._raw(real) is not None:
            raise FsError("EEXIST", path)
        self._writable_parent(real, user)
        self._put(real, Node("link", 0o777, owner=user, group=user, mtime=time.time(), target=target))

    def write_node(self, path: str, node: Node, user: str = "root") -> None:
        """place a prepared file node (used for simulated downloads)."""
        real = self.realpath(path)
        existing = self._raw(real)
        if existing is not None and existing.type == "dir":
            raise FsError("EISDIR", path)
        if existing is None:
            self._writable_parent(real, user)
        elif not self.allowed(existing, user, 0o2):
            raise FsError("EACCES", path)
        self._put(real, node)

    def chmod(self, path: str, mode: int, user: str = "root") -> None:
        node = self.stat(path, user)
        if user != "root" and node.owner != user:
            raise FsError("EACCES", path)
        self._put(self.realpath(path), replace(node, mode=mode))

    def chown(self, path: str, owner: str, group: str | None, user: str = "root") -> None:
        node = self.stat(path, user)
        if user != "root":
            raise FsError("EACCES", path)
        self._put(self.realpath(path), replace(node, owner=owner, group=group or node.group))
