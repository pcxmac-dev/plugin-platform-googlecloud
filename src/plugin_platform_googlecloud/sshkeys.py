"""The project-wide SSH keys, kept in the project's common metadata under `ssh-keys` as Google's guide to adding SSH keys
gives them (https://docs.cloud.google.com/compute/docs/connect/add-ssh-keys, read 2026-11-11): one key a line,
USERNAME:KEY_VALUE (an expiring one ends `google-ssh {"userName":...,"expireOn":...}`). They let their users in to
every server of the project but those blocking project-wide keys, and are ignored by a server with OS Login on.

The metadata is written whole (setCommonInstanceMetadata), so a key is added or removed by reading it afresh, changing
the `ssh-keys` value alone (every other line, and every other item, kept exactly as read) and writing it with the
fingerprint it was read with: Google refuses the write (412 conditionNotMet) when the metadata changed since, so a
change made meanwhile is never overwritten. That is what makes the change safe; nothing here writes without it."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .records import Refusal

KEY = "ssh-keys"
LEGACY = "sshKeys"  # the older key, read and kept as it is
OS_LOGIN = "enable-oslogin"
BLOCK = "block-project-ssh-keys"
TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa",
         "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$")
METADATA_MOST = 512 * 1024  # every key and value of the metadata together (Google's limit)
VALUE_MOST = 262144  # one value


@dataclass(frozen=True)
class Entry:
    """One line of `ssh-keys`: its user, its key's type, its fingerprint (SHA256:..., as ssh-keygen -l says it), its
    comment, its expiry (an expiring key's), the line as read."""

    user: str
    kind: str
    fingerprint: str
    comment: str
    expires: str
    line: str

    def describe(self) -> dict:
        return {"user": self.user, "type": self.kind, "fingerprint": self.fingerprint, "comment": self.comment,
                "expires": self.expires}


def fingerprint_of(blob_b64: str) -> str:
    """The key's SHA-256 fingerprint as OpenSSH writes it ("" when its base64 is none)."""
    try:
        blob = base64.b64decode(blob_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def parse_line(line: str) -> Entry | None:
    """A line of `ssh-keys` (USERNAME:KEY_VALUE) as an Entry; None when it is no key line."""
    text = line.strip()
    user, sep, rest = text.partition(":")
    if not sep or not user or not rest.strip():
        return None
    parts = rest.split()
    if len(parts) < 2:
        return None
    kind, blob = parts[0], parts[1]
    tail = rest.split(None, 2)[2] if len(parts) > 2 else ""
    expires, comment = "", tail
    m = re.match(r"^google-ssh\s+(\{.*\})\s*$", tail)
    if m:
        found = re.search(r'"expireOn"\s*:\s*"([^"]+)"', m.group(1))
        expires, comment = (found.group(1) if found else ""), "google-ssh"
    return Entry(user=user.strip(), kind=kind, fingerprint=fingerprint_of(blob), comment=comment.strip(), expires=expires,
                 line=line)


def item(items: Sequence[Mapping], key: str) -> str | None:
    for x in items or []:
        if x.get("key") == key:
            return str(x.get("value") or "")
    return None


def entries(items: Sequence[Mapping], key: str = KEY) -> list[Entry]:
    value = item(items, key)
    return [e for e in (parse_line(x) for x in (value or "").splitlines()) if e is not None]


def os_login(items: Sequence[Mapping]) -> bool:
    return str(item(items, OS_LOGIN) or "").strip().lower() == "true"


def blocks_project_keys(instance: Mapping) -> bool:
    items = (instance.get("metadata") or {}).get("items") or []
    return str(item(items, BLOCK) or "").strip().lower() == "true"


def check_key(key: str) -> tuple[str, str]:
    """A public key as typed (its type, its base64, a comment) checked: (the key's text as written, its fingerprint)."""
    text = " ".join(str(key or "").split())
    parts = text.split(" ", 2)
    if len(parts) < 2:
        raise ValueError("a public key is its type and its base64, then a comment: ssh-ed25519 AAAAC3... you@pc")
    if text.startswith("-----") or "PRIVATE KEY" in text.upper():
        raise ValueError("that is a private key: paste the public one (the .pub file's line)")
    kind, blob = parts[0], parts[1]
    if kind not in TYPES:
        raise ValueError(f"{kind[:40]!r} is no public key type here: {', '.join(TYPES)}")
    not_one = "its base64 is not a public key's (paste the .pub file's line whole)"
    try:
        raw = base64.b64decode(blob.encode("ascii"), validate=True)
        (size,) = struct.unpack(">I", raw[:4])
        inner = raw[4:4 + size].decode("ascii") if 0 < size <= min(64, len(raw) - 4) else ""
    except (binascii.Error, ValueError, UnicodeError, struct.error):
        raise ValueError(not_one) from None
    if inner not in TYPES:
        raise ValueError(not_one)
    if inner != kind:
        raise ValueError(f"its base64 is a {inner} key, not {kind}")
    return text, fingerprint_of(blob)


def check_user(user: str) -> str:
    u = str(user or "").strip()
    if not USER.match(u):
        raise ValueError(f"{u[:40]!r} is not a user name (letters, digits, dots, dashes and underscores, at most 32)")
    return u


def size_of(items: Sequence[Mapping]) -> int:
    return sum(len(str(x.get("key") or "").encode()) + len(str(x.get("value") or "").encode()) for x in items)


def with_value(items: Sequence[Mapping], value: str | None) -> list[dict]:
    """The items with `ssh-keys` set to `value` (None: taken out), every other item exactly as read, in its place."""
    out: list[dict] = []
    placed = False
    for x in items or []:
        if x.get("key") == KEY:
            if value is not None and not placed:
                out.append({"key": KEY, "value": value})
            placed = True
            continue
        out.append({"key": x.get("key"), "value": x.get("value")})
    if value is not None and not placed:
        out.append({"key": KEY, "value": value})
    return out


def plan_add(items: Sequence[Mapping], user: str, key: str) -> tuple[list[dict] | None, str]:
    """The items with a key added for `user` (None when it is there already), and what that does in words."""
    u = check_user(user)
    text, fp = check_key(key)
    held = entries(items)
    if any(e.user == u and e.fingerprint == fp for e in held):
        return None, f"{u}'s key {fp} is there already: nothing written"
    value = item(items, KEY) or ""
    line = f"{u}:{text}"
    new = (value + ("" if not value or value.endswith("\n") else "\n") + line) if value else line
    if len(new.encode()) > VALUE_MOST:
        raise ValueError("the project's ssh-keys would pass Google's 256 KiB for one value")
    out = with_value(items, new)
    if size_of(out) >= METADATA_MOST:
        raise ValueError("the project's metadata would pass Google's 512 KB")
    return out, f"added {u}'s {text.split(' ', 1)[0]} key {fp}"


def plan_remove(items: Sequence[Mapping], user: str, fingerprint: str) -> tuple[list[dict], str]:
    """The items with `user`'s key of `fingerprint` taken out of `ssh-keys` (every other line kept as it is)."""
    u = str(user or "").strip()
    fp = str(fingerprint or "").strip()
    value = item(items, KEY)
    lines = (value or "").split("\n")
    gone = [x for x in lines if (e := parse_line(x)) is not None and e.user == u and e.fingerprint == fp]
    if not gone:
        raise Refusal(f"no key {fp or '(none named)'} of {u or '(no user)'} in the project's ssh-keys")
    rest = "\n".join(x for x in lines if x not in gone)
    out = with_value(items, rest if rest.strip() else None)
    return out, f"removed {u}'s key {fp}" + (f" ({len(gone)} lines)" if len(gone) > 1 else "")


def only_keys_changed(before: Sequence[Mapping], after: Sequence[Mapping]) -> bool:
    """Whether two items lists differ in `ssh-keys` alone (every other item the same, in the same order)."""
    strip = lambda xs: [(x.get("key"), x.get("value")) for x in xs if x.get("key") != KEY]  # noqa: E731
    return strip(before) == strip(after)
