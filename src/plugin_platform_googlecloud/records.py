"""A Cloud DNS zone's records changed the way Cloud DNS's API changes them (https://docs.cloud.google.com/dns/docs/
reference/rest/v1/changes, read 2026-11-11): one change, applied at once, its deletions record sets that "must match
existing data exactly" and its additions the record sets as they are to be. A record set is a name (www.example.com.),
a type, a TTL and its data (rrdatas: one value or several). So a record is set or removed by reading the name's record
sets afresh, then deleting the one of its type exactly as read and adding it back changed: every other record of the
zone, and every other value of the set, is kept, and a change made meanwhile by anyone else makes the deletion no
longer match, so Google refuses it and nothing is overwritten.

Refused, with nothing sent: the zone's own SOA and NS records at its apex, a record set with a routing policy (geo or
weighted: changed in the console), a CNAME beside other records or other records beside a CNAME, a forwarding, peering
or other zone that serves no records of its own; a value that is not one of its type's."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence

TTL_DEFAULT = 300
TTL_MIN, TTL_MAX = 1, 86400
LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
TARGET_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
CAA_TAG = re.compile(r"^[a-z0-9]{1,15}$")
MAX_TEXT = 4000
# the types the page's form sets, in the order offered, with what each holds and does
TYPES = {
    "A": "an IPv4 address; replaces the name's A record",
    "AAAA": "an IPv6 address; replaces the name's AAAA record",
    "CNAME": "a host name the name stands for; it holds nothing else, and the zone's own name takes none",
    "TXT": "text (SPF, DKIM, DMARC, a verification); added beside the name's other TXT values",
    "MX": "a preference and a mail server (10 mail.example.com); added beside the others",
    "CAA": "flags, a tag and a value (0 issue \"letsencrypt.org\"); added beside the others",
    "SRV": "priority, weight, port and target (10 5 5060 sip.example.com); added beside the others",
    "NS": "a name server of a subdomain delegated elsewhere; added beside the others",
}
APEX = frozenset({"SOA", "NS", "DNSKEY"})  # the zone's own records at its apex: never changed here
DNSSEC = frozenset({"DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM"})  # DNSSEC's, Cloud DNS's own to keep
SINGLE = frozenset({"A", "AAAA", "CNAME"})  # set: the name's record set of the type replaced by the one value
NAMED = frozenset({"CNAME", "NS"})  # a value that is a host name
UNSERVED = ("forwardingConfig", "peeringConfig", "reverseLookupConfig", "serviceDirectoryConfig")


class Refusal(ValueError):
    """A change not made, and why: nothing was sent. `accept`: the argument that, set, makes it anyway (the page asks it
    as a second, explicit confirmation)."""

    def __init__(self, message: str, accept: str | None = None):
        super().__init__(message)
        self.accept = accept


def dot(name: str) -> str:
    n = str(name or "").strip().lower()
    return n if n.endswith(".") else n + "."


def undot(name: str) -> str:
    return str(name or "").strip().rstrip(".")


def unwritable(zone: Mapping) -> str | None:
    """Why the zone's records are not written here (a zone that serves no records of its own), or None."""
    for key in UNSERVED:
        if zone.get(key):
            kind = {"forwardingConfig": "forwarding", "peeringConfig": "peering", "reverseLookupConfig": "reverse lookup",
                    "serviceDirectoryConfig": "Service Directory"}[key]
            return f"a {kind} zone: it serves no records of its own here (changed in the console)"
    return None


def fqdn(name: str, zone: Mapping) -> str:
    """A name as typed (@, www, home.example.com, home.example.com.) as the full name in the zone (with its dot);
    ValueError when it is none, or not in the zone."""
    origin = dot(zone.get("dnsName") or "")
    n = str(name or "").strip().lower()
    if n in ("", "@"):
        if not n:
            raise ValueError("no name given: @ is the zone's own name, www is www." + undot(origin))
        return origin
    if n.endswith("."):
        full = n
    elif n == undot(origin) or n.endswith("." + undot(origin)):
        full = n + "."
    else:
        full = f"{n}.{origin}"
    if full != origin and not full.endswith("." + origin):
        raise ValueError(f"{undot(full)} is not in the zone {undot(origin)}")
    labels = full[: -len(origin)].rstrip(".").split(".") if full != origin else []
    if len(full) > 254 or not all(LABEL.match(x) or (i == 0 and x == "*") for i, x in enumerate(labels)):
        raise ValueError(f"{str(name).strip()!r} is not a name: @, www, home, *, _dmarc")
    return full


def host_value(value: str, what: str) -> str:
    n = str(value or "").strip().lower()
    labels = n.rstrip(".").split(".")
    if len(n) > 254 or len(labels) < 2 or not all(TARGET_LABEL.match(x) for x in labels):
        raise ValueError(f"{str(value).strip()!r} is not a host name ({what})")
    return dot(n)


def number(value: str, what: str, most: int) -> int:
    try:
        n = int(str(value).strip())
    except ValueError:
        raise ValueError(f"{str(value).strip()!r} is not a number ({what})") from None
    if not 0 <= n <= most:
        raise ValueError(f"{what} is 0 to {most}")
    return n


def quoted(text: str) -> str:
    """Text as a TXT or CAA value's character strings: quoted, at most 255 characters each (a longer text split)."""
    t = str(text)
    chunks = [t[i:i + 255] for i in range(0, len(t), 255)] or [""]
    return " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)


def value_for(rtype: str, value: str) -> str:
    """The data of a record of `rtype` as written (rrdatas' form); ValueError when it is none."""
    v = str(value or "").strip()
    if not v:
        raise ValueError("no data given")
    if any(ord(c) < 32 or ord(c) == 127 for c in v) or len(v) > MAX_TEXT:
        raise ValueError(f"a value is one line of at most {MAX_TEXT} characters")
    if rtype == "A":
        try:
            return str(ipaddress.IPv4Address(v))
        except ValueError:
            raise ValueError(f"{v!r} is not an IPv4 address (an A record's)") from None
    if rtype == "AAAA":
        try:
            return str(ipaddress.IPv6Address(v))
        except ValueError:
            raise ValueError(f"{v!r} is not an IPv6 address (an AAAA record's)") from None
    if rtype in NAMED:
        return host_value(v, f"a {rtype} record's")
    if rtype == "MX":
        parts = v.split()
        if len(parts) != 2:
            raise ValueError("an MX record is a preference and a mail server: 10 mail.example.com")
        server = host_value(parts[1], "an MX record's server")
        return f"{number(parts[0], 'an MX preference', 65535)} {server}"
    if rtype == "SRV":
        parts = v.split()
        if len(parts) != 4:
            raise ValueError("an SRV record is priority, weight, port and target: 10 5 5060 sip.example.com")
        p, w, port = (number(x, what, 65535) for x, what in zip(parts[:3], ("a priority", "a weight", "a port")))
        target = host_value(parts[3], "an SRV record's target")
        return f"{p} {w} {port} {target}"
    if rtype == "CAA":
        parts = v.split(None, 2)
        if len(parts) != 3 or not CAA_TAG.match(parts[1].lower()):
            raise ValueError('a CAA record is flags, a tag and a value: 0 issue "letsencrypt.org"')
        flags, tag, rest = number(parts[0], "CAA flags", 255), parts[1].lower(), parts[2].strip()
        return f"{flags} {tag} {rest if rest.startswith(chr(34)) else quoted(rest)}"
    if rtype == "TXT":
        return v if v.startswith('"') and v.endswith('"') and len(v) >= 2 else quoted(v)
    raise ValueError(f"{rtype!r} is no record type here: {', '.join(TYPES)}")


def same_value(rtype: str, a: str, b: str) -> bool:
    """Whether two values of a record set of `rtype` are the same value."""
    def norm(v: str) -> str:
        v = " ".join(str(v or "").split())
        try:
            return value_for(rtype, v) if rtype in TYPES else v
        except ValueError:
            return v.lower() if rtype in NAMED else v
    return norm(a) == norm(b)


def record_type(value: str) -> str:
    t = str(value or "").strip().upper()
    if t not in TYPES:
        raise ValueError(f"{value!r} is no record type here: {', '.join(TYPES)}")
    return t


def ttl_of(value) -> int:
    try:
        t = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"the TTL is a number of seconds, {TTL_MIN} to {TTL_MAX}") from None
    if not TTL_MIN <= t <= TTL_MAX:
        raise ValueError(f"the TTL is {TTL_MIN} to {TTL_MAX} seconds")
    return t


def as_sent(rrset: Mapping) -> dict:
    """A record set as a change names it: the fields that make it, exactly as read."""
    return {k: rrset[k] for k in ("name", "type", "ttl", "rrdatas", "signatureRrdatas") if k in rrset}


def said(name: str, rtype: str, values: Sequence[str]) -> str:
    shown = ", ".join(v if len(v) <= 60 else v[:59] + "…" for v in values)
    return f"{undot(name)} {rtype} {shown}"


def check_name(zone: Mapping, full: str, rtype: str, at_name: Sequence[Mapping], removing: bool = False) -> Mapping | None:
    """The record set of `rtype` at `full` among `at_name` (the name's record sets, read afresh), after the refusals:
    the zone's own records, a routing policy, a CNAME beside others."""
    origin = dot(zone.get("dnsName") or "")
    why = unwritable(zone)
    if why:
        raise Refusal(f"{undot(origin)} is {why}")
    at_name = [r for r in at_name if dot(r.get("name") or "") == full]
    if rtype in DNSSEC or (full == origin and rtype in APEX):
        raise Refusal(f"the {rtype} record of {undot(full)} is the zone's own: not changed here")
    mine = next((r for r in at_name if str(r.get("type", "")).upper() == rtype), None)
    if mine is not None and mine.get("routingPolicy"):
        raise Refusal(f"{undot(full)} {rtype} has a routing policy (geo or weighted): changed in the console")
    if not removing:
        others = sorted({str(r.get("type", "")).upper() for r in at_name} - {rtype})
        if rtype == "CNAME" and full == origin:
            raise Refusal(f"a CNAME cannot stand for the zone's own name ({undot(origin)}): it holds the SOA and NS")
        if rtype == "CNAME" and others:
            raise Refusal(f"{undot(full)} holds other records ({', '.join(others)}): a CNAME stands alone")
        if rtype != "CNAME" and "CNAME" in others:
            raise Refusal(f"{undot(full)} is a CNAME: it holds no {rtype} record beside it")
    return mine


def plan_set(zone: Mapping, name: str, rtype: str, data: str, ttl=None,
             at_name: Sequence[Mapping] = ()) -> tuple[list[dict], list[dict], str]:
    """The change setting a record: (additions, deletions, what it does in words). An A, AAAA or CNAME replaces the
    name's record set of its type; a TXT, MX, CAA, SRV or NS value is added beside the set's others. Nothing to do:
    ([], [], words)."""
    t = record_type(rtype)
    full = fqdn(name, zone)
    value = value_for(t, data)
    mine = check_name(zone, full, t, at_name)
    new_ttl = ttl_of(ttl) if ttl not in (None, "") else int(mine.get("ttl") or TTL_DEFAULT) if mine else TTL_DEFAULT
    held = [str(v) for v in (mine.get("rrdatas") or [])] if mine else []
    if t in SINGLE:
        values = [value]
    else:
        values = held + ([] if any(same_value(t, h, value) for h in held) else [value])
    if mine and held == values and int(mine.get("ttl") or 0) == new_ttl:
        return [], [], f"{said(full, t, [value])} is there already: nothing written"
    addition = {"name": full, "type": t, "ttl": new_ttl, "rrdatas": values}
    deletions = [as_sent(mine)] if mine else []
    if not mine:
        words = f"added {said(full, t, [value])}"
    elif t in SINGLE and held != values:
        words = f"set {said(full, t, [value])} (it was {', '.join(held) or 'empty'})"
    elif held != values:
        words = f"added {said(full, t, [value])} beside {len(held)} other value{'s' if len(held) != 1 else ''}"
    else:
        words = f"{said(full, t, [value])}: TTL {new_ttl}"
    return [addition], deletions, words


def plan_remove(zone: Mapping, name: str, rtype: str, data: str,
                at_name: Sequence[Mapping] = ()) -> tuple[list[dict], list[dict], str]:
    """The change removing one value of a record set (the whole set when it is its last): (additions, deletions, words)."""
    t = str(rtype or "").strip().upper()
    full = fqdn(name, zone)
    mine = check_name(zone, full, t, at_name, removing=True)
    if not re.match(r"^[A-Z0-9]{1,10}$", t):
        raise ValueError(f"{rtype!r} is no record type")
    if mine is None:
        raise Refusal(f"{undot(zone.get('dnsName') or '')} has no {t} record at {undot(full)}")
    held = [str(v) for v in mine.get("rrdatas") or []]
    rest = [h for h in held if not same_value(t, h, data)]
    if len(rest) == len(held):
        raise Refusal(f"{undot(full)} {t} holds no {str(data).strip()[:80]!r}: nothing removed")
    gone = [h for h in held if h not in rest]
    additions = [{"name": full, "type": t, "ttl": int(mine.get("ttl") or TTL_DEFAULT), "rrdatas": rest}] if rest else []
    words = f"removed {said(full, t, gone)}" + (f" ({len(rest)} other value{'s' if len(rest) != 1 else ''} kept)" if rest else "")
    return additions, [as_sent(mine)], words


def rows_of(rrsets: Sequence[Mapping]) -> list[tuple[str, str, int, str, bool]]:
    """A zone's record sets as rows, one a value: (name, type, ttl, value, routing policy), the apex first."""
    out = []
    for r in rrsets:
        values = [str(v) for v in r.get("rrdatas") or []] or (["(a routing policy)"] if r.get("routingPolicy") else [""])
        for v in values:
            out.append((str(r.get("name") or ""), str(r.get("type") or ""), int(r.get("ttl") or 0), v, bool(r.get("routingPolicy"))))
    return out
