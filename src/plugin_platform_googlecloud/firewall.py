"""VPC firewall rules as Compute Engine's API gives them (https://docs.cloud.google.com/compute/docs/reference/rest/v1/
firewalls and Google's overview of firewall rules, read 2026-11-11): a rule of a network, ingress or egress, allowing or
denying protocols and ports from source ranges (to destination ranges), applied to the network's servers with its target
tags or service accounts, or to every server of the network when it names none; the lower priority wins; a network
denies ingress and allows egress unless a rule says otherwise. The rules cost nothing (their logging would: it stays
off here).

What a rule reaches is worked out from the servers read (their network interfaces, network tags and service accounts).
A change is risky, and asked twice (an audit before any key went in, 2026-11-11, widened it):
- adding a rule that denies SSH (it may lock you out), or one letting anything in from the whole internet (0.0.0.0/0
  or ::/0) but the web's ports 80 and 443: SSH, RDP, Docker's API, SSH moved to 2222, any other port, every port, ping;
- removing the rule that lets SSH or RDP in to a server it reaches, or one denying ingress to such a server."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence

from .api import name_of

NAME = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$")  # a rule's, a network's and a network tag's name
PROTOCOLS = {"tcp": "TCP (ports)", "udp": "UDP (ports)", "icmp": "ICMP (ping)"}  # offered by the page's form
PORTED = frozenset({"tcp", "udp", "sctp"})
SSH = 22
WEB = frozenset({80, 443})  # the ports let in from the whole internet on one confirmation: a website's alone
REMOTE = ((22, "SSH"), (3389, "RDP"))  # the ways in to a server: the rule letting them in is asked twice to remove
KNOWN = {22: "SSH", 23: "Telnet", 445: "SMB", 2222: "SSH, moved", 2375: "Docker's API, unauthenticated",
         2376: "Docker's API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
         5986: "WinRM", 6379: "Redis", 9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB"}  # named in words
PRIORITY_DEFAULT = 1000
RANGES_MOST = 64  # ranges taken by one rule here


def network_of(rule_or_nic: Mapping) -> str:
    return name_of(rule_or_nic.get("network"))


def proto_of(entry: Mapping) -> str:
    return str(entry.get("IPProtocol") or "").strip().lower()


def direction_of(rule: Mapping) -> str:
    return str(rule.get("direction") or "INGRESS").upper()


def what(entries: Sequence[Mapping]) -> str:
    """A rule's protocols and ports in words: tcp:22,80 · udp · icmp; every protocol."""
    out = []
    for e in entries or []:
        p = proto_of(e)
        ports = [str(x) for x in e.get("ports") or []]
        if p == "all":
            out.append("every protocol")
        else:
            out.append(f"{p}:{','.join(ports)}" if ports else f"{p} (every port)" if p in PORTED else p)
    return " · ".join(out) or "nothing"


def action_of(rule: Mapping) -> str:
    return "deny" if rule.get("denied") else "allow"


def entries_of(rule: Mapping) -> list[Mapping]:
    return list(rule.get("denied") or rule.get("allowed") or [])


def ranges_of(rule: Mapping) -> list[str]:
    key = "destinationRanges" if direction_of(rule) == "EGRESS" else "sourceRanges"
    return [str(r) for r in rule.get(key) or []]


def covers(entries: Sequence[Mapping], protocol: str, port: int | None) -> bool:
    """Whether the rule's protocols and ports take `protocol` (and `port`, when given)."""
    for e in entries or []:
        p = proto_of(e)
        if p == "all":
            return True
        if p != protocol:
            continue
        ports = e.get("ports") or []
        if not ports or port is None:
            return True
        for x in ports:
            lo, _, hi = str(x).partition("-")
            try:
                if int(lo) <= port <= int(hi or lo):
                    return True
            except ValueError:
                continue
    return False


def web_only(entries: Sequence[Mapping]) -> bool:
    """Whether a rule takes the web's ports alone: 80 and 443 of tcp or udp, each named (no range, no other port)."""
    if not entries:
        return False
    for e in entries:
        if proto_of(e) not in ("tcp", "udp") or not e.get("ports"):
            return False
        for x in e.get("ports") or []:
            lo, _, hi = str(x).partition("-")
            try:
                low, high = int(lo), int(hi or lo)
            except ValueError:
                return False
            if low != high or low not in WEB:
                return False
    return True


def from_everywhere(rule: Mapping) -> bool:
    """An ingress rule whose sources are the whole internet (a range of /0, or no source at all: Google then takes
    0.0.0.0/0)."""
    if direction_of(rule) != "INGRESS":
        return False
    ranges = ranges_of(rule)
    if not ranges and not rule.get("sourceTags") and not rule.get("sourceServiceAccounts"):
        return True
    return any(_is_everywhere(r) for r in ranges)


def _is_everywhere(r: str) -> bool:
    try:
        return ipaddress.ip_network(r, strict=False).prefixlen == 0
    except ValueError:
        return False


def targets(rule: Mapping) -> str:
    tags, accounts = rule.get("targetTags") or [], rule.get("targetServiceAccounts") or []
    if tags:
        return "tags " + ", ".join(tags)
    if accounts:
        return "service accounts " + ", ".join(accounts)
    return f"every server of {network_of(rule)}"


def reaches(rule: Mapping, instances: Iterable[Mapping]) -> list[str]:
    """The servers (of those read) the rule applies to, by name: on its network, with one of its target tags or
    service accounts, or every one of the network when it names none."""
    net = network_of(rule)
    tags, accounts = set(rule.get("targetTags") or []), set(rule.get("targetServiceAccounts") or [])
    out = []
    for inst in instances:
        nets = {network_of(nic) for nic in inst.get("networkInterfaces") or []}
        if net not in nets:
            continue
        mine_tags = set((inst.get("tags") or {}).get("items") or [])
        mine_accounts = {str(a.get("email") or "") for a in inst.get("serviceAccounts") or []}
        if (not tags and not accounts) or (tags & mine_tags) or (accounts & mine_accounts):
            out.append(str(inst.get("name") or ""))
    return sorted(out)


def remote_ways(rule: Mapping) -> list[str]:
    """The ways in to a server a rule's protocols and ports take, in words: SSH (tcp:22), RDP (tcp:3389)."""
    entries = entries_of(rule)
    return [f"{label} (tcp:{port})" for port, label in REMOTE if covers(entries, "tcp", port)]


def opened(entries: Sequence[Mapping]) -> str:
    """What a rule's protocols and ports take, in words, the well-known services named: tcp:3389 (RDP), tcp:2222 (SSH,
    moved), every port of udp, icmp."""
    parts = []
    for e in entries or []:
        p = proto_of(e)
        if p == "all":
            parts.append("every protocol")
            continue
        if p not in PORTED:
            parts.append(p)
            continue
        ports = [str(x) for x in e.get("ports") or []]
        if not ports:
            parts.append(f"every port of {p}" + (" (SSH and RDP among them)" if p == "tcp" else ""))
            continue
        named = []
        for x in ports:
            label = KNOWN.get(int(x)) if x.isdigit() else None
            named.append(f"{p}:{x}" + (f" ({label})" if label else ""))
        parts.append(", ".join(named))
    return " and ".join(parts) or "nothing"


def _servers(rule: Mapping, instances: Sequence[Mapping]) -> str:
    reached = reaches(rule, instances)
    shown = ", ".join(reached[:6]) + (f" and {len(reached) - 6} more" if len(reached) > 6 else "")
    return targets(rule) + (f" ({shown})" if reached else "")


def risky_addition(rule: Mapping, instances: Sequence[Mapping] = ()) -> str | None:
    """Why adding the rule is risky, in words (asked twice), or None (module docstring): a deny taking SSH, or an
    allow letting in from the whole internet anything but the web's ports 80 and 443."""
    entries = entries_of(rule)
    on = _servers(rule, instances)
    if action_of(rule) == "deny":
        if not covers(entries, "tcp", SSH):
            return None
        if direction_of(rule) == "INGRESS":
            return (f"it denies {opened(entries)} in from {', '.join(ranges_of(rule)) or '0.0.0.0/0'} to {on}: you may "
                    "lock yourself out of them (SSH)")
        return (f"it denies {opened(entries)} out of {on} to {', '.join(ranges_of(rule)) or 'anywhere'}: they can no "
                "longer reach other servers by SSH")
    if not from_everywhere(rule) or web_only(entries):
        return None
    everywhere = ", ".join(r for r in ranges_of(rule) if _is_everywhere(r)) or "0.0.0.0/0"
    return f"it lets {opened(entries)} in from the whole internet ({everywhere}) to {on}"


def risky_removal(rule: Mapping, instances: Sequence[Mapping]) -> str | None:
    """Why removing the rule is risky, in words (asked twice), or None: it lets SSH or RDP in to a server it reaches
    (removed, you may be locked out of it), or it denies ingress to one (removed, what it kept out may come in)."""
    if rule.get("disabled") or direction_of(rule) != "INGRESS":
        return None
    servers = reaches(rule, instances)
    if not servers:
        return None
    shown = ", ".join(servers[:6]) + (f" and {len(servers) - 6} more" if len(servers) > 6 else "")
    ways = remote_ways(rule)
    if action_of(rule) == "allow" and ways:
        return (f"{rule.get('name')} lets {' and '.join(ways)} in to {shown}: removing it may lock you out of "
                f"{'them' if len(servers) > 1 else 'it'} unless another rule lets {'them' if len(ways) > 1 else 'it'} in")
    if action_of(rule) == "deny":
        return (f"{rule.get('name')} denies {what(entries_of(rule))} from {', '.join(ranges_of(rule)) or 'its sources'} to "
                f"{shown}: removing it may let that in")
    return None


def parse_ports(text: str | None, protocol: str) -> list[str]:
    parts = [p for p in re.split(r"[,\s]+", str(text or "").strip()) if p]
    if not parts:
        return []
    if protocol not in PORTED:
        raise ValueError(f"{protocol} has no ports: leave them empty")
    out = []
    for p in parts:
        m = re.match(r"^(\d{1,5})(?:-(\d{1,5}))?$", p)
        if not m:
            raise ValueError(f"{p!r} is not a port or a range of ports (22, 8000-8100)")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not 0 <= lo <= hi <= 65535:
            raise ValueError(f"{p!r}: ports are 0 to 65535, the lower first")
        out.append(str(lo) if lo == hi else f"{lo}-{hi}")
    return out


def parse_ranges(text: str | None) -> list[str]:
    parts = [p for p in re.split(r"[,\s]+", str(text or "").strip()) if p]
    if not parts:
        raise ValueError("no addresses given: the ranges the rule takes (203.0.113.7/32, 198.51.100.0/24, 0.0.0.0/0)")
    if len(parts) > RANGES_MOST:
        raise ValueError(f"at most {RANGES_MOST} ranges a rule here")
    out = []
    for p in parts:
        try:
            out.append(str(ipaddress.ip_network(p, strict=False)))
        except ValueError:
            raise ValueError(f"{p!r} is not an address or a range (CIDR: 203.0.113.0/24)") from None
    return list(dict.fromkeys(out))


def parse_tags(text: str | None) -> list[str]:
    tags = [t for t in re.split(r"[,\s]+", str(text or "").strip().lower()) if t]
    for t in tags:
        if not NAME.match(t):
            raise ValueError(f"{t!r} is not a network tag (lowercase letters, digits and dashes, a letter first)")
    return list(dict.fromkeys(tags))


def build(name: str, network: str, direction: str, action: str, protocol: str, ports, ranges, target_tags,
          priority, description) -> dict:
    """A rule's body as firewalls.insert takes it, every field checked; ValueError in words otherwise. Its logging is
    left off (it would cost)."""
    n = str(name or "").strip().lower()
    if not NAME.match(n):
        raise ValueError(f"{str(name).strip()!r} is not a rule's name: 1 to 63 lowercase letters, digits and dashes, a letter first")
    net = str(network or "default").strip().lower()
    if not NAME.match(net):
        raise ValueError(f"{net!r} is not a network's name")
    d = str(direction or "INGRESS").strip().upper()
    if d not in ("INGRESS", "EGRESS"):
        raise ValueError("the direction is INGRESS (in) or EGRESS (out)")
    a = str(action or "allow").strip().lower()
    if a not in ("allow", "deny"):
        raise ValueError("the action is allow or deny")
    p = str(protocol or "tcp").strip().lower()
    if p not in PROTOCOLS:
        raise ValueError(f"the protocol is one of {', '.join(PROTOCOLS)}")
    try:
        prio = PRIORITY_DEFAULT if priority in (None, "") else int(priority)
    except (TypeError, ValueError):
        raise ValueError("the priority is a number, 0 to 65535") from None
    if not 0 <= prio <= 65535:
        raise ValueError("the priority is 0 (first) to 65535 (last)")
    text = " ".join(str(description or "").split())
    if len(text) > 2048:
        raise ValueError("a description is at most 2,048 characters")
    entry = {"IPProtocol": p}
    port_list = parse_ports(ports, p)
    if port_list:
        entry["ports"] = port_list
    body = {"name": n, "network": f"global/networks/{net}", "direction": d, "priority": prio,
            ("allowed" if a == "allow" else "denied"): [entry],
            ("sourceRanges" if d == "INGRESS" else "destinationRanges"): parse_ranges(ranges)}
    tags = parse_tags(target_tags)
    if tags:
        body["targetTags"] = tags
    if text:
        body["description"] = text
    return body


def describe(rule: Mapping) -> str:
    """A rule in one line: allow tcp:22 in from 0.0.0.0/0 to every server of default, priority 1000."""
    d = direction_of(rule)
    ranges = ", ".join(ranges_of(rule)) or ("its source tags" if rule.get("sourceTags")
                                            else "0.0.0.0/0" if d == "INGRESS" else "anywhere")
    return (f"{action_of(rule)} {what(entries_of(rule))} {'in from' if d == 'INGRESS' else 'out to'} {ranges} "
            f"on {targets(rule)}, priority {rule.get('priority', PRIORITY_DEFAULT)}")
