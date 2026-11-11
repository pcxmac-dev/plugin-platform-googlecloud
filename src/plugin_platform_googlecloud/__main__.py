"""`python -m plugin_platform_googlecloud ...`: the plugin from the command line, its settings read from the environment
(an EnvironmentLogin: the variables as this shell has them).

    status                              the project read, then the plugin's status (JSON)
    servers                             the servers of every zone
    domains                             the Cloud DNS zones
    records ZONE                        a zone's records (ZONE: its name or its DNS name)
    ddns [--now]                        a Dynamic DNS pass: a host's record set where it differs (--now: every host)
    firewalls                           the VPC firewall rules and the servers each reaches
    keys                                the project-wide SSH keys
    power NAME on|off|reboot            a server started, stopped, or reset (hard: asked twice), each asked "yes" first
    set ZONE NAME TYPE DATA [--ttl N]   a record set (every other record kept), asked "yes" first
    remove ZONE NAME TYPE DATA          a record's value removed, asked "yes" first

--json prints the answer as JSON. Firewall rules and SSH keys are changed from the platform's page."""
from __future__ import annotations

import argparse
import json
import sys

from liminal_libs.machines.rest import RestError

from . import ACCEPT_RESET, MACHINE, STATES, when


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m plugin_platform_googlecloud",
                                description="Google Cloud for Liminal: servers, Cloud DNS, firewall rules, SSH keys, Dynamic DNS")
    p.add_argument("--json", action="store_true", help="print the answer as JSON")
    sub = p.add_subparsers(dest="what")
    sub.add_parser("status", help="the project read, then the plugin's status")
    sub.add_parser("servers", help="the servers of every zone")
    sub.add_parser("domains", help="the Cloud DNS zones")
    r = sub.add_parser("records", help="a zone's records")
    r.add_argument("zone")
    d = sub.add_parser("ddns", help="a Dynamic DNS pass")
    d.add_argument("--now", action="store_true", help="every host's record set, whether it differs or not")
    sub.add_parser("firewalls", help="the VPC firewall rules")
    sub.add_parser("keys", help="the project-wide SSH keys")
    w = sub.add_parser("power", help="a server started, stopped or reset")
    w.add_argument("name")
    w.add_argument("to", choices=("on", "off", "reboot"))
    s = sub.add_parser("set", help="a record set, every other record kept")
    for a in ("zone", "name", "type", "data"):
        s.add_argument(a)
    s.add_argument("--ttl", type=int)
    m = sub.add_parser("remove", help="a record's value removed")
    for a in ("zone", "name", "type", "data"):
        m.add_argument(a)
    return p


def confirmed(question: str, ask, say) -> bool:
    say(question)
    try:
        answer = ask("Type yes to go on: ")
    except EOFError:
        return False
    return str(answer or "").strip().lower() == "yes"


def main(argv: list[str] | None = None, plugin=None, out=None, err=None, ask=None) -> int:
    p = plugin if plugin is not None else MACHINE
    say = out or (lambda s: print(s))
    tell = err or (lambda s: print(s, file=sys.stderr))
    ask = ask or input
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    what = args.what or "status"
    try:
        if what == "status":
            if p.config().ready:
                try:
                    p.refresh()
                except RestError:
                    pass  # the status says it
            say(json.dumps(p.status(), indent=1))
            return 0
        if what in ("servers", "firewalls", "keys", "power"):
            p.refresh()
        if what == "servers":
            answer = p.servers()
            lines = [f"{s['name']:<28} {s['zone']:<18} {STATES.get(str(s['status']), str(s['status'])):<10} "
                     f"{s['machineType']:<16} {', '.join(s['ipv4']) or '–'}" for s in answer] or ["no servers in the project"]
        elif what == "domains":
            answer = p.domains()
            lines = [f"{z['dnsName']:<36} {z['name']:<24} {z['visibility']:<8} DNSSEC {z['dnssec']}" for z in answer] \
                or ["no Cloud DNS zones in the project"]
        elif what == "records":
            answer = p.records(args.zone)
            lines = [f"{r['name']:<40} {r['type']:<6} {r['ttl']:>6}  {r['data']}" for r in answer] or ["no records"]
        elif what == "ddns":
            answer = p.ddns_update(force=args.now)
            lines = [f"{h['host']:<36} {h['address'] or '–':<16} {h['result']} (checked {when(h['checkedAt'])})" for h in answer] \
                or ["no host is in a public Cloud DNS zone of the project"]
        elif what == "firewalls":
            answer = p.firewalls()
            lines = [f"{r['name']:<32} {r['rule']}" + (" [off]" if r["disabled"] else "")
                     + (f"\n{'':<32} reaches {', '.join(r['reaches'])}" if r["reaches"] else "") for r in answer] \
                or ["no firewall rules"]
        elif what == "keys":
            answer = p.ssh_keys()
            lines = [f"{k['user']:<20} {k['type']:<20} {k['fingerprint']}  {k['comment']}" for k in answer] \
                or ["no project-wide SSH keys"]
        elif what == "power":
            found = [s for s in p.servers() if s["name"] == args.name]
            if len(found) != 1:
                tell(f"refused: {'no server' if not found else 'several servers'} named {args.name} in the project")
                return 1
            zone = found[0]["zone"]
            if args.to == "on":
                if not confirmed(f"{args.name} is started: its vCPUs and memory bill again while it runs.", ask, say):
                    tell("not asked: no yes")
                    return 1
                answer = p.start_server(zone, args.name)
            elif args.to == "off":
                if not confirmed(f"{args.name} is shut down (up to 120 seconds for its guest); its disks and static "
                                 "addresses keep billing, an ephemeral address is let go.", ask, say):
                    tell("not asked: no yes")
                    return 1
                answer = p.stop_server(zone, args.name)
            else:
                if not confirmed(f"{args.name} is reset: a hard reset, no shutdown of its guest.", ask, say) or not confirmed(
                        "Again: unsaved data is lost and its disks' file systems may be corrupted.", ask, say):
                    tell("not asked: no yes")
                    return 1
                answer = p.reset_server(zone, args.name, **{ACCEPT_RESET: True})
            lines = [answer["said"], *(f"  {x}" for x in answer.get("lines") or [])]
        elif what in ("set", "remove"):
            verb = "set in" if what == "set" else "removed from"
            if not confirmed(f"{args.name} {args.type.upper()} {args.data} is {verb} {args.zone}; every other record kept.",
                             ask, say):
                tell("not asked: no yes")
                return 1
            answer = (p.set_record(args.zone, args.name, args.type, args.data, ttl=args.ttl) if what == "set"
                      else p.remove_record(args.zone, args.name, args.type, args.data))
            lines = [answer["said"], *(f"  {x}" for x in answer.get("lines") or [])]
        else:
            return 2
    except RestError as e:
        tell(f"googlecloud: {e}")
        return 1
    except (ValueError, RuntimeError, LookupError) as e:  # a refusal, a setting not set, a pass under way
        tell(f"refused: {e}")
        return 1
    if args.json:
        say(json.dumps(answer, indent=1))
    else:
        for line in lines:
            say(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
