"""`python -m plugin_platform_googlecloud ...` over the stand-ins: the reads print, each change asks "yes" on the
terminal first (a reset twice) and sends nothing without it."""
from __future__ import annotations

import json

from conftest import HOME, PROJECT, settings_of
from plugin_platform_googlecloud.__main__ import main

C = f"/compute/v1/projects/{PROJECT}"


def run(p, *argv, answers=()):
    out, err, asked = [], [], list(answers)
    code = main(list(argv), plugin=p, out=out.append, err=err.append, ask=lambda prompt: asked.pop(0) if asked else "")
    return code, out, err


def test_the_reads_print(made, env):
    env(settings_of())
    p, fake = made()
    code, out, _ = run(p, "servers")
    assert code == 0 and len(out) == 3 and out[0].split()[:4] == ["web-1", "us-central1-a", "running", "e2-micro"]
    code, out, _ = run(p, "--json", "domains")
    assert code == 0 and [z["dnsName"] for z in json.loads(out[0])] == ["example.com.", "corp.internal."]
    code, out, _ = run(p, "records", "example.com")
    assert code == 0 and out[0].split()[:4] == ["example.com.", "A", "300", "198.51.100.7"]
    code, out, _ = run(p, "firewalls")
    assert code == 0 and any(line.startswith("default-allow-ssh") for line in out)
    code, out, _ = run(p, "keys")
    assert code == 0 and [line.split()[0] for line in out] == ["alice", "bob"]
    code, out, _ = run(p, "status")
    assert code == 0 and json.loads("\n".join(out))["valid"] is True
    assert fake.writes() == []


def test_a_change_asks_yes_first_and_a_reset_twice(made, env):
    env(settings_of())
    p, fake = made()
    code, out, err = run(p, "power", "web-1", "off", answers=["no"])
    assert code == 1 and err == ["not asked: no yes"] and fake.writes() == []
    assert "keep billing" in out[0]
    code, out, _ = run(p, "power", "web-1", "off", answers=["yes"])
    assert code == 0 and out[1] == "asked Google to stop web-1"
    assert fake.writes()[-1]["path"] == f"{C}/zones/us-central1-a/instances/web-1/stop"
    fake.instances[("us-central1-a", "web-1")]["status"] = "RUNNING"
    code, _, err = run(p, "power", "web-1", "reboot", answers=["yes", "no"])
    assert code == 1 and len(fake.writes()) == 1
    code, out, _ = run(p, "power", "web-1", "reboot", answers=["yes", "yes"])
    assert code == 0 and fake.writes()[-1]["path"].endswith("/web-1/reset")
    code, _, err = run(p, "power", "nobody", "on", answers=["yes"])
    assert code == 1 and err == ["refused: no server named nobody in the project"]
    code, out, _ = run(p, "set", "example-com", "home", "A", HOME, "--ttl", "120", answers=["yes"])
    assert code == 0 and out[1] == f"added home.example.com A {HOME}"
    assert fake.writes()[-1]["body"]["additions"][0]["ttl"] == 120
    code, out, _ = run(p, "remove", "example.com", "home", "A", HOME, answers=["yes"])
    assert code == 0 and out[1] == f"removed home.example.com A {HOME}"
    code, _, err = run(p, "set", "example-com", "www", "A", HOME, answers=["yes"])
    assert code == 1 and err[0].startswith("refused: www.example.com is a CNAME")
