"""Dynamic DNS through Cloud DNS (the library's ddns.Keeper): hosts of the project's public zones kept at this network's
public IPv4 address, each host's A record read through the API and set with one change (its old record set deleted
exactly as read) only when it differs; hosts in no public zone said. Over the stand-ins (this network's address too)."""
from __future__ import annotations

import pytest

from conftest import HOME, PROJECT, settings_of
from plugin_platform_googlecloud import PUBLIC_IPV4

D = f"/dns/v1/projects/{PROJECT}/managedZones"


def test_the_public_address_is_asked_of_the_name_servers_the_plugin_names():
    assert PUBLIC_IPV4 == (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
                           ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))


def test_a_pass_sets_only_the_hosts_that_differ_with_one_change_each(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com, @.example.com db.corp.internal; other.org",
                    GOOGLECLOUD_DDNS_MINUTES="10"))
    p, fake = made()
    p.refresh()
    st = p.status()
    assert st["tables"][0]["title"] == "Dynamic DNS" and st["ddnsEvery"] == "every 10 min, once attached"
    assert [r[0] for r in st["tables"][0]["rows"]] == ["home.example.com", "example.com"]
    assert "db.corp.internal is in none of the account's domains (its public Cloud DNS zones)" in st["problem"]
    assert "other.org is in none of the account's domains" in st["problem"]
    assert [a["hook"] for a in st["actions"]] == ["refresh", "ddns_update"]
    fake.requests.clear()
    out = p.ddns_update(force=False)
    assert [(h["host"], h["result"], h["ok"]) for h in out] == [("home.example.com", "made (was none)", True),
                                                               ("example.com", "set (was 198.51.100.7)", True)]
    posts = [r for r in fake.requests if r["method"] == "POST"]
    assert [r["path"] for r in posts] == [f"{D}/example-com/changes"] * 2
    assert posts[0]["body"] == {"additions": [
        {"name": "home.example.com.", "type": "A", "ttl": 300, "rrdatas": [HOME]}],
        "deletions": []}
    assert posts[1]["body"]["deletions"] == [{"name": "example.com.", "type": "A", "ttl": 300, "rrdatas": ["198.51.100.7"]}]
    assert posts[1]["body"]["additions"][0]["rrdatas"] == [HOME] and posts[1]["body"]["additions"][0]["ttl"] == 300
    reads = [r["query"] for r in fake.requests if r["method"] == "GET"]
    assert {"name": "home.example.com.", "type": "A"} in reads and {"name": "example.com.", "type": "A"} in reads
    others = {(s["name"], s["type"]) for s in fake.rrsets["example-com"]}
    assert {("example.com.", "TXT"), ("example.com.", "MX"), ("www.example.com.", "CNAME")} <= others  # kept
    fake.requests.clear()
    assert [h["result"] for h in p.ddns_update(force=False)] == ["current", "current"]
    assert [r["method"] for r in fake.requests] == ["GET", "GET"]  # read, nothing written
    fake.requests.clear()
    assert [h["result"] for h in p.ddns_update(force=True)] == ["current", "current"]  # Update DNS now: nothing to change
    assert all(r["method"] == "GET" for r in fake.requests)
    table = p.status()["tables"][0]
    assert [r[:2] for r in table["rows"]] == [["home.example.com", HOME], ["example.com", HOME]]
    assert table["note"] == f"every 10 min, once attached · this network's address: {HOME}"


def test_without_this_networks_address_nothing_is_written(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com"))
    p, fake = made(public=(None, "neither OpenDNS nor Google answered"))
    p.refresh()
    fake.requests.clear()
    (host,) = p.ddns_update()
    assert host["ok"] is False and host["result"] == ("this network's address was not found: neither OpenDNS nor Google "
                                                      "answered") and fake.requests == []


def test_a_cname_host_is_never_written_over(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="www.example.com"))
    p, fake = made()
    p.refresh()
    (host,) = p.ddns_update()
    assert host["ok"] is False and host["result"].startswith("not updated: www.example.com is a CNAME")
    assert not any(r["method"] == "POST" for r in fake.requests if r["path"] != "/token")


def test_dynamic_dns_not_set_says_what_to_set(made, env):
    env(settings_of())
    p, _ = made()
    with pytest.raises(ValueError, match="Dynamic DNS is not set up: GOOGLECLOUD_DDNS_HOSTS is not set"):
        p.ddns_update()
