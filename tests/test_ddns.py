"""Dynamic DNS through Cloud DNS (the library's ddns.Keeper, 1.49.2): hosts of the project's public zones kept at this
network's public IPv4 address, changing only what is the keeper's own (a host with no A record, one already pointing
here, one it set before, one the user took over); a host holding another address, or several, is left as it is, its
row offering Take over…; each write one change, its old record set deleted exactly as read. Over the stand-ins (this
network's address too)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from conftest import HOME, PROJECT, FakeGoogle, Platform, settings_of
from liminal_libs.machines.ddns import TakeOverRefused
from plugin_platform_googlecloud import PUBLIC_IPV4, GoogleCloudPlugin

D = f"/dns/v1/projects/{PROJECT}/managedZones"
NEW = "93.184.216.80"  # this network's address after it changed


def changes(fake) -> list[dict]:
    return [r["body"] for r in fake.requests if r["method"] == "POST" and r["path"].endswith("/changes")]


def a_record(fake, name: str) -> list[str] | None:
    return next((s["rrdatas"] for s in fake.rrsets["example-com"] if s["name"] == name and s["type"] == "A"), None)


def table(p) -> dict:
    return next(t for t in p.status()["tables"] if t["title"] == "Dynamic DNS")


def test_the_public_address_is_asked_of_the_name_servers_the_plugin_names():
    assert PUBLIC_IPV4 == (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
                           ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))


def test_a_host_holding_another_address_is_left_as_it_is_and_a_new_one_made(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com, @.example.com db.corp.internal; other.org",
                    GOOGLECLOUD_DDNS_MINUTES="10"))
    p, fake = made()
    p.refresh()
    st = p.status()
    assert st["tables"][0]["title"] == "Dynamic DNS" and st["ddnsEvery"] == "every 10 min, once attached"
    assert [r[0] for r in st["tables"][0]["rows"]] == ["home.example.com", "example.com"]
    assert "db.corp.internal is in none of the account's domains (its public Cloud DNS zones)" in st["problem"]
    assert "other.org is in none of the account's domains" in st["problem"]
    assert {"form": "ddns-now", "title": "Update DNS now",
            "note": "each Dynamic DNS host that is its own set now to this network's address"} in st["actions"]
    assert not any(a.get("hook") == "ddns_update" for a in st["actions"])  # Update DNS now is confirmed first
    forms = {f["id"]: f for f in st["forms"]}
    assert forms["ddns-now"]["hook"] == "ddns_update" and forms["ddns-now"]["confirm"]["yes"] == "Update now"
    assert forms["ddns-take"]["hook"] == "ddns_take_over" and forms["ddns-take"]["confirm"]["danger"] is True
    fake.requests.clear()
    out = p.ddns_update(force=False)
    hosts = {h["host"]: h for h in out["hosts"]}
    assert hosts["home.example.com"]["result"] == "made (was none)" and hosts["home.example.com"]["ok"] is True
    apex = hosts["example.com"]  # the website's own address: never pointed at home unasked
    assert apex["foreign"] is True and apex["holds"] == ["198.51.100.7"]
    assert apex["result"] == "holds 198.51.100.7, not this network's address: left as it is (Take over… to point it here)"
    assert out["said"] == "Dynamic DNS: 2 hosts checked, 1 left as it is" and out["ok"] is True
    (made_it,) = changes(fake)
    assert made_it == {"additions": [{"name": "home.example.com.", "type": "A", "ttl": 300, "rrdatas": [HOME]}],
                       "deletions": []}
    assert a_record(fake, "example.com.") == ["198.51.100.7"]
    rows = {r[0]: r for r in table(p)["rows"]}
    assert rows["example.com"][1] == "198.51.100.7" and rows["example.com"][-1] == {
        "form": "ddns-take", "title": "Take over…", "label": "Take over example.com",
        "values": {"host": "example.com", "holds": "198.51.100.7"}}
    assert rows["home.example.com"][-1] == ""  # its own: nothing to take over
    fake.requests.clear()
    assert [h["result"] for h in p.ddns_update(force=False)["hosts"]][0] == "current"
    assert changes(fake) == []
    state = json.loads((Path(os.environ["LIMINAL_PLATFORM_DIR"]) / "googlecloud" / "ddns.json").read_text(encoding="utf-8"))
    assert state == {"own": {"home.example.com": HOME}, "taken": {}}  # kept under the platform's folder


def test_taking_a_host_over_is_asked_twice_then_a_pass_points_it_here(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="@.example.com"))
    p, fake = made()
    p.refresh()
    p.ddns_update(force=False)
    assert changes(fake) == []
    take = next(f for f in p.status()["forms"] if f["id"] == "ddns-take")
    assert [x["name"] for x in take["fields"]] == ["host", "holds", "accept_take_over"]
    assert take["fields"][2]["type"] == "accept"
    with pytest.raises(TakeOverRefused) as refused:  # the page's first yes alone: nothing taken
        p.ask("ddns_take_over", "example.com", "198.51.100.7", False)
    assert refused.value.accept == "accept_take_over" and "holds 198.51.100.7" in str(refused.value)
    for given in ("true", 1, "yes"):  # a program's text or number is no second yes
        with pytest.raises(TakeOverRefused):
            p.ask("ddns_take_over", "example.com", "198.51.100.7", given)
    assert not p.keeper().taken("example.com") and changes(fake) == []
    rep = p.ask("ddns_take_over", "example.com", "198.51.100.7", True)  # both confirmations given
    assert p.keeper().own("example.com") == HOME and not p.keeper().taken("example.com")  # its consent used up: its own
    assert rep["ok"] and rep["said"] == "example.com taken over: set (was 198.51.100.7)"
    (taken,) = changes(fake)
    assert taken["deletions"] == [{"name": "example.com.", "type": "A", "ttl": 300, "rrdatas": ["198.51.100.7"]}]
    assert taken["additions"] == [{"name": "example.com.", "type": "A", "ttl": 300, "rrdatas": [HOME]}]
    assert a_record(fake, "example.com.") == [HOME]
    with pytest.raises(ValueError, match="none of the Dynamic DNS hosts set"):
        p.ddns_take_over("www.example.org", None, True)


def test_a_take_over_is_refused_when_the_record_no_longer_holds_what_the_page_showed(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="@.example.com"))
    p, fake = made()
    p.refresh()
    p.ddns_update(force=False)
    next(s for s in fake.rrsets["example-com"] if s["name"] == "example.com." and s["type"] == "A")["rrdatas"] = ["198.51.100.8"]
    with pytest.raises(ValueError, match=r"example.com holds 198.51.100.8 now, not what the page showed \(198.51.100.7\)"):
        p.ddns_take_over("example.com", "198.51.100.7", True)
    assert not p.keeper().taken("example.com") and changes(fake) == []
    row = next(r for r in table(p)["rows"] if r[0] == "example.com")  # its Take over… carries what it holds now
    assert row[1] == "198.51.100.8" and row[-1]["values"] == {"host": "example.com", "holds": "198.51.100.8"}


def test_a_host_taken_over_then_taken_out_of_the_setting_is_let_go(env):
    """Taken over, then taken out of the setting: the next pass lets it go (the keeper's settle). Put back later, after
    the network's address changed, its record (at the old address) is no longer the keeper's: left as it is, its row
    offering Take over… again."""
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="@.example.com"))
    fake, address = FakeGoogle(), [HOME]
    p = GoogleCloudPlugin(transport=fake, public=lambda: (address[0], "a stand-in"), sleep=lambda s: None)
    p.app = Platform()  # the serving platform's plugin (its background not started here): the one that settles
    p.refresh()
    p.ddns_update(force=False)
    p.ddns_take_over("example.com", "198.51.100.7", True)
    assert a_record(fake, "example.com.") == [HOME] and p.keeper().known() == ["example.com"]
    env({"GOOGLECLOUD_DDNS_HOSTS": "home.example.com"})  # example.com taken out of the setting
    p.settings_changed()
    p.ddns_update(force=False)
    assert "example.com" not in p.keeper().known() and not p.keeper().taken("example.com")
    address[0] = NEW  # the network moved; then example.com is put back in the setting
    env({"GOOGLECLOUD_DDNS_HOSTS": "home.example.com, @.example.com"})
    p.settings_changed()
    fake.requests.clear()
    hosts = {h["host"]: h for h in p.ddns_update(force=True)["hosts"]}
    assert hosts["example.com"]["foreign"] is True and hosts["example.com"]["result"].startswith(f"holds {HOME}, not this")
    assert a_record(fake, "example.com.") == [HOME] and not any(c["additions"][0]["name"] == "example.com."
                                                                for c in changes(fake))
    row = next(r for r in table(p)["rows"] if r[0] == "example.com")
    assert row[-1]["form"] == "ddns-take" and row[-1]["values"] == {"host": "example.com", "holds": HOME}


def test_a_refresh_lets_go_of_a_host_taken_out_while_the_plugin_was_not_running(made, env):
    """What the keeper holds outlives the plugin (its state file); a host taken out of the setting meanwhile is let go
    by the first refresh that reads the zones, never by one that could not."""
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com"))
    p, fake = made()
    p.refresh()
    p.ddns_update(force=False)
    assert p.keeper().known() == ["home.example.com"]
    env({"GOOGLECLOUD_DDNS_HOSTS": ""})  # taken out while no plugin ran
    again = GoogleCloudPlugin(transport=fake, public=lambda: (HOME, "a stand-in"), sleep=lambda s: None)
    again.app = Platform()  # the serving platform's plugin: the one that settles
    fake.fail[("GET", r"/managedZones$")] = (503, {"error": {"code": 503, "message": "backend", "status": "UNAVAILABLE"}})
    again.refresh()  # the zones not read: nothing let go on a list left short
    assert again.keeper().known() == ["home.example.com"]
    del fake.fail[("GET", r"/managedZones$")]
    again.refresh()
    assert again.keeper().known() == []


def test_only_the_serving_platform_settles(made, env):
    """The plugin's own command line (and the platform's one-shot commands) runs where the setting may lack the hosts:
    unattached, the setting emptied, what the keeper holds as its own is kept; under the serving platform it is let go."""
    from plugin_platform_googlecloud.__main__ import main

    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com"))
    p, fake = made()
    p.refresh()
    p.ddns_update(force=False)
    assert p.keeper().own("home.example.com") == HOME
    env({"GOOGLECLOUD_DDNS_HOSTS": ""})  # a shell whose setting lacks the hosts
    p.settings_changed()
    p.refresh()
    assert main(["status"], plugin=p, out=lambda s: None, err=lambda s: None) == 0
    assert p.keeper().own("home.example.com") == HOME  # unattached: kept
    p.app = type("Once", (), {"NAME": "platform", "once": True})()  # the platform's one-shot command: kept too
    p.refresh()
    assert p.keeper().own("home.example.com") == HOME
    p.app = Platform()  # the serving platform: let go as before
    p.refresh()
    assert p.keeper().own("home.example.com") is None and p.keeper().known() == []


def test_a_host_with_several_addresses_is_never_cut_to_one(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="multi.example.com"))
    p, fake = made()
    fake.rrsets["example-com"].append({"kind": "dns#resourceRecordSet", "name": "multi.example.com.", "type": "A", "ttl": 60,
                                       "rrdatas": [HOME, "198.51.100.7"]})  # this network among two servers
    p.refresh()
    for force in (False, True):  # Update DNS now too: never a host that is not its own
        (host,) = p.ddns_update(force=force)["hosts"]
        assert host["foreign"] is True and host["result"].startswith(f"holds 2 addresses ({HOME}, 198.51.100.7): left as it is")
    assert changes(fake) == [] and a_record(fake, "multi.example.com.") == [HOME, "198.51.100.7"]


def test_its_own_old_address_is_updated_after_the_network_moved_even_after_a_restart(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com"))
    p, fake = made()
    p.refresh()
    assert p.ddns_update(force=False)["hosts"][0]["result"] == "made (was none)"
    # the network's address changes; a plugin started afresh (the state file kept) knows the old address as its own
    again = GoogleCloudPlugin(transport=fake, public=lambda: (NEW, "a stand-in"), sleep=lambda s: None)
    again.refresh()
    fake.requests.clear()
    (host,) = again.ddns_update(force=False)["hosts"]
    assert host["result"] == f"set (was {HOME})" and a_record(fake, "home.example.com.") == [NEW]
    (moved,) = changes(fake)
    assert moved["deletions"] == [{"name": "home.example.com.", "type": "A", "ttl": 300, "rrdatas": [HOME]}]


def test_a_record_changed_by_someone_else_during_a_pass_is_left_as_it_is(made, env):
    """Between the keeper's read and its write the record is changed elsewhere: read afresh before the change, it is
    no longer the keeper's own, so nothing is written."""
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com"))
    p, fake = made()
    p.refresh()
    real = fake._route

    def meanwhile(method, host, path, query, body):
        answer = real(method, host, path, query, body)
        if method == "GET" and path.endswith("/rrsets") and query.get("type") == "A":  # the keeper's read: then a change
            fake.rrsets["example-com"].append({"kind": "dns#resourceRecordSet", "name": "home.example.com.", "type": "A",
                                               "ttl": 300, "rrdatas": ["198.51.100.99"]})
        return answer
    fake._route = meanwhile
    (host,) = p.ddns_update(force=False)["hosts"]
    assert host["ok"] is False and host["result"] == "not updated: it changed meanwhile to 198.51.100.99: left as it is"
    assert changes(fake) == [] and a_record(fake, "home.example.com.") == ["198.51.100.99"]


def test_a_host_taken_out_of_the_settings_is_let_go(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com"))
    p, fake = made()
    p.refresh()
    p.ddns_update(force=False)
    assert p.keeper().own("home.example.com") == HOME
    p.app = Platform()  # the serving platform's plugin: the one that settles
    env({"GOOGLECLOUD_DDNS_HOSTS": "@.example.com"})
    p.settings_changed()
    p.ddns_update(force=False)
    assert p.keeper().own("home.example.com") is None  # no longer the keeper's: a record there is never its own again


def test_without_this_networks_address_nothing_is_written(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com"))
    p, fake = made(public=(None, "neither OpenDNS nor Google answered"))
    p.refresh()
    fake.requests.clear()
    (host,) = p.ddns_update()["hosts"]
    assert host["ok"] is False and host["result"] == ("this network's address was not found: neither OpenDNS nor Google "
                                                      "answered") and fake.requests == []


def test_a_cname_host_is_never_written_over(made, env):
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="www.example.com"))
    p, fake = made()
    p.refresh()
    (host,) = p.ddns_update()["hosts"]
    assert host["ok"] is False and host["result"].startswith("not updated: www.example.com is a CNAME")
    assert changes(fake) == []


def test_dynamic_dns_not_set_says_what_to_set(made, env):
    env(settings_of())
    p, _ = made()
    with pytest.raises(ValueError, match="Dynamic DNS is not set up: GOOGLECLOUD_DDNS_HOSTS is not set"):
        p.ddns_update()
