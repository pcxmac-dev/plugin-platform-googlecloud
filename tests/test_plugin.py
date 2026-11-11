"""The plugin's status as the platform's page draws it: not set up, a key that cannot be used, a refresh drawing every
table from what was read (no request made to answer the status), valid while a part works, troubles in words with the
secrets taken out, what it learned of its APIs, and its reading in the background while attached. Over the stand-ins."""
from __future__ import annotations

import threading
import time

import pytest

from conftest import ACCOUNT, PEM, PROJECT, Charts, FakeGoogle, Pairs, Platform, err, key_json, settings_of
from liminal_libs.machines.rest import RestError
from plugin_platform_googlecloud import NOT_SET, STOPPED_BILLS, GoogleCloudPlugin
from plugin_platform_googlecloud.api import ENDPOINTS, GoogleCloud


def titles(status: dict) -> list[str]:
    return [t["title"] for t in status["tables"]]


def table(status: dict, title: str) -> dict:
    return next(t for t in status["tables"] if t["title"] == title)


def texts(row) -> list[str]:
    return [c.get("text", c.get("title", "")) if isinstance(c, dict) else c for c in row]


def test_not_set_up_names_the_settings_and_where_a_key_is_made(made):
    p, fake = made()
    st = p.status()
    assert st["present"] is False and st["valid"] is False and st["summary"] == "not set up"
    assert st["why"] == NOT_SET and "GOOGLECLOUD_KEY" in st["why"] and "roles/compute.viewer" in st["why"]
    assert "https://console.cloud.google.com/iam-admin/serviceaccounts" in st["why"]
    assert st["settingsNotSet"] == "GOOGLECLOUD_KEY, GOOGLECLOUD_PROJECT, GOOGLECLOUD_DDNS_HOSTS, GOOGLECLOUD_DDNS_MINUTES"
    assert st["tables"] == st["actions"] == st["forms"] == [] and fake.requests == [] and p.api_facts() == {}
    with pytest.raises(ValueError, match="not set up: GOOGLECLOUD_KEY"):
        p.refresh()


def test_a_key_that_cannot_be_used_says_why_and_nothing_of_it(made, env):
    env({"GOOGLECLOUD_KEY": key_json(token_uri="https://evil.example.com/token")})
    p, fake = made()
    st = p.status()
    assert st["present"] is True and st["valid"] is False and st["summary"] == "the key cannot be used"
    assert st["why"].startswith("GOOGLECLOUD_KEY cannot be used: its token_uri") and PEM[40:80] not in str(st)
    assert st["settingsSet"] == "GOOGLECLOUD_KEY" and fake.requests == []
    env({"GOOGLECLOUD_KEY": key_json(project_id=None)})
    p.settings_changed()
    assert p.status()["why"] == "the key names no project (project_id): set GOOGLECLOUD_PROJECT"
    env({"GOOGLECLOUD_PROJECT": "Not A Project!"})
    p.settings_changed()
    assert "GOOGLECLOUD_PROJECT is not a project ID" in p.status()["why"]


def test_the_settings_come_from_the_attached_apps_login(made):
    p, fake = made()
    login = Pairs(settings_of(GOOGLECLOUD_PROJECT="other-project-1"))
    p.app, p.login = object(), login  # attached, without its background (attach would start it)
    cfg = p.config(fresh=True)
    assert cfg.ready and cfg.project == "other-project-1" and cfg.project_given and cfg.account == ACCOUNT
    assert set(login.asked) == {"googlecloud-key", "googlecloud-project"}  # the pairs it holds, asked by their names
    p.app = p.login = None


def test_a_refresh_draws_every_table_and_the_status_asks_nothing(made, env):
    env(settings_of())
    p, fake = made()
    st = p.status()
    assert st["valid"] is True and st["summary"] == "the project is read once attached" and st["forms"] == []
    assert st["project"] == f"{PROJECT} (the key's)" and st["serviceAccount"] == ACCOUNT and fake.requests == []
    got = p.refresh()
    assert got["servers"] == 3 and got["zones"] == 2 and got["troubles"] == []
    asked = len(fake.requests)
    st = p.status()
    assert len(fake.requests) == asked  # drawn from what was read
    assert st["valid"] is True and "problem" not in st
    assert st["summary"] == "3 servers (2 running) · 4 firewall rules · 2 DNS zones · billing on"
    assert st["billing"] == "on: My Billing Account · billingAccounts/012345-567890-ABCDEF (open)"
    assert st["servers"] == "3: 2 running, 1 stopped" and st["stoppedServers"] == STOPPED_BILLS
    assert st["prices"].startswith("not in Google's APIs") and st["readAt"]
    assert titles(st) == ["Servers", "Disks", "Addresses", "Firewall rules", "Project-wide SSH keys", "DNS zones",
                          "example.com records", "corp.internal records", "Regions in use", "In the project"]
    for t in st["tables"]:
        assert all(len(r) == len(t["columns"]) for r in t["rows"]), t["title"]
    servers = table(st, "Servers")
    assert "Google's APIs give no prices" in servers["note"] and STOPPED_BILLS in servers["note"]
    rows = {texts(r)[0]: r for r in servers["rows"]}
    web = rows["web-1"]
    assert texts(web)[:7] == ["web-1", "running", "e2-micro", "34.123.45.67 (static)", "10.128.0.2", "2 disks", "2026-03-01"]
    assert web[2]["sub"] == "2 vCPUs (shared) · 1 GB" and web[5]["sub"] == "120 GB"
    assert web[7]["form"] == "stop:us-central1-a/web-1" and web[8]["form"] == "reset:us-central1-a/web-1"
    assert web[7]["values"] == {"zone": "us-central1-a", "instance": "web-1"}
    batch = rows["batch-1"]
    assert texts(batch)[1] == "stopped" and batch[7]["form"] == "start:us-central1-a/batch-1" and batch[8] == ""
    assert batch[2]["sub"] == "2 vCPUs · 8 GB"
    scratch = rows["scratch-1"]  # a Local SSD: stopped in the console, not here; its custom shape read from its name
    assert scratch[7] == "" and scratch[2]["sub"] == "4 vCPUs · 8 GB" and texts(scratch)[3] == "35.240.1.2"
    disks = table(st, "Disks")
    assert [texts(r)[:5] for r in disks["rows"]] == [["spare", "50", "pd-ssd", "ready", "none (not attached)"],
                                                     ["web-1-0", "20", "pd-balanced", "ready", "web-1"],
                                                     ["web-1-1", "100", "pd-standard", "ready", "web-1"]]
    assert "a disk bills while it exists" in disks["note"]
    addresses = table(st, "Addresses")
    assert [texts(r)[:5] for r in addresses["rows"]] == [
        ["34.111.22.33", "lb-ip", "external, global", "premium", "reserved"],
        ["34.99.88.77", "held-ip", "external, us-central1", "premium", "reserved"],
        ["34.123.45.67", "web-ip", "external, us-central1", "premium", "in use by web-1"]]
    rules = table(st, "Firewall rules")
    assert rules["actions"] == [{"form": "firewall:add", "title": "Add a rule…"}]
    by = {texts(r)[0]: texts(r) for r in rules["rows"]}
    assert by["default-allow-ssh"][1:9] == ["in", "allow", "tcp:22", "0.0.0.0/0", "every server of default",
                                            "batch-1, scratch-1, web-1", "65534", "on"]
    assert by["allow-http"][5:7] == ["tags http-server", "web-1"]
    assert by["deny-smtp-out"][1:4] == ["out", "deny", "tcp:25"]
    keys = table(st, "Project-wide SSH keys")
    assert [texts(r)[:2] for r in keys["rows"]] == [["alice", "ssh-ed25519"], ["bob", "ssh-ed25519"]]
    assert texts(keys["rows"][1])[4] == "2026-12-01T00:00:00+0000" and "(scratch-1)" in keys["note"]
    assert keys["rows"][0][-1]["form"] == "ssh:remove" and keys["actions"] == [{"form": "ssh:add", "title": "Add a key…"}]
    zones = table(st, "DNS zones")
    assert [texts(r) for r in zones["rows"]] == [
        ["example.com", "public", "off", "6", "ns-cloud-a1.googledomains.com, ns-cloud-a2.googledomains.com"],
        ["corp.internal", "private", "off", "2", "ns-gcp-private.googledomains.com"]]
    records = table(st, "example.com records")
    assert texts(records["rows"][0])[:4] == ["example.com", "A", "300", "198.51.100.7"]
    own = {(texts(r)[0], texts(r)[1]): r[-1] for r in records["rows"]}
    assert own[("example.com", "SOA")] == "" and own[("example.com", "NS")] == ""  # the zone's own: no Remove
    assert own[("www.example.com", "CNAME")]["values"] == {"name": "www.example.com.", "rtype": "CNAME", "data": "example.com."}
    regions = table(st, "Regions in use")
    assert [texts(r) for r in regions["rows"]] == [
        ["us-central1", "cpus 4 of 24, disks total gb 170 of 4,096, static addresses 2 of 8"], ["europe-west1", "cpus 4 of 24"]]
    kinds = table(st, "In the project")
    assert [texts(r) for r in kinds["rows"]] == [["firewalls", "4", "200"], ["networks", "1", "15"], ["snapshots", "3", "5,000"]]
    assert [a["hook"] for a in st["actions"]] == ["refresh"]  # no Dynamic DNS hosts set
    assert {f["id"] for f in st["forms"]} == {"stop:us-central1-a/web-1", "reset:us-central1-a/web-1",
                                              "start:us-central1-a/batch-1", "reset:europe-west1-b/scratch-1",
                                              "firewall:add", "firewall:remove", "set:example-com", "remove:example-com",
                                              "set:internal", "remove:internal", "ssh:add", "ssh:remove"}
    assert fake.writes() == []  # drawn: nothing changed


def test_a_refresh_asks_little_and_only_reads(made, env):
    env(settings_of())
    p, fake = made()
    fake.page_size = 3  # four rules: two pages
    p.refresh()
    reads = fake.calls()
    gets = {f"/compute/v1{t}" if w == "compute" else f"/dns/v1{t}" if w == "dns" else f"/v1{t}"
            for w, m, t in ENDPOINTS.values() if m == "GET"}
    assert all(m == "GET" or path == "/token" for m, path in reads)
    templates = [g.replace("{project}", PROJECT) for g in gets]
    assert all(any(_matches(path, t) for t in templates) for m, path in reads if path != "/token")
    assert reads.count(("GET", f"/compute/v1/projects/{PROJECT}/global/firewalls")) == 2  # its pages followed
    assert reads.count(("POST", "/token")) == 1 and len(reads) == 17
    fake.requests.clear()
    p.refresh()  # the machine types, the zones and the billing account are not asked again within the hour
    assert len(fake.requests) == 12 and not any("machineTypes" in path or path.endswith("/zones") or "billingAccounts" in path
                                                for _, path in fake.calls())


def _matches(path: str, template: str) -> bool:
    import re

    return re.fullmatch(re.sub(r"\\\{[A-Za-z]+\\\}", "[^/]+", re.escape(template)), path) is not None


def test_valid_while_a_part_works_and_its_trouble_said_beside(made, env):
    env(settings_of())
    fake = FakeGoogle()
    fake.fail[("GET", r"/aggregated/instances$")] = (403, err(403, f"Required 'compute.instances.list' permission for "
                                                                 f"'projects/{PROJECT}'", "PERMISSION_DENIED", "forbidden"))
    p, fake = made(fake)
    got = p.refresh()
    assert got["troubles"] == [f"Compute Engine: GET /compute/v1/projects/{PROJECT}/aggregated/instances: HTTP 403: "
                               f"Required 'compute.instances.list' permission for 'projects/{PROJECT}' (the service account "
                               "lacks this permission: grant it the role the README names)"]
    st = p.status()
    assert st["valid"] is True and st["problem"].startswith("Compute Engine: GET ")
    assert st["summary"].startswith("Compute Engine: GET ") and st["summary"].endswith("· 2 DNS zones")
    fake.fail[("GET", r"/managedZones$")] = (403, err(403, "Cloud DNS API has not been used in project 555666777 before or "
                                                           "it is disabled.", "PERMISSION_DENIED", "accessNotConfigured",
                                                      [{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                                                        "reason": "SERVICE_DISABLED", "domain": "googleapis.com"}]))
    with pytest.raises(RestError, match="Compute Engine: .*; Cloud DNS: .*the API is not enabled for the project"):
        p.refresh()
    st = p.status()
    assert st["valid"] is False and st["why"].startswith("Compute Engine: ") and "Cloud DNS: " in st["why"]
    del fake.fail[("GET", r"/aggregated/instances$")], fake.fail[("GET", r"/managedZones$")]
    p.refresh()
    assert p.status()["valid"] is True and "problem" not in p.status()


def test_errors_are_worded_with_the_secrets_taken_out(made, env):
    env(settings_of())
    fake = FakeGoogle()
    line = PEM.splitlines()[3]
    fake.echo_secret = line
    fake.fail[("GET", r"/global/firewalls$")] = (500, err(500, "backend said SECRET", "INTERNAL", "backendError"))
    p, fake = made(fake)
    p.refresh()
    st = p.status()
    assert line not in str(st) and "backend said •••" in st["problem"]
    assert p.slept == [2.0, 4.0]  # a read tried again twice (backing off), never slept for real
    fake.echo_secret = None
    p.refresh()
    token = fake.tokens[-1]
    fake.fail[("GET", r"/global/firewalls$")] = (400, err(400, f"bad request {token}", "INVALID_ARGUMENT", "invalid"))
    with pytest.raises(RestError) as e:
        p.client().firewalls()
    assert token not in str(e.value) and "bad request •••" in str(e.value)


def test_a_refused_token_is_asked_anew_once(made, env):
    env(settings_of())
    p, fake = made()
    p.refresh()
    fake.revoked.add(fake.tokens[-1])  # Google no longer takes it: a 401, a new token, the request again
    assert p.client().firewalls() and len(fake.tokens) == 2


def test_what_it_learned_of_its_apis_asks_nothing(made, env):
    env(settings_of())
    p, fake = made()
    p.refresh()
    asked = len(fake.requests)
    facts = p.api_facts()
    assert len(fake.requests) == asked and set(facts) == {"Compute Engine API", "Cloud DNS API", "Cloud Billing API",
                                                          "Google OAuth 2.0"}
    assert facts["Compute Engine API"]["Requests"] == "10 made" and facts["Compute Engine API"]["Machine types kept"] == "3"
    assert facts["Compute Engine API"]["Last read"] and facts["Cloud DNS API"]["Requests"] == "3 made"
    assert facts["Cloud Billing API"]["Requests"] == "2 made" and facts["Google OAuth 2.0"]["Tokens asked"] == "1"
    assert facts["Google OAuth 2.0"]["Token"].startswith("held until ")
    assert all(f["Last answer"].startswith("HTTP 200") for f in facts.values())


def wait_for(check, most_s: float = 10.0) -> bool:
    deadline = time.monotonic() + most_s
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.02)
    return False


def test_attached_by_the_platform_it_reads_in_the_background_and_detached_nothing_runs(made):
    p, fake = made()
    interface = p.attach(Platform(), Pairs(settings_of()))
    try:
        assert "refresh" in interface["hooks"] and p.working
        assert wait_for(lambda: p.status().get("readAt") is not None) and fake.calls("GET")
    finally:
        p.detach()
    assert not p.working and p.login is None and p.app is None
    asked = len(fake.requests)
    time.sleep(0.2)
    assert len(fake.requests) == asked


@pytest.mark.parametrize("app", [Charts(), object()])
def test_attached_by_another_app_it_starts_no_reading(made, app):
    """The charts app run alone attaches every plugin it finds: no background reading starts but the platform's."""
    p, fake = made()
    p.attach(app, Pairs(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com")))
    try:
        time.sleep(0.2)
        assert not p.working and fake.requests == []
    finally:
        p.detach()


def test_a_pass_under_way_ends_once_detached_reading_no_settings_and_writing_nothing(made, env, monkeypatch):
    """Disabled while a Dynamic DNS pass waits on Google's answer longer than the detach waits for it: the pass ends
    there. It reads no settings again (not from the process's environment, where a key saved on the page is too) and
    sends no change, though the record it read was its own to make."""
    import plugin_platform_googlecloud as module
    import plugin_platform_googlecloud.settings as settings_mod

    monkeypatch.setattr(module, "JOIN_S", 0.2)
    env(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com"))  # the process's environment holds a key too
    p, fake = made()
    reached, release = threading.Event(), threading.Event()
    real = fake._route

    def slow(method, host, path, query, body):
        if method == "GET" and path.endswith("/rrsets") and query.get("type") == "A":  # the pass's read of the host
            reached.set()
            release.wait(10)
        return real(method, host, path, query, body)
    fake._route = slow
    reads: list = []
    original = settings_mod.read

    def counted(login=None):
        reads.append((login, threading.current_thread().name))
        return original(login)
    monkeypatch.setattr(settings_mod, "read", counted)
    p.attach(Platform(), Pairs(settings_of(GOOGLECLOUD_DDNS_HOSTS="home.example.com")))
    try:
        assert reached.wait(10)  # the worker's pass is in its read
        started = time.monotonic()
        p.detach()
        assert time.monotonic() - started < 2 and p.working  # the detach waited its while; the thread still in its read
        reads.clear()
    finally:
        release.set()
    assert wait_for(lambda: not p.working)
    assert [r for r in reads if r[1] == "googlecloud"] == []  # no settings read by the ended pass
    assert not any(r["method"] == "POST" and r["path"].endswith("/changes") for r in fake.requests)
    assert fake.rrsets["example-com"] and not any(s["name"] == "home.example.com." for s in fake.rrsets["example-com"])


def test_a_new_key_lets_go_of_what_was_read(made, env):
    env(settings_of())
    p, fake = made()
    p.refresh()
    assert p.servers()
    env({"GOOGLECLOUD_PROJECT": "another-project"})
    p.settings_changed()
    assert isinstance(p.client(), GoogleCloud) and p.servers() == [] and p.status()["summary"] == "the project is read once attached"


def test_a_plugin_made_by_the_registry_is_the_platforms(made):
    """The registry's module plugin: no stand-ins, nothing read until asked."""
    from plugin_platform_googlecloud import MACHINE

    assert isinstance(MACHINE, GoogleCloudPlugin) and MACHINE.status()["present"] is False
