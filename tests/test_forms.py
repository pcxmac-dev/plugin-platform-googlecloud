"""The platform's page changes what costs nothing through the plugin's forms, each confirmed by the user with the change
named (and what keeps billing said), the risky ones asked a second time: each form's hook sends exactly the request
Google's reference gives (its method, its path, its body), and nothing is sent for a change refused. Over the stand-ins."""
from __future__ import annotations

import inspect
import re

import pytest

from conftest import HOME, PROJECT, SSH_ED25519, FakeGoogle, err, settings_of, ssh_public
from liminal_libs.machines.rest import RestError
from plugin_platform_googlecloud import ACCEPT_OPEN, ACCEPT_REMOVE, ACCEPT_RESET
from plugin_platform_googlecloud.records import Refusal
from plugin_platform_googlecloud.sshkeys import fingerprint_of

C = f"/compute/v1/projects/{PROJECT}"
D = f"/dns/v1/projects/{PROJECT}/managedZones"


def page_args(form: dict, values: dict, accepted=()) -> list:
    """What the platform's page sends for a form (platform.js argsOf): the fields' values in order, a field whose `when` is
    unmet or left empty null (the hook's default), a number as a number, an accept field true only once accepted."""
    now = {**{x["name"]: x.get("value") for x in form["fields"]}, **values}
    out = []
    for x in form["fields"]:
        if x["type"] == "accept":
            out.append(x["name"] in accepted)
            continue
        shown = all(str(now.get(k) or "") in [str(v) for v in vs] for k, vs in (x.get("when") or {}).items())
        v = now.get(x["name"])
        out.append(None if not shown or v in (None, "") else int(v) if x["type"] == "number" else v)
    return out


def forms_of(status: dict) -> dict:
    return {f["id"]: f for f in status["forms"]}


@pytest.fixture
def ready(made, env):
    """A plugin over the stand-ins with the project read: (plugin, fake Google, its forms)."""
    def make(fake: FakeGoogle | None = None, **settings):
        env(settings_of(**settings))
        p, fake = made(fake)
        p.refresh()
        fake.requests.clear()
        return p, fake, forms_of(p.status())
    return make


def test_each_form_is_its_hooks_arguments_in_order(ready):
    p, fake, forms = ready()
    hooks = p.interface()["hooks"]
    for f in forms.values():
        assert f["hook"] in hooks, f["id"]
        assert [x["name"] for x in f["fields"]] == list(inspect.signature(getattr(p, f["hook"])).parameters), f["id"]
        assert all(x["type"] in ("text", "number", "choice", "fixed", "accept") for x in f["fields"])
        assert f["confirm"]["title"] and f["confirm"]["words"] and f["confirm"]["yes"]
        for x in f["fields"]:
            if x["type"] == "accept":
                assert x["name"] in (ACCEPT_RESET, ACCEPT_OPEN, ACCEPT_REMOVE) and x["words"] and x["yes"]
    assert fake.requests == []  # drawn: nothing asked


def test_stop_says_what_keeps_billing_and_sends_the_documented_request(ready):
    p, fake, forms = ready()
    f = forms["stop:us-central1-a/web-1"]
    words = f["confirm"]["words"]
    assert words.startswith("web-1 is shut down: Google sends its guest an ACPI shutdown signal and gives it up to 120 seconds.")
    assert "Stopped, its vCPUs and memory no longer bill" in words
    assert "its 2 disks (120 GB) and its static address 34.123.45.67 keep billing while they exist" in words
    assert f["confirm"]["danger"] is True
    rep = p.ask(f["hook"], *page_args(f, {}))
    assert fake.calls() == [("GET", f"{C}/zones/us-central1-a/instances/web-1"),  # read afresh first
                            ("POST", f"{C}/zones/us-central1-a/instances/web-1/stop")]
    sent = fake.requests[-1]
    assert sent["body"] is None and set(sent["query"]) == {"requestId"} and len(sent["query"]["requestId"]) == 36
    assert rep["ok"] and rep["said"] == "asked Google to stop web-1" and rep["operation"] == "operation-1-stop"
    assert "its 2 disks (120 GB) and its static address 34.123.45.67 keep billing while they exist" in rep["lines"]


def test_stopping_a_server_with_an_ephemeral_address_says_it_is_let_go(ready):
    fake = FakeGoogle()
    fake.instances[("us-central1-a", "web-1")]["networkInterfaces"][0]["accessConfigs"][0]["natIP"] = "34.1.1.1"
    p, fake, forms = ready(fake)
    words = forms["stop:us-central1-a/web-1"]["confirm"]["words"]
    assert "its 2 disks (120 GB) keep billing while they exist" in words
    assert "its ephemeral address 34.1.1.1 is let go: started again, it gets another (a DNS record holding it is then wrong)" in words


def test_start_sends_the_documented_request_and_says_it_bills_again(ready):
    p, fake, forms = ready()
    f = forms["start:us-central1-a/batch-1"]
    assert "bill again while it runs" in f["confirm"]["words"]
    rep = p.ask(f["hook"], *page_args(f, {}))
    assert fake.calls()[-1] == ("POST", f"{C}/zones/us-central1-a/instances/batch-1/start") and fake.requests[-1]["body"] is None
    assert rep["ok"] and "its vCPUs and memory bill again while it runs" in rep["lines"]
    with pytest.raises(Refusal, match="batch-1 is staging: only a stopped server is started"):
        p.start_server("us-central1-a", "batch-1")  # read afresh: no longer stopped
    assert [m for m, _ in fake.calls()].count("POST") == 1


def test_a_reset_is_hard_so_it_is_asked_twice(ready):
    p, fake, forms = ready()
    f = forms["reset:us-central1-a/web-1"]
    assert "a hard reset" in f["confirm"]["words"] and "asked again" in f["confirm"]["words"]
    with pytest.raises(Refusal, match="unsaved data is lost and its disks' file systems may be corrupted") as refused:
        p.ask(f["hook"], *page_args(f, {}))
    assert refused.value.accept == ACCEPT_RESET and fake.writes() == []
    rep = p.ask(f["hook"], *page_args(f, {}, accepted={ACCEPT_RESET}))
    assert fake.calls()[-1] == ("POST", f"{C}/zones/us-central1-a/instances/web-1/reset") and rep["ok"]


def test_power_changes_refused_say_why_and_send_nothing(ready):
    p, fake, _ = ready()
    with pytest.raises(Refusal, match="has a Local SSD: .* stopped in the console"):
        p.stop_server("europe-west1-b", "scratch-1")
    with pytest.raises(Refusal, match="web-1 is running: only a stopped server is started"):
        p.start_server("us-central1-a", "web-1")
    with pytest.raises(Refusal, match="batch-1 is stopped: only a running server is reset"):
        p.reset_server("us-central1-a", "batch-1", accept_hard_reset=True)
    with pytest.raises(Refusal, match="is not among the servers read: Refresh first"):
        p.stop_server("us-central1-a", "elsewhere")
    assert fake.writes() == []


def test_a_firewall_rule_is_added_with_the_documented_body(ready):
    p, fake, forms = ready()
    f = forms["firewall:add"]
    assert [c["value"] for c in next(x for x in f["fields"] if x["name"] == "network")["choices"]] == ["default"]
    args = page_args(f, {"name": "allow-home-ssh", "ports": "22", "ranges": f"{HOME}/32", "target_tags": "",
                         "priority": "", "description": "from home"})
    assert args == ["allow-home-ssh", "default", "INGRESS", "allow", "tcp", "22", f"{HOME}/32", None, None, "from home", False]
    rep = p.ask(f["hook"], *args)
    assert fake.calls() == [("GET", f"{C}/global/firewalls"), ("POST", f"{C}/global/firewalls"),
                            ("GET", f"{C}/global/operations/operation-1-insert"), ("GET", f"{C}/global/firewalls")]
    assert fake.requests[1]["body"] == {"name": "allow-home-ssh", "network": "global/networks/default", "direction": "INGRESS",
                                        "priority": 1000, "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                                        "sourceRanges": [f"{HOME}/32"], "description": "from home"}
    assert rep["ok"] and rep["said"].startswith("added allow-home-ssh: allow tcp:22 in from 93.184.216.34/32")
    assert rep["lines"] == ["operation operation-1-insert: done", "it reaches batch-1, scratch-1, web-1",
                            "VPC firewall rules cost nothing (its logging is off)"]
    assert "allow-home-ssh" in fake.firewalls and "logConfig" not in fake.firewalls["allow-home-ssh"]
    with pytest.raises(Refusal, match="a rule named allow-home-ssh is there already"):
        p.ask(f["hook"], *args)
    with pytest.raises(ValueError, match="'22-1': ports are 0 to 65535, the lower first"):
        p.ask(f["hook"], *page_args(f, {"name": "x-1", "ports": "22-1", "ranges": "10.0.0.0/8"}))
    with pytest.raises(ValueError, match="no addresses given"):
        p.ask(f["hook"], *page_args(f, {"name": "x-1", "ports": "80", "ranges": ""}))
    egress = p.ask(f["hook"], *page_args(f, {"name": "deny-irc-out", "direction": "EGRESS", "action": "deny",
                                              "ports": "6667", "ranges": "0.0.0.0/0", "priority": "500"}))
    assert egress["ok"] and fake.firewalls["deny-irc-out"]["destinationRanges"] == ["0.0.0.0/0"]
    assert fake.firewalls["deny-irc-out"]["denied"] == [{"IPProtocol": "tcp", "ports": ["6667"]}]


def test_a_rule_opening_ssh_or_every_port_to_the_internet_is_asked_twice(ready):
    p, fake, forms = ready()
    f = forms["firewall:add"]
    for values, opened in (({"name": "open-ssh", "ports": "22", "ranges": "0.0.0.0/0"}, "SSH (tcp:22)"),
                           ({"name": "open-all", "ports": "", "ranges": "203.0.113.0/24, ::/0", "target_tags": "web"},
                            "every port of tcp"),
                           ({"name": "open-udp", "protocol": "udp", "ports": "", "ranges": "0.0.0.0/0"}, "every port of udp")):
        with pytest.raises(Refusal, match=f"it opens {re.escape(opened)}.* to the whole internet") as refused:
            p.ask(f["hook"], *page_args(f, values))
        assert refused.value.accept == ACCEPT_OPEN
    assert [m for m, _ in fake.calls()] == ["GET", "GET", "GET"]  # each read the rules: nothing added
    rep = p.ask(f["hook"], *page_args(f, {"name": "open-ssh", "ports": "22", "ranges": "0.0.0.0/0"}, accepted={ACCEPT_OPEN}))
    assert rep["ok"] and fake.firewalls["open-ssh"]["sourceRanges"] == ["0.0.0.0/0"]
    p.ask(f["hook"], *page_args(f, {"name": "ping", "protocol": "icmp", "ranges": "0.0.0.0/0"}))  # ping: not risky
    assert fake.firewalls["ping"]["allowed"] == [{"IPProtocol": "icmp"}]


def test_removing_the_rule_letting_ssh_in_is_asked_twice(ready):
    p, fake, forms = ready()
    f = forms["firewall:remove"]
    with pytest.raises(Refusal, match="default-allow-ssh lets SSH .* in to batch-1, scratch-1, web-1: removing it may lock "
                                      "you out of them") as refused:
        p.ask(f["hook"], *page_args(f, {"name": "default-allow-ssh"}))
    assert refused.value.accept == ACCEPT_REMOVE and "default-allow-ssh" in fake.firewalls and fake.writes() == []
    rep = p.ask(f["hook"], *page_args(f, {"name": "default-allow-ssh"}, accepted={ACCEPT_REMOVE}))
    assert ("DELETE", f"{C}/global/firewalls/default-allow-ssh") in fake.calls() and rep["ok"]
    assert fake.requests[[r["method"] for r in fake.requests].index("DELETE")]["body"] is None
    assert "default-allow-ssh" not in fake.firewalls
    p.ask(f["hook"], *page_args(f, {"name": "deny-smtp-out"}))  # an egress rule: one confirmation
    assert "deny-smtp-out" not in fake.firewalls
    with pytest.raises(Refusal, match="no firewall rule named 'gone'"):
        p.ask(f["hook"], *page_args(f, {"name": "gone"}))


def test_a_failed_operation_is_said_in_googles_words(ready):
    p, fake, forms = ready()
    fake.op_polls = 3
    fake.op_error = {"errors": [{"code": "RESOURCE_NOT_FOUND", "message": "The resource 'projects/liminal-test/global/"
                                 "networks/nope' was not found"}]}
    with pytest.raises(RestError, match="networks/nope' was not found") as failed:
        p.ask("add_firewall_rule", *page_args(forms["firewall:add"], {"name": "x-1", "network": "default", "ports": "80",
                                                                      "ranges": "10.0.0.0/8"}))
    assert failed.value.code == "RESOURCE_NOT_FOUND" and p.slept[-3:] == [1.0, 2.0, 4.0]  # backing off, never slept for real


def test_a_record_is_set_with_one_change_and_every_other_record_kept(ready):
    p, fake, forms = ready()
    f = forms["set:example-com"]
    assert "deleted exactly as it was read" in f["confirm"]["words"] and "nothing is overwritten" in f["confirm"]["words"]
    rep = p.ask(f["hook"], *page_args(f, {"name": "home", "rtype": "A", "data": HOME}))
    assert fake.calls() == [("GET", f"{D}/example-com/rrsets"), ("POST", f"{D}/example-com/changes"),
                            ("GET", f"{D}/example-com/rrsets")]
    assert fake.requests[0]["query"] == {"name": "home.example.com."}  # the name's record sets read afresh
    assert fake.requests[1]["body"] == {"additions": [
        {"name": "home.example.com.", "type": "A", "ttl": 300, "rrdatas": [HOME]}],
        "deletions": []}
    assert rep["said"] == f"added home.example.com A {HOME}" and rep["changed"] and rep["change"] == "1"
    fake.requests.clear()
    rep = p.ask(f["hook"], *page_args(f, {"name": "@", "rtype": "A", "data": "203.0.113.9", "ttl": "120"}))
    assert fake.requests[1]["body"]["deletions"] == [{"name": "example.com.", "type": "A", "ttl": 300,
                                                      "rrdatas": ["198.51.100.7"]}]  # exactly as read
    assert fake.requests[1]["body"]["additions"][0]["rrdatas"] == ["203.0.113.9"] and rep["said"].endswith("(it was 198.51.100.7)")
    fake.requests.clear()
    rep = p.ask(f["hook"], *page_args(f, {"name": "example.com", "rtype": "TXT", "data": "keybase-site-verification=x y"}))
    sets = {(s["name"], s["type"]): s for s in fake.rrsets["example-com"]}
    assert sets[("example.com.", "TXT")]["rrdatas"] == ['"v=spf1 include:_spf.google.com ~all"',
                                                       '"google-site-verification=abc123"', '"keybase-site-verification=x y"']
    assert rep["said"] == 'added example.com TXT "keybase-site-verification=x y" beside 2 other values'
    assert sets[("example.com.", "MX")]["rrdatas"] == ["1 smtp.google.com."]  # every other record kept
    rep = p.ask(f["hook"], *page_args(f, {"name": "home", "rtype": "A", "data": HOME}))
    assert rep["changed"] is False and "nothing written" in rep["said"]
    p.ask(f["hook"], *page_args(f, {"name": "@", "rtype": "MX", "data": "5 alt1.aspmx.l.google.com"}))
    assert {s["type"]: s for s in fake.rrsets["example-com"] if s["name"] == "example.com."}["MX"]["rrdatas"] == [
        "1 smtp.google.com.", "5 alt1.aspmx.l.google.com."]


def test_a_record_is_removed_and_the_zones_own_and_conflicts_are_refused(ready):
    p, fake, forms = ready()
    status = p.status()
    records = next(t for t in status["tables"] if t["title"] == "example.com records")
    removes = [r[-1]["values"] for r in records["rows"] if isinstance(r[-1], dict)]
    spf = next(v for v in removes if "spf1" in v["data"])
    f = forms["remove:example-com"]
    assert f["confirm"]["danger"] is True and page_args(f, spf) == ["example-com", "example.com.", "TXT", spf["data"]]
    rep = p.ask(f["hook"], *page_args(f, spf))
    assert fake.requests[1]["body"] == {"additions": [
        {"name": "example.com.", "type": "TXT", "ttl": 300,
         "rrdatas": ['"google-site-verification=abc123"']}],
        "deletions": [{"name": "example.com.", "type": "TXT", "ttl": 300,
                       "rrdatas": ['"v=spf1 include:_spf.google.com ~all"', '"google-site-verification=abc123"']}]}
    assert rep["said"].startswith("removed example.com TXT") and rep["said"].endswith("(1 other value kept)")
    s = forms["set:example-com"]
    calls = len(fake.requests)
    for values, why in (({"name": "@", "rtype": "CNAME", "data": "other.example.net"}, "cannot stand for the zone's own name"),
                        ({"name": "www", "rtype": "A", "data": HOME}, "www.example.com is a CNAME"),
                        ({"name": "@", "rtype": "NS", "data": "ns1.example.net"}, "is the zone's own"),
                        ({"name": "x.example.org.", "rtype": "A", "data": HOME}, "is not in the zone"),
                        ({"name": "home", "rtype": "A", "data": "not-an-ip"}, "is not an IPv4 address")):
        with pytest.raises(ValueError, match=why):
            p.ask(s["hook"], *page_args(s, values))
    with pytest.raises(Refusal, match="the SOA record of example.com is the zone's own"):
        p.remove_record("example-com", "@", "SOA", fake.rrsets["example-com"][2]["rrdatas"][0])
    assert all(r["method"] == "GET" for r in fake.requests[calls:])
    # a change Google refuses (another made meanwhile: the deletion no longer matches) changes nothing, and says so
    fake.fail[("POST", r"/changes$")] = (412, err(412, "The resource 'entity.change.deletions[www.example.com.][CNAME]' does "
                                                       "not match the existing data", "FAILED_PRECONDITION", "conditionNotMet"))
    with pytest.raises(RestError, match=r"the change \(removed www.example.com CNAME example.com.\) was refused, nothing "
                                        r"changed: .*does not match the existing data \(it changed since it was read"):
        p.remove_record("example-com", "www.example.com.", "CNAME", "example.com.")


def test_ssh_keys_are_changed_with_the_metadatas_fingerprint_and_every_other_item_kept(ready):
    p, fake, forms = ready()
    before = [dict(x) for x in fake.metadata["items"]]
    f = forms["ssh:add"]
    carol = ssh_public()
    rep = p.ask(f["hook"], *page_args(f, {"user": "carol", "key": f"{carol} carol@pc"}))
    assert fake.calls() == [("GET", C), ("POST", f"{C}/setCommonInstanceMetadata"),
                            ("GET", f"{C}/global/operations/operation-1-setMetadata"), ("GET", C)]
    body = fake.requests[1]["body"]
    assert set(body) == {"fingerprint", "items"} and body["fingerprint"] == "fp-1"  # as Google's guide sends it
    assert [x["key"] for x in body["items"]] == ["startup-script", "ssh-keys", "enable-guest-attributes"]
    assert body["items"][0] == before[0] and body["items"][2] == before[2]  # every other item exactly as read
    assert body["items"][1]["value"] == before[1]["value"] + f"\ncarol:{carol} carol@pc"
    fp = fingerprint_of(carol.split()[1])
    assert rep["ok"] and rep["said"] == f"added carol's ssh-ed25519 key {fp}"
    assert rep["lines"][1:] == ["read back: the project's ssh-keys as written", "every other metadata item kept"]
    keys = {k["user"]: k for k in p.ssh_keys()}
    assert set(keys) == {"alice", "bob", "carol"} and keys["carol"]["fingerprint"] == fp
    rep = p.ask(f["hook"], *page_args(f, {"user": "carol", "key": f"{carol} again"}))
    assert rep["changed"] is False and "there already" in rep["said"]
    remove = forms["ssh:remove"]
    alice = fingerprint_of(SSH_ED25519.split()[1])
    fake.requests.clear()
    rep = p.ask(remove["hook"], *page_args(remove, {"user": "alice", "fingerprint": alice}))
    value = fake.requests[1]["body"]["items"][1]["value"]
    assert "alice:" not in value and value.startswith("bob:") and value.endswith(f"carol:{carol} carol@pc") and rep["ok"]
    with pytest.raises(ValueError, match="that is a private key"):
        p.add_ssh_key("dave", "-----BEGIN OPENSSH PRIVATE KEY----- abc")
    with pytest.raises(ValueError, match="not a public key's"):
        p.add_ssh_key("dave", "ssh-ed25519 bm90IGEga2V5")
    with pytest.raises(Refusal, match="no key SHA256:nope of alice"):
        p.remove_ssh_key("alice", "SHA256:nope")


def test_a_metadata_changed_meanwhile_is_never_overwritten(ready):
    p, fake, _ = ready()
    real = fake._route

    def someone_else_first(method, host, path, query, body):
        if method == "POST" and path.endswith("/setCommonInstanceMetadata"):
            fake.metadata = {**fake.metadata, "fingerprint": "fp-9"}  # a change elsewhere, after this one's read
        return real(method, host, path, query, body)
    fake._route = someone_else_first
    with pytest.raises(RestError, match=r"the project's metadata changed since it was read \(another change came first\): "
                                        "nothing was written") as refused:
        p.add_ssh_key("carol", ssh_public())
    assert refused.value.status == 412 and "carol" not in fake.metadata["items"][1]["value"]
