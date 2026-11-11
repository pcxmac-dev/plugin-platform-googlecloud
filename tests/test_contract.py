"""Every plugin here conforms to the class contract (plugin API 2.2): liminal_libs.sources.conformance, read from the
plugin alone (nothing runs); its API card names the calls its client really makes, every part of each reference, real
addresses (asked only with LIMINAL_VENDOR_PAGES=1); and nothing in its client starts a charge."""
from __future__ import annotations

import inspect
import os
import re
from urllib.parse import urlsplit

import pytest

import plugin_platform_googlecloud as module
from liminal_libs.sources.apis import dead_links, problems
from liminal_libs.sources.conformance import assert_module_conforms
from plugin_platform_googlecloud import api, auth, card


def test_every_plugin_here_conforms_to_the_class_contract():
    found = assert_module_conforms(module)
    assert found and all(p.api == "2.2" and not p.is_record for p in found)
    assert {p.SYSTEM for p in found} == {"platform"} and {p.KIND for p in found} == {"machine"}
    assert {(p.name, p.title, p.order, p.ICON, p.version) for p in found} == {("googlecloud", "Google Cloud", 765,
                                                                                "googlecloud", "0.1.1")}
    assert module.__version__ == "0.1.1" and problems(module.MACHINE.apis) == []
    assert module.MACHINE.interface()["apis"] == ["Compute Engine API", "Cloud DNS API", "Cloud Billing API",
                                                  "Google OAuth 2.0"]


def test_its_settings_are_pairs_named_by_their_variables():
    p = module.MACHINE
    assert [k.pair for k in p.keys] == ["googlecloud-key", "googlecloud-project", "googlecloud-ddns-hosts",
                                         "googlecloud-ddns-minutes"]
    assert {k.name for k in p.keys if k.secret} == {"GOOGLECLOUD_KEY"}
    hooks = p.interface()["hooks"]
    assert {"present", "status", "refresh", "servers", "start_server", "stop_server", "reset_server", "firewalls",
            "add_firewall_rule", "remove_firewall_rule", "domains", "records", "set_record", "remove_record", "ssh_keys",
            "add_ssh_key", "remove_ssh_key", "ddns_update", "ddns_take_over"} <= set(hooks)
    assert "check" not in hooks and "setup" not in hooks and "run" not in hooks


def _call_names() -> dict[str, set[str]]:
    """The calls the client makes, named as the card names them: METHOD /path under the host."""
    out: dict[str, set[str]] = {card.COMPUTE_NAME: set(), card.DNS_NAME: set(), card.BILLING_NAME: set()}
    names = {"compute": card.COMPUTE_NAME, "dns": card.DNS_NAME, "billing": card.BILLING_NAME}
    for which, method, path in api.ENDPOINTS.values():
        out[names[which]].add(f"{method} {urlsplit(api.BASES[which]).path}{path}")
    out[card.OAUTH_NAME] = {f"POST {urlsplit(auth.TOKEN_URI).path}"}
    return out


def test_the_card_names_the_calls_the_client_makes_and_no_other_as_used():
    made = _call_names()
    for a in card.APIS:
        assert {c.name for c in a.used} == made[a.name], a.name
        assert all(c.docs for c in a.calls) and all(x.covered for x in a.areas if x.name in {c.area for c in a.used})
        assert {c.area for c in a.calls} <= {x.name for x in a.areas}, a.name
        writes = {c.name for c in a.used if c.writes}
        assert writes == {f"{m} {urlsplit(api.BASES[w]).path}{p}" for k, (w, m, p) in api.ENDPOINTS.items()
                          if k in api.WRITES and card.APIS[["compute", "dns", "billing"].index(w)].name == a.name}
    used_costs = [c.name for a in card.APIS for c in a.used if c.costs]
    assert used_costs == ["POST /compute/v1/projects/{project}/zones/{zone}/instances/{instance}/start"]  # said before it is asked


def test_every_part_of_the_compute_reference_is_on_the_card():
    named = [r for a in card.COMPUTE_AREAS for r in re.findall(r"\b[a-z][A-Za-z]+\b", a.about.rsplit("(", 1)[-1])]
    assert sorted(named) == sorted(card.COMPUTE_RESOURCES) and len(card.COMPUTE_RESOURCES) == 131
    assert len(card.DNS.areas) == 12 and len(card.BILLING.areas) == 7
    for a in card.APIS:
        assert a.verified == "2026-11-11" and a.docs and a.link("status" if a.name != card.OAUTH_NAME else "auth")
    assert card.COMPUTE.link("pricing") and card.DNS.link("pricing")
    assert "a stopped server's disks and static addresses keep billing" in card.COMPUTE.costs


def test_nothing_billable_in_the_client():
    """The client holds the free changes alone (the user, 2026-11-11: "Free changes only"): its changes are exactly
    these, sent through one place that refuses any other, and the paths of the calls that make, resize, snapshot,
    reserve or delete a billable thing are named on the card alone."""
    assert api.WRITES == {"start", "stop", "reset", "firewall_add", "firewall_remove", "set_metadata", "change"}
    assert {k for k, (_, m, _) in api.ENDPOINTS.items() if m != "GET"} == api.WRITES
    source = inspect.getsource(api)
    assert source.count(".request(") == 1 and not re.search(r"\.(post|put|patch|delete)\(", source)
    for billable in ("bulkInsert", "setMachineType", "createSnapshot", "/resize", "/resume", "/suspend", "/snapshots",
                     "machineImages", "/images", "/reservations", "/commitments", "instanceTemplates", "updateBillingInfo",
                     "/zones/{zone}/disks", "/regions/{region}/addresses", '/zones/{zone}/instances"', 'setMetadata"',
                     "insert"):
        assert billable not in source, billable
    # the paths a POST (a new address, a new zone) or a DELETE (a server destroyed) would bill or destroy at: read alone
    for path in ("/projects/{project}/global/addresses", "/projects/{project}/managedZones",
                 "/projects/{project}/zones/{zone}/instances/{instance}"):
        assert [m for _, m, p in api.ENDPOINTS.values() if p == path] == ["GET"]
    client = api.GoogleCloud("liminal-test", lambda: "t", transport=lambda *a: pytest.fail("sent"))
    api.ENDPOINTS["sneaky"] = ("compute", "POST", "/projects/{project}/zones/{zone}/instances")
    try:
        with pytest.raises(RuntimeError, match="not one of the plugin's changes"):
            client._send("sneaky", zone="us-central1-a")
    finally:
        del api.ENDPOINTS["sneaky"]


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="asks Google's pages: LIMINAL_VENDOR_PAGES=1")
def test_every_address_on_the_card_answers():
    assert dead_links(module.MACHINE.apis) == []


def test_its_icon_is_its_makers_mark_drawn_by_the_library():
    from liminal_libs.ui import STATIC

    drawn = set(re.findall(r"^\s*([a-z]+):\s*'", (STATIC / "icons.js").read_text(encoding="utf-8"), re.M))
    assert module.MACHINE.ICON == "googlecloud" and "googlecloud" in drawn
