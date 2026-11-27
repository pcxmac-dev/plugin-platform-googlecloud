"""Who may ask the plugin's changes (0.1.5; the independent review's PLT-H1 and the sweep of the plugins after it,
2026-11-25). Its changes are asked only from its page (PAGE_ONLY_HOOKS, as liminal-libs 1.66.0's apps/asking.py and
liminal-platform 0.34.0 read them): a server started, stopped or reset, a firewall rule added or removed, a record set or
removed, a project-wide SSH key added or removed, a Dynamic DNS pass and a host taken over. Another plugin's ask is
refused, and so is an ask that names no one; over HTTP the platform also asks its login whether you are at the page.
Before, any program on this PC asked them of the platform with a header anyone can send, and the service account's key
did the rest: a key of the asker's added to the project's SSH keys (a login with sudo on every server that takes them)
and a server stopped with no second question at all; a stopped server started (its charges resumed), RDP opened to the
whole internet and the rule letting SSH in removed, each second confirmation being only an argument. Its reads are asked
asked only from its page too since 0.1.6 (closed by default: the account's key makes them; `present` and
`status` alone are anyone's). Asked through the library's own App (its ask names who asks as the platform's does), over the
stand-in Google: nothing reaches Google or the network."""
from __future__ import annotations

import pytest

pytest.importorskip("liminal_libs.apps.asking", reason="no hook is asked only from its page before liminal-libs 1.66.0")

from conftest import HOME, PROJECT, SSH_ED25519, FakeGoogle, settings_of, ssh_public  # noqa: E402 - after the skip, as each
from liminal_libs import internal  # noqa: E402
from liminal_libs.apps import App, EnvironmentLogin, asking  # noqa: E402
from liminal_libs.machines.plugin import MachinePlugin  # noqa: E402
from plugin_platform_googlecloud import MACHINE  # noqa: E402
from plugin_platform_googlecloud import firewall as fw  # noqa: E402
from plugin_platform_googlecloud.sshkeys import fingerprint_of  # noqa: E402

CHANGES = ("start_server", "stop_server", "reset_server", "add_firewall_rule", "remove_firewall_rule", "set_record",
           "remove_record", "add_ssh_key", "remove_ssh_key", "ddns_update", "ddns_take_over")
READS = ("present", "status", "refresh", "servers", "firewalls", "domains", "records", "ssh_keys")
# 0.1.6, closed by default (the user, 2026-11-26: "Page-only"): the reads made with the account's key are its
# page's alone too; the contract's own two stay anyone's
OPEN_READS = ("present", "status")
PAGE_READS = tuple(h for h in READS if h not in OPEN_READS)
READ_ARGS = {'records': ('example-com',)}  # the argument a read takes, as another program words it
HOSTS = "new.example.com, @.example.com"  # Dynamic DNS's: one with no record yet, the domain itself holding another address
ALLOW_SSH = fw.describe(FakeGoogle().firewalls["default-allow-ssh"])  # the rule in words, as any read shows it
ASKED = {  # each change as another program worded it: the hook's arguments, a second confirmation said where it has one
    "start_server": ("us-central1-a", "batch-1", True),  # its charges resumed, "accepted"
    "stop_server": ("us-central1-a", "web-1"),
    "reset_server": ("europe-west1-b", "scratch-1", True),  # a hard reset, "accepted"
    "add_firewall_rule": ("rdp-anywhere", "default", "INGRESS", "allow", "tcp", "3389", "0.0.0.0/0", None, None, None, True),
    "remove_firewall_rule": ("default-allow-ssh", ALLOW_SSH, True),  # the rule letting SSH in
    "set_record": ("example-com", "www", "CNAME", "example.org."),  # the site's name, pointed at another's
    "remove_record": ("example-com", "@", "TXT", "v=spf1 include:_spf.google.com ~all"),
    "add_ssh_key": ("mallory", ssh_public()),  # a login with sudo on every server that takes the project's keys
    "remove_ssh_key": ("alice", fingerprint_of(SSH_ED25519.split()[1])),
    "ddns_update": (),
    "ddns_take_over": ("example.com", None, True),  # the domain's own address pointed at this network
}
COMPUTE, DNS = f"/compute/v1/projects/{PROJECT}", f"/dns/v1/projects/{PROJECT}/managedZones/example-com/changes"
SENT = [  # what the same asks send from the page, in CHANGES' order
    ("POST", f"{COMPUTE}/zones/us-central1-a/instances/batch-1/start"),
    ("POST", f"{COMPUTE}/zones/us-central1-a/instances/web-1/stop"),
    ("POST", f"{COMPUTE}/zones/europe-west1-b/instances/scratch-1/reset"),
    ("POST", f"{COMPUTE}/global/firewalls"), ("DELETE", f"{COMPUTE}/global/firewalls/default-allow-ssh"),
    ("POST", DNS), ("POST", DNS), ("POST", f"{COMPUTE}/setCommonInstanceMetadata"),
    ("POST", f"{COMPUTE}/setCommonInstanceMetadata"),
    ("POST", DNS),  # Update DNS now: new.example.com made, example.com left as it is
    ("POST", DNS),  # example.com taken over
]


def sent_by(fake) -> list[tuple[str, str]]:
    return [(r["method"], r["path"]) for r in fake.writes()]


class Neighbour(MachinePlugin):
    """Another plugin of the platform, asking Google Cloud's through its app as any plugin may (a container plugin, or
    the MCP plugin for a local agent)."""

    name, title = "neighbour", "Neighbour"

    def wants(self, hook, *args):
        """Not a hook: one of Google Cloud's asked through the app."""
        return self.app.ask("googlecloud", hook, *args)


class Platform(App):
    """The library's App asking as the platform does: from its page's route, the page named in so many words, or from
    its own code, no one named. It holds the plugin as the platform's one-shot commands do (`once`): the plugin's
    background reads and Dynamic DNS passes are not started, so every request the stand-in sees is an ask's."""

    NAME, TITLE, ICON = "platform", "Platform", "chip"
    once = True

    def from_page(self, hook, *args):
        """As the page's route asks a hook."""
        with asking.asking(asking.PAGE):
            return self.ask("googlecloud", hook, *args)

    def on_its_own(self, hook, *args):
        """As the app's own code asks a hook."""
        return self.ask("googlecloud", hook, *args)


@pytest.fixture
def attached(made):
    """The plugin over the stand-in Google, attached with another plugin to an app whose login holds its settings (the
    service account's key and two Dynamic DNS hosts); let go after."""
    plugin, fake = made()
    neighbour = Neighbour()
    app = Platform(log=lambda m: None, login=EnvironmentLogin(env=settings_of(GOOGLECLOUD_DDNS_HOSTS=HOSTS)))
    app.attach(plugin)
    app.attach(neighbour)
    yield app, plugin, neighbour, fake
    app.detach(neighbour.name)
    app.detach(plugin.name)


def test_its_changes_are_said_to_be_asked_only_from_its_page_and_its_reads_with_the_key_too():
    assert set(internal.page_only(MACHINE)) == {*CHANGES, *PAGE_READS}  # what the platform reads
    assert internal.plugin_only(MACHINE) == ()
    assert internal.problems(MACHINE) == []  # each a hook of its own, and someone may ask it
    assert set(CHANGES) | set(READS) == set(MACHINE.interface()["hooks"]) and set(ASKED) == set(CHANGES)
    for hook in (*CHANGES, *PAGE_READS):
        assert asking.refusal(MACHINE, hook, asking.PAGE) == ""
        assert asking.refusal(MACHINE, hook, "neighbour") == (f"googlecloud's {hook} is asked only from its page, "
                                                              "never by another plugin: neighbour asked it.")
        assert asking.refusal(MACHINE, hook, None).endswith("This ask names no asker: neither the page nor a plugin.")
    for hook in OPEN_READS:
        assert {asking.refusal(MACHINE, hook, who) for who in (asking.PAGE, "neighbour", None)} == {""}


def test_another_plugin_or_no_one_asking_a_change_sends_nothing_and_its_page_does(attached):
    app, plugin, neighbour, fake = attached
    for hook in CHANGES:
        for ask in (neighbour.wants, app.on_its_own):
            with pytest.raises(asking.AskRefused, match=f"googlecloud's {hook} is asked only from its page"):
                ask(hook, *ASKED[hook])
    for hook in PAGE_READS:  # 0.1.6: a read made with the key is refused them too, and nothing is sent for it
        for ask in (neighbour.wants, app.on_its_own):
            with pytest.raises(asking.AskRefused, match=f"googlecloud's {hook} is asked only from its page"):
                ask(hook, *READ_ARGS.get(hook, ()))
    assert fake.requests == []  # nothing sent, nor read: not a token asked for, not the read a change makes first
    assert neighbour.wants("present") is True and neighbour.wants("status")["valid"] is True  # the contract's reads, anyone's as before
    assert app.from_page("refresh") is not None
    assert [s["name"] for s in app.from_page("servers")] == ["web-1", "batch-1", "scratch-1"]
    assert len(app.from_page("records", "example-com")) == 8 and fake.writes() == []  # a row a value
    for hook in CHANGES:  # the same asks from its page: each one sent
        sent = len(fake.writes())
        assert app.from_page(hook, *ASKED[hook]) is not None
        assert len(fake.writes()) == sent + 1, hook
    assert sent_by(fake) == SENT
    keys = fake.metadata["items"][1]["value"]
    assert "mallory:" in keys and "alice:" not in keys
    apex = next(r for r in fake.rrsets["example-com"] if (r["name"], r["type"]) == ("example.com.", "A"))
    assert apex["rrdatas"] == [HOME]


def test_its_own_code_asks_nothing_of_the_app_and_runs_as_before(attached):
    """The background's Dynamic DNS pass and the command line call the plugin's code themselves: not an ask, so no asker
    is named and none is needed."""
    app, plugin, neighbour, fake = attached
    assert asking.asker() is None
    new, apex = plugin.ddns_update(force=False)["hosts"]
    assert new["ok"] is True and apex["foreign"] is True
    assert sent_by(fake) == [("POST", DNS)]


def test_no_hook_is_left_undeclared():
    """0.1.6, closed by default (liminal-libs 1.107.0): every hook it answers says who may ask it, so none is left to
    the default and the library's conformance has no warning. Read from its words, so it holds on an older library."""
    from liminal_libs.sources import conformance

    said = {h for word in ("READ_HOOKS", "SERVICE_HOOKS", "PLUGIN_ONLY_HOOKS", "PAGE_ONLY_HOOKS")
            for h in internal.declared(MACHINE, word)}
    own = [h for h in MACHINE.interface()["hooks"] if h not in ("setup", "run", "scan")]
    assert own and [h for h in own if h not in said] == []
    assert set(PAGE_READS) <= set(internal.declared(MACHINE, "PAGE_ONLY_HOOKS"))
    assert not set(PAGE_READS) & set(internal.declared(MACHINE, "READ_HOOKS"))  # none is opened again as a read
    warnings = getattr(conformance, "warnings", None)  # liminal-libs 1.107.0
    assert warnings is None or warnings(MACHINE) == []
