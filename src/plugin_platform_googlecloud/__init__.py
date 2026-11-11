"""Google Cloud for Liminal (the user, 2026-11-11: "lets roll plugins for EC2, vultr, azure and google cloud"; for the
clouds, "Free changes only"): a project through Google's own APIs. It shows everything (the project, its billing, the
servers of every zone with their state, machine type and addresses, the disks, the addresses, the VPC firewall rules
and the servers each reaches, the Cloud DNS zones and their records, the project-wide SSH keys, the regions in use and
their quotas, and a count of every other kind the project holds) and changes only what costs nothing, each change
confirmed first: a server stopped, or reset (hard: asked twice), a record set or removed (every other record kept), a
firewall rule added or removed (a risky one asked twice), a project-wide SSH key added or removed (with the metadata's
fingerprint), and Dynamic DNS keeping hosts of a public zone at this network's address, only those that are its own
(made by it, pointing here already, or taken over once the user confirmed it). The one change that starts a charge is
a server's start (its vCPUs and memory, and any GPU, bill again while it runs): asked twice, the charge named. No new
server, disk, snapshot, image or reserved address, no resize, nothing deleted but a firewall rule. A stopped server
still bills: its disks and static addresses keep billing while they exist (said on the page).

Its settings are pairs asked of the login of the app it is attached to (settings.py: GOOGLECLOUD_KEY, the service
account's JSON key itself; GOOGLECLOUD_PROJECT; GOOGLECLOUD_DDNS_HOSTS and GOOGLECLOUD_DDNS_MINUTES), never a file of its
own. Attached to the platform app (and only to it: the charts app run alone attaches every plugin it finds) it reads
the project every quarter of an hour and checks the Dynamic DNS hosts every few minutes in a thread of its own, with
the settings of the platform's login; detached, that thread ends before its next write and reads nothing more. Its
status is what was read last (no request is made to answer it): the platform's page draws its tables, its actions
(Refresh, Update DNS now) and its forms.

An audit before any key went in (2026-11-11) asked: Start asked twice; a firewall rule denying SSH, or letting anything
but the web's 80 and 443 in from the whole internet, asked twice; Dynamic DNS through the library's Keeper (a host
holding another address left as it is until taken over); a pass ending once the plugin is detached; a second
confirmation counted only when it is exactly true.

    python -m plugin_platform_googlecloud status | servers | domains | records ZONE | ddns [--now] | firewalls | keys
        | power NAME on|off|reboot | set ZONE NAME TYPE DATA [--ttl N] | remove ZONE NAME TYPE DATA
"""
from __future__ import annotations

import os
import re
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from liminal_libs.machines.ddns import Host, Keeper, hosts_of
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.machines.rest import RestError

from . import firewall as fw
from . import records as rec
from . import settings as settings_mod
from . import sshkeys
from .api import GoogleCloud, name_of
from .auth import Tokens
from .card import APIS, BILLING_NAME, COMPUTE_NAME, DNS_NAME, OAUTH_NAME
from .records import Refusal
from .settings import CONSOLE_KEYS, DDNS_HOSTS, KEY, KEYS, NAMES, Config

__version__ = "0.1.1"
REFRESH_S = 900.0  # the project read again at most this often while attached (or by Refresh)
CONFIG_S = 30.0  # the settings asked of the login again after this long
RETRY_S = 900.0  # a part that failed is taken as untried after this long while detached: attached again, it is tried again
SOON_S = (45.0, 150.0)  # after a power change, the project read again this long after it (a stop takes up to 120 s)
HOURLY_S = 3600.0  # the zones and the billing account read at most this often
ZONES_MAX = 12  # the Cloud DNS zones whose records a refresh reads (the rest: `records ZONE`)
MACHINE_TYPES_MAX = 24  # machine types read by one refresh (each read once; the rest the next time)
JOIN_S = 10.0  # detached, the background thread waited for this long; one still in a request ends before its next write
PLATFORM = "platform"  # the one app whose attaching starts the background reading (App.NAME)
DIR_VAR = "LIMINAL_PLATFORM_DIR"  # the platform's own folder (its app's variable): Dynamic DNS's state goes under it
# this network's public IPv4 address, asked of DNS (as the hw-stats plugin asks it): the name servers are named here
PUBLIC_IPV4 = (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
               ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))
ACCEPT_RESET = "accept_hard_reset"  # the hooks' arguments a second, explicit confirmation sets (a Refusal's accept)
ACCEPT_COSTS = "accept_costs"
ACCEPT_OPEN = "accept_open_to_internet"
ACCEPT_REMOVE = "accept_risky_removal"
ROLES = ("Compute Viewer (roles/compute.viewer) and DNS Reader (roles/dns.reader) for the reads, and for the free "
         "changes a custom role holding their permissions alone (the README lists them)")
NOT_SET = (f"not set up: {KEY}, a service account's JSON key, made in Google Cloud's console (IAM & Admin > Service "
           f"accounts > the account > Keys > Add key > JSON: {CONSOLE_KEYS}), the account given {ROLES}")
STOPPED_BILLS = "a stopped server's disks and static addresses keep billing: Compute Engine bills them while they exist"
NO_PRICES = "not in Google's APIs: the pricing pages are on the Compute Engine API's card below"
STATES = {"RUNNING": "running", "TERMINATED": "stopped", "STOPPING": "stopping", "PENDING_STOP": "stopping",
          "PROVISIONING": "provisioning", "STAGING": "staging", "SUSPENDING": "suspending", "SUSPENDED": "suspended",
          "REPAIRING": "repairing"}
CUSTOM = re.compile(r"(?:^|-)custom-(\d+)-(\d+)(?:-ext)?$")  # a custom machine type: its vCPUs and memory in its name
READ_ERRORS = (RestError, ValueError, TypeError, KeyError, AttributeError)  # a read's trouble, said in words


def accepted(value) -> bool:
    """A second confirmation counts only when it is exactly true (the page sends JSON true): "false", "yes" or 1 from
    a program of its own is refused like a missing one."""
    return value is True


def state_dir() -> Path:
    """Where the plugin keeps what Dynamic DNS holds as its own: the platform's folder's googlecloud/ (LIMINAL_PLATFORM_DIR,
    else the data folder's platform/)."""
    named = (os.environ.get(DIR_VAR) or "").strip()
    if named:
        return Path(named).expanduser() / "googlecloud"
    from liminal_libs import layout

    return layout.data_dir() / "platform" / "googlecloud"


class Detached(RuntimeError):
    """The plugin was detached while its background pass ran: nothing more is read or written."""


def when(t: float | None) -> str:
    return "–" if not t else time.strftime("%b %d %H:%M", time.localtime(t))


def day(stamp) -> str:
    """An RFC 3339 time's day (2026-11-11), as Google writes them."""
    s = str(stamp or "")
    return s[:10] if re.match(r"^\d{4}-\d{2}-\d{2}", s) else "–"


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n:,} {word if n == 1 else many or word + 's'}"


def cell(text, sub: str | None = None):
    return {"text": text, "sub": sub} if sub else text


def number(v) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return f"{int(f):,}" if f == int(f) else f"{f:,.1f}"


def metric_words(metric: str) -> str:
    return str(metric or "").replace("_", " ").lower()


def shorten(text: str, most: int = 200) -> str:
    t = " ".join(str(text).split())
    return t if len(t) <= most else t[: most - 1] + "…"


@dataclass
class Outcome:
    """A part's last read (compute, dns): worked (None: not tried), its trouble, when, the settings it is of."""

    ok: bool | None = None
    error: str = ""
    at: float | None = None
    print: str = ""


class _Runtime:
    """What the plugin read and holds, shared by its copies (the registry's with_ makes them)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.config: tuple[float, Config] | None = None
        self.entered = 0  # settings entered on the page so far (settings_changed): the background reads them anew too
        self.client: tuple[str, Tokens, GoogleCloud] | None = None
        self.keeper: Keeper | None = None
        self.project: dict | None = None
        self.instances: list[dict] = []
        self.disks: list[dict] = []
        self.addresses: list[dict] = []
        self.firewalls: list[dict] = []
        self.regions: list[dict] = []
        self.zones: dict[str, dict] = {}
        self.zones_at: float | None = None
        self.machine_types: dict[tuple[str, str], dict] = {}
        self.notes: list[str] = []  # the last compute read's scopes not reached
        self.billing: dict | None = None
        self.billing_error = ""
        self.account: dict | None = None
        self.account_at: float | None = None
        self.account_error = ""
        self.dns_zones: list[dict] | None = None
        self.records: dict[str, list[dict] | str] = {}
        self.refreshed_at: float | None = None
        self.parts = {"compute": Outcome(), "dns": Outcome()}
        self.ddns_print = ""
        self.ddns_seen: set[str] = set()  # the Dynamic DNS hosts of the settings as last seen (one taken out: let go)
        self.passing = threading.Lock()  # one Dynamic DNS pass at a time, with its settings and stop below
        self.pass_cfg: Config | None = None
        self.pass_stop: threading.Event | None = None
        self.worker: threading.Thread | None = None
        self.stop: threading.Event | None = None
        self.lingering: list[threading.Thread] = []  # a detached thread still ending a request (it writes nothing more)
        self.wake = threading.Event()
        self.refreshing = threading.Lock()
        self.soon: list[float] = []  # monotonic times the project is read again (after a power change)


class GoogleCloudPlugin(MachinePlugin):
    """Google Cloud: a project through Google's APIs, the free changes confirmed, Dynamic DNS through Cloud DNS;
    reading in the background while attached."""

    name = "googlecloud"
    title = "Google Cloud"
    about = ("A Google Cloud project through Google's APIs: its servers, disks, addresses, firewall rules, Cloud DNS "
             "zones and project-wide SSH keys; the free changes (power, records, rules, keys) each confirmed, and "
             "Dynamic DNS through Cloud DNS")
    api = "2.2"
    version = __version__
    order = 765
    ICON = "googlecloud"  # Google Cloud's mark (liminal-libs 1.49.0's icons.js)
    HOOKS = (*MachinePlugin.HOOKS, "refresh", "servers", "start_server", "stop_server", "reset_server", "firewalls",
             "add_firewall_rule", "remove_firewall_rule", "domains", "records", "set_record", "remove_record",
             "ssh_keys", "add_ssh_key", "remove_ssh_key", "ddns_update", "ddns_take_over")
    keys = KEYS
    signup = CONSOLE_KEYS
    limits = ("Compute Engine: rate quotas per project and minute (its Quotas page), 36 project metadata writes a "
              "minute; Cloud DNS: a change at most 1,000 additions and 1,000 deletions; Cloud Billing: 300 calls a "
              "minute; the plugin: about a dozen reads every quarter of an hour, a token an hour")
    apis = APIS

    def __init__(self, transport=None, public=None, clock=None, sleep=None, folder: Path | None = None):
        self._transport = transport  # (method, url, headers, body, timeout) -> (status, headers, body): a test's
        self._public = public  # () -> (this network's IPv4 address, whose): a test's; else DNS (PUBLIC_IPV4)
        self._clock = clock or time.time
        self._sleep = sleep or time.sleep
        self._folder = Path(folder) if folder is not None else None  # Dynamic DNS's state: a test's; else state_dir()
        self._rt = _Runtime()

    # -- the settings, the client, the keeper ----------------------------------------------------------------------------
    def config(self, fresh: bool = False) -> Config:
        """The settings, asked of the login (the attached app's, else the environment's); kept CONFIG_S."""
        now = time.monotonic()
        with self._rt.lock:
            kept = self._rt.config
        if kept is not None and not fresh and now - kept[0] < CONFIG_S:
            return kept[1]
        cfg = settings_mod.read(self.login)
        with self._rt.lock:
            self._rt.config = (now, cfg)
        return cfg

    def settings_changed(self) -> None:
        """Its settings were just entered (the platform's Settings…, kept through the login): read anew at once, by the
        background too."""
        with self._rt.lock:
            self._rt.config = None
            self._rt.entered += 1
        self._rt.wake.set()

    def client(self, cfg: Config | None = None) -> GoogleCloud:
        """The APIs with the settings as they are (`cfg`: as the background read them; else asked now), ValueError when
        they are not set. A new key or project: what was read of the old one is let go."""
        cfg = cfg if cfg is not None else self.config()
        if not cfg.ready:
            raise ValueError(self._not_ready(cfg))
        with self._rt.lock:
            held = self._rt.client
        if held is not None and held[0] == cfg.api_print:
            return held[2]
        tokens = Tokens(cfg.key, transport=self._transport, clock=self._clock, sleep=self._sleep)
        made = GoogleCloud(cfg.project, tokens, forget=tokens.forget, transport=self._transport, secrets=cfg.secrets,
                           clock=self._clock, sleep=self._sleep)
        with self._rt.lock:
            if self._rt.client is not None and self._rt.client[0] != cfg.api_print:
                rt = self._rt
                rt.project, rt.instances, rt.disks, rt.addresses, rt.firewalls, rt.regions = None, [], [], [], [], []
                rt.zones, rt.zones_at, rt.machine_types, rt.notes = {}, None, {}, []
                rt.billing, rt.billing_error, rt.account, rt.account_at, rt.account_error = None, "", None, None, ""
                rt.dns_zones, rt.records, rt.refreshed_at = None, {}, None
            self._rt.client = (cfg.api_print, tokens, made)
        return made

    @staticmethod
    def _not_ready(cfg: Config) -> str:
        if KEY not in cfg.present:
            return NOT_SET
        return "; ".join(cfg.problems) or NOT_SET

    @property
    def state_file(self) -> Path:
        """Dynamic DNS's own: the addresses it set or found pointing here, and the hosts it was let take over."""
        return (self._folder if self._folder is not None else state_dir()) / "ddns.json"

    def keeper(self) -> Keeper:
        with self._rt.lock:
            if self._rt.keeper is None:
                self._rt.keeper = Keeper(read=self._ddns_read, write=self._ddns_write, servers=PUBLIC_IPV4,
                                         public=self._public, clock=self._clock, state=self.state_file)
            return self._rt.keeper

    # -- the hooks: reads --------------------------------------------------------------------------------------------------
    def present(self) -> bool:
        """Whether anything of it is set."""
        return bool(self.config().present)

    def refresh(self) -> dict:
        """The project read again now (a dozen requests or so): what the status shows until the next."""
        cfg = self.config(fresh=True)
        if not cfg.ready:
            raise ValueError(self._not_ready(cfg))
        if not self._rt.refreshing.acquire(timeout=120):
            raise RuntimeError("a refresh is under way")
        try:
            return self._refresh(cfg)
        finally:
            self._rt.refreshing.release()

    def _refresh(self, cfg: Config, stop: threading.Event | None = None) -> dict:
        """The project read with `cfg` (the background's `stop` set: it ends at the next part, keeping nothing more)."""
        now = self._clock()
        api = self.client(cfg)
        troubles: dict[str, str] = {}
        try:
            self._read_compute(api, now, stop)
        except Detached:
            return {"servers": 0, "zones": 0, "readAt": when(now), "troubles": ["detached"]}
        except READ_ERRORS as e:
            troubles["compute"] = _words(e)
        if stop is not None and stop.is_set():
            return {"servers": 0, "zones": 0, "readAt": when(now), "troubles": ["detached"]}
        self._read_billing(api, now)
        try:
            self._read_dns(api, stop)
        except Detached:
            return {"servers": 0, "zones": 0, "readAt": when(now), "troubles": ["detached"]}
        except READ_ERRORS as e:
            troubles["dns"] = _words(e)
        with self._rt.lock:
            for part in ("compute", "dns"):
                o = self._rt.parts[part]
                o.ok, o.error, o.at, o.print = part not in troubles, troubles.get(part, ""), now, cfg.api_print
            if "compute" not in troubles or "dns" not in troubles:
                self._rt.refreshed_at = now
        if len(troubles) == 2:
            raise RestError(f"Compute Engine: {troubles['compute']}; Cloud DNS: {troubles['dns']}")
        with self._rt.lock:
            servers, zones = len(self._rt.instances), len(self._rt.dns_zones or [])
        return {"servers": servers, "zones": zones, "readAt": when(now),
                "troubles": [f"{'Compute Engine' if p == 'compute' else 'Cloud DNS'}: {t}" for p, t in troubles.items()]}

    @staticmethod
    def _going_on(stop: threading.Event | None) -> None:
        if stop is not None and stop.is_set():
            raise Detached("the plugin was detached: nothing more is read or written")

    def _read_compute(self, api: GoogleCloud, now: float, stop: threading.Event | None = None) -> None:
        project = api.project_info()
        instances, notes = api.instances()
        disks, more = api.disks()
        notes += more
        addresses, more = api.addresses()
        notes += more
        self._going_on(stop)
        firewalls = api.firewalls()
        regions = api.regions()
        with self._rt.lock:
            zones, zones_at, types = dict(self._rt.zones), self._rt.zones_at, dict(self._rt.machine_types)
        if not zones or zones_at is None or now - zones_at >= HOURLY_S:
            zones, zones_at = {str(z.get("name")): z for z in api.zones()}, now
        asked = 0
        for inst in instances:
            key = (name_of(inst.get("zone")), name_of(inst.get("machineType")))
            if key in types or not all(key):
                continue
            m = CUSTOM.search(key[1])
            if m:
                types[key] = {"guestCpus": int(m.group(1)), "memoryMb": int(m.group(2)), "custom": True}
                continue
            if asked >= MACHINE_TYPES_MAX:
                continue
            self._going_on(stop)
            asked += 1
            try:
                types[key] = api.machine_type(*key)
            except RestError:
                types[key] = {}  # its name alone shown; not asked again until the plugin starts again
        self._going_on(stop)
        with self._rt.lock:
            rt = self._rt
            rt.project, rt.instances, rt.disks, rt.addresses, rt.firewalls = project, instances, disks, addresses, firewalls
            rt.regions, rt.zones, rt.zones_at, rt.machine_types, rt.notes = regions, zones, zones_at, types, notes

    def _read_billing(self, api: GoogleCloud, now: float) -> None:
        """The project's billing info, and its account at most hourly: troubles kept as words, never failing the read."""
        try:
            info, error = api.billing_info(), ""
        except READ_ERRORS as e:
            info, error = None, _words(e)
        with self._rt.lock:
            self._rt.billing, self._rt.billing_error = info, error
            account_at = self._rt.account_at
        name = (info or {}).get("billingAccountName") or ""
        if name and (account_at is None or now - account_at >= HOURLY_S):
            try:
                account, why = api.billing_account(name), ""
            except READ_ERRORS as e:
                account, why = None, _words(e)
            with self._rt.lock:
                self._rt.account, self._rt.account_error, self._rt.account_at = account, why, now

    def _read_dns(self, api: GoogleCloud, stop: threading.Event | None = None) -> None:
        zones = api.managed_zones()
        found: dict[str, list[dict] | str] = {}
        for z in zones[:ZONES_MAX]:
            self._going_on(stop)
            try:
                found[str(z.get("name"))] = api.rrsets(str(z.get("name")))
            except READ_ERRORS as e:
                found[str(z.get("name"))] = _words(e)
        for z in zones[ZONES_MAX:]:
            found[str(z.get("name"))] = (f"not read with the rest (more than {ZONES_MAX} zones): "
                                         f"python -m plugin_platform_googlecloud records {z.get('name')}")
        self._going_on(stop)
        with self._rt.lock:
            self._rt.dns_zones, self._rt.records = zones, found

    def servers(self) -> list[dict]:
        """The servers as last read (Refresh reads them again), in plain fields."""
        with self._rt.lock:
            instances, addresses, types = list(self._rt.instances), list(self._rt.addresses), dict(self._rt.machine_types)
        static = _static_ips(addresses)
        out = []
        for inst in instances:
            ext4, ext6 = _external(inst)
            mt = types.get((name_of(inst.get("zone")), name_of(inst.get("machineType")))) or {}
            out.append({"name": inst.get("name"), "zone": name_of(inst.get("zone")), "status": inst.get("status"),
                        "machineType": name_of(inst.get("machineType")), "vcpus": mt.get("guestCpus"),
                        "memoryMb": mt.get("memoryMb"), "ipv4": ext4, "ipv6": ext6,
                        "static": [ip for ip in ext4 if ip in static], "created": inst.get("creationTimestamp"),
                        "spot": _spot(inst)})
        return out

    def firewalls(self) -> list[dict]:
        """The VPC firewall rules as last read, each with the servers it reaches."""
        with self._rt.lock:
            rules, instances = list(self._rt.firewalls), list(self._rt.instances)
        return [{"name": r.get("name"), "network": fw.network_of(r), "rule": fw.describe(r),
                 "reaches": fw.reaches(r, instances), "disabled": bool(r.get("disabled"))} for r in rules]

    def domains(self) -> list[dict]:
        """The Cloud DNS zones, read now."""
        zones = self.client().managed_zones()
        with self._rt.lock:
            self._rt.dns_zones = zones
        return [{"name": z.get("name"), "dnsName": z.get("dnsName"), "visibility": z.get("visibility"),
                 "dnssec": (z.get("dnssecConfig") or {}).get("state") or "off", "nameServers": z.get("nameServers") or []}
                for z in zones]

    def records(self, zone: str) -> list[dict]:
        """A zone's records (by its name or its DNS name), read now."""
        z = self._zone(zone, fresh=True)
        sets = self.client().rrsets(str(z.get("name")))
        with self._rt.lock:
            self._rt.records[str(z.get("name"))] = sets
        return [{"name": n, "type": t, "ttl": ttl, "data": v} for n, t, ttl, v, _ in rec.rows_of(sets)]

    def ssh_keys(self) -> list[dict]:
        """The project-wide SSH keys as last read."""
        with self._rt.lock:
            project = self._rt.project
        return [e.describe() for e in sshkeys.entries(_items(project))]

    # -- the hooks: the free changes --------------------------------------------------------------------------------------
    def start_server(self, zone: str, instance: str, accept_costs=False) -> dict:
        """A stopped server started: its vCPUs and memory (and any GPU) bill again while it runs, so it is started only
        once that is accepted (asked twice), the charge named."""
        api, inst = self._fresh(zone, instance)
        if inst.get("status") not in ("TERMINATED",):
            raise Refusal(f"{instance} is {STATES.get(str(inst.get('status')), inst.get('status'))}: only a stopped server is started")
        if not accepted(accept_costs):
            with self._rt.lock:
                types = dict(self._rt.machine_types)
            raise Refusal(f"starting {instance} resumes its charges: {_start_charges(inst, types)}; its disks and "
                          "static addresses bill already. Started only once that is accepted", accept=ACCEPT_COSTS)
        op = api.start(zone, instance)
        self._soon()
        return {"said": f"asked Google to start {instance}", "ok": True, "operation": op.get("name"),
                "lines": [f"operation {op.get('name') or '?'}: {op.get('status') or 'sent'}",
                          "its vCPUs and memory bill again while it runs", "the servers are read again in a minute or so"]}

    def stop_server(self, zone: str, instance: str) -> dict:
        """A running server shut down gracefully (its disks and static addresses keep billing)."""
        api, inst = self._fresh(zone, instance)
        if inst.get("status") not in ("RUNNING", "PROVISIONING", "STAGING", "REPAIRING"):
            raise Refusal(f"{instance} is {STATES.get(str(inst.get('status')), inst.get('status'))}: only a running server is stopped")
        if _local_ssd(inst):
            raise Refusal(f"{instance} has a Local SSD: stopping it discards or keeps that data as you choose, so it is "
                          "stopped in the console (Compute Engine > VM instances), not here")
        op = api.stop(zone, instance)
        self._soon()
        with self._rt.lock:
            addresses = list(self._rt.addresses)
        return {"said": f"asked Google to stop {instance}", "ok": True, "operation": op.get("name"),
                "lines": [f"operation {op.get('name') or '?'}: {op.get('status') or 'sent'}",
                          *_stop_lines(inst, addresses), "the servers are read again in a minute or so"]}

    def reset_server(self, zone: str, instance: str, accept_hard_reset=False) -> dict:
        """A running server reset: hard, its guest given no shutdown; done only once that is accepted (asked twice)."""
        api, inst = self._fresh(zone, instance)
        if inst.get("status") != "RUNNING":
            raise Refusal(f"{instance} is {STATES.get(str(inst.get('status')), inst.get('status'))}: only a running server is reset")
        if not accepted(accept_hard_reset):
            raise Refusal(f"a reset of {instance} is hard: Compute Engine restarts it at once without an ACPI shutdown "
                          "signal, so unsaved data is lost and its disks' file systems may be corrupted (it stays "
                          "running, and billing, throughout); done only once that is accepted", accept=ACCEPT_RESET)
        op = api.reset(zone, instance)
        self._soon()
        return {"said": f"asked Google to reset {instance}", "ok": True, "operation": op.get("name"),
                "lines": [f"operation {op.get('name') or '?'}: {op.get('status') or 'sent'}",
                          "its guest was given no shutdown: check its services once it is back"]}

    def add_firewall_rule(self, name: str, network: str = "default", direction: str = "INGRESS", action: str = "allow",
                          protocol: str = "tcp", ports=None, ranges=None, target_tags=None, priority=None,
                          description=None, accept_open_to_internet=False) -> dict:
        """A VPC firewall rule added (free; its logging left off); one letting anything but the web's ports 80 and 443
        in from the whole internet, or denying SSH, only once that is accepted (asked twice)."""
        body = fw.build(name, network, direction, action, protocol, ports, ranges, target_tags, priority, description)
        api = self.client()
        rules = api.firewalls()
        if any(r.get("name") == body["name"] for r in rules):
            raise Refusal(f"a rule named {body['name']} is there already: choose another name")
        with self._rt.lock:
            self._rt.firewalls = rules
            instances = list(self._rt.instances)
        risky = fw.risky_addition(body, instances)
        if risky and not accepted(accept_open_to_internet):
            raise Refusal(f"{risky}: added only once that is accepted", accept=ACCEPT_OPEN)
        done = api.wait_global(api.add_firewall(body))
        self._reread_rules(api)
        reached = fw.reaches(body, instances)
        return {"said": f"added {body['name']}: {fw.describe(body)}", "ok": True,
                "lines": [_op_line(done), f"it reaches {', '.join(reached) if reached else 'no server read'}",
                          "VPC firewall rules cost nothing (its logging is off)"]}

    def remove_firewall_rule(self, name: str, accept_risky_removal=False) -> dict:
        """A VPC firewall rule removed; the one letting SSH or RDP in to a server it reaches (or denying ingress to one)
        only once that is accepted (asked twice)."""
        n = str(name or "").strip()
        api = self.client()
        rules = api.firewalls()
        rule = next((r for r in rules if r.get("name") == n), None)
        with self._rt.lock:
            self._rt.firewalls = rules
            instances = list(self._rt.instances)
        if rule is None:
            raise Refusal(f"no firewall rule named {n!r} in the project")
        risky = fw.risky_removal(rule, instances)
        if risky and not accepted(accept_risky_removal):
            raise Refusal(f"{risky}; removed only once that is accepted", accept=ACCEPT_REMOVE)
        done = api.wait_global(api.remove_firewall(n))
        self._reread_rules(api)
        return {"said": f"removed {n} ({fw.describe(rule)})", "ok": True,
                "lines": [_op_line(done), "what it let in or kept out is decided by the rules left (a network denies "
                                          "ingress unless a rule allows it)"]}

    def set_record(self, zone: str, name: str, rtype: str, data: str, ttl=None) -> dict:
        """A record set in a Cloud DNS zone: one change, the name's record set of the type deleted exactly as read and
        added back with the value (A, AAAA, CNAME: in place of its values; TXT, MX, CAA, SRV, NS: beside them)."""
        z = self._zone(zone)
        api = self.client()
        full = rec.fqdn(name, z)
        additions, deletions, words = rec.plan_set(z, full, rtype, data, ttl, api.rrsets(str(z["name"]), name=full))
        return self._change(api, z, additions, deletions, words)

    def remove_record(self, zone: str, name: str, rtype: str, data: str) -> dict:
        """One value of a record set removed (the set itself when it is its last), every other record kept."""
        z = self._zone(zone)
        api = self.client()
        full = rec.fqdn(name, z)
        additions, deletions, words = rec.plan_remove(z, full, rtype, data, api.rrsets(str(z["name"]), name=full))
        return self._change(api, z, additions, deletions, words)

    def _change(self, api: GoogleCloud, z: Mapping, additions: list, deletions: list, words: str) -> dict:
        if not additions and not deletions:
            return {"said": words, "lines": [], "ok": True, "changed": False}
        try:
            change = api.change(str(z["name"]), additions, deletions)
        except RestError as e:
            if e.status == 0 or e.status >= 500:  # no answer, or Google's own trouble: it may have been made
                raise RestError(f"the change ({words}) was sent but no answer said whether it was made: {e}. Refresh "
                                "shows the zone as it is; sending it again is safe (a deletion that no longer matches "
                                "is refused)", e.status, e.code, e.request_id) from None
            raise RestError(f"the change ({words}) was refused, nothing changed: {e}", e.status, e.code, e.request_id) from None
        try:
            sets = api.rrsets(str(z["name"]))
            with self._rt.lock:
                self._rt.records[str(z["name"])] = sets
        except READ_ERRORS:
            pass  # the change is made; the table is read again with the rest
        status = change.get("status") or "pending"
        return {"said": words, "ok": True, "changed": True, "change": change.get("id"),
                "lines": [f"Cloud DNS change {change.get('id') or '?'}: {status} (done once sent to the zone's name servers)",
                          "every other record of the zone kept"]}

    def add_ssh_key(self, user: str, key: str) -> dict:
        """A project-wide SSH key added: the metadata read afresh, its ssh-keys alone changed, written with its fingerprint."""
        return self._metadata(lambda items: sshkeys.plan_add(items, user, key))

    def remove_ssh_key(self, user: str, fingerprint: str) -> dict:
        """A project-wide SSH key removed (by its user and fingerprint), every other key and item kept."""
        return self._metadata(lambda items: sshkeys.plan_remove(items, user, fingerprint))

    def _metadata(self, plan) -> dict:
        api = self.client()
        project = api.project_info()
        meta = project.get("commonInstanceMetadata") or {}
        items = [x for x in meta.get("items") or [] if isinstance(x, Mapping)]
        fingerprint = str(meta.get("fingerprint") or "")
        with self._rt.lock:
            self._rt.project = project
        new_items, words = plan(items)
        if new_items is None:
            return {"said": words, "lines": [], "ok": True, "changed": False}
        if not fingerprint:
            raise Refusal("the project's metadata came without its fingerprint: nothing is written without it")
        if not sshkeys.only_keys_changed(items, new_items):
            raise RuntimeError("the metadata planned differs beyond its ssh-keys: nothing was written")
        try:
            op = api.set_metadata(fingerprint, new_items)
        except RestError as e:
            if e.status == 412:
                raise RestError("the project's metadata changed since it was read (another change came first): nothing "
                                f"was written; Refresh and try again ({e})", 412, e.code) from None
            raise
        done = api.wait_global(op)
        after = api.project_info()
        with self._rt.lock:
            self._rt.project = after
        after_items = _items(after)
        wanted = sshkeys.item(new_items, sshkeys.KEY)
        ok = sshkeys.item(after_items, sshkeys.KEY) == wanted
        kept = sshkeys.only_keys_changed(items, after_items)
        lines = [_op_line(done),
                 "read back: the project's ssh-keys as written" if ok
                 else "read back: the project's ssh-keys differ from what was written",
                 "every other metadata item kept" if kept else "other metadata items differ from before (another change since?)"]
        if sshkeys.os_login(after_items):
            lines.append("OS Login is on for the project: its servers ignore these keys")
        return {"said": words, "ok": ok and kept, "changed": True, "lines": lines}

    def ddns_update(self, force: bool = True) -> dict:
        """A Dynamic DNS pass now (the page's Update DNS now, once confirmed: `force`, each host that is its own set
        whether it differs or not; the command line's `ddns` without --now sets only those that differ). A host holding
        another address is left as it is (Take over… on the page)."""
        cfg = self.config(fresh=True)
        if not cfg.ddns_ready:
            raise ValueError(f"Dynamic DNS is not set up: {DDNS_HOSTS} is not set" if cfg.ready else self._not_ready(cfg))
        hosts = self._ddns_pass(cfg, force=bool(force))
        left = [h for h in hosts if h.get("foreign")]
        return {"said": f"Dynamic DNS: {plural(len(hosts), 'host')} checked" + (f", {len(left)} left as it is" if left else ""),
                "ok": all(h.get("ok") is not False or h.get("foreign") for h in hosts), "hosts": hosts,
                "lines": [f"{h['host']}: {h['result']}" for h in hosts]}

    def ddns_take_over(self, host: str, holds=None) -> dict:
        """A Dynamic DNS host the user let the keeper take over (the page's Take over…, once confirmed: `holds`, what the
        record held as the page showed it), then a pass for it: its A record pointed at this network's address."""
        cfg = self.config(fresh=True)
        if not cfg.ddns_ready:
            raise ValueError(f"Dynamic DNS is not set up: {DDNS_HOSTS} is not set" if cfg.ready else self._not_ready(cfg))
        want = str(host or "").strip().rstrip(".").lower()
        hosts, _ = self._hosts(cfg, read=True)
        found = next((h for h in hosts if h.fqdn == want), None)
        if found is None:
            raise Refusal(f"{want or '(no host)'} is none of the Dynamic DNS hosts set ({DDNS_HOSTS}) in a public zone")
        self.keeper().take_over(found.fqdn)
        states = self._ddns_pass(cfg, force=False, only=found.fqdn)
        state = states[0] if states else {"host": found.fqdn, "ok": None, "result": "not checked yet"}
        lines = ([f"it held {holds}"] if holds else []) + ["kept at this network's address from now on"]
        return {"said": f"{found.fqdn} taken over: {state['result']}", "ok": state.get("ok") is not False,
                "host": state, "lines": lines}

    def _ddns_pass(self, cfg: Config, force: bool, wait: float = 120.0, stop: threading.Event | None = None,
                   only: str | None = None) -> list[dict]:
        """A pass over the hosts of `cfg` (`only`: that one) with `cfg`'s client; `stop` (the background's) set ends it
        before its next write. A host taken out of the settings is let go first."""
        if not self._rt.passing.acquire(timeout=max(0.0, wait)):
            raise RuntimeError("a Dynamic DNS pass is under way")
        try:
            self._rt.pass_cfg, self._rt.pass_stop = cfg, stop
            self._let_go(cfg)
            hosts, _ = self._hosts(cfg, read=True)
            if only is not None:
                hosts = [h for h in hosts if h.fqdn == only]
            out = self.keeper().run_pass(hosts, force=force, wait=wait, stop=stop)
            with self._rt.lock:
                self._rt.ddns_print = cfg.ddns_print
            return out
        finally:
            self._rt.pass_cfg, self._rt.pass_stop = None, None
            self._rt.passing.release()

    def _let_go(self, cfg: Config) -> None:
        """The hosts taken out of the settings since they were last seen: no longer the keeper's own."""
        now = {_fqdn(x) for x in re.split(r"[,;\s]+", cfg.hosts) if x.strip()}
        with self._rt.lock:
            gone, self._rt.ddns_seen = self._rt.ddns_seen - now, now
        for fqdn in sorted(gone):
            self.keeper().let_go(fqdn)

    # -- Dynamic DNS through Cloud DNS ------------------------------------------------------------------------------------
    def _public_zones(self) -> list[dict]:
        with self._rt.lock:
            zones = list(self._rt.dns_zones or [])
        return [z for z in zones if str(z.get("visibility") or "public") == "public" and not rec.unwritable(z)]

    def _hosts(self, cfg: Config, read: bool = False) -> tuple[list[Host], list[str]]:
        """The Dynamic DNS hosts of the settings, each in a public zone of the project (the zones read first when none
        is known yet and `read`), and in words the ones in none."""
        with self._rt.lock:
            known = self._rt.dns_zones is not None
        if read and not known:
            try:
                zones = self.client(cfg).managed_zones()
                with self._rt.lock:
                    self._rt.dns_zones = zones
            except READ_ERRORS:
                pass
        names = [rec.undot(z.get("dnsName")) for z in self._public_zones()]
        hosts, wrong = hosts_of(cfg.hosts, zones=names)
        return hosts, [f"{DDNS_HOSTS}: {w} (its public Cloud DNS zones)" for w in wrong]

    def _zone_of(self, host: Host) -> dict:
        for z in self._public_zones():
            if rec.undot(z.get("dnsName")).lower() == host.zone.lower():
                return z
        raise Refusal(f"{host.fqdn} is in no public Cloud DNS zone of the project")

    def _pass_client(self) -> GoogleCloud:
        """The client of the pass under way, with its settings (never read anew from a login once it began)."""
        self._going_on(self._rt.pass_stop)
        return self.client(self._rt.pass_cfg)

    def _ddns_read(self, host: Host) -> list[str]:
        z = self._zone_of(host)
        full = rec.dot(host.fqdn)
        for s in self._pass_client().rrsets(str(z["name"]), name=full, rtype="A"):
            if str(s.get("type")) == "A" and rec.dot(s.get("name")) == full:
                return [str(v) for v in s.get("rrdatas") or []]
        return []

    def _ddns_write(self, host: Host, ip: str) -> str:
        """The host's A record set to `ip` alone: read afresh, and left as it is if it changed meanwhile to what is not
        the keeper's own (another address, or several); one change, its old record set deleted exactly as read."""
        z = self._zone_of(host)
        api = self._pass_client()
        full = rec.dot(host.fqdn)
        at_name = api.rrsets(str(z["name"]), name=full)
        held = next(([str(v) for v in s.get("rrdatas") or []] for s in at_name
                     if str(s.get("type")) == "A" and rec.dot(s.get("name")) == full), [])
        keeper = self.keeper()
        if held and held != [ip] and not keeper.taken(host.fqdn) and held != [keeper.own(host.fqdn)]:
            raise Refusal(f"it changed meanwhile to {', '.join(held)}: left as it is")
        additions, deletions, _ = rec.plan_set(z, full, "A", ip, None, at_name)
        if not additions:
            return "current"
        self._going_on(self._rt.pass_stop)
        api.change(str(z["name"]), additions, deletions)
        return "set" if deletions else "made"

    # -- what the changes stand on ----------------------------------------------------------------------------------------
    def _fresh(self, zone: str, instance: str) -> tuple[GoogleCloud, dict]:
        """A server among those read (else refused: Refresh first), read afresh."""
        z, n = str(zone or "").strip(), str(instance or "").strip()
        with self._rt.lock:
            known = any(name_of(i.get("zone")) == z and i.get("name") == n for i in self._rt.instances)
        if not known:
            raise Refusal(f"{n or '(no name)'} in {z or '(no zone)'} is not among the servers read: Refresh first")
        api = self.client()
        inst = api.instance(z, n)
        with self._rt.lock:
            self._rt.instances = [inst if (name_of(i.get("zone")) == z and i.get("name") == n) else i for i in self._rt.instances]
        return api, inst

    def _zone(self, zone: str, fresh: bool = False) -> dict:
        """A Cloud DNS zone by its name or its DNS name, among those read (read now when `fresh` or none is known)."""
        want = str(zone or "").strip().lower()
        with self._rt.lock:
            zones = self._rt.dns_zones
        if fresh or zones is None:
            zones = self.client().managed_zones()
            with self._rt.lock:
                self._rt.dns_zones = zones
        for z in zones or []:
            if want in (str(z.get("name") or "").lower(), rec.undot(z.get("dnsName")).lower(), str(z.get("dnsName") or "").lower()):
                return z
        raise Refusal(f"no Cloud DNS zone {zone!r} in the project (its zones: "
                      f"{', '.join(str(z.get('name')) for z in zones or []) or 'none'})")

    def _reread_rules(self, api: GoogleCloud) -> None:
        try:
            rules = api.firewalls()
        except READ_ERRORS:
            return
        with self._rt.lock:
            self._rt.firewalls = rules

    def _soon(self) -> None:
        now = time.monotonic()
        with self._rt.lock:
            self._rt.soon = sorted({*self._rt.soon, *(now + s for s in SOON_S)})
        self._rt.wake.set()

    # -- what it learned of its APIs ----------------------------------------------------------------------------------------
    def api_facts(self) -> dict:
        """What the answers said (RestClient.facts: the requests made, the last answer, its trouble) and when the
        project was last read; nothing asked to say it."""
        with self._rt.lock:
            held, read_at, types = self._rt.client, self._rt.refreshed_at, len(self._rt.machine_types)
        if held is None:
            return {}
        _, tokens, api = held
        compute = api.facts("compute")
        if read_at:
            compute["Last read"] = when(read_at)
        compute["Machine types kept"] = str(types)
        oauth = tokens.client.facts()
        oauth["Token"] = f"held until {time.strftime('%H:%M', time.localtime(tokens.until))}" if tokens.until else "none held"
        oauth["Tokens asked"] = str(tokens.asked)
        return {COMPUTE_NAME: compute, DNS_NAME: api.facts("dns"), BILLING_NAME: api.facts("billing"), OAUTH_NAME: oauth}

    # -- attached: the reading in the background --------------------------------------------------------------------------
    def attach(self, app, login=None) -> dict:
        """Attached: its settings asked of the app's login from now on. Attached by the platform (and by no other app:
        the charts app run alone attaches every plugin it finds), the project is read and the Dynamic DNS hosts checked
        in the background."""
        interface = super().attach(app, login)
        with self._rt.lock:
            self._rt.config = None
        if getattr(app, "NAME", "") == PLATFORM:
            self._start(login)
        return interface

    def detach(self) -> None:
        """Detached (the platform ending, the plugin disabled or not valid): the background reading ends, a request
        under way the last thing it does (nothing more read, nothing written)."""
        self._stop()
        super().detach()
        with self._rt.lock:
            self._rt.config = None

    @property
    def working(self) -> bool:
        """Whether a background thread of its own is alive (one detached but still ending a request too)."""
        with self._rt.lock:
            threads = [t for t in (self._rt.worker, *self._rt.lingering) if t is not None]
            self._rt.lingering = [t for t in self._rt.lingering if t.is_alive()]
        return any(t.is_alive() for t in threads)

    def _start(self, login) -> None:
        with self._rt.lock:
            if self._rt.worker is not None and self._rt.worker.is_alive():
                return
            stop = threading.Event()
            t = threading.Thread(target=self._work, args=(stop, login), name="googlecloud", daemon=True)
            self._rt.worker, self._rt.stop = t, stop
            self._rt.wake.clear()
        t.start()

    def _stop(self) -> None:
        with self._rt.lock:
            t, stop = self._rt.worker, self._rt.stop
            self._rt.worker = self._rt.stop = None
        if stop is not None:
            stop.set()
            self._rt.wake.set()
        if t is not None and t is not threading.current_thread():
            t.join(timeout=JOIN_S)
            if t.is_alive():  # still in a request: it ends there, reading and writing nothing more (its stop is set)
                with self._rt.lock:
                    self._rt.lingering.append(t)

    def _work(self, stop: threading.Event, login) -> None:
        """The background: the project read every REFRESH_S (and soon after a power change), the Dynamic DNS hosts
        checked every GOOGLECLOUD_DDNS_MINUTES, with the settings of the login it was attached with (asked again every
        CONFIG_S); nothing done for what is not set, and nothing at all once `stop` is set (detached)."""
        next_read = next_ddns = 0.0
        kept: tuple[float, int, Config] | None = None
        while not stop.is_set():
            now = time.monotonic()
            cfg = None
            try:
                with self._rt.lock:
                    entered = self._rt.entered
                if kept is None or now - kept[0] >= CONFIG_S or kept[1] != entered:
                    kept = (now, entered, settings_mod.read(login))
                cfg = kept[2]
                with self._rt.lock:
                    due_soon = bool(self._rt.soon) and self._rt.soon[0] <= now
                    if due_soon:
                        self._rt.soon = [t for t in self._rt.soon if t > now]
                if cfg.ready and (now >= next_read or due_soon) and not stop.is_set():
                    if now >= next_read:
                        next_read = now + REFRESH_S
                    if self._rt.refreshing.acquire(blocking=False):  # Refresh asked meanwhile: that one is enough
                        try:
                            self._refresh(cfg, stop)
                        except Exception:  # noqa: BLE001 - kept as its parts' outcome, shown by the status
                            pass
                        finally:
                            self._rt.refreshing.release()
                if cfg.ddns_ready and now >= next_ddns and not stop.is_set():
                    next_ddns = now + cfg.minutes * 60.0
                    try:
                        self._ddns_pass(cfg, force=False, wait=0.5, stop=stop)
                    except Exception:  # noqa: BLE001 - a pass under way (Update DNS now), or its trouble kept by the hosts
                        pass
            except Exception:  # noqa: BLE001 - the background never ends on a trouble; the status says it
                pass
            with self._rt.lock:
                soon = self._rt.soon[0] if self._rt.soon else None
            due = [t for t, on in ((next_read, cfg is not None and cfg.ready), (next_ddns, cfg is not None and cfg.ddns_ready),
                                   (soon or 0.0, soon is not None)) if on]
            wait = min([60.0, *(t - time.monotonic() for t in due)])
            self._rt.wake.wait(max(1.0, wait))  # Refresh, a power change or the detach (it sets the stop and this) wakes it
            self._rt.wake.clear()

    # -- what the platform's page shows -------------------------------------------------------------------------------------
    def status(self) -> dict:
        """What was read last, asking nothing of Google: the settings set (by name), the summary, valid (a part that
        works or is untried) and why not, the facts, the tables, the actions and the forms."""
        cfg = self.config()
        if not cfg.present:
            return {"present": False, "valid": False, "why": NOT_SET, "summary": "not set up",
                    "settingsNotSet": ", ".join(NAMES), "tables": [], "actions": [], "forms": []}
        out: dict = {"present": True, "settingsSet": ", ".join(n for n in NAMES if n in cfg.present)}
        missing = [n for n in NAMES if n not in cfg.present]
        if missing:
            out["settingsNotSet"] = ", ".join(missing)
        if not cfg.ready:
            out.update({"valid": False, "why": self._not_ready(cfg),
                        "summary": "the key cannot be used" if KEY in cfg.present else "not set up",
                        "tables": [], "actions": [], "forms": []})
            return out
        rt, now, attached = self._rt, self._clock(), self.app is not None
        with rt.lock:
            project, instances, disks, addresses = rt.project, list(rt.instances), list(rt.disks), list(rt.addresses)
            rules, regions, zones, types = list(rt.firewalls), list(rt.regions), dict(rt.zones), dict(rt.machine_types)
            billing, billing_error, account, account_error = rt.billing, rt.billing_error, rt.account, rt.account_error
            dns_zones, records, notes, read_at = rt.dns_zones, dict(rt.records), list(rt.notes), rt.refreshed_at
            parts = {p: Outcome(o.ok, o.error, o.at, o.print) for p, o in rt.parts.items()}
            keeper, ddns_print = rt.keeper, rt.ddns_print
        works: dict[str, bool | None] = {}
        for p, o in parts.items():
            w = o.ok if o.print == cfg.api_print else None
            if w is False and not attached and o.at is not None and now - o.at >= RETRY_S:
                w = None  # tried again once the platform attaches it
            works[p] = w
        hosts, wrong = self._hosts(cfg) if cfg.ddns_ready else ([], [])
        troubles = [f"{'Compute Engine' if p == 'compute' else 'Cloud DNS'}: {parts[p].error}" for p, w in works.items() if w is False]
        valid = any(w is not False for w in works.values())
        notes_all = [*cfg.problems, *wrong, *(f"not read: {n}" for n in notes[:4])]
        if billing_error and works.get("compute") is not False:
            notes_all.append(f"billing: {billing_error}")
        out["valid"] = valid
        if not valid:
            out["why"] = "; ".join(troubles) or NOT_SET
        elif troubles or notes_all:
            out["problem"] = "; ".join([*troubles, *notes_all])
        out["summary"] = self._summary(works, parts, instances, rules, dns_zones, billing, attached)
        out["project"] = cfg.project + ("" if cfg.project_given else " (the key's)")
        out["serviceAccount"] = cfg.account
        out["billing"] = _billing_words(billing, billing_error, account, account_error)
        out["balance"] = "not in Google's APIs: the console's Billing pages show the spend"
        if instances:
            out["servers"] = _servers_words(instances)
            out["stoppedServers"] = STOPPED_BILLS
        out["prices"] = NO_PRICES
        if read_at:
            out["readAt"] = when(read_at)
        if sshkeys.os_login(_items(project)):
            out["osLogin"] = "on for the project: its servers ignore the metadata's SSH keys"
        if cfg.ddns_ready:
            out["ddnsEvery"] = f"every {cfg.minutes:g} min" + ("" if attached else ", once attached")
        out["tables"] = self._tables(cfg, project, instances, disks, addresses, rules, regions, zones, types, dns_zones,
                                     records, hosts, keeper, attached)
        out["forms"] = self._forms(project is not None, instances, addresses, rules, dns_zones, records, types)
        if cfg.ddns_ready:
            k = keeper or self.keeper()
            out["forms"] += [k.take_form(), k.now_form()]
        out["actions"] = [{"hook": "refresh", "args": [], "title": "Refresh",
                           "note": "the project read again now (a dozen requests or so)"}]
        if cfg.ddns_ready:
            out["actions"].append({"form": "ddns-now", "title": "Update DNS now",
                                   "note": "each Dynamic DNS host that is its own set now to this network's address"})
        return out

    def _summary(self, works, parts, instances, rules, dns_zones, billing, attached) -> str:
        bits = []
        if works.get("compute") is True:
            running = sum(1 for i in instances if i.get("status") == "RUNNING")
            bits.append(f"{plural(len(instances), 'server')} ({running:,} running) · {plural(len(rules), 'firewall rule')}")
        elif works.get("compute") is None:
            bits.append("reading the project…" if attached else "the project is read once attached")
        else:
            bits.append(f"Compute Engine: {shorten(parts['compute'].error or 'failed', 100)}")
        if works.get("dns") is True:
            bits.append(plural(len(dns_zones or []), "DNS zone"))
        elif works.get("dns") is False and works.get("compute") is not False:
            bits.append("Cloud DNS: not read")
        if billing and works.get("compute") is True:
            bits.append("billing on" if billing.get("billingEnabled") else "billing off")
        return " · ".join(bits)

    # -- the tables ----------------------------------------------------------------------------------------------------------
    def _tables(self, cfg, project, instances, disks, addresses, rules, regions, zones, types, dns_zones, records, hosts,
                keeper, attached) -> list[dict]:
        out = []
        if cfg.ddns_ready:
            k = keeper or self.keeper()
            empty = None if hosts else (f"No host of {DDNS_HOSTS} is in a public Cloud DNS zone of the project"
                                        + ("" if dns_zones is not None else " (the zones are read first)") + ".")
            out.append(k.table(hosts, cfg.minutes, attached=attached, when=when, empty=empty, take=True))
        static = _static_ips(addresses)
        if project is not None or instances:
            out.append(self._servers_table(instances, static, types))
            out.append(_disks_table(disks))
            out.append(_addresses_table(addresses))
            out.append(self._rules_table(rules, instances))
            out.append(_keys_table(project, instances))
        if dns_zones is not None:
            out.append(_dns_zones_table(dns_zones, records))
            for z in dns_zones:
                out.append(_records_table(z, records.get(str(z.get("name")))))
        if regions:
            used = _regions_used(instances, disks, addresses, zones)
            if used:
                out.append(_regions_table(regions, used))
        if project is not None:
            out.append(_kinds_table(project))
        return out

    @staticmethod
    def _servers_table(instances, static, types) -> dict:
        rows = []
        for inst in sorted(instances, key=lambda i: (name_of(i.get("zone")), str(i.get("name")))):
            name, zone, status = str(inst.get("name")), name_of(inst.get("zone")), str(inst.get("status") or "")
            ext4, ext6 = _external(inst)
            mt_name = name_of(inst.get("machineType"))
            mt = types.get((zone, mt_name)) or {}
            shape = _shape(mt)
            disks = [d for d in inst.get("disks") or [] if d.get("type") != "SCRATCH"]
            gb = sum(int(d.get("diskSizeGb") or 0) for d in disks)
            ips = [f"{ip} (static)" if ip in static else ip for ip in ext4]
            internal = [str(n.get("networkIP")) for n in inst.get("networkInterfaces") or [] if n.get("networkIP")]
            values = {"zone": zone, "instance": name}
            power = ({"form": f"stop:{zone}/{name}", "title": "Stop…", "label": f"Stop {name}", "values": values}
                     if status in ("RUNNING", "PROVISIONING", "STAGING", "REPAIRING") and not _local_ssd(inst)
                     else {"form": f"start:{zone}/{name}", "title": "Start…", "label": f"Start {name}", "values": values}
                     if status == "TERMINATED" else "")
            reset = {"form": f"reset:{zone}/{name}", "title": "Reset…", "label": f"Reset {name}", "values": values} \
                if status == "RUNNING" else ""
            rows.append([cell(name, zone), cell(STATES.get(status, status.lower() or "–"), "Spot" if _spot(inst) else None),
                         cell(mt_name or "–", shape or None), cell(", ".join(ips) or "–", ", ".join(ext6) or None),
                         ", ".join(internal) or "–", cell(plural(len(disks), "disk"), f"{gb:,} GB" if gb else None),
                         day(inst.get("creationTimestamp")), power, reset])
        return {"title": "Servers", "note": ("every zone's instances · Google's APIs give no prices: the pricing pages are "
                                             "on the Compute Engine API's card · " + STOPPED_BILLS),
                "columns": [{"title": "Server"}, {"title": "State"}, {"title": "Machine type"}, {"title": "External IP"},
                            {"title": "Internal IP"}, {"title": "Disks"}, {"title": "Created"}, {"title": ""}, {"title": ""}],
                "rows": rows, "empty": "No servers in the project."}

    @staticmethod
    def _rules_table(rules, instances) -> dict:
        rows = []
        for r in sorted(rules, key=lambda r: (fw.network_of(r), int(r.get("priority", 1000)), str(r.get("name")))):
            d = str(r.get("direction") or "INGRESS").upper()
            reached = fw.reaches(r, instances)
            sources = fw.ranges_of(r) or [f"tags {', '.join(r.get('sourceTags'))}" if r.get("sourceTags") else
                                          "0.0.0.0/0" if d == "INGRESS" else "anywhere"]
            rows.append([cell(str(r.get("name")), fw.network_of(r)), "in" if d == "INGRESS" else "out",
                         fw.action_of(r), fw.what(fw.entries_of(r)), cell(", ".join(sources)[:120]), fw.targets(r),
                         cell(", ".join(reached[:6]) or "–", f"{len(reached) - 6} more" if len(reached) > 6 else None),
                         str(r.get("priority", 1000)), "off" if r.get("disabled") else "on",
                         {"form": "firewall:remove", "title": "Remove", "label": f"Remove {r.get('name')}",
                          "values": {"name": r.get("name")}}])
        return {"title": "Firewall rules", "note": ("the VPC rules of every network, the lowest priority first; a network "
                                                    "denies ingress unless a rule allows it · rules cost nothing"),
                "columns": [{"title": "Rule"}, {"title": "Way"}, {"title": "Action"}, {"title": "Protocols"},
                            {"title": "From / to"}, {"title": "Targets"}, {"title": "Reaches"},
                            {"title": "Priority", "num": True}, {"title": "In force"}, {"title": ""}],
                "rows": rows, "empty": "No firewall rules: every network denies ingress.",
                "actions": [{"form": "firewall:add", "title": "Add a rule…"}]}

    # -- the forms (the platform's status.forms: each confirmed, a risky one asked twice) -------------------------------------
    @staticmethod
    def _forms(compute_read: bool, instances, addresses, rules, dns_zones, records, types) -> list[dict]:
        """The forms for what was read: each server's power, the firewall rules', each zone's records', the keys'."""
        out: list[dict] = []
        for inst in instances:
            out += _power_forms(inst, addresses, types)
        if compute_read:
            networks = sorted({fw.network_of(r) for r in rules} | {fw.network_of(n) for i in instances
                                                                   for n in i.get("networkInterfaces") or []} - {""})
            out += [_add_rule_form(networks or ["default"]), _remove_rule_form()]
        for z in dns_zones or []:
            if not rec.unwritable(z) and isinstance(records.get(str(z.get("name"))), list):
                out += _record_forms(z)
        if compute_read:
            out += _key_forms()
        return out


# -- the tables' parts ------------------------------------------------------------------------------------------------------
def _words(e: Exception) -> str:
    return str(e) if isinstance(e, (RestError, ValueError)) else f"{type(e).__name__}: {e}"


def _items(project) -> list[dict]:
    return [x for x in ((project or {}).get("commonInstanceMetadata") or {}).get("items") or [] if isinstance(x, Mapping)]


def _external(inst: Mapping) -> tuple[list[str], list[str]]:
    v4, v6 = [], []
    for nic in inst.get("networkInterfaces") or []:
        v4 += [str(a.get("natIP")) for a in nic.get("accessConfigs") or [] if a.get("natIP")]
        v6 += [str(a.get("externalIpv6")) for a in nic.get("ipv6AccessConfigs") or [] if a.get("externalIpv6")]
    return v4, v6


def _static_ips(addresses: Iterable[Mapping]) -> set[str]:
    return {str(a.get("address")) for a in addresses if str(a.get("addressType") or "EXTERNAL") == "EXTERNAL" and a.get("address")}


def _spot(inst: Mapping) -> bool:
    s = inst.get("scheduling") or {}
    return s.get("provisioningModel") == "SPOT" or bool(s.get("preemptible"))


def _local_ssd(inst: Mapping) -> bool:
    return any(d.get("type") == "SCRATCH" for d in inst.get("disks") or [])


def _shape(mt: Mapping) -> str:
    cpus, mem = mt.get("guestCpus"), mt.get("memoryMb")
    if not cpus and not mem:
        return ""
    gb = f"{float(mem) / 1024:g} GB" if mem else ""
    return f"{plural(int(cpus or 0), 'vCPU')}" + (" (shared)" if mt.get("isSharedCpu") else "") + (f" · {gb}" if gb else "")


def _servers_words(instances) -> str:
    by: dict[str, int] = {}
    for i in instances:
        s = STATES.get(str(i.get("status")), str(i.get("status") or "?").lower())
        by[s] = by.get(s, 0) + 1
    return f"{len(instances):,}: " + ", ".join(f"{n:,} {s}" for s, n in sorted(by.items(), key=lambda x: -x[1]))


def _billing_words(billing, error, account, account_error) -> str:
    if billing is None:
        return f"not read: {shorten(error, 120)}" if error else "not read yet"
    name = str(billing.get("billingAccountName") or "")
    if not billing.get("billingEnabled"):
        return "off: no open billing account (paid services stop)" + (f" · {name}" if name else "")
    shown = (account or {}).get("displayName") or ""
    state = "" if not account else " (open)" if account.get("open") else " (closed)"
    unnamed = "" if account or not account_error else " · its name needs Billing Account Viewer on it"
    return f"on: {shown + ' · ' if shown else ''}{name}{state}{unnamed}"


def _stop_lines(inst: Mapping, addresses) -> list[str]:
    """What stopping a server means for its bill and its addresses (Compute Engine's guides, read 2026-11-11)."""
    static = _static_ips(addresses)
    ext4, _ = _external(inst)
    disks = [d for d in inst.get("disks") or [] if d.get("type") != "SCRATCH"]
    gb = sum(int(d.get("diskSizeGb") or 0) for d in disks)
    keeps = []
    if disks:
        keeps.append(f"its {plural(len(disks), 'disk')}" + (f" ({gb:,} GB)" if gb else ""))
    kept_ips = [ip for ip in ext4 if ip in static]
    if kept_ips:
        keeps.append(f"its static address{'es' if len(kept_ips) > 1 else ''} {', '.join(kept_ips)}")
    out = ["stopped, its vCPUs and memory no longer bill"]
    if keeps:
        out.append(f"{' and '.join(keeps)} keep billing while {'they exist' if len(keeps) > 1 or len(disks) > 1 else 'it exists'}")
    gone = [ip for ip in ext4 if ip not in static]
    if gone:
        out.append(f"its ephemeral address {', '.join(gone)} is let go: started again, it gets another "
                   "(a DNS record holding it is then wrong)")
    return out


def _fqdn(text: str) -> str:
    """A host of the settings as the keeper names it (home.example.com; @.example.com is example.com)."""
    name = str(text or "").strip().rstrip(".").lower()
    return name[2:] if name.startswith("@.") else name


def _gpus(inst: Mapping, mt: Mapping) -> tuple[list[str], int]:
    """The GPUs a server carries, in words (2 × nvidia-tesla-t4), its own and its machine type's, and how many."""
    found = [(int(a.get("acceleratorCount") or 1), name_of(a.get("acceleratorType")))
             for a in inst.get("guestAccelerators") or [] if a.get("acceleratorType")]
    found += [(int(a.get("guestAcceleratorCount") or 1), str(a.get("guestAcceleratorType")))
              for a in mt.get("accelerators") or [] if a.get("guestAcceleratorType")]
    return [f"{n} × {kind}" for n, kind in found], sum(n for n, _ in found)


def _start_charges(inst: Mapping, types: Mapping) -> str:
    """What starting a server bills again, in words: its machine type's vCPUs and memory, its GPUs, a premium image's
    licence (Compute Engine bills them while it runs)."""
    mt_name = name_of(inst.get("machineType"))
    mt = types.get((name_of(inst.get("zone")), mt_name)) or {}
    shape = _shape(mt)
    gpus, count = _gpus(inst, mt)
    licensed = any(d.get("licenses") for d in inst.get("disks") or [])
    return (f"its vCPUs and memory ({mt_name or 'its machine type'}{': ' + shape if shape else ''}) bill again while it runs"
            + (f", and its GPU{'' if count == 1 else 's'} ({', '.join(gpus)})" if gpus else "")
            + (", with any premium image licence its disks carry" if licensed else ""))


def _power_forms(inst: Mapping, addresses, types: Mapping) -> list[dict]:
    name, zone, status = str(inst.get("name")), name_of(inst.get("zone")), str(inst.get("status") or "")
    fields = [{"name": "zone", "label": "Zone", "type": "fixed", "value": zone},
              {"name": "instance", "label": "Server", "type": "fixed", "value": name}]
    out = []
    if status == "TERMINATED":
        charges = _start_charges(inst, types)
        out.append({"id": f"start:{zone}/{name}", "hook": "start_server", "title": f"Start {name}",
                    "fields": [*fields, {"name": ACCEPT_COSTS, "type": "accept", "title": "Resume its charges?",
                                         "yes": "Start it, billing",
                                         "words": f"Started, {name} bills until it is stopped again: the charges named above."}],
                    "confirm": {"title": f"Start {name}?",
                                "words": (f"{name} is started in {zone}: {charges} (Compute Engine bills a running "
                                          "server; a stopped one only its disks and addresses). An ephemeral external "
                                          "address it gets is a new one. You are asked again before it is sent."),
                                "yes": "Start it", "danger": True}})
    if status in ("RUNNING", "PROVISIONING", "STAGING", "REPAIRING") and not _local_ssd(inst):
        seconds = 30 if _spot(inst) else 120
        lines = _stop_lines(inst, addresses)
        out.append({"id": f"stop:{zone}/{name}", "hook": "stop_server", "title": f"Stop {name}", "fields": fields,
                    "confirm": {"title": f"Stop {name}?",
                                "words": (f"{name} is shut down: Google sends its guest an ACPI shutdown signal and gives "
                                          f"it up to {seconds} seconds{' (a Spot VM)' if seconds == 30 else ''}. "
                                          + _first_up("; ".join(lines)) + "."),
                                "yes": "Stop it", "danger": True}})
    if status == "RUNNING":
        out.append({"id": f"reset:{zone}/{name}", "hook": "reset_server", "title": f"Reset {name}",
                    "fields": [*fields, {"name": ACCEPT_RESET, "type": "accept", "title": "Reset it anyway?",
                                         "yes": "Reset it anyway",
                                         "words": ("{instance} gets no shutdown: whatever it has not saved is lost, and "
                                                   "its disks' file systems may be corrupted.")}],
                    "confirm": {"title": f"Reset {name}?",
                                "words": (f"{name} is reset: a hard reset, restarted at once with no graceful shutdown "
                                          "of its guest. You are asked again before it is sent."),
                                "yes": "Reset it", "danger": True}})
    return out


def _add_rule_form(networks: list[str]) -> dict:
    return {"id": "firewall:add", "hook": "add_firewall_rule", "title": "Add a VPC firewall rule",
            "note": "Free: VPC firewall rules cost nothing (their logging would, and it stays off).",
            "fields": [
                {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "allow-home-ssh",
                 "note": "lowercase letters, digits and dashes, a letter first (1 to 63)"},
                {"name": "network", "label": "Network", "type": "choice", "value": networks[0],
                 "choices": [{"value": n, "title": n} for n in networks]},
                {"name": "direction", "label": "Direction", "type": "choice", "value": "INGRESS",
                 "choices": [{"value": "INGRESS", "title": "In (ingress)", "note": "traffic coming in to the servers"},
                             {"value": "EGRESS", "title": "Out (egress)", "note": "traffic the servers send out"}]},
                {"name": "action", "label": "Action", "type": "choice", "value": "allow",
                 "choices": [{"value": "allow", "title": "Allow"}, {"value": "deny", "title": "Deny"}]},
                {"name": "protocol", "label": "Protocol", "type": "choice", "value": "tcp",
                 "choices": [{"value": p, "title": t} for p, t in fw.PROTOCOLS.items()]},
                {"name": "ports", "label": "Ports", "type": "text", "placeholder": "22, 80, 8000-8100",
                 "when": {"protocol": ["tcp", "udp"]}, "empty": "every port"},
                {"name": "ranges", "label": "Addresses", "type": "text", "required": True,
                 "placeholder": "203.0.113.7/32, 198.51.100.0/24",
                 "note": "where traffic comes from (in) or goes to (out); 0.0.0.0/0 is the whole internet"},
                {"name": "target_tags", "label": "Target tags", "type": "text", "placeholder": "web, ssh",
                 "empty": "every server of the network", "note": "the servers with one of these network tags"},
                {"name": "priority", "label": "Priority", "type": "number", "min": 0, "max": 65535,
                 "placeholder": str(fw.PRIORITY_DEFAULT), "empty": f"{fw.PRIORITY_DEFAULT} (lower comes first)"},
                {"name": "description", "label": "Description", "type": "text", "placeholder": "what it is for",
                 "empty": "none"},
                {"name": ACCEPT_OPEN, "type": "accept", "title": "Add this rule anyway?", "yes": "Add it anyway",
                 "words": ("Added, it does what is said above: anyone on the internet may then reach and try what it "
                           "opens on the servers it applies to, or SSH denied may lock you out of them.")}],
            "submit": "Review the rule",
            "confirm": {"title": "Add this rule?",
                        "words": ("{name} is added to {network}: {action}, {direction}, {protocol} {ports}, addresses "
                                  "{ranges}, targets {target_tags}, priority {priority}. A rule letting anything but "
                                  "the web's ports 80 and 443 in from the whole internet, or denying SSH, is asked "
                                  "again."),
                        "yes": "Add the rule"}}


def _remove_rule_form() -> dict:
    return {"id": "firewall:remove", "hook": "remove_firewall_rule", "title": "Remove a VPC firewall rule",
            "fields": [{"name": "name", "label": "Rule", "type": "fixed"},
                       {"name": ACCEPT_REMOVE, "type": "accept", "title": "Remove it anyway?", "yes": "Remove it anyway",
                        "words": ("Removing {name} may lock you out of the servers named (SSH or RDP), or let in what it "
                                  "kept out, until another rule is added.")}],
            "confirm": {"title": "Remove this rule?",
                        "words": ("{name} is removed: what it allowed or denied is then decided by the rules left (a "
                                  "network denies ingress unless a rule allows it). A rule letting SSH or RDP in to a "
                                  "server, or denying ingress to one, is asked again."),
                        "yes": "Remove the rule", "danger": True}}


def _record_forms(z: Mapping) -> list[dict]:
    name, dns = str(z.get("name")), rec.undot(z.get("dnsName"))
    zone = {"name": "zone", "label": "Zone", "type": "fixed", "value": name}
    safe = "Every other record is kept, and a change made meanwhile makes Google refuse it: nothing is overwritten."
    kept = f"One change: the name's record set of the type is deleted exactly as it was read and added back changed. {safe}"
    gone = ("One change: the name's record set of the type is deleted exactly as it was read and added back without this "
            f"value (not at all when it was its last). {safe}")
    return [
        {"id": f"set:{name}", "hook": "set_record", "title": f"Set a record in {dns}",
         "note": ("An A, AAAA or CNAME replaces the name's values of its type; a TXT, MX, CAA, SRV or NS value is added "
                  "beside the others."),
         "fields": [zone,
                    {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "@, www, home",
                     "note": f"@ is {dns} itself; home is home.{dns}"},
                    {"name": "rtype", "label": "Type", "type": "choice", "value": "A",
                     "choices": [{"value": t, "title": t, "note": rec.TYPES[t]} for t in rec.TYPES]},
                    {"name": "data", "label": "Data", "type": "text", "required": True,
                     "placeholder": "an address, a host name or text, as its type says"},
                    {"name": "ttl", "label": "TTL (seconds)", "type": "number", "min": rec.TTL_MIN, "max": rec.TTL_MAX,
                     "placeholder": str(rec.TTL_DEFAULT), "empty": f"the record set's own, else {rec.TTL_DEFAULT}"}],
         "submit": "Review the change",
         "confirm": {"title": f"Set this record in {dns}?", "words": "{name} {rtype} {data} is set in " + dns + ". " + kept,
                     "yes": "Set the record"}},
        {"id": f"remove:{name}", "hook": "remove_record", "title": f"Remove a record from {dns}",
         "fields": [zone, {"name": "name", "label": "Name", "type": "fixed"}, {"name": "rtype", "label": "Type", "type": "fixed"},
                    {"name": "data", "label": "Data", "type": "fixed"}],
         "confirm": {"title": f"Remove this record from {dns}?",
                     "words": "{name} {rtype} {data} is removed from " + dns + ". " + gone,
                     "yes": "Remove the record", "danger": True}},
    ]


def _key_forms() -> list[dict]:
    safe = ("The project's metadata is read afresh, its ssh-keys alone changed (every other key and item kept as it is) "
            "and written with the fingerprint it was read with: a change made meanwhile makes Google refuse it.")
    return [
        {"id": "ssh:add", "hook": "add_ssh_key", "title": "Add a project-wide SSH key",
         "note": "It lets its user in to every server of the project but those blocking project-wide keys or with OS Login on.",
         "fields": [{"name": "user", "label": "User", "type": "text", "required": True, "placeholder": "you",
                     "note": "the user it logs in as on the servers"},
                    {"name": "key", "label": "Public key", "type": "text", "required": True,
                     "placeholder": "ssh-ed25519 AAAAC3… you@pc", "note": "the .pub file's line, never the private key"}],
         "submit": "Review the key",
         "confirm": {"title": "Add this key?",
                     "words": ("{user} may then log in with this key to every server of the project that takes "
                               "project-wide keys, as an administrator: Google's guest agent adds the accounts it makes "
                               "from metadata keys to google-sudoers, whose members get sudo. " + safe),
                     "yes": "Add the key", "danger": True}},
        {"id": "ssh:remove", "hook": "remove_ssh_key", "title": "Remove a project-wide SSH key",
         "fields": [{"name": "user", "label": "User", "type": "fixed"}, {"name": "fingerprint", "label": "Key", "type": "fixed"}],
         "confirm": {"title": "Remove this key?",
                     "words": "{user}'s key {fingerprint} is taken out of the project's metadata. " + safe,
                     "yes": "Remove the key", "danger": True}},
    ]


def _first_up(text: str) -> str:
    return text[:1].upper() + text[1:]


def _op_line(op: Mapping) -> str:
    status = str(op.get("status") or "?")
    return (f"operation {op.get('name') or '?'}: done" if status == "DONE"
            else f"operation {op.get('name') or '?'}: {status.lower()} (Google finishes it; Refresh shows it)")


def _disks_table(disks) -> dict:
    rows = []
    for d in sorted(disks, key=lambda d: (str(d.get("_scope")), str(d.get("name")))):
        where = name_of(d.get("zone")) or name_of(d.get("region"))
        users = [name_of(u) for u in d.get("users") or []]
        rows.append([cell(str(d.get("name")), where + (" (regional)" if d.get("region") and not d.get("zone") else "")),
                     number(d.get("sizeGb") or 0), name_of(d.get("type")), str(d.get("status") or "–").lower(),
                     ", ".join(users) or "none (not attached)", day(d.get("creationTimestamp"))])
    return {"title": "Disks", "note": "a disk bills while it exists: attached or not, its server running or stopped",
            "columns": [{"title": "Disk"}, {"title": "Size (GB)", "num": True}, {"title": "Type"}, {"title": "State"},
                        {"title": "Attached to"}, {"title": "Created"}],
            "rows": rows, "empty": "No disks."}


def _addresses_table(addresses) -> dict:
    rows = []
    for a in sorted(addresses, key=lambda a: (str(a.get("_scope")), str(a.get("name")))):
        kind = str(a.get("addressType") or "EXTERNAL").lower()
        where = "global" if a.get("_scope") == "global" or not a.get("region") else name_of(a.get("region"))
        users = [name_of(u) for u in a.get("users") or []]
        status = str(a.get("status") or "")
        rows.append([str(a.get("address") or "–"), cell(str(a.get("name")), a.get("description") or None),
                     f"{kind}, {where}", str(a.get("networkTier") or "–").lower(),
                     f"in use by {', '.join(users)}" if status == "IN_USE" and users else status.lower().replace("_", " ") or "–",
                     day(a.get("creationTimestamp"))])
    return {"title": "Addresses", "note": ("reserved static addresses; an external one bills while it is reserved, whatever "
                                           "its server's state (the network pricing page has the rates)"),
            "columns": [{"title": "Address"}, {"title": "Name"}, {"title": "Kind"}, {"title": "Tier"}, {"title": "State"},
                        {"title": "Created"}],
            "rows": rows, "empty": "No reserved addresses."}


def _keys_table(project, instances) -> dict:
    items = _items(project)
    rows = []
    for e in sshkeys.entries(items):
        rows.append([e.user, e.kind, cell(e.fingerprint or "–"), e.comment or "–", e.expires or "never",
                     {"form": "ssh:remove", "title": "Remove", "label": f"Remove {e.user}'s key {e.fingerprint}",
                      "values": {"user": e.user, "fingerprint": e.fingerprint}}])
    blocking = [str(i.get("name")) for i in instances if sshkeys.blocks_project_keys(i)]
    note = ("the project's common metadata (ssh-keys): every server takes them but those blocking project-wide keys"
            + (f" ({', '.join(blocking)})" if blocking else "") + " or with OS Login on · changed with the metadata's "
            "fingerprint, so a change made meanwhile elsewhere is never overwritten")
    if sshkeys.os_login(items):
        note = "OS Login is on for the project: its servers ignore these keys · " + note
    if sshkeys.item(items, sshkeys.LEGACY):
        note += f" · the older {sshkeys.LEGACY} item is kept as it is"
    return {"title": "Project-wide SSH keys", "note": note,
            "columns": [{"title": "User"}, {"title": "Type"}, {"title": "Fingerprint"}, {"title": "Comment"},
                        {"title": "Expires"}, {"title": ""}],
            "rows": rows, "empty": "No project-wide SSH keys.", "actions": [{"form": "ssh:add", "title": "Add a key…"}]}


def _dns_zones_table(zones, records) -> dict:
    rows = []
    for z in zones:
        held = records.get(str(z.get("name")))
        rows.append([cell(rec.undot(z.get("dnsName")) or "–", str(z.get("name"))), str(z.get("visibility") or "public"),
                     str((z.get("dnssecConfig") or {}).get("state") or "off"),
                     str(len(held)) if isinstance(held, list) else "–",
                     cell(", ".join(rec.undot(n) for n in (z.get("nameServers") or [])[:2]) or "–",
                          f"{len(z.get('nameServers') or []) - 2} more" if len(z.get("nameServers") or []) > 2 else None)])
    return {"title": "DNS zones", "note": ("Cloud DNS's managed zones (a zone bills while it exists; its pricing names no "
                                           "charge for a record change)"),
            "columns": [{"title": "Zone"}, {"title": "Visibility"}, {"title": "DNSSEC"}, {"title": "Record sets", "num": True},
                        {"title": "Name servers"}],
            "rows": rows, "empty": "No Cloud DNS zones in the project."}


def _records_table(z: Mapping, held) -> dict:
    dns, name = rec.undot(z.get("dnsName")), str(z.get("name"))
    if not isinstance(held, list):
        return {"title": f"{dns} records", "note": str(held or "not read yet"), "columns": [{"title": "Name"}],
                "rows": [], "empty": "Not read."}
    why = rec.unwritable(z)
    origin = rec.dot(z.get("dnsName"))
    rows = []
    for n, t, ttl, v, routed in sorted(rec.rows_of(held), key=lambda r: (r[0] != origin, r[0], r[1], r[3])):
        shown = v if len(v) <= 64 else v[:63] + "…"
        own = t in rec.DNSSEC or (n == origin and t in rec.APEX) or routed
        row = [rec.undot(n) or "@", t, str(ttl), cell(shown)]
        if not why:
            row.append("" if own else {"form": f"remove:{name}", "title": "Remove", "label": f"Remove {rec.undot(n)} {t} {shown}",
                                       "values": {"name": n, "rtype": t, "data": v}})
        rows.append(row)
    table = {"title": f"{dns} records",
             "note": (f"{z.get('visibility') or 'public'} zone {name} · " + (f"not written here: {why}" if why else
                      "set and removed here: one change each, every other record kept")),
             "columns": [{"title": "Name"}, {"title": "Type"}, {"title": "TTL", "num": True}, {"title": "Data"},
                         *([{"title": ""}] if not why else [])],
             "rows": rows, "empty": "No records."}
    if not why:
        table["actions"] = [{"form": f"set:{name}", "title": "Set a record…"}]
    return table


def _region_of(zone: str, zones: Mapping) -> str:
    z = zones.get(zone) or {}
    return name_of(z.get("region")) or (zone.rsplit("-", 1)[0] if "-" in zone else zone)


def _regions_used(instances, disks, addresses, zones) -> list[str]:
    used = {_region_of(name_of(i.get("zone")), zones) for i in instances}
    used |= {_region_of(name_of(d.get("zone")), zones) if d.get("zone") else name_of(d.get("region")) for d in disks}
    used |= {name_of(a.get("region")) for a in addresses if a.get("region")}
    return sorted(u for u in used if u)


def _regions_table(regions, used) -> dict:
    rows = []
    for r in regions:
        if str(r.get("name")) not in used:
            continue
        quotas = [q for q in r.get("quotas") or [] if float(q.get("usage") or 0) > 0]
        rows.append([cell(str(r.get("name")), str(r.get("status") or "").lower() or None),
                     ", ".join(f"{metric_words(q.get('metric'))} {number(q.get('usage'))} of {number(q.get('limit'))}"
                               for q in quotas) or "nothing counted"])
    return {"title": "Regions in use", "note": "each region's quotas the project uses (its Quotas page raises them)",
            "columns": [{"title": "Region"}, {"title": "Quotas used"}], "rows": rows, "empty": "None."}


def _kinds_table(project) -> dict:
    quotas = [q for q in (project or {}).get("quotas") or [] if float(q.get("usage") or 0) > 0]
    rows = [[metric_words(q.get("metric")), number(q.get("usage")), number(q.get("limit"))]
            for q in sorted(quotas, key=lambda q: str(q.get("metric")))]
    return {"title": "In the project", "note": "what the project holds of each kind, as its quotas count it (one read: projects.get)",
            "columns": [{"title": "Kind"}, {"title": "Count", "num": True}, {"title": "Quota", "num": True}],
            "rows": rows, "empty": "Nothing counted."}


MACHINE = GoogleCloudPlugin()
