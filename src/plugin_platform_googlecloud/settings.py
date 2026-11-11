"""The plugin's settings, read through the library's Login interface and nothing else (the user, 2026-11-08: "again, all
the settings are stored on a login-app db"; "but we are not integrating login-app right now"). Each setting is a pair
named by its variable (GOOGLECLOUD_KEY is the pair `googlecloud-key`: apps.authorization.pair_name), asked of the login
of the app the plugin is attached to: the platform's EnvironmentLogin today, the login app's pairs once the platform
binds it. Not attached (the command line), an EnvironmentLogin of its own. The plugin keeps no settings file: the key
(a service account's JSON key, pasted whole) is never written anywhere, never shown, and only the names of the settings
set are said."""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from liminal_libs.apps import EnvironmentLogin, Login
from liminal_libs.machines.ddns import MINUTES, minutes_of
from liminal_libs.sources.keys import KeyVar

from .auth import BadKey, ServiceAccountKey, parse_key

KEY = "GOOGLECLOUD_KEY"
PROJECT = "GOOGLECLOUD_PROJECT"
DDNS_HOSTS = "GOOGLECLOUD_DDNS_HOSTS"
DDNS_MINUTES = "GOOGLECLOUD_DDNS_MINUTES"
CONSOLE_KEYS = "https://console.cloud.google.com/iam-admin/serviceaccounts"

# what the login app's "Pairs your plugins ask for" lists, once it lists the platform's plugins
KEYS = (
    KeyVar(KEY, label="Service account key",
           hint=("a service account's JSON key, pasted whole: IAM & Admin > Service accounts > the account > Keys > Add key "
                 "> Create new key > JSON (the README names the roles it needs: the reads, and the free changes alone)")),
    KeyVar(PROJECT, label="Project", secret=False,
           hint="optional: the ID of the project acted on (the key's own project_id unless set)"),
    KeyVar(DDNS_HOSTS, label="Dynamic DNS hosts", secret=False,
           hint=("the hosts kept at this network's address, comma separated, each in a public Cloud DNS zone of the "
                 "project: home.example.com, @.example.com (the zone's own name)")),
    KeyVar(DDNS_MINUTES, label="Dynamic DNS minutes", secret=False,
           hint="optional: minutes between checks, 1 to 1440 (5 unless set)"),
)
NAMES = tuple(k.name for k in KEYS)
# a project ID: 6 to 30 lowercase letters, digits and hyphens, a letter first (an older domain-scoped one: example.com:name)
PROJECT_ID = re.compile(r"^(?:[a-z0-9][a-z0-9.-]{0,61}[a-z0-9]:)?[a-z][a-z0-9-]{4,28}[a-z0-9]$")


@dataclass(frozen=True)
class Config:
    """The settings as read (`present`: the names of those set; `problems`: what was set but could not be taken, in
    words that never hold a secret)."""

    key: ServiceAccountKey | None = field(default=None, repr=False)
    project: str = ""
    project_given: bool = False  # GOOGLECLOUD_PROJECT set (else the key's own project_id)
    hosts: str = ""  # the Dynamic DNS hosts as typed (split against the project's public zones when they are known)
    minutes: float = MINUTES[2]
    present: frozenset = frozenset()
    problems: tuple[str, ...] = ()
    key_problem: str = ""  # why the key set cannot be used

    @property
    def ready(self) -> bool:
        """A key that can be used and a project to act on."""
        return self.key is not None and bool(self.project)

    @property
    def ddns_ready(self) -> bool:
        return self.ready and bool(self.hosts.strip())

    @property
    def secrets(self) -> tuple[str, ...]:
        return self.key.secrets if self.key is not None else ()

    @property
    def account(self) -> str:
        """The service account's address (the key's client_email)."""
        return self.key.client_email if self.key is not None else ""

    @property
    def api_print(self) -> str:
        """A fingerprint of the key and the project (kept in memory to notice a change; never shown nor written)."""
        key = self.key.fingerprint if self.key is not None else ""
        return hashlib.sha256(f"{key}\0{self.project}".encode()).hexdigest()

    @property
    def ddns_print(self) -> str:
        return hashlib.sha256(f"{self.api_print}\0{self.hosts}".encode()).hexdigest()


def parse(values: Mapping[str, str]) -> Config:
    """The settings from their values by variable (those not set left out or empty)."""
    v = {n: str(values.get(n) or "").strip() for n in NAMES}
    present = frozenset(n for n in NAMES if v[n])
    problems: list[str] = []
    key, key_problem = None, ""
    if v[KEY]:
        try:
            key = parse_key(v[KEY])
        except BadKey as e:
            key_problem = f"{KEY} cannot be used: {e}"
            problems.append(key_problem)
    project, given = "", False
    if v[PROJECT]:
        if PROJECT_ID.match(v[PROJECT]):
            project, given = v[PROJECT], True
        else:
            problems.append(f"{PROJECT} is not a project ID (6 to 30 lowercase letters, digits and hyphens, a letter first)"
                            + (": the key's own project is used" if key is not None and key.project_id else ""))
    if not project and key is not None:
        if PROJECT_ID.match(key.project_id or ""):
            project = key.project_id
        else:
            problems.append(f"the key names no project (project_id): set {PROJECT}")
    minutes = minutes_of(v[DDNS_MINUTES])
    if v[DDNS_MINUTES]:
        try:
            float(v[DDNS_MINUTES])
        except ValueError:
            problems.append(f"{DDNS_MINUTES} is not a number of minutes: {MINUTES[2]:g} is used")
    hosts = ", ".join(h for h in re.split(r"[,;\s]+", v[DDNS_HOSTS]) if h)
    return Config(key=key, project=project, project_given=given, hosts=hosts, minutes=minutes, present=present,
                  problems=tuple(problems), key_problem=key_problem)


def read(login: Login | None = None) -> Config:
    """The settings as `login` furnishes them (the login of the app the plugin is attached to), else an
    EnvironmentLogin's: the variables set, by their pairs' names; a login that cannot be asked furnishes none, and says so."""
    asked = login if login is not None else EnvironmentLogin()
    try:
        values = asked.variables(NAMES)
    except Exception as e:  # noqa: BLE001 - a login that cannot be asked: nothing set, and why
        return Config(problems=(f"the settings could not be read from the login: {type(e).__name__}",))
    return parse(values)
