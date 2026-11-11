"""Google Cloud's REST APIs as the plugin asks them (their references read 2026-11-11): Compute Engine v1
(https://compute.googleapis.com/compute/v1), Cloud DNS v1 (https://dns.googleapis.com/dns/v1) and Cloud Billing v1
(https://cloudbilling.googleapis.com/v1), each request bearing the service account's access token (auth.Tokens), through
the library's RestClient: a rate limit waited out, a read tried again, a write never sent twice, every word said with the
key's secrets taken out.

Every request the plugin makes is one of ENDPOINTS (the API card names each: the contract test compares them), and the
only changes among them are the free ones (WRITES): a server started, stopped or reset; a VPC firewall rule added or
removed; the project's common metadata set (its SSH keys, with the metadata's fingerprint); a Cloud DNS change (record
sets added and deleted). `_send` refuses any other write before anything is sent. Nothing here makes, resizes,
snapshots, reserves or deletes a billable thing.

Lists are read across their pages (pageToken, nextPageToken); an aggregated list's items are a map of scopes (zones,
regions) to their resources, read with returnPartialSuccess as Google recommends, the scopes it could not reach said
(`unreachables`). A Compute change answers an Operation, followed (`wait_global`) with get requests that back off, as
Google's guide on handling API responses asks, until it says DONE or the wait ends."""
from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from urllib.parse import quote

from liminal_libs.machines.rest import Answer, RestClient, RestError, bearer, scrub

COMPUTE = "https://compute.googleapis.com/compute/v1"
DNS = "https://dns.googleapis.com/dns/v1"
BILLING = "https://cloudbilling.googleapis.com/v1"
BASES = {"compute": COMPUTE, "dns": DNS, "billing": BILLING}

# every request the plugin makes: what it is for -> (the API, the method, the path under the API's base)
ENDPOINTS: dict[str, tuple[str, str, str]] = {
    "project": ("compute", "GET", "/projects/{project}"),
    "instances": ("compute", "GET", "/projects/{project}/aggregated/instances"),
    "instance": ("compute", "GET", "/projects/{project}/zones/{zone}/instances/{instance}"),
    "machine_type": ("compute", "GET", "/projects/{project}/zones/{zone}/machineTypes/{machineType}"),
    "disks": ("compute", "GET", "/projects/{project}/aggregated/disks"),
    "addresses": ("compute", "GET", "/projects/{project}/aggregated/addresses"),
    "global_addresses": ("compute", "GET", "/projects/{project}/global/addresses"),
    "firewalls": ("compute", "GET", "/projects/{project}/global/firewalls"),
    "zones": ("compute", "GET", "/projects/{project}/zones"),
    "regions": ("compute", "GET", "/projects/{project}/regions"),
    "global_operation": ("compute", "GET", "/projects/{project}/global/operations/{operation}"),
    "start": ("compute", "POST", "/projects/{project}/zones/{zone}/instances/{instance}/start"),
    "stop": ("compute", "POST", "/projects/{project}/zones/{zone}/instances/{instance}/stop"),
    "reset": ("compute", "POST", "/projects/{project}/zones/{zone}/instances/{instance}/reset"),
    "firewall_add": ("compute", "POST", "/projects/{project}/global/firewalls"),
    "firewall_remove": ("compute", "DELETE", "/projects/{project}/global/firewalls/{firewall}"),
    "set_metadata": ("compute", "POST", "/projects/{project}/setCommonInstanceMetadata"),
    "managed_zones": ("dns", "GET", "/projects/{project}/managedZones"),
    "rrsets": ("dns", "GET", "/projects/{project}/managedZones/{managedZone}/rrsets"),
    "change": ("dns", "POST", "/projects/{project}/managedZones/{managedZone}/changes"),
    "billing_info": ("billing", "GET", "/projects/{project}/billingInfo"),
    "billing_account": ("billing", "GET", "/billingAccounts/{account}"),
}
# the changes the plugin makes: free ones alone (the user, 2026-11-11: "Free changes only")
WRITES = frozenset({"start", "stop", "reset", "firewall_add", "firewall_remove", "set_metadata", "change"})
PAGES_MOST = 20  # a list read across at most this many pages
PAGE_SIZE = 500  # Compute's most a page
WAIT_S = (1.0, 2.0, 4.0, 4.0, 4.0, 5.0)  # an operation asked again after each of these (backing off), then left running
QUIET = frozenset({"NO_RESULTS_ON_PAGE"})  # a scope's warning that says nothing went wrong

# Google's error reasons in words of what to do; Google's own message comes first
HINTS = {
    "SERVICE_DISABLED": "the API is not enabled for the project: enable it (APIs & Services > Library) and Refresh",
    "accessNotConfigured": "the API is not enabled for the project: enable it (APIs & Services > Library) and Refresh",
    "IAM_PERMISSION_DENIED": "the service account lacks this permission: grant it the role the README names",
    "forbidden": "the service account lacks this permission: grant it the role the README names",
    "insufficientPermissions": "the service account lacks this permission: grant it the role the README names",
    "PERMISSION_DENIED": "the service account lacks this permission: grant it the role the README names",
    "rateLimitExceeded": "a rate quota of the project: the plugin tries again later",
    "RATE_LIMIT_EXCEEDED": "a rate quota of the project: the plugin tries again later",
    "conditionNotMet": "it changed since it was read: nothing was written; read it again and retry",
    "FAILED_PRECONDITION": "it changed since it was read, or is not in a state for this: nothing was done",
    "BILLING_DISABLED": "the project has no open billing account",
    "UNAUTHENTICATED": "the access token was refused: a new one is asked next time",
    "invalid_grant": "Google refused the key's signed request: the key was deleted or disabled, or this PC's clock is off",
    "invalid_client": "Google refused the key's account: disabled or deleted",
    "disabled_client": "Google refused the key's account: it is disabled",
    "deleted_client": "Google refused the key's account: it was deleted",
    "unauthorized_client": "Google refused the key's account for this grant",
    "invalid_scope": "Google refused the scopes asked",
    "admin_policy_enforced": "an organization policy refuses the key's account",
}


class OperationError(RestError):
    """A change Google took and then failed (its Operation's error), in Google's words."""


def google_words(answer: Answer) -> tuple[str, str]:
    """A Google API's error answer in words and its reason: the message of {"error": {code, message, status, errors[],
    details[]}} (AIP-193), or the token endpoint's {"error", "error_description"}, with what to do about it."""
    data = answer.data
    if not isinstance(data, Mapping):
        return "", ""
    err = data.get("error")
    if isinstance(err, str):  # the OAuth token endpoint
        desc = str(data.get("error_description") or "").strip()
        words = f"{err}: {desc}" if desc else err
        hint = HINTS.get(err, "")
        return (f"{words} ({hint})" if hint else words), err
    if not isinstance(err, Mapping):
        return "", ""
    message = " ".join(str(err.get("message") or "").split())
    reasons = [str(d.get("reason") or "") for d in err.get("details") or [] if isinstance(d, Mapping)]
    reasons += [str(e.get("reason") or "") for e in err.get("errors") or [] if isinstance(e, Mapping)]
    reasons.append(str(err.get("status") or ""))
    reason = next((r for r in reasons if r in HINTS), next((r for r in reasons if r), ""))
    hint = HINTS.get(reason, "")
    words = message or reason or f"HTTP {answer.status}"
    if hint and hint not in words:
        words = f"{words} ({hint})"
    return words, reason


def name_of(url: str | None) -> str:
    """The last part of a resource's address (a zone's, a machine type's, a network's): zones/us-central1-a -> us-central1-a."""
    return str(url or "").rstrip("/").rsplit("/", 1)[-1]


def warning_words(warning) -> str:
    if not isinstance(warning, Mapping):
        return ""
    return " ".join(str(warning.get("message") or warning.get("code") or "").split())


class GoogleCloud:
    """The project's resources through Google's APIs (module docstring). `token()` gives the current access token
    (auth.Tokens); `forget()` drops it (a 401: the next request asks a new one); `transport` is a test's stand-in."""

    def __init__(self, project: str, token: Callable[[], str], forget: Callable[[], None] | None = None,
                 transport=None, secrets: Iterable[str] = (), clock=time.time, sleep=time.sleep):
        self.project = project
        self._forget = forget
        self._sleep = sleep
        self._secrets = tuple(secrets)
        self._token = token
        self.clients = {api: RestClient(base, auth=bearer(token), transport=transport, secrets=self._secrets,
                                        error=google_words, clock=clock, sleep=sleep)
                        for api, base in BASES.items()}

    # -- sending ------------------------------------------------------------------------------------------------------
    @staticmethod
    def path(what: str, **names: str) -> tuple[str, str, str]:
        """(the API, the method, the path) of an endpoint, its names put in (each one path part, quoted)."""
        api, method, template = ENDPOINTS[what]
        parts = {k: quote(str(v), safe="") for k, v in names.items()}
        return api, method, template.format(**parts)

    def _send(self, what: str, params: Mapping | None = None, body=None, **names: str):
        """One request of ENDPOINTS; a change only if it is one of WRITES (refused before anything is sent otherwise).
        A 401 drops the token and asks once more with a new one (nothing was done: Google refused who asked)."""
        api, method, path = self.path(what, project=self.project, **names)
        if method != "GET" and what not in WRITES:
            raise RuntimeError(f"{what}: not one of the plugin's changes")
        client = self.clients[api]
        for attempt in (1, 2):
            try:
                return client.request(method, path, params=params, json=body).data
            except RestError as e:
                if e.status == 401 and attempt == 1 and self._forget is not None:
                    self._forget()
                    continue
                raise RestError(self._scrub(str(e)), e.status, e.code, e.request_id, e.retry_after) from None
        raise AssertionError("unreachable")

    def _scrub(self, text: str) -> str:
        held = ""
        try:
            held = getattr(self._token, "held", "") or ""
        except Exception:  # noqa: BLE001 - words without the token's are still words
            held = ""
        return scrub(text, (*self._secrets, held))

    def _list(self, what: str, key: str = "items", params: Mapping | None = None, **names: str) -> list:
        """Every item of a list across its pages."""
        params = dict(params or {})
        out: list = []
        for _ in range(PAGES_MOST):
            data = self._send(what, params=params, **names) or {}
            out += [x for x in data.get(key) or [] if isinstance(x, Mapping)]
            token = data.get("nextPageToken")
            if not token:
                break
            params["pageToken"] = token
        return out

    def _aggregated(self, what: str, key: str) -> tuple[list[dict], list[str]]:
        """Every resource of an aggregated list (each with its scope as `_scope`: zones/us-central1-a, regions/...), and
        in words the scopes it could not read."""
        params: dict = {"maxResults": PAGE_SIZE, "returnPartialSuccess": "true"}
        found: list[dict] = []
        troubles: list[str] = []
        for _ in range(PAGES_MOST):
            data = self._send(what, params=params) or {}
            for scope, held in (data.get("items") or {}).items():
                if not isinstance(held, Mapping):
                    continue
                for item in held.get(key) or []:
                    if isinstance(item, Mapping):
                        found.append({**item, "_scope": scope})
                w = held.get("warning")
                if isinstance(w, Mapping) and w.get("code") not in QUIET:
                    troubles.append(f"{scope}: {warning_words(w)}")
            troubles += [f"not reached: {u}" for u in data.get("unreachables") or []]
            token = data.get("nextPageToken")
            if not token:
                break
            params["pageToken"] = token
        return found, troubles

    # -- the reads -------------------------------------------------------------------------------------------------------
    def project_info(self) -> dict:
        """The project (Compute's projects.get): its quotas and its common metadata, with the metadata's fingerprint."""
        return self._send("project") or {}

    def instances(self) -> tuple[list[dict], list[str]]:
        return self._aggregated("instances", "instances")

    def instance(self, zone: str, instance: str) -> dict:
        return self._send("instance", zone=zone, instance=instance) or {}

    def machine_type(self, zone: str, machine_type: str) -> dict:
        return self._send("machine_type", zone=zone, machineType=machine_type) or {}

    def disks(self) -> tuple[list[dict], list[str]]:
        return self._aggregated("disks", "disks")

    def addresses(self) -> tuple[list[dict], list[str]]:
        """The regional addresses (aggregated) and the global ones."""
        regional, troubles = self._aggregated("addresses", "addresses")
        seen = {a.get("selfLink") or a.get("id") for a in regional}
        glob = [{**a, "_scope": "global"} for a in self._list("global_addresses", params={"maxResults": PAGE_SIZE})
                if (a.get("selfLink") or a.get("id")) not in seen]
        return regional + glob, troubles

    def firewalls(self) -> list[dict]:
        return self._list("firewalls", params={"maxResults": PAGE_SIZE})

    def zones(self) -> list[dict]:
        return self._list("zones", params={"maxResults": PAGE_SIZE})

    def regions(self) -> list[dict]:
        return self._list("regions", params={"maxResults": PAGE_SIZE})

    def managed_zones(self) -> list[dict]:
        return self._list("managed_zones", key="managedZones")

    def rrsets(self, managed_zone: str, name: str | None = None, rtype: str | None = None) -> list[dict]:
        """A zone's record sets (`name`: those of one name, `rtype` with it: of one type)."""
        params = {"name": name, "type": rtype if name else None}
        return self._list("rrsets", key="rrsets", params=params, managedZone=managed_zone)

    def billing_info(self) -> dict:
        return self._send("billing_info") or {}

    def billing_account(self, account: str) -> dict:
        """A billing account by its name (billingAccounts/012345-567890-ABCDEF or the id alone)."""
        return self._send("billing_account", account=name_of(account)) or {}

    def operation(self, name: str) -> dict:
        return self._send("global_operation", operation=name) or {}

    def wait_global(self, op: Mapping) -> dict:
        """A global Operation followed until it says DONE (or the waits run out: it is given back as it is); an
        OperationError when it ended in an error."""
        current = dict(op or {})
        for delay in (0.0, *WAIT_S):
            if delay:
                self._sleep(delay)
                current = self.operation(str(current.get("name") or ""))
            if current.get("status") == "DONE":
                break
        err = current.get("error")
        if current.get("status") == "DONE" and isinstance(err, Mapping):
            said = "; ".join(" ".join(str(e.get("message") or e.get("code") or "").split())
                             for e in err.get("errors") or [] if isinstance(e, Mapping)) or "it failed"
            raise OperationError(self._scrub(said), int(current.get("httpErrorStatusCode") or 0),
                                 str(next((e.get("code") for e in err.get("errors") or [] if isinstance(e, Mapping)), "")))
        return current

    # -- the free changes ---------------------------------------------------------------------------------------------
    def start(self, zone: str, instance: str) -> dict:
        return self._send("start", params={"requestId": request_id()}, zone=zone, instance=instance) or {}

    def stop(self, zone: str, instance: str) -> dict:
        return self._send("stop", params={"requestId": request_id()}, zone=zone, instance=instance) or {}

    def reset(self, zone: str, instance: str) -> dict:
        return self._send("reset", params={"requestId": request_id()}, zone=zone, instance=instance) or {}

    def add_firewall(self, rule: Mapping) -> dict:
        return self._send("firewall_add", params={"requestId": request_id()}, body=dict(rule)) or {}

    def remove_firewall(self, name: str) -> dict:
        return self._send("firewall_remove", params={"requestId": request_id()}, firewall=name) or {}

    def set_metadata(self, fingerprint: str, items: list[dict]) -> dict:
        """The project's common metadata written whole, with the fingerprint it was read with (Google refuses it, 412,
        when the metadata changed since: nothing is lost)."""
        return self._send("set_metadata", params={"requestId": request_id()},
                          body={"fingerprint": fingerprint, "items": items}) or {}

    def change(self, managed_zone: str, additions: list[dict], deletions: list[dict]) -> dict:
        """One Cloud DNS change: the record sets deleted (exactly as they are) and added, at once."""
        body = {"additions": additions, "deletions": deletions}
        return self._send("change", body=body, managedZone=managed_zone) or {}

    # -- what the answers said ------------------------------------------------------------------------------------------
    def facts(self, api: str) -> dict[str, str]:
        return self.clients[api].facts()


def request_id() -> str:
    """A change's requestId (a UUID): Google ignores it sent again once done."""
    return str(uuid.uuid4())
