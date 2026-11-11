"""Stand-ins for Google Cloud: the tests never reach Google, a resolver or the network. `FakeGoogle` is the token endpoint,
Compute Engine, Cloud DNS and Cloud Billing as a transport (a project in memory, its answers laid out as the APIs'
references give them: aggregated lists by scope, Operations, managed zones and record sets, ProjectBillingInfo, errors as
{"error": {code, message, status, errors[]}}); it checks each token request's JWT with the stand-in key's public half and
each API request's bearer token. The key is made here, for the tests alone (no account's). `Pairs` is a Login holding
pairs by name."""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

import liminal_libs.dns as dns_mod
import liminal_libs.machines.rest as rest_mod
from liminal_libs.apps import Login, Unauthorized, pair_name
from plugin_platform_googlecloud import GoogleCloudPlugin
from plugin_platform_googlecloud.settings import NAMES

PROJECT = "liminal-test"
ACCOUNT = f"liminal-plugin@{PROJECT}.iam.gserviceaccount.com"
KEY_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"
HOME = "93.184.216.34"  # this network's public address in the tests
TOKEN_URI = "https://oauth2.googleapis.com/token"
_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # the tests' own key, made for them alone
PEM = _PRIVATE.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")
PUBLIC = _PRIVATE.public_key()


def ssh_public() -> str:
    """A public SSH key of a key made for the tests (ssh-ed25519 AAAA...), as a .pub file holds it."""
    k = ed25519.Ed25519PrivateKey.generate().public_key()
    return k.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode("ascii")


SSH_ED25519 = ssh_public()  # alice's
SSH_RSA_USER = ssh_public()  # bob's (an expiring key)


def key_json(**changes) -> str:
    """A service account's key as Google gives it (the fields of its key file), pretty-printed as downloaded."""
    data = {"type": "service_account", "project_id": PROJECT, "private_key_id": KEY_ID, "private_key": PEM,
            "client_email": ACCOUNT, "client_id": "112233445566778899000",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": TOKEN_URI,
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{ACCOUNT}",
            "universe_domain": "googleapis.com"}
    data.update(changes)
    return json.dumps({k: v for k, v in data.items() if v is not None}, indent=2)


def b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def err(code: int, message: str, status: str, reason: str, details=None) -> dict:
    out = {"error": {"code": code, "message": message, "errors": [{"message": message, "domain": "global", "reason": reason}],
                     "status": status}}
    if details:
        out["error"]["details"] = details
    return out


def _self(path: str) -> str:
    return f"https://www.googleapis.com/compute/v1/projects/{PROJECT}/{path}"


def instance(name, zone, status="RUNNING", mt="e2-micro", nat=None, tags=(), disks=((10, "PERSISTENT"),), spot=False,
             metadata=()) -> dict:
    nic = {"name": "nic0", "network": _self("global/networks/default"), "networkIP": "10.128.0.2",
           "subnetwork": _self(f"regions/{zone.rsplit('-', 1)[0]}/subnetworks/default")}
    if nat:
        nic["accessConfigs"] = [{"type": "ONE_TO_ONE_NAT", "name": "External NAT", "natIP": nat, "networkTier": "PREMIUM"}]
    return {"kind": "compute#instance", "id": str(abs(hash(name)) % 10**18), "name": name, "status": status,
            "creationTimestamp": "2026-03-01T09:30:00.123-08:00", "zone": _self(f"zones/{zone}"),
            "machineType": _self(f"zones/{zone}/machineTypes/{mt}"), "networkInterfaces": [nic],
            "disks": [{"type": t, "mode": "READ_WRITE", "boot": i == 0, "diskSizeGb": str(gb), "deviceName": f"{name}-{i}",
                       **({"source": _self(f"zones/{zone}/disks/{name}-{i}")} if t == "PERSISTENT" else {})}
                      for i, (gb, t) in enumerate(disks)],
            "tags": {"items": list(tags), "fingerprint": "42WmSpB8rSM="},
            "serviceAccounts": [{"email": f"123456789-compute@developer.gserviceaccount.com",
                                 "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
            "scheduling": {"provisioningModel": "SPOT" if spot else "STANDARD", "preemptible": spot},
            "metadata": {"kind": "compute#metadata", "fingerprint": "abcd", "items": [dict(x) for x in metadata]},
            "selfLink": _self(f"zones/{zone}/instances/{name}")}


class FakeGoogle:
    """Google's token endpoint and the three APIs in memory; every request kept (`requests`: method, path, query, body)."""

    def __init__(self):
        self.requests: list[dict] = []
        self.tokens: list[str] = []
        self.revoked: set[str] = set()
        self.token_error: tuple[int, dict] | None = None
        self.fail: dict[tuple[str, str], tuple[int, dict]] = {}  # (method, a path's regex) -> (status, body)
        self.echo_secret: str | None = None  # every API error message holds this (a secret the plugin must scrub)
        self.op_polls = 1  # gets of a global operation before it says DONE
        self.op_error: dict | None = None  # the next global operation ends in this error
        self.page_size = 500  # a plain list's items a page (smaller: its pages followed)
        self.ops: dict[str, dict] = {}
        self.instances = {
            ("us-central1-a", "web-1"): instance("web-1", "us-central1-a", nat="34.123.45.67", tags=("http-server",),
                                                 disks=((20, "PERSISTENT"), (100, "PERSISTENT"))),
            ("us-central1-a", "batch-1"): instance("batch-1", "us-central1-a", status="TERMINATED", mt="e2-standard-2"),
            ("europe-west1-b", "scratch-1"): instance("scratch-1", "europe-west1-b", mt="n2-custom-4-8192",
                                                      nat="35.240.1.2", disks=((10, "PERSISTENT"), (375, "SCRATCH")),
                                                      metadata=({"key": "block-project-ssh-keys", "value": "true"},)),
        }
        self.machine_types = {
            ("us-central1-a", "e2-micro"): {"kind": "compute#machineType", "name": "e2-micro", "guestCpus": 2,
                                            "memoryMb": 1024, "isSharedCpu": True,
                                            "description": "Efficient Instance, 2 vCPU (1/8 shared physical core) and 1 GB RAM",
                                            "zone": "us-central1-a"},
            ("us-central1-a", "e2-standard-2"): {"kind": "compute#machineType", "name": "e2-standard-2", "guestCpus": 2,
                                                 "memoryMb": 8192, "isSharedCpu": False, "zone": "us-central1-a"},
        }
        self.disks = [
            {"name": "web-1-0", "sizeGb": "20", "type": _self("zones/us-central1-a/diskTypes/pd-balanced"), "status": "READY",
             "zone": _self("zones/us-central1-a"), "users": [_self("zones/us-central1-a/instances/web-1")],
             "creationTimestamp": "2026-03-01T09:30:00.123-08:00", "selfLink": _self("zones/us-central1-a/disks/web-1-0")},
            {"name": "web-1-1", "sizeGb": "100", "type": _self("zones/us-central1-a/diskTypes/pd-standard"), "status": "READY",
             "zone": _self("zones/us-central1-a"), "users": [_self("zones/us-central1-a/instances/web-1")],
             "creationTimestamp": "2026-03-02T09:30:00.123-08:00", "selfLink": _self("zones/us-central1-a/disks/web-1-1")},
            {"name": "spare", "sizeGb": "50", "type": _self("zones/us-central1-a/diskTypes/pd-ssd"), "status": "READY",
             "zone": _self("zones/us-central1-a"), "creationTimestamp": "2026-04-01T09:30:00.123-08:00",
             "selfLink": _self("zones/us-central1-a/disks/spare")},
        ]
        self.addresses = [
            {"name": "web-ip", "address": "34.123.45.67", "addressType": "EXTERNAL", "status": "IN_USE",
             "region": _self("regions/us-central1"), "networkTier": "PREMIUM", "ipVersion": "IPV4",
             "users": [_self("zones/us-central1-a/instances/web-1")], "creationTimestamp": "2026-03-01T09:00:00.000-08:00",
             "selfLink": _self("regions/us-central1/addresses/web-ip")},
            {"name": "held-ip", "address": "34.99.88.77", "addressType": "EXTERNAL", "status": "RESERVED",
             "region": _self("regions/us-central1"), "networkTier": "PREMIUM", "creationTimestamp": "2026-05-01T09:00:00.000-07:00",
             "selfLink": _self("regions/us-central1/addresses/held-ip")},
        ]
        self.global_addresses = [
            {"name": "lb-ip", "address": "34.111.22.33", "addressType": "EXTERNAL", "status": "RESERVED",
             "networkTier": "PREMIUM", "ipVersion": "IPV4", "creationTimestamp": "2026-06-01T09:00:00.000-07:00",
             "selfLink": _self("global/addresses/lb-ip")},
        ]
        self.firewalls = {r["name"]: r for r in [
            {"name": "default-allow-ssh", "network": _self("global/networks/default"), "direction": "INGRESS",
             "priority": 65534, "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
             "selfLink": _self("global/firewalls/default-allow-ssh")},
            {"name": "default-allow-icmp", "network": _self("global/networks/default"), "direction": "INGRESS",
             "priority": 65534, "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "icmp"}],
             "selfLink": _self("global/firewalls/default-allow-icmp")},
            {"name": "allow-http", "network": _self("global/networks/default"), "direction": "INGRESS", "priority": 1000,
             "sourceRanges": ["0.0.0.0/0"], "targetTags": ["http-server"], "allowed": [{"IPProtocol": "tcp", "ports": ["80"]}],
             "selfLink": _self("global/firewalls/allow-http")},
            {"name": "deny-smtp-out", "network": _self("global/networks/default"), "direction": "EGRESS", "priority": 900,
             "destinationRanges": ["0.0.0.0/0"], "denied": [{"IPProtocol": "tcp", "ports": ["25"]}],
             "selfLink": _self("global/firewalls/deny-smtp-out")},
        ]}
        self.zones = [{"kind": "compute#zone", "name": z, "status": "UP", "region": _self(f"regions/{z.rsplit('-', 1)[0]}")}
                      for z in ("us-central1-a", "us-central1-b", "europe-west1-b")]
        self.regions = [
            {"kind": "compute#region", "name": "us-central1", "status": "UP",
             "quotas": [{"metric": "CPUS", "limit": 24, "usage": 4}, {"metric": "DISKS_TOTAL_GB", "limit": 4096, "usage": 170},
                        {"metric": "STATIC_ADDRESSES", "limit": 8, "usage": 2},
                        {"metric": "INSTANCE_GROUPS", "limit": 100, "usage": 0}]},
            {"kind": "compute#region", "name": "europe-west1", "status": "UP",
             "quotas": [{"metric": "CPUS", "limit": 24, "usage": 4}]},
            {"kind": "compute#region", "name": "asia-east1", "status": "UP", "quotas": [{"metric": "CPUS", "limit": 24, "usage": 0}]},
        ]
        self.metadata = {"kind": "compute#metadata", "fingerprint": "fp-1", "items": [
            {"key": "startup-script", "value": "#! /bin/bash\necho hello > /tmp/hello"},
            {"key": "ssh-keys", "value": f"alice:{SSH_ED25519} alice@laptop\n"
                                         f"bob:{SSH_RSA_USER} google-ssh "
                                         '{"userName":"bob@example.com","expireOn":"2026-12-01T00:00:00+0000"}'},
            {"key": "enable-guest-attributes", "value": "TRUE"}]}
        self.project_quotas = [{"metric": "SNAPSHOTS", "limit": 5000, "usage": 3}, {"metric": "NETWORKS", "limit": 15, "usage": 1},
                               {"metric": "FIREWALLS", "limit": 200, "usage": 4}, {"metric": "IMAGES", "limit": 2000, "usage": 0}]
        self.managed_zones = [
            {"kind": "dns#managedZone", "name": "example-com", "dnsName": "example.com.", "id": "4321", "visibility": "public",
             "nameServers": ["ns-cloud-a1.googledomains.com.", "ns-cloud-a2.googledomains.com.",
                             "ns-cloud-a3.googledomains.com.", "ns-cloud-a4.googledomains.com."],
             "dnssecConfig": {"state": "off"}, "creationTime": "2026-02-01T10:00:00.000Z"},
            {"kind": "dns#managedZone", "name": "internal", "dnsName": "corp.internal.", "id": "4322", "visibility": "private",
             "nameServers": ["ns-gcp-private.googledomains.com."], "creationTime": "2026-02-02T10:00:00.000Z"},
        ]
        self.rrsets = {
            "example-com": [
                {"kind": "dns#resourceRecordSet", "name": "example.com.", "type": "A", "ttl": 300, "rrdatas": ["198.51.100.7"]},
                {"kind": "dns#resourceRecordSet", "name": "example.com.", "type": "NS", "ttl": 21600,
                 "rrdatas": ["ns-cloud-a1.googledomains.com.", "ns-cloud-a2.googledomains.com."]},
                {"kind": "dns#resourceRecordSet", "name": "example.com.", "type": "SOA", "ttl": 21600,
                 "rrdatas": ["ns-cloud-a1.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300"]},
                {"kind": "dns#resourceRecordSet", "name": "example.com.", "type": "TXT", "ttl": 300,
                 "rrdatas": ['"v=spf1 include:_spf.google.com ~all"', '"google-site-verification=abc123"']},
                {"kind": "dns#resourceRecordSet", "name": "example.com.", "type": "MX", "ttl": 3600,
                 "rrdatas": ["1 smtp.google.com."]},
                {"kind": "dns#resourceRecordSet", "name": "www.example.com.", "type": "CNAME", "ttl": 300,
                 "rrdatas": ["example.com."]},
            ],
            "internal": [
                {"kind": "dns#resourceRecordSet", "name": "corp.internal.", "type": "SOA", "ttl": 21600,
                 "rrdatas": ["ns-gcp-private.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300"]},
                {"kind": "dns#resourceRecordSet", "name": "db.corp.internal.", "type": "A", "ttl": 300, "rrdatas": ["10.128.0.9"]},
            ],
        }
        self.changes = 0
        self.billing = {"name": f"projects/{PROJECT}/billingInfo", "projectId": PROJECT,
                        "billingAccountName": "billingAccounts/012345-567890-ABCDEF", "billingEnabled": True}
        self.account = {"name": "billingAccounts/012345-567890-ABCDEF", "open": True, "displayName": "My Billing Account",
                        "masterBillingAccount": "", "currencyCode": "USD"}

    # -- what was asked ---------------------------------------------------------------------------------------------------
    def calls(self, method: str | None = None) -> list[tuple[str, str]]:
        return [(r["method"], r["path"]) for r in self.requests if method is None or r["method"] == method]

    def writes(self) -> list[dict]:
        return [r for r in self.requests if r["method"] != "GET" and r["path"] != "/token"]

    # -- the transport ------------------------------------------------------------------------------------------------------
    def __call__(self, method, url, headers, body, timeout):
        parts = urlsplit(url)
        query = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parts.query).items()}
        sent = None
        if body:
            text = body.decode("utf-8")
            sent = json.loads(text) if headers.get("Content-Type") == "application/json" else \
                {k: v[0] for k, v in parse_qs(text).items()}
        self.requests.append({"method": method, "host": parts.hostname, "path": parts.path, "query": query, "body": sent,
                              "headers": dict(headers)})
        if url.startswith(TOKEN_URI):
            return self._token(method, headers, sent)
        token = str(headers.get("Authorization") or "").removeprefix("Bearer ")
        if token not in self.tokens or token in self.revoked:
            return self._json(401, err(401, "Request had invalid authentication credentials. Expected OAuth 2 access token.",
                                       "UNAUTHENTICATED", "authError"))
        for (m, pattern), (status, answer) in self.fail.items():
            if m == method and re.search(pattern, parts.path):
                if self.echo_secret:
                    answer = json.loads(json.dumps(answer).replace("SECRET", self.echo_secret))
                return self._json(status, answer)
        try:
            status, answer = self._route(method, parts.hostname, parts.path, query, sent)
        except LookupError as e:
            status, answer = 404, err(404, f"The resource '{e}' was not found", "NOT_FOUND", "notFound")
        return self._json(status, answer)

    @staticmethod
    def _json(status, data):
        return status, {"Content-Type": "application/json; charset=UTF-8"}, json.dumps(data).encode()

    def _token(self, method, headers, form):
        assert method == "POST" and headers.get("Content-Type") == "application/x-www-form-urlencoded"
        if self.token_error:
            return self._json(*self.token_error)
        assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        head, claims, signature = form["assertion"].split(".")
        PUBLIC.verify(b64url_decode(signature), f"{head}.{claims}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        c = json.loads(b64url_decode(claims))
        assert c["iss"] == ACCOUNT and c["aud"] == TOKEN_URI and c["exp"] - c["iat"] <= 3600
        token = f"ya29.stand-in-token-{len(self.tokens) + 1}"
        self.tokens.append(token)
        return self._json(200, {"access_token": token, "expires_in": 3599, "token_type": "Bearer", "scope": c["scope"]})

    def _op(self, kind: str, target: str, zone: str | None = None) -> dict:
        name = f"operation-{len(self.ops) + 1}-{kind}"
        op = {"kind": "compute#operation", "id": str(len(self.ops) + 1), "name": name, "operationType": kind,
              "targetLink": target, "status": "RUNNING", "progress": 0, "user": ACCOUNT,
              "insertTime": "2026-11-11T10:00:00.000-08:00",
              "selfLink": _self(f"zones/{zone}/operations/{name}" if zone else f"global/operations/{name}"),
              "_polls": 0}
        if zone:
            op["zone"] = _self(f"zones/{zone}")
        if self.op_error and not zone:
            op["_error"], self.op_error = self.op_error, None
        self.ops[name] = op
        return {k: v for k, v in op.items() if not k.startswith("_")}

    def _route(self, method, host, path, query, body):
        P = f"/compute/v1/projects/{PROJECT}"
        if host == "compute.googleapis.com":
            assert path.startswith(P), path
            rest = path[len(P):]
            if method == "GET" and rest == "":
                return 200, {"kind": "compute#project", "name": PROJECT, "id": "555666777", "commonInstanceMetadata": self.metadata,
                             "quotas": self.project_quotas, "defaultServiceAccount": "123456789-compute@developer.gserviceaccount.com",
                             "defaultNetworkTier": "PREMIUM", "creationTimestamp": "2025-01-01T00:00:00.000-08:00"}
            if method == "GET" and rest in ("/aggregated/instances", "/aggregated/disks", "/aggregated/addresses"):
                assert query.get("returnPartialSuccess") == "true" and query.get("maxResults") == "500"
                return 200, self._aggregated(rest.rsplit("/", 1)[1])
            m = re.match(r"^/zones/([^/]+)/instances/([^/]+)$", rest)
            if method == "GET" and m:
                inst = self.instances.get((m.group(1), m.group(2)))
                if inst is None:
                    raise LookupError(f"projects/{PROJECT}/zones/{m.group(1)}/instances/{m.group(2)}")
                return 200, inst
            m = re.match(r"^/zones/([^/]+)/instances/([^/]+)/(start|stop|reset)$", rest)
            if method == "POST" and m:
                assert body is None and re.match(r"^[0-9a-f-]{36}$", query.get("requestId", "")), (body, query)
                inst = self.instances[(m.group(1), m.group(2))]
                inst["status"] = {"start": "STAGING", "stop": "STOPPING", "reset": "RUNNING"}[m.group(3)]
                return 200, self._op(m.group(3), inst["selfLink"], zone=m.group(1))
            m = re.match(r"^/zones/([^/]+)/machineTypes/([^/]+)$", rest)
            if method == "GET" and m:
                mt = self.machine_types.get((m.group(1), m.group(2)))
                if mt is None:
                    raise LookupError(f"projects/{PROJECT}/zones/{m.group(1)}/machineTypes/{m.group(2)}")
                return 200, mt
            if method == "GET" and rest == "/global/addresses":
                return 200, self._page(self.global_addresses, query, "compute#addressList")
            if method == "GET" and rest == "/global/firewalls":
                return 200, self._page(list(self.firewalls.values()), query, "compute#firewallList")
            if method == "POST" and rest == "/global/firewalls":
                assert re.match(r"^[0-9a-f-]{36}$", query.get("requestId", ""))
                if body["name"] in self.firewalls:
                    return 409, err(409, f"The resource 'projects/{PROJECT}/global/firewalls/{body['name']}' already exists",
                                    "ALREADY_EXISTS", "alreadyExists")
                self.firewalls[body["name"]] = {**body, "network": _self(body["network"]),
                                                "selfLink": _self(f"global/firewalls/{body['name']}")}
                return 200, self._op("insert", _self(f"global/firewalls/{body['name']}"))
            m = re.match(r"^/global/firewalls/([^/]+)$", rest)
            if method == "DELETE" and m:
                assert body is None and re.match(r"^[0-9a-f-]{36}$", query.get("requestId", ""))
                if m.group(1) not in self.firewalls:
                    raise LookupError(f"projects/{PROJECT}/global/firewalls/{m.group(1)}")
                del self.firewalls[m.group(1)]
                return 200, self._op("delete", _self(f"global/firewalls/{m.group(1)}"))
            m = re.match(r"^/global/operations/([^/]+)$", rest)
            if method == "GET" and m:
                op = self.ops.get(m.group(1))
                if op is None:
                    raise LookupError(f"projects/{PROJECT}/global/operations/{m.group(1)}")
                op["_polls"] += 1
                if op["_polls"] >= self.op_polls:
                    op["status"], op["progress"] = "DONE", 100
                    if op.get("_error"):
                        op["error"], op["httpErrorStatusCode"], op["httpErrorMessage"] = op["_error"], 400, "BAD REQUEST"
                return 200, {k: v for k, v in op.items() if not k.startswith("_")}
            if method == "POST" and rest == "/setCommonInstanceMetadata":
                assert re.match(r"^[0-9a-f-]{36}$", query.get("requestId", ""))
                if body.get("fingerprint") != self.metadata["fingerprint"]:
                    return 412, err(412, "Supplied fingerprint does not match current metadata fingerprint.",
                                    "FAILED_PRECONDITION", "conditionNotMet")
                n = int(self.metadata["fingerprint"].split("-")[1]) + 1
                self.metadata = {"kind": "compute#metadata", "fingerprint": f"fp-{n}", "items": body["items"]}
                return 200, self._op("setMetadata", _self(""))
            if method == "GET" and rest == "/zones":
                return 200, self._page(self.zones, query, "compute#zoneList")
            if method == "GET" and rest == "/regions":
                return 200, self._page(self.regions, query, "compute#regionList")
            raise AssertionError(f"compute: {method} {path}")
        if host == "dns.googleapis.com":
            D = f"/dns/v1/projects/{PROJECT}/managedZones"
            if method == "GET" and path == D:
                return 200, {"kind": "dns#managedZonesListResponse", "managedZones": self.managed_zones}
            m = re.match(rf"^{D}/([^/]+)/rrsets$", path)
            if method == "GET" and m:
                sets = self.rrsets.get(m.group(1))
                if sets is None:
                    raise LookupError(f"managedZones/{m.group(1)}")
                name, rtype = query.get("name"), query.get("type")
                found = [s for s in sets if (not name or s["name"] == name) and (not rtype or s["type"] == rtype)]
                return 200, {"kind": "dns#resourceRecordSetsListResponse", "rrsets": found}
            m = re.match(rf"^{D}/([^/]+)/changes$", path)
            if method == "POST" and m:
                return self._change(m.group(1), body)
            raise AssertionError(f"dns: {method} {path}")
        if host == "cloudbilling.googleapis.com":
            if method == "GET" and path == f"/v1/projects/{PROJECT}/billingInfo":
                return 200, self.billing
            if method == "GET" and path == f"/v1/{self.account['name']}":
                return 200, self.account
            raise AssertionError(f"billing: {method} {path}")
        raise AssertionError(f"a host no test answers: {host}")

    def _aggregated(self, what: str) -> dict:
        items: dict = {}
        if what == "instances":
            for (zone, _), inst in self.instances.items():
                items.setdefault(f"zones/{zone}", {"instances": []})["instances"].append(inst)
            items["zones/asia-east1-a"] = {"warning": {"code": "NO_RESULTS_ON_PAGE",
                                                       "message": "There are no results for scope 'zones/asia-east1-a' on this page.",
                                                       "data": [{"key": "scope", "value": "zones/asia-east1-a"}]}}
        elif what == "disks":
            for d in self.disks:
                items.setdefault(f"zones/{d['zone'].rsplit('/', 1)[1]}", {"disks": []})["disks"].append(d)
        else:
            for a in self.addresses:
                items.setdefault(f"regions/{a['region'].rsplit('/', 1)[1]}", {"addresses": []})["addresses"].append(a)
        kind = {"instances": "instance", "disks": "disk", "addresses": "address"}[what]
        return {"kind": f"compute#{kind}AggregatedList", "id": f"projects/{PROJECT}/aggregated/{what}", "items": items,
                "selfLink": _self(f"aggregated/{what}")}

    def _page(self, items: list, query: dict, kind: str) -> dict:
        start = int(query.get("pageToken") or 0)
        size = min(self.page_size, int(query.get("maxResults") or 500))
        out = {"kind": kind, "id": f"projects/{PROJECT}", "items": items[start:start + size]}
        if start + size < len(items):
            out["nextPageToken"] = str(start + size)
        return out

    def _change(self, zone: str, body: dict):
        sets = self.rrsets[zone]
        assert set(body) <= {"additions", "deletions"}
        for d in body.get("deletions") or []:
            match = next((s for s in sets if s["name"] == d["name"] and s["type"] == d["type"]), None)
            if match is None or match["ttl"] != d.get("ttl") or match["rrdatas"] != d.get("rrdatas"):
                return 412, err(412, f"The resource 'entity.change.deletions[{d['name']}][{d['type']}]' does not match "
                                     "the existing data", "FAILED_PRECONDITION", "conditionNotMet")
        for a in body.get("additions") or []:
            left = [s for s in sets if not any(s["name"] == d["name"] and s["type"] == d["type"] for d in body.get("deletions") or [])]
            if any(s["name"] == a["name"] and s["type"] == a["type"] for s in left):
                return 409, err(409, f"The resource 'entity.change.additions[{a['name']}][{a['type']}]' already exists",
                                "ALREADY_EXISTS", "alreadyExists")
        for d in body.get("deletions") or []:
            sets[:] = [s for s in sets if not (s["name"] == d["name"] and s["type"] == d["type"])]
        for a in body.get("additions") or []:
            sets.append({**a})
        self.changes += 1
        return 200, {"kind": "dns#change", "additions": body.get("additions") or [], "deletions": body.get("deletions") or [],
                     "startTime": "2026-11-11T18:00:00.000Z", "id": str(self.changes), "status": "pending"}


class Pairs(Login):
    """A login holding pairs by name (the login app's store, as the Login interface asks it)."""

    NAMESPACE = "test"

    def __init__(self, values: dict[str, str]):
        self.pairs = {pair_name(k): v for k, v in values.items()}
        self.asked: list[str] = []

    def user(self) -> dict:
        return {"name": "tester"}

    def vector(self, name: str) -> str:
        self.asked.append(name)
        if name not in self.pairs:
            raise Unauthorized(f"no {name}", 404)
        return self.pairs[name]

    def names(self) -> set[str]:
        return set(self.pairs)


def settings_of(**more) -> dict[str, str]:
    return {"GOOGLECLOUD_KEY": key_json(), **more}


@pytest.fixture(autouse=True)
def _no_google_no_network(monkeypatch):
    """No test reaches Google, a resolver or this machine's settings: HTTPS and nslookup refused, every GOOGLECLOUD_
    variable cleared."""
    def refused(*a, **k):
        raise AssertionError("a test reached for the network")
    monkeypatch.setattr(rest_mod, "_requests_transport", refused)
    monkeypatch.setattr(dns_mod, "query", refused)
    for n in NAMES:
        monkeypatch.delenv(n, raising=False)


@pytest.fixture
def env(monkeypatch):
    """Sets the plugin's variables (the EnvironmentLogin's: what the platform reads today)."""
    def put(values: dict[str, str]):
        for k, v in values.items():
            monkeypatch.setenv(k, v)
    return put


@pytest.fixture
def made():
    """A plugin over the stand-ins: (plugin, fake Google). Its sleeps are kept, never slept."""
    def make(fake: FakeGoogle | None = None, public=(HOME, "a stand-in")):
        fake = fake or FakeGoogle()
        slept: list[float] = []
        p = GoogleCloudPlugin(transport=fake, public=(lambda: public), sleep=slept.append)
        p.slept = slept
        return p, fake
    return make
