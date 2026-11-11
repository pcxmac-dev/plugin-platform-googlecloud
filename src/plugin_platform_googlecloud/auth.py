"""A service account's access token, as Google's guide to OAuth 2.0 for server to server applications gives it
(https://developers.google.com/identity/protocols/oauth2/service-account, read 2026-11-11): a JWT whose header says RS256
and JWT (and the key's id), whose claims name the account (iss), the scopes asked (scope, space separated), the token
endpoint (aud: the key's token_uri), when it was made (iat) and when it ends (exp: an hour at most), signed with the
account's private key (RSA with SHA-256; base64url, no padding), then posted to the key's token_uri as the JWT bearer
grant (grant_type urn:ietf:params:oauth:grant-type:jwt-bearer, assertion). The answer's access_token is borne by every
request (RestClient's bearer) until its expires_in, kept by the library's TokenSource until a minute before it ends.

The key is the JSON Google gives when a service account's key is made (type service_account, project_id,
private_key_id, private_key, client_email, token_uri ...), read from the login's pair GOOGLECLOUD_KEY, never written
anywhere; its private parts are taken out of every word said, and a key whose token_uri is not Google's is refused (its
signed request goes nowhere else)."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from liminal_libs.machines.rest import RestClient, RestError, TokenSource

from .api import google_words

TOKEN_URI = "https://oauth2.googleapis.com/token"
GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
LIFETIME_S = 3600  # the longest a JWT may last (exp - iat), and an access token's usual life
UNIVERSE = "googleapis.com"  # the plugin speaks to Google Cloud's own APIs alone
# the scopes asked: Compute Engine (reads and the power, firewall and metadata changes), Cloud DNS (reads and changes),
# Cloud Billing (reads); the service account's roles decide what of them it may do (README)
SCOPES = ("https://www.googleapis.com/auth/compute",
          "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
          "https://www.googleapis.com/auth/cloud-billing.readonly")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TOKEN_HOSTS = ("oauth2.googleapis.com", "accounts.google.com")  # and any host under .googleapis.com


class BadKey(ValueError):
    """A key that cannot be used, in words that hold nothing of it."""


@dataclass(frozen=True)
class ServiceAccountKey:
    """A service account's key as read (its private key loaded, never shown)."""

    client_email: str
    private_key: str = field(repr=False)
    private_key_id: str = field(default="", repr=False)
    project_id: str = ""
    token_uri: str = TOKEN_URI
    client_id: str = ""
    signer: object = field(default=None, repr=False, compare=False)

    @property
    def secrets(self) -> tuple[str, ...]:
        """What is taken out of every word: the private key (whole and line by line) and its id."""
        lines = [x.strip() for x in self.private_key.splitlines() if len(x.strip()) >= 16 and "PRIVATE KEY" not in x]
        return tuple(s for s in (self.private_key, self.private_key_id, *lines) if s)

    @property
    def fingerprint(self) -> str:
        """A hash of the key (kept in memory to notice a change; never shown nor written)."""
        return hashlib.sha256("\0".join((self.client_email, self.private_key_id, self.private_key)).encode()).hexdigest()


def parse_key(text: str) -> ServiceAccountKey:
    """A service account's key from its JSON as Google gave it (line breaks between its fields or none); BadKey when
    it is none."""
    raw = str(text or "").strip()
    if not raw:
        raise BadKey("nothing is set")
    try:
        data = json.loads(raw)
    except ValueError:
        raise BadKey("it is not JSON: paste the whole key file Google gave (it starts with {)") from None
    if not isinstance(data, dict):
        raise BadKey("it is not a key file's JSON object")
    kind = data.get("type")
    if kind != "service_account":
        raise BadKey(f"it is a key of type {kind!r}, not a service account's (type service_account)" if kind
                     else "it holds no type: not a service account's key file")
    email = str(data.get("client_email") or "").strip()
    if not EMAIL.match(email):
        raise BadKey("its client_email is not a service account's address")
    pem = str(data.get("private_key") or "")
    if "PRIVATE KEY-----" not in pem:
        raise BadKey("it holds no private key (private_key)")
    token_uri = str(data.get("token_uri") or TOKEN_URI).strip()
    parts = urlsplit(token_uri)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not (host in TOKEN_HOSTS or host.endswith("." + UNIVERSE)):
        raise BadKey(f"its token_uri ({token_uri[:80]}) is not Google's token endpoint: the key's signed request goes to Google alone")
    universe = str(data.get("universe_domain") or UNIVERSE).strip().lower()
    if universe != UNIVERSE:
        raise BadKey(f"it is a key of another universe ({universe[:40]}): the plugin speaks to {UNIVERSE} alone")
    try:
        signer = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise BadKey("its private key could not be read (paste the key file whole, as Google gave it)") from None
    if not isinstance(signer, rsa.RSAPrivateKey):
        raise BadKey("its private key is not an RSA key (RS256 needs one)")
    return ServiceAccountKey(client_email=email, private_key=pem, private_key_id=str(data.get("private_key_id") or ""),
                             project_id=str(data.get("project_id") or "").strip(), token_uri=token_uri,
                             client_id=str(data.get("client_id") or ""), signer=signer)


def b64url(data: bytes) -> str:
    """Base64url without padding (the JWT's encoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _compact(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=False).encode("utf-8")


def assertion(key: ServiceAccountKey, scopes, now: float, lifetime: float = LIFETIME_S) -> str:
    """The signed JWT asking `scopes` for `key`'s account (module docstring), made at `now`."""
    iat = int(now)
    header = {"alg": "RS256", "typ": "JWT"}
    if key.private_key_id:
        header["kid"] = key.private_key_id
    claims = {"iss": key.client_email, "scope": " ".join(scopes), "aud": key.token_uri,
              "exp": iat + int(min(lifetime, LIFETIME_S)), "iat": iat}
    signing = f"{b64url(_compact(header))}.{b64url(_compact(claims))}"
    signature = key.signer.sign(signing.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing}.{b64url(signature)}"


class Tokens:
    """The access token of a key, asked of its token_uri (a RestClient of its own) with the JWT bearer grant and kept
    by a TokenSource until a minute before it ends. Called, it gives the token (a request's bearer); `forget()` drops
    it (refused: a 401)."""

    def __init__(self, key: ServiceAccountKey, transport=None, clock=time.time, sleep=time.sleep, scopes=SCOPES):
        self.key = key
        self.scopes = tuple(scopes)
        self._clock = clock
        self.client = RestClient(key.token_uri, transport=transport, secrets=key.secrets, error=google_words,
                                 clock=clock, sleep=sleep)
        self.source = TokenSource(self._fetch, clock=clock)
        self.until: float | None = None  # when the token held ends
        self.asked = 0  # tokens asked
        self.held = ""  # the token held (taken out of every word)

    def _fetch(self) -> tuple[str, float]:
        data = self.client.post("", form={"grant_type": GRANT, "assertion": assertion(self.key, self.scopes, self._clock())})
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise RestError("Google's token endpoint answered without an access token")
        try:
            lasts = float(data.get("expires_in") or LIFETIME_S)
        except (TypeError, ValueError):
            lasts = float(LIFETIME_S)
        self.until, self.held = self._clock() + lasts, token
        self.asked += 1
        return token, lasts

    def __call__(self) -> str:
        return self.source()

    def forget(self) -> None:
        self.source.forget()
        self.until, self.held = None, ""
