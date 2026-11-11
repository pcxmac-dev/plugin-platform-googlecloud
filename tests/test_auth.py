"""The service account's access token (auth.py), as Google's guide to OAuth 2.0 for server to server applications gives
it: a JWT signed RS256 with the key's private key, its claims as the guide names them, posted to the key's token_uri
with the JWT bearer grant, the token kept until a minute before it ends. Over the stand-ins alone (the key is the tests'
own, made in conftest)."""
from __future__ import annotations

import json

import pytest

from conftest import ACCOUNT, KEY_ID, PEM, TOKEN_URI, FakeGoogle, b64url_decode, key_json
from liminal_libs.machines.rest import RestError
from plugin_platform_googlecloud.auth import GRANT, SCOPES, BadKey, Tokens, parse_key


def test_the_jwt_is_signed_rs256_with_the_claims_googles_guide_names():
    fake = FakeGoogle()  # its token endpoint checks the signature with the key's public half
    now = [1_800_000_000.0]
    tokens = Tokens(parse_key(key_json()), transport=fake, clock=lambda: now[0])
    assert tokens() == "ya29.stand-in-token-1" and tokens() == "ya29.stand-in-token-1"  # kept: asked once
    (asked,) = [r for r in fake.requests if r["path"] == "/token"]
    assert asked["method"] == "POST" and asked["host"] == "oauth2.googleapis.com"
    assert asked["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert set(asked["body"]) == {"grant_type", "assertion"} and asked["body"]["grant_type"] == GRANT
    head, claims, signature = asked["body"]["assertion"].split(".")
    assert "=" not in head + claims + signature  # base64url without padding
    assert json.loads(b64url_decode(head)) == {"alg": "RS256", "typ": "JWT", "kid": KEY_ID}
    c = json.loads(b64url_decode(claims))
    assert c == {"iss": ACCOUNT, "scope": " ".join(SCOPES), "aud": TOKEN_URI, "exp": 1_800_003_600, "iat": 1_800_000_000}
    assert c["scope"].split(" ") == ["https://www.googleapis.com/auth/compute",
                                     "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
                                     "https://www.googleapis.com/auth/cloud-billing.readonly"]
    assert tokens.asked == 1 and tokens.held == "ya29.stand-in-token-1" and tokens.until == now[0] + 3599
    now[0] += 3599 - 59  # a minute before it ends: a new one
    assert tokens() == "ya29.stand-in-token-2" and tokens.asked == 2
    tokens.forget()  # refused (a 401): asked anew
    assert tokens() == "ya29.stand-in-token-3" and tokens.client.facts()["Requests"] == "3 made"


def test_a_key_pasted_on_one_line_or_downloaded_is_the_same_key():
    pretty, flat = parse_key(key_json()), parse_key(key_json().replace("\n", ""))  # a password field drops line breaks
    assert pretty == flat and pretty.client_email == ACCOUNT and pretty.project_id == "liminal-test"
    assert PEM not in repr(pretty) and KEY_ID not in repr(pretty)  # never shown


@pytest.mark.parametrize("text, words", [
    ("", "nothing is set"),
    ("{not json", "it is not JSON"),
    ("[1, 2]", "not a key file's JSON object"),
    ('{"type": "authorized_user", "client_id": "x"}', "not a service account's"),
    (key_json(private_key=None), "it holds no private key"),
    (key_json(client_email="nobody"), "not a service account's address"),
    (key_json(token_uri="https://evil.example.com/token"), "is not Google's token endpoint"),
    (key_json(token_uri="http://oauth2.googleapis.com/token"), "is not Google's token endpoint"),
    (key_json(universe_domain="example-sovereign.cloud"), "another universe"),
    (key_json(private_key="-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), "could not be read"),
])
def test_a_key_that_cannot_be_used_is_refused_in_words_without_its_secrets(text, words):
    with pytest.raises(BadKey, match=words) as refused:
        parse_key(text)
    said = str(refused.value)
    assert "PRIVATE KEY" not in said and KEY_ID not in said and PEM[40:80] not in said


def test_a_refused_key_is_worded_with_googles_reason_and_nothing_of_it():
    fake = FakeGoogle()
    fake.token_error = (400, {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
    tokens = Tokens(parse_key(key_json()), transport=fake)
    with pytest.raises(RestError) as refused:
        tokens()
    said = str(refused.value)
    assert refused.value.status == 400 and refused.value.code == "invalid_grant"
    assert said == ("POST /token: HTTP 400: invalid_grant: Invalid JWT Signature. (Google refused the key's signed "
                    "request: the key was deleted or disabled, or this PC's clock is off)")
    assert tokens.held == "" and tokens.asked == 0
