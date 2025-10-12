# pylint: disable=redefined-outer-name

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
import pytest

from simple_oauth_server.asymmetric_key_pair import AsymmetricKeyPair
from simple_oauth_server.token_validator import AuthTokenValidator


ISSUER = "https://oauth.local/"


@pytest.fixture(scope="module")
def rsa_keys() -> AsymmetricKeyPair:
    return AsymmetricKeyPair()


@pytest.fixture
def validator(rsa_keys: AsymmetricKeyPair) -> AuthTokenValidator:
    return AuthTokenValidator(rsa_keys.public_key_pem, ISSUER)


def sign_token(
    keys: AsymmetricKeyPair,
    sub: str,
    audience: str,
    scope: str,
    permissions: list[str] | None = None,
    expires_in: int = 3600,
) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "iss": ISSUER,
        "sub": sub,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "scope": scope,
        "permissions": permissions or [],
    }
    headers = {"kid": "test-key"}
    return jwt.encode(
        payload,
        keys.private_key_pem,
        algorithm="RS256",
        headers=headers,
    )


def make_rest_event(
    method: str, resource_path: str, token: str
) -> Dict[str, Any]:
    method_arn = (
        "arn:aws:execute-api:us-east-1:123456789012:apiid/dev/"
        f"{method}{resource_path}"
    )
    return {
        "type": "TOKEN",
        "methodArn": method_arn,
        "authorizationToken": f"Bearer {token}",
        "headers": {},
    }


def parse_error(resp: Dict[str, Any]) -> Dict[str, Any]:
    if resp.get("statusCode") in (401, 500):
        return json.loads(resp.get("body", "{}"))
    return {}


def test_scope_exact_allows_read(
    validator: AuthTokenValidator, rsa_keys: AsymmetricKeyPair
) -> None:
    token = sign_token(
        rsa_keys, sub="reader", audience="dev", scope="read:pets"
    )
    event = make_rest_event("GET", "/pets", token)
    policy_or_resp = validator.handler(event, None)
    assert "policyDocument" in policy_or_resp  # allowed


def test_scope_insufficient_denied(
    validator: AuthTokenValidator, rsa_keys: AsymmetricKeyPair
) -> None:
    token = sign_token(
        rsa_keys, sub="reader", audience="dev", scope="read:pets"
    )
    event = make_rest_event("DELETE", "/pets/1", token)
    resp = validator.handler(event, None)
    assert resp.get("statusCode") == 401
    body = parse_error(resp)
    assert body.get("error") == "insufficient_scope"
    assert body.get("required_scope") == "delete:pets"


def test_scope_action_wildcard_allows_any_entity(
    validator: AuthTokenValidator, rsa_keys: AsymmetricKeyPair
) -> None:
    token = sign_token(rsa_keys, sub="writer", audience="dev", scope="write:*")
    event = make_rest_event("POST", "/albums", token)
    policy_or_resp = validator.handler(event, None)
    assert "policyDocument" in policy_or_resp  # allowed due to write:*


def test_scope_global_wildcard_allows_all(
    validator: AuthTokenValidator, rsa_keys: AsymmetricKeyPair
) -> None:
    token = sign_token(rsa_keys, sub="admin", audience="dev", scope="*")
    event = make_rest_event("DELETE", "/anything/42", token)
    policy_or_resp = validator.handler(event, None)
    assert "policyDocument" in policy_or_resp  # allowed due to *
