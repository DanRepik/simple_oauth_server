# pylint: disable=redefined-outer-name

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, cast

import jwt
import pytest

from simple_oauth_server.asymmetric_key_pair import AsymmetricKeyPair
from simple_oauth_server.token_validator import (
    AuthTokenValidator,
    DEFAULT_ARN,
)
import simple_oauth_server.token_validator as token_validator


ISSUER = "https://oauth.local/"


@pytest.fixture(scope="module")
def rsa_keys() -> AsymmetricKeyPair:
    return AsymmetricKeyPair()


@pytest.fixture
def validator(rsa_keys: AsymmetricKeyPair) -> AuthTokenValidator:
    v = AuthTokenValidator(rsa_keys.public_key_pem, ISSUER)
    # Inject module-level attribute used in debug logging inside decode_token.
    setattr(token_validator, "public_key", rsa_keys.public_key_pem)
    return v


def sign_token(
    keys: AsymmetricKeyPair,
    sub: str,
    audience: str,
    scope: str = "",
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
        payload, keys.private_key_pem, algorithm="RS256", headers=headers
    )


def make_rest_event(token: str, region: str = "us-east-1") -> Dict[str, Any]:
    method_arn = (
        f"arn:aws:execute-api:{region}:123456789012:apiid/dev/GET/pets"
    )
    return {
        "type": "TOKEN",
        "methodArn": method_arn,
        "authorizationToken": f"Bearer {token}",
        "headers": {},
    }


def make_ws_event(token: str, region: str = "us-east-1") -> Dict[str, Any]:
    # Include @connections for WS so arn pieces length fits expectations
    method_arn = (
        f"arn:aws:execute-api:{region}:123456789012:apiid/dev/@connections"
    )
    return {
        "methodArn": method_arn,
        "headers": {
            "sec-websocket-protocol": ", ".join(["proto1", token]),
        },
    }


def get_statement_resources(policy: Dict[str, Any]) -> list[str]:
    pd = cast(Dict[str, Any], policy["policyDocument"])  # type: ignore[index]
    statements_val = pd["Statement"]  # type: ignore[index]
    statements = cast(list[Dict[str, Any]], statements_val)
    assert len(statements) == 1
    return cast(list[str], statements[0]["Resource"])  # type: ignore[index]


def test_rest_success_with_mappings(
    validator: AuthTokenValidator, rsa_keys: AsymmetricKeyPair
) -> None:
    # Configure permissions mapping
    token_validator.AUTH_MAPPINGS = {  # type: ignore[attr-defined]
        "read:pets": [
            {"method": "GET", "resourcePath": "/pets"},
            {"method": "GET", "resourcePath": "/pets/{petId}"},
        ],
        "admin": [
            {"method": "DELETE", "resourcePath": "/pets/{petId}"},
        ],
        "principalId": [
            {"method": "POST", "resourcePath": "/echo"},
        ],
    }

    token = sign_token(
        rsa_keys, sub="user123", audience="dev", permissions=["read:pets"]
    )
    event = make_rest_event(token)

    policy = validator.handler(event, None)
    assert policy["principalId"] == "user123"

    base = validator.build_policy_resource_base(event)
    resources = get_statement_resources(policy)
    assert f"{base}GET/pets" in resources
    assert f"{base}GET/pets/{{petId}}" in resources
    assert f"{base}POST/echo" in resources
    assert f"{base}DELETE/pets/{{petId}}" not in resources


def test_ws_success_with_mappings(
    validator: AuthTokenValidator, rsa_keys: AsymmetricKeyPair
) -> None:
    token_validator.AUTH_MAPPINGS = {  # type: ignore[attr-defined]
        "ws:connect": [{"routeKey": "$connect"}],
        "principalId": [{"routeKey": "$default"}],
    }

    token = sign_token(
        rsa_keys, sub="userws", audience="dev", permissions=["ws:connect"]
    )
    event = make_ws_event(token)

    policy = validator.handler(event, None)
    assert policy["principalId"] == "userws"
    base = validator.build_policy_resource_base(event)
    resources = get_statement_resources(policy)
    assert f"{base}$connect" in resources
    assert f"{base}$default" in resources


def test_default_arn_when_no_mappings(
    validator: AuthTokenValidator, rsa_keys: AsymmetricKeyPair
) -> None:
    token_validator.AUTH_MAPPINGS = {}  # type: ignore[attr-defined]
    token = sign_token(rsa_keys, sub="u", audience="dev")
    event = make_rest_event(token)
    policy = validator.handler(event, None)
    resources = get_statement_resources(policy)
    assert resources == [DEFAULT_ARN]


def test_invalid_signature_returns_401(
    rsa_keys: AsymmetricKeyPair,
) -> None:
    bad_keys = AsymmetricKeyPair()
    validator = AuthTokenValidator(rsa_keys.public_key_pem, ISSUER)
    setattr(token_validator, "public_key", rsa_keys.public_key_pem)

    token = sign_token(bad_keys, sub="user123", audience="dev")
    event = make_rest_event(token)
    resp = validator.handler(event, None)
    assert resp.get("statusCode") == 401
    body = cast(Dict[str, Any], json.loads(resp["body"]))
    assert body["message"] == "Unauthorized"


def test_wrong_audience_returns_401(
    validator: AuthTokenValidator, rsa_keys: AsymmetricKeyPair
) -> None:
    token = sign_token(rsa_keys, sub="user123", audience="prod")
    event = make_rest_event(token)
    resp = validator.handler(event, None)
    assert resp.get("statusCode") == 401


def test_expired_token_returns_401(
    validator: AuthTokenValidator, rsa_keys: AsymmetricKeyPair
) -> None:
    token = sign_token(
        rsa_keys, sub="user123", audience="dev", expires_in=-10
    )
    event = make_rest_event(token)
    resp = validator.handler(event, None)
    assert resp.get("statusCode") == 401


def test_missing_fields_returns_500(
    validator: AuthTokenValidator,
) -> None:
    # Missing authorizationToken for TOKEN event
    event = {
        "type": "TOKEN",
        "methodArn": "arn:aws:execute-api:us-east-1:123:apiid/dev/GET/pets",
        "headers": {},
    }
    resp = validator.handler(event, None)
    assert resp.get("statusCode") == 500

