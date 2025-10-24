
# pylint: disable=redefined-outer-name

import base64
import json
import urllib.parse

import jwt
import pytest
from typing import Any, Dict, cast

from simple_oauth_server.asymmetric_key_pair import AsymmetricKeyPair
from simple_oauth_server.token_authorizer import TokenAuthorizer


@pytest.fixture(scope="module")
def rsa_keys() -> AsymmetricKeyPair:
    return AsymmetricKeyPair()


@pytest.fixture(scope="module")
def token_authorizer_fixture(
    rsa_keys: AsymmetricKeyPair,
) -> TokenAuthorizer:
    clients: Dict[str, Dict[str, Any]] = {
        "client1": {
            "client_secret": "client_secret_1",
            "audience": "audience_1",
            "sub": "client1-sub",
            "scope": "scope_1",
            "permissions": ["permission_1"],
        }
    }
    return TokenAuthorizer(
        clients=clients,
        private_key=rsa_keys.private_key_pem,
        issuer="https://oauth.local/"
    )


def make_event_json(
    payload: Dict[str, Any],
    headers: Dict[str, str] | None = None,
    base64_body: bool = False,
) -> Dict[str, Any]:
    body = json.dumps(payload)
    if base64_body:
        body = base64.b64encode(body.encode("utf-8")).decode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    return {
        "headers": hdrs,
        "isBase64Encoded": base64_body,
        "body": body,
    }


def make_event_form(
    payload: Dict[str, Any],
    headers: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    body = urllib.parse.urlencode(payload)
    hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        hdrs.update(headers)
    return {
        "headers": hdrs,
        "isBase64Encoded": False,
        "body": body,
    }


def get_json_body(resp: Dict[str, Any]) -> Dict[str, Any]:
    raw = resp.get("body")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
    else:
        parsed = raw
    result: Dict[str, Any] = (
        cast(Dict[str, Any], parsed) if isinstance(parsed, dict) else {}
    )
    return result


def decode_token(
    token: str, keys: AsymmetricKeyPair, audience: str
) -> Dict[str, Any]:
    return jwt.decode(
        token,
        keys.public_key_pem,
        algorithms=["RS256"],
        audience=audience,
        issuer="https://oauth.local/",
    )


def test_success_json_body(
    token_authorizer_fixture: TokenAuthorizer,
    rsa_keys: AsymmetricKeyPair,
) -> None:
    event = make_event_json(
        {
            "client_id": "client1",
            "client_secret": "client_secret_1",
            "audience": "audience_1",
            "grant_type": "client_credentials",
        }
    )

    resp = token_authorizer_fixture.handler(event, None)
    assert resp["statusCode"] == 200
    data = get_json_body(resp)
    assert data["token_type"] == "Bearer"
    token = data["token"]
    claims = decode_token(token, rsa_keys, audience="audience_1")
    assert claims["iss"] == "https://oauth.local/"
    assert claims["aud"] == "audience_1"
    assert claims["sub"] == "client1-sub"


def test_subject_from_roles_when_present(
    rsa_keys: AsymmetricKeyPair,
) -> None:
    clients: Dict[str, Dict[str, Any]] = {
        "client2": {
            "client_secret": "s2",
            "audience": "audience_2",
            "roles": ["sales_manager", "sales_associate"],
            "scope": "read:pets",
        }
    }
    ta = TokenAuthorizer(
        clients,
        rsa_keys.private_key_pem,
        "https://oauth.local/"
    )
    event = make_event_json(
        {
            "client_id": "client2",
            "client_secret": "s2",
            "audience": "audience_2",
            "grant_type": "client_credentials",
        }
    )
    resp = ta.handler(event, None)
    assert resp["statusCode"] == 200
    body = get_json_body(resp)
    token = body["token"]
    claims = decode_token(token, rsa_keys, audience="audience_2")
    assert claims["sub"] == "client2"


def test_success_basic_auth_header(
    token_authorizer_fixture: TokenAuthorizer,
    rsa_keys: AsymmetricKeyPair,
) -> None:
    basic = base64.b64encode(b"client1:client_secret_1").decode("utf-8")
    headers = {"Authorization": f"Basic {basic}"}
    event = make_event_json(
        {
            "client_id": "client1",
            # No client_secret in body; should come from Basic header
            "audience": "audience_1",
            "grant_type": "client_credentials",
        },
        headers=headers,
    )

    resp = token_authorizer_fixture.handler(event, None)
    assert resp["statusCode"] == 200
    data = get_json_body(resp)
    token = data["token"]
    decode_token(token, rsa_keys, audience="audience_1")


def test_success_form_urlencoded(
    token_authorizer_fixture: TokenAuthorizer,
    rsa_keys: AsymmetricKeyPair,
) -> None:
    event = make_event_form(
        {
            "client_id": "client1",
            "client_secret": "client_secret_1",
            "audience": "audience_1",
            "grant_type": "client_credentials",
        }
    )

    resp = token_authorizer_fixture.handler(event, None)
    assert resp["statusCode"] == 200
    data = get_json_body(resp)
    token = data["token"]
    decode_token(token, rsa_keys, audience="audience_1")


def test_success_base64_body(
    token_authorizer_fixture: TokenAuthorizer,
    rsa_keys: AsymmetricKeyPair,
) -> None:
    event = make_event_json(
        {
            "client_id": "client1",
            "client_secret": "client_secret_1",
            "audience": "audience_1",
            "grant_type": "client_credentials",
        },
        base64_body=True,
    )
    resp = token_authorizer_fixture.handler(event, None)
    assert resp["statusCode"] == 200
    data = get_json_body(resp)
    token = data["token"]
    decode_token(token, rsa_keys, audience="audience_1")


def test_error_unsupported_grant(
    token_authorizer_fixture: TokenAuthorizer,
) -> None:
    event = make_event_json(
        {
            "client_id": "client1",
            "client_secret": "client_secret_1",
            "audience": "audience_1",
            "grant_type": "password",
        }
    )
    resp = token_authorizer_fixture.handler(event, None)
    assert resp["statusCode"] == 400
    body = get_json_body(resp)
    assert body["error"] == "unsupported_grant_type"


def test_error_missing_params(
    token_authorizer_fixture: TokenAuthorizer,
) -> None:
    event = make_event_json({})
    resp = token_authorizer_fixture.handler(event, None)
    assert resp["statusCode"] == 400
    body = get_json_body(resp)
    assert body["error"] == "unsupported_grant_type"


def test_error_unknown_client(
    token_authorizer_fixture: TokenAuthorizer,
) -> None:
    event = make_event_json(
        {
            "client_id": "nope",
            "client_secret": "client_secret_1",
            "audience": "audience_1",
            "grant_type": "client_credentials",
        }
    )
    resp = token_authorizer_fixture.handler(event, None)
    assert resp["statusCode"] == 401
    body = get_json_body(resp)
    assert body["error"] == "invalid_client"


def test_error_invalid_client_secret(
    token_authorizer_fixture: TokenAuthorizer,
) -> None:
    event = make_event_json(
        {
            "client_id": "client1",
            "client_secret": "bad",
            "audience": "audience_1",
            "grant_type": "client_credentials",
        }
    )
    resp = token_authorizer_fixture.handler(event, None)
    assert resp["statusCode"] == 401
    body = get_json_body(resp)
    assert body["error"] == "invalid_client"


def test_error_audience_mismatch(
    token_authorizer_fixture: TokenAuthorizer,
) -> None:
    event = make_event_json(
        {
            "client_id": "client1",
            "client_secret": "client_secret_1",
            "audience": "wrong",
            "grant_type": "client_credentials",
        }
    )
    resp = token_authorizer_fixture.handler(event, None)
    assert resp["statusCode"] == 401
    body = get_json_body(resp)
    assert body["error"] == "invalid_audience"


