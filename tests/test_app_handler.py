import pytest
import os
import json
from unittest.mock import patch, MagicMock
from jwt import InvalidTokenError
from simple_oauth_server.token_validator import handler, check_event_for_error, parse_token_from_event, build_policy_resource_base, validate_token, get_policy, create_policy, create_statement

# Mock environment variables
@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch):
    monkeypatch.setenv("AUTH0_AUTH_MAPPINGS", json.dumps({
        "principalId": ["GET/resource1", "POST/resource2"]
    }))
    monkeypatch.setenv("AUTH0_DOMAIN", "https://example.auth0.com")
    monkeypatch.setenv("AUDIENCE", "test-audience")
    monkeypatch.setenv("DECODE_OPTIONS", json.dumps({"verify_exp": False}))

# Mock logger
@pytest.fixture(autouse=True)
def mock_logger(monkeypatch):
    logger_mock = MagicMock()
    monkeypatch.setattr("my_module.logger", logger_mock)

def test_check_event_for_error_token_type():
    event = {
        "type": "TOKEN",
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:/dev/POST/resource",
        "authorizationToken": "Bearer some_token"
    }
    result = check_event_for_error(event)
    assert "headers" in result
    assert result["authorizationToken"] == "Bearer some_token"

def test_check_event_for_error_missing_fields():
    event = {"type": "TOKEN"}
    with pytest.raises(Exception, match=r'Missing required fields'):
        check_event_for_error(event)

def test_check_event_for_error_invalid_ws_protocol():
    event = {
        "headers": {
            "sec-websocket-protocol": "protocol1"
        }
    }
    with pytest.raises(Exception, match="Invalid token, required protocols not found."):
        check_event_for_error(event)

def test_parse_token_from_event_valid_token():
    event = {"authorizationToken": "Bearer valid_token"}
    token = parse_token_from_event(event)
    assert token == "valid_token"

def test_parse_token_from_event_invalid_token():
    event = {"authorizationToken": "InvalidToken"}
    with pytest.raises(Exception, match="Invalid AuthorizationToken."):
        parse_token_from_event(event)

def test_build_policy_resource_base_no_mappings():
    event = {"methodArn": "arn:aws:execute-api:us-east-1:123456789012:/dev/POST/resource"}
    resource_base = build_policy_resource_base(event)
    assert resource_base == "arn:aws:execute-api:us-east-1:123456789012:/dev/"

@patch("my_module.PyJWKClient.get_signing_key")
@patch("my_module.decode")
@patch("my_module.get_unverified_header")
def test_validate_token_valid(mock_get_unverified_header, mock_decode, mock_get_signing_key):
    mock_get_unverified_header.return_value = {"kid": "valid_kid", "alg": "RS256"}
    mock_get_signing_key.return_value.key = "fake_key"
    mock_decode.return_value = {"sub": "user123", "permissions": ["read", "write"]}

    token = "fake_token"
    result = validate_token(token)
    assert result == {"sub": "user123", "permissions": ["read", "write"]}

@patch("my_module.PyJWKClient.get_signing_key")
def test_validate_token_no_kid(mock_get_signing_key):
    with pytest.raises(InvalidTokenError, match="No kid found in token header."):
        validate_token("invalid_token")

def test_get_policy_valid():
    decoded_token = {"sub": "user123", "permissions": ["principalId"]}
    policy = get_policy("arn:aws:execute-api:us-east-1:123456789012:/dev/", decoded_token, False)
    assert "principalId" in policy
    assert policy["principalId"] == "user123"
    assert "policyDocument" in policy
    assert policy["policyDocument"]["Statement"][0]["Effect"] == "Allow"

def test_create_statement_valid():
    statement = create_statement("Allow", ["arn:aws:execute-api:us-east-1:123456789012:/dev/"], ["execute-api:Invoke"])
    assert statement["Effect"] == "Allow"
    assert "arn:aws:execute-api:us-east-1:123456789012:/dev/" in statement["Resource"]

def test_create_policy_valid():
    statements = [create_statement("Allow", ["arn:aws:execute-api:us-east-1:123456789012:/dev/"], ["execute-api:Invoke"])]
    policy = create_policy("user123", statements, {"scope": "read"})
    assert policy["principalId"] == "user123"
    assert policy["policyDocument"]["Version"] == "2012-10-17"
    assert policy["context"]["scope"] == "read"
