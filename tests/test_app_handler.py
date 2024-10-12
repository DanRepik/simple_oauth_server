import pytest
from simple_oauth_server.token_validator import handler, check_event_for_error, parse_token_from_event, build_policy_resource_base, validate_token, get_policy, create_statement

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

def test_handler():
    event = {
        "type": "TOKEN", 
        "methodArn": "arn:aws:execute-api:us-east-1:905242188214:aosqduvrv6/test-api/GET/greet", 
        "authorizationToken": "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InlvdXIta2V5LWlkIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL3lvdXItb2F1dGgtbW9jay1kb21haW4vIiwic3ViIjoiY2xpZW50MS1zdWJqZWN0IiwiYXVkIjoiaHR0cHM6Ly9hcGkueW91cnNlcnZpY2UuY29tIiwiaWF0IjoxNzI4NzQ2NDYwLCJleHAiOjE3Mjg4MzI4NjAsInNjb3BlIjoicmVhZDpkYXRhIiwicGVybWlzc2lvbnMiOlsicmVhZDpkYXRhIl19.hDzccp4ZdElEy5FrUJTQ2841EqChvz2Q5NyDinu_UCZv75VvZQsvXT6OWLvjn12zqtQic7cpAxpTxIfQahGgO4PSWIOPs7ZfstE42LB0H28LwfF7WmF07QacCX2lTLeOSFNFqTO32YQMeEXg1N2vjBb9VHEt84iFs9GHrNcFXtVQD3FOJv4YwAlOvcQdCPINMj2fcn1F5RNv7kKn2NhP0XOkGbzeqmHAYi-HzZzsrAOQMa87gSbr6iqgClAeR4aXUTuAE2o_cAkOWq-ckbuZPH-IYMSJjsJLlgN64WNffUoU5Q4Ae25YCHFWbEHm3NYqIbCKs9sKy3QPh_Ybjkv5-Q"
    }
    result = handler(event, {})
    print(result)
    assert False

def test_build_policy_resource_base_no_mappings():
    event = {"methodArn": "arn:aws:execute-api:us-east-1:123456789012:/dev/POST/resource"}
    resource_base = build_policy_resource_base(event)
    assert resource_base == "arn:aws:execute-api:us-east-1:123456789012:/dev/"

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
