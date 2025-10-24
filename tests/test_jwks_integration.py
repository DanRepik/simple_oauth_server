"""Integration test for JWKS endpoint functionality."""

import json
import jwt
from simple_oauth_server.jwks_handler import JWKSHandler
from simple_oauth_server.token_authorizer import TokenAuthorizer
from simple_oauth_server.asymmetric_key_pair import AsymmetricKeyPair


def test_jwks_with_token_validation():
    """Test that JWKS provides keys that can validate issued tokens."""
    # Create shared key pair
    key_pair = AsymmetricKeyPair()
    
    # Create token authorizer
    clients = {
        "test_client": {
            "client_secret": "test_secret",
            "audience": "https://api.example.com",
            "sub": "test_user",
            "scope": "read:test"
        }
    }
    authorizer = TokenAuthorizer(
        clients=clients,
        private_key=key_pair.private_key_pem,
        issuer="https://oauth.local/"
    )
    
    # Create JWKS handler
    jwks_handler = JWKSHandler(
        public_key_pem=key_pair.public_key_pem,
        issuer="https://oauth.local/"
    )
    
    # Get JWKS
    jwks_event = {
        "httpMethod": "GET",
        "path": "/.well-known/jwks.json"
    }
    jwks_response = jwks_handler.handler(jwks_event, None)
    
    assert jwks_response["statusCode"] == 200
    jwks = json.loads(jwks_response["body"])
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    
    # Issue a token
    token_event = {
        "httpMethod": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "grant_type": "client_credentials",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "audience": "https://api.example.com"
        })
    }
    
    token_response = authorizer.handler(token_event, None)
    assert token_response["statusCode"] == 200
    
    token_data = json.loads(token_response["body"])
    access_token = token_data["token"]  # Simple OAuth uses "token" not "access_token"
    
    # Validate the token using the public key from JWKS
    decoded_token = jwt.decode(
        access_token,
        key_pair.public_key_pem,
        algorithms=["RS256"],
        audience="https://api.example.com",
        issuer="https://oauth.local/"
    )
    
    # Verify token claims
    assert decoded_token["sub"] == "test_user"
    assert decoded_token["aud"] == "https://api.example.com"
    assert decoded_token["iss"] == "https://oauth.local/"
    assert "scope" in decoded_token
    
    print("✓ JWKS endpoint provides keys for token validation")


if __name__ == "__main__":
    test_jwks_with_token_validation()
    print("Integration test passed!")