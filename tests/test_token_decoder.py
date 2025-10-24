"""Test fixtures and cases for the token_decoder decorator.

This test module focuses on testing the token_decoder decorator functionality
by creating an authorized greet function and testing it directly.
"""

import json
import os
import jwt
import pytest
from typing import Any, Dict
from unittest.mock import patch, MagicMock

from simple_oauth_server.asymmetric_key_pair import AsymmetricKeyPair
from simple_oauth_server.token_decoder import token_decoder
from simple_oauth_server.token_authorizer import TokenAuthorizer


@pytest.fixture(scope="module")
def rsa_keys() -> AsymmetricKeyPair:
    """Provide RSA key pair for testing."""
    return AsymmetricKeyPair()


@pytest.fixture(scope="module")
def test_token_authorizer(rsa_keys: AsymmetricKeyPair) -> TokenAuthorizer:
    """Provide a token authorizer for creating test tokens."""
    clients: Dict[str, Dict[str, Any]] = {
        "test_client": {
            "client_secret": "test_secret",
            "audience": "greet-api",
            "sub": "test-user",
            "scope": "read:greetings write:greetings",
            "permissions": ["read:greetings", "write:greetings"],
            "roles": ["user"],
            "groups": ["testers"]
        }
    }
    return TokenAuthorizer(
        clients=clients,
        private_key=rsa_keys.private_key_pem,
        issuer="https://oauth.local/"
    )


@pytest.fixture
def valid_jwt_token(test_token_authorizer: TokenAuthorizer) -> str:
    """Generate a valid JWT token for testing."""
    event: Dict[str, Any] = {
        "headers": {"Content-Type": "application/json"},
        "isBase64Encoded": False,
        "body": json.dumps({
            "client_id": "test_client",
            "client_secret": "test_secret",
            "audience": "greet-api",
            "grant_type": "client_credentials",
        })
    }
    
    resp = test_token_authorizer.handler(event, None)
    assert resp["statusCode"] == 200
    
    body = json.loads(resp["body"])
    return body["token"]


@pytest.fixture
def mock_jwks_response(rsa_keys: AsymmetricKeyPair) -> Dict[str, Any]:
    """Mock JWKS response for testing."""
    # Create a mock JWKS response
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    # Load the public key and ensure it's RSA
    public_key = serialization.load_pem_public_key(rsa_keys.public_key_pem.encode())
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Expected RSA public key")
    
    # Convert to JWK format
    numbers = public_key.public_numbers()
    
    # Convert integers to base64url
    import base64
    def int_to_base64url(val: int) -> str:
        byte_length = (val.bit_length() + 7) // 8
        val_bytes = val.to_bytes(byte_length, 'big')
        return base64.urlsafe_b64encode(val_bytes).decode('ascii').rstrip('=')
    
    jwks_response: Dict[str, Any] = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-id",
                "n": int_to_base64url(numbers.n),
                "e": int_to_base64url(numbers.e),
                "alg": "RS256"
            }
        ]
    }
    return jwks_response


@pytest.fixture
def authorized_greet_handler():
    """Create an authorized greet function using the token_decoder decorator."""
    
    @token_decoder()
    def greet_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """A simple greet handler that uses JWT token information."""
        # Access JWT claims through standard authorizer context
        request_context = event.get('requestContext', {})
        authorizer = request_context.get('authorizer', {}) if request_context else {}
        
        user_sub = authorizer.get('sub', 'unknown') if authorizer else 'unknown'
        user_scope = authorizer.get('scope', '') if authorizer else ''
        user_roles = authorizer.get('roles', '[]') if authorizer else '[]'
        
        # Parse roles if they're JSON-encoded
        try:
            roles_list = json.loads(user_roles) if isinstance(user_roles, str) else user_roles
        except json.JSONDecodeError:
            roles_list = []
        
        greeting = f"Hello {user_sub}!"
        if 'read:greetings' in user_scope:
            greeting += " You have read access."
        if roles_list and 'user' in roles_list:
            greeting += " Welcome, user!"
            
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': greeting,
                'user': user_sub,
                'scope': user_scope,
                'roles': roles_list
            })
        }
    
    return greet_handler


def test_authorized_greet_with_valid_token(
    authorized_greet_handler,
    valid_jwt_token: str,
    mock_jwks_response: Dict[str, Any],
    rsa_keys: AsymmetricKeyPair
):
    """Test the greet handler with a valid JWT token."""
    
    # Mock the JWKS endpoint
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = mock_jwks_response
        mock_response.raise_for_status.return_value = None
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        # Set up environment variables
        with patch.dict(os.environ, {
            'JWKS_HOST': 'oauth.local',
            'JWT_ISSUER': 'https://oauth.local/',
            'JWT_ALLOWED_AUDIENCES': 'greet-api'
        }):
            # Create event with Authorization header
            event: Dict[str, Any] = {
                'headers': {
                    'Authorization': f'Bearer {valid_jwt_token}'
                },
                'requestContext': {}
            }
            
            # Call the handler
            response = authorized_greet_handler(event, None)
            
            # Verify response
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            assert 'Hello test-user!' in body['message']
            assert 'You have read access.' in body['message']
            assert 'Welcome, user!' in body['message']
            assert body['user'] == 'test-user'
            assert 'read:greetings' in body['scope']
            assert 'user' in body['roles']


def test_authorized_greet_without_token(authorized_greet_handler):
    """Test the greet handler without an Authorization header."""
    
    with patch.dict(os.environ, {
        'JWKS_HOST': 'oauth.local',
        'JWT_ISSUER': 'https://oauth.local/',
        'JWT_ALLOWED_AUDIENCES': 'greet-api'
    }):
        # Create event without Authorization header
        event: Dict[str, Any] = {
            'headers': {},
            'requestContext': {}
        }
        
        # Call the handler - should return 500 due to missing token
        response = authorized_greet_handler(event, None)
        
        # Verify error response
        assert response['statusCode'] == 500
        body = json.loads(response['body'])
        assert 'error' in body


def test_authorized_greet_with_invalid_token(
    authorized_greet_handler,
    mock_jwks_response: Dict[str, Any]
):
    """Test the greet handler with an invalid JWT token."""
    
    # Mock the JWKS endpoint
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = mock_jwks_response
        mock_response.raise_for_status.return_value = None
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        with patch.dict(os.environ, {
            'JWKS_HOST': 'oauth.local',
            'JWT_ISSUER': 'https://oauth.local/',
            'JWT_ALLOWED_AUDIENCES': 'greet-api'
        }):
            # Create event with invalid token
            event: Dict[str, Any] = {
                'headers': {
                    'Authorization': 'Bearer invalid.token.here'
                },
                'requestContext': {}
            }
            
            # Call the handler - should return 500 due to invalid token
            response = authorized_greet_handler(event, None)
            
            # Verify error response
            assert response['statusCode'] == 500
            body = json.loads(response['body'])
            assert 'error' in body


def test_authorized_greet_skip_jwt_when_no_host(authorized_greet_handler):
    """Test that JWT processing is skipped when JWKS_HOST is not set."""
    
    with patch.dict(os.environ, {}, clear=True):
        # Create event 
        event: Dict[str, Any] = {
            'headers': {
                'Authorization': 'Bearer some.token.here'
            },
            'requestContext': {}
        }
        
        # Call the handler - should process without JWT validation
        response = authorized_greet_handler(event, None)
        
        # Verify response
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        
        # Should use 'unknown' as user since no authorizer context
        assert 'Hello unknown!' in body['message']
        assert body['user'] == 'unknown'


def test_authorized_greet_with_existing_authorizer(authorized_greet_handler):
    """Test that existing authorizer context is preserved."""
    
    with patch.dict(os.environ, {
        'JWKS_HOST': 'oauth.local',
        'JWT_ISSUER': 'https://oauth.local/',
        'JWT_ALLOWED_AUDIENCES': 'greet-api'
    }):
        # Create event with existing authorizer context
        event: Dict[str, Any] = {
            'headers': {
                'Authorization': 'Bearer some.token.here'
            },
            'requestContext': {
                'authorizer': {
                    'sub': 'existing-user',
                    'scope': 'admin:all',
                    'roles': '["admin"]'
                }
            }
        }
        
        # Call the handler - should use existing authorizer
        response = authorized_greet_handler(event, None)
        
        # Verify response uses existing authorizer data
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        
        assert 'Hello existing-user!' in body['message']
        assert body['user'] == 'existing-user'
        assert body['scope'] == 'admin:all'
        assert 'admin' in body['roles']


def test_token_decoder_preserves_handler_metadata(authorized_greet_handler):
    """Test that the token_decoder decorator preserves the original handler metadata."""
    
    # The decorator should preserve function name and other metadata
    assert hasattr(authorized_greet_handler, '__name__')
    assert 'greet_handler' in authorized_greet_handler.__name__


def test_jwt_decoder_singleton_behavior(
    authorized_greet_handler,
    valid_jwt_token: str,
    mock_jwks_response: Dict[str, Any]
):
    """Test that JWTDecoder instance is reused across calls."""
    
    # Mock the JWKS endpoint
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = mock_jwks_response
        mock_response.raise_for_status.return_value = None
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        with patch.dict(os.environ, {
            'JWKS_HOST': 'oauth.local',
            'JWT_ISSUER': 'https://oauth.local/',
            'JWT_ALLOWED_AUDIENCES': 'greet-api'
        }):
            # Create event
            event: Dict[str, Any] = {
                'headers': {
                    'Authorization': f'Bearer {valid_jwt_token}'
                },
                'requestContext': {}
            }
            
            # Call handler twice
            response1 = authorized_greet_handler(event, None)
            response2 = authorized_greet_handler(event, None)
            
            # Both should succeed
            assert response1['statusCode'] == 200
            assert response2['statusCode'] == 200
            
            # JWKS should only be called once due to singleton behavior
            assert mock_get.call_count == 1


def test_greet_handler_direct_call():
    """Test calling the greet handler directly without the decorator for comparison."""
    
    def simple_greet_handler(
        event: Dict[str, Any], context: Any  # pylint: disable=unused-argument
    ) -> Dict[str, Any]:
        """A simple greet handler without JWT processing."""
        _ = event  # Use event to avoid unused warning
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Hello world!',
                'user': 'anonymous'
            })
        }
    
    event: Dict[str, Any] = {'headers': {}, 'requestContext': {}}
    response = simple_greet_handler(event, None)
    
    assert response['statusCode'] == 200
    body = json.loads(response['body'])
    assert body['message'] == 'Hello world!'
    assert body['user'] == 'anonymous'
