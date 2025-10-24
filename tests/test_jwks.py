"""Test JWKS endpoint functionality."""

import json
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from simple_oauth_server.jwks_handler import JWKSHandler, handler


def test_jwks_handler_get_success():
    """Test that JWKS handler returns valid JWKS on GET request."""
    # Create a test RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Create handler
    jwks_handler = JWKSHandler(public_key_pem, "https://oauth.local/")
    
    # Simulate GET request
    event = {
        "httpMethod": "GET",
        "path": "/.well-known/jwks.json"
    }
    
    # Call handler
    response = jwks_handler.handler(event, None)
    
    # Verify response
    assert response["statusCode"] == 200
    assert response["headers"]["Content-Type"] == "application/json"
    assert "Cache-Control" in response["headers"]
    
    # Parse response body
    jwks = json.loads(response["body"])
    
    # Verify JWKS structure
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    
    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert "kid" in key
    assert "n" in key  # RSA modulus
    assert "e" in key  # RSA exponent


def test_jwks_handler_method_not_allowed():
    """Test that JWKS handler rejects non-GET requests."""
    public_key_pem = "dummy_key"  # Won't be used for this test
    jwks_handler = JWKSHandler(public_key_pem, "https://oauth.local/")
    
    # Simulate POST request
    event = {
        "httpMethod": "POST",
        "path": "/.well-known/jwks.json"
    }
    
    # Call handler
    response = jwks_handler.handler(event, None)
    
    # Verify response
    assert response["statusCode"] == 405
    body = json.loads(response["body"])
    assert body["error"] == "method_not_allowed"


def test_jwks_handler_caching():
    """Test that JWKS are cached properly."""
    # Create a test RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Create handler
    jwks_handler = JWKSHandler(public_key_pem, "https://oauth.local/")
    
    # Call _get_jwks twice
    jwks1 = jwks_handler._get_jwks()
    jwks2 = jwks_handler._get_jwks()
    
    # Should be the same object (cached)
    assert jwks1 is jwks2


def test_key_id_generation():
    """Test that key ID is generated consistently."""
    # Create a test RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Create two handlers with the same key
    handler1 = JWKSHandler(public_key_pem, "https://oauth.local/")
    handler2 = JWKSHandler(public_key_pem, "https://oauth.local/")
    
    # Generate key IDs
    kid1 = handler1._generate_kid()
    kid2 = handler2._generate_kid()
    
    # Should be the same
    assert kid1 == kid2
    
    # Should be base64url encoded (no padding)
    assert "=" not in kid1
    assert len(kid1) > 0


def test_lambda_handler_integration(monkeypatch):
    """Test the lambda handler entry point."""
    # Mock file loading
    test_public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf+xGmWmUJKgOVNBmx6bJGFV4r4g3A8ZQWcKKyKr
n1zOiZ8qmZ4qXYgOoXRqz7ZUQLBdXw0JKHhMaEYzL0Jb1RAOJv1j3UzZg2BrUK2J
6yUqx2r/Lxz8OlMzXs1kBc8FwFsL4t3Xm8Kw5KxZ3z2w7nOF6Z0zZdZq4F8yYHmV
3x8gLKK3LUzZ1qy+IzZ2RKqMBJgEfj3Dz2/o8YBJ1MXZ8K4oElktMGv1PYO2dBzk
1eLi4a6rlCQ4gLdKyOPLgz4A3D8OzD1HqKu1g9z3K8s9b+KwH0pA7X7/x2ZXyLUx
2wIDAQAB
-----END PUBLIC KEY-----"""
    
    def mock_load_public_key():
        return test_public_key_pem
    
    monkeypatch.setattr("simple_oauth_server.jwks_handler.load_public_key", mock_load_public_key)
    
    # Test GET request
    event = {
        "httpMethod": "GET",
        "path": "/.well-known/jwks.json"
    }
    
    response = handler(event, None)
    
    assert response["statusCode"] == 200
    jwks = json.loads(response["body"])
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1