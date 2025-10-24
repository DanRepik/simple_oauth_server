"""JWKS (JSON Web Key Set) endpoint Lambda handler.

Serves the public keys used for JWT signature verification at /.well-known/jwks.json
following RFC 7517 (JSON Web Key) and RFC 7518 (JSON Web Algorithms).
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any, Dict
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


logging.basicConfig(
    format="%(levelname)s\t%(filename)s:%(lineno)d:%(funcName)s\t%(message)s",
    level=os.environ.get("LOGGING_LEVEL", "DEBUG"),
)
log = logging.getLogger(__name__)
log.setLevel(os.environ.get("LOGGING_LEVEL", "DEBUG"))


def _json_response(status: int, body: Dict[str, Any]) -> Dict[str, Any]:
    """Create a JSON response with appropriate headers."""
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=3600",  # Cache for 1 hour
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Allow-Headers": "Content-Type",
        },
        "body": json.dumps(body),
    }


class JWKSHandler:
    """Handler for JWKS endpoint."""
    
    def __init__(self, public_key_pem: str, issuer: str):
        """Initialize JWKS handler.
        
        Args:
            public_key_pem: PEM-encoded RSA public key
            issuer: JWT issuer URL
        """
        self.issuer = issuer
        self.public_key_pem = public_key_pem
        self._jwks_cache: Dict[str, Any] | None = None
    
    def _load_public_key(self) -> rsa.RSAPublicKey:
        """Load RSA public key from PEM string."""
        public_key = serialization.load_pem_public_key(
            self.public_key_pem.encode('utf-8')
        )
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Expected RSA public key")
        return public_key
    
    def _generate_kid(self) -> str:
        """Generate a key ID (kid) from the public key."""
        # Use SHA-256 hash of the public key PEM as kid
        key_hash = hashlib.sha256(self.public_key_pem.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(key_hash[:16]).decode('utf-8').rstrip('=')
    
    def _public_key_to_jwk(self) -> Dict[str, Any]:
        """Convert RSA public key to JWK format."""
        try:
            public_key = self._load_public_key()
            numbers = public_key.public_numbers()
            
            # Convert RSA components to base64url-encoded strings
            def int_to_base64url(value: int) -> str:
                # Convert integer to bytes (big-endian)
                byte_length = (value.bit_length() + 7) // 8
                byte_value = value.to_bytes(byte_length, 'big')
                # Base64url encode (no padding)
                return base64.urlsafe_b64encode(byte_value).decode('utf-8').rstrip('=')
            
            n = int_to_base64url(numbers.n)  # Modulus
            e = int_to_base64url(numbers.e)  # Exponent
            
            kid = self._generate_kid()
            
            return {
                "kty": "RSA",        # Key Type
                "use": "sig",        # Public Key Use
                "alg": "RS256",      # Algorithm
                "kid": kid,          # Key ID
                "n": n,              # Modulus
                "e": e,              # Exponent
            }
            
        except Exception as e:
            log.error("Failed to convert public key to JWK: %s", e)
            raise
    
    def _get_jwks(self) -> Dict[str, Any]:
        """Get the JWKS (JSON Web Key Set)."""
        if self._jwks_cache is None:
            try:
                jwk = self._public_key_to_jwk()
                self._jwks_cache = {
                    "keys": [jwk]
                }
                log.debug("Generated JWKS: %s", self._jwks_cache)
            except Exception as e:
                log.error("Failed to generate JWKS: %s", e)
                raise
        
        return self._jwks_cache
    
    def handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Lambda handler for JWKS endpoint."""
        try:
            log.debug("JWKS request: %s", event)
            
            # Only support GET requests
            http_method = event.get("httpMethod", "").upper()
            if http_method != "GET":
                return _json_response(405, {
                    "error": "method_not_allowed",
                    "error_description": "Only GET method is supported"
                })
            
            # Return JWKS
            jwks = self._get_jwks()
            return _json_response(200, jwks)
            
        except Exception as e:
            log.error("JWKS handler error: %s", e)
            return _json_response(500, {
                "error": "server_error",
                "error_description": "Internal server error"
            })


def load_public_key() -> str:
    """Load public key from file."""
    with open("public_key.pem", "r", encoding="utf-8") as f:
        return f.read()


_jwks_singleton: JWKSHandler | None = None


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for JWKS endpoint."""
    global _jwks_singleton
    
    # Lazy initialization
    if _jwks_singleton is None:
        try:
            public_key_pem = load_public_key()
            issuer = os.getenv("ISSUER", "https://oauth.local/")
            _jwks_singleton = JWKSHandler(public_key_pem, issuer)
        except (FileNotFoundError, OSError, ValueError) as e:
            log.error("Failed to initialize JWKS handler: %s", e)
            return _json_response(500, {
                "error": "server_error",
                "error_description": "Failed to load configuration"
            })
    
    return _jwks_singleton.handler(event, context)