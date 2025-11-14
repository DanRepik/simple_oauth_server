"""JWT Decoder Filter for AWS Lambda Functions.

This module provides a decorator-based JWT token decoder that extracts JWT tokens
from Authorization headers and exposes the claims through requestContext.authorizer
to maintain compatibility with API Gateway TOKEN authorizers.

The filter acts like a Java servlet filter but for Lambda functions, providing
a clean separation of concerns between authentication and business logic.
"""

import json
import logging
import functools
import os
import base64
from typing import Callable, Any, Dict, Optional

__all__ = ['token_decoder', 'generate_jwks_response']

log = logging.getLogger(__name__)

# Narrow import for error handling in wrapper; fallback keeps module import-safe
try:
    from jwt import InvalidTokenError as JWTInvalidTokenError  # type: ignore
except Exception:  # noqa: BLE001
    class JWTInvalidTokenError(Exception):
        pass


def _log_jwt_configuration():
    """Log current JWT configuration for debugging."""
    log.debug("=== JWT Configuration Debug ===")
    log.debug("JWKS_HOST: %s", os.getenv("JWKS_HOST", "NOT_SET"))
    log.debug("JWT_ISSUER: %s", os.getenv("JWT_ISSUER", "NOT_SET"))
    log.debug("JWT_ALLOWED_AUDIENCES: %s", 
             os.getenv("JWT_ALLOWED_AUDIENCES", "NOT_SET"))
    log.debug("Logging level: %s", logging.getLogger().getEffectiveLevel())
    log.debug("===============================")


def token_decoder(jwks_url: Optional[str] = None, 
                  audience: Optional[str] = None, 
                  issuer: Optional[str] = None, 
                  algorithms: Optional[list[str]] = None):
    """
    Decorator filter that decodes JWT tokens from Authorization header.
    
    This filter extracts JWT tokens from the Authorization header, validates them,
    and passes the decoded token as a keyword argument to the handler function.
    
    Args:
        jwks_url: URL to fetch JWKS from (e.g., "https://oauth.local/.well-known/jwks.json")
        audience: Expected audience claim (or list of audiences)
        issuer: Expected issuer claim
        algorithms: List of allowed algorithms (defaults to ["RS256"])
    
    Returns:
        Decorated handler function that processes JWT tokens before execution
        
    Example:
        @token_decoder(
            jwks_url="https://your-oauth-server/.well-known/jwks.json",
            audience="test-api",
            issuer="https://oauth.local/",
            algorithms=["RS256"]
        )
        def handler(event, context, decoded_token=None):
            user_sub = decoded_token['sub']
            return {'statusCode': 200, 'body': f'Hello {user_sub}'}
    """
    def decorator(handler: Callable) -> Callable:
        @functools.wraps(handler)
        def wrapper(event: dict, context: Any) -> dict:
            log.debug("JWT token decoder starting for function: %s",
                     handler.__name__)

            # Log configuration for debugging
            if log.isEnabledFor(logging.DEBUG):
                _log_jwt_configuration()

            log.debug("Event structure: %s", json.dumps(event, default=str))

            # Determine configuration source: parameters vs environment variables
            config_jwks_url = jwks_url or f"https://{os.getenv('JWKS_HOST')}/.well-known/jwks.json" if os.getenv('JWKS_HOST') else None
            config_issuer = issuer or os.getenv("JWT_ISSUER")
            config_audience = audience or os.getenv("JWT_ALLOWED_AUDIENCES", "").split(",") if os.getenv("JWT_ALLOWED_AUDIENCES") else []
            config_algorithms = algorithms or ["RS256"]

            # Skip JWT decoding if no JWKS URL is configured
            if not config_jwks_url:
                log.debug("No JWKS URL configured, skipping JWT decoding")
                return handler(event, context)

            try:
                log.debug("Processing JWT token extraction and validation")

                # Check if authorizer already exists (preserve existing context)
                if event.get('requestContext', {}).get('authorizer'):
                    log.debug("Authorizer already exists, skipping JWT processing")
                    return handler(event, context)

                # Set up a singleton JWTDecoder instance
                if not hasattr(wrapper, "_jwt_decoder"):
                    log.debug("Creating new JWTDecoder instance")
                    log.debug("JWT configuration - jwks_url: %s, issuer: %s, audience: %s, algorithms: %s", 
                            config_jwks_url, config_issuer, config_audience, config_algorithms)
                    wrapper._jwt_decoder = JWTDecoder(
                        jwks_url=config_jwks_url,
                        issuer=config_issuer,
                        allowed_audiences=set(config_audience) if config_audience else None,
                        algorithms=config_algorithms
                    )
                else:
                    log.debug("Using existing JWTDecoder instance")
                jwt_decoder = wrapper._jwt_decoder

                log.debug("Decoding JWT token")
                decoded_token = jwt_decoder.decode(event)
                log.debug("JWT token successfully decoded")

                # Optional DB-backed authorization enrichment
                try:
                    if os.getenv("AUTHZ_DB_ENABLED", "").strip().lower() in (
                        "true",
                        "1",
                        "yes",
                        "on",
                    ):
                        from .utils.authz_db import (
                            enrich_authorizer_if_enabled,
                        )

                        if decoded_token is None:
                            raise ValueError("Decoded token is None")
                        decoded_token = enrich_authorizer_if_enabled(
                            decoded_token
                        )
                except (
                    ImportError,
                    ValueError,
                    RuntimeError,
                    PermissionError,
                ) as e:
                    log.debug("AuthZ DB enrichment skipped/failed: %s", e)

                # Populate requestContext for Lambda handler compatibility
                if 'requestContext' not in event:
                    event['requestContext'] = {}
                event['requestContext']['authorizer'] = decoded_token
                return handler(event, context)

            except (
                ValueError,
                KeyError,
                RuntimeError,
                JWTInvalidTokenError,
            ) as e:
                log.error("JWT filter critical error: %s", e)
                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'Internal server error'})
                }

        return wrapper
    return decorator

class JWTDecoder:
    def __init__(
        self,
        jwks_url: str,
        issuer: Optional[str] = None,
        allowed_audiences: Optional[set] = None,
        algorithms: Optional[list] = None,
    ) -> None:
        log.debug(
            "Initializing JWTDecoder with jwks_url: %s, issuer: %s",
            jwks_url,
            issuer,
        )
        self.jwks_url = jwks_url
        self.public_key = self.fetch_public_key_from_jwks(jwks_url)
        self.issuer = issuer
        self.allowed_audiences = allowed_audiences or set()
        self.algorithms = algorithms or ["RS256"]
        log.debug(
            "JWTDecoder initialized with %d allowed audiences, algorithms: %s",
            len(self.allowed_audiences),
            self.algorithms,
        )

    def fetch_public_key_from_jwks(
        self, jwks_url: str, kid: Optional[str] = None
    ) -> Optional[str]:
        """
        Fetch the public key from a JWKS endpoint.

        Args:
            jwks_url: The full JWKS endpoint URL
            kid: Optional key ID to select a specific key

        Returns:
            PEM-formatted public key string, or None if not found
        """
        import requests
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        try:
            log.debug("Fetching JWKS from URL: %s", jwks_url)
            resp = requests.get(jwks_url, timeout=5)
            resp.raise_for_status()
            log.debug("JWKS request successful, status: %d", resp.status_code)

            jwks = resp.json()
            keys = jwks.get("keys", [])
            log.debug("Found %d keys in JWKS response", len(keys))

            if not keys:
                log.warning("No keys found in JWKS response")
                return None

            # Select key by kid if provided, else use first key
            key = None
            if kid:
                log.debug("Looking for specific key ID: %s", kid)
                for k in keys:
                    if k.get("kid") == kid:
                        key = k
                        log.debug("Found matching key for kid: %s", kid)
                        break
                if not key:
                    log.warning("Key ID %s not found, using first key", kid)
            if not key:
                key = keys[0]
                log.debug(
                    "Using first available key with kid: %s",
                    key.get("kid", "unknown"),
                )
            # Convert JWK to PEM (requires cryptography)

            def b64url_decode(val):
                val += '=' * (-len(val) % 4)
                return base64.urlsafe_b64decode(val)

            n = int.from_bytes(b64url_decode(key["n"]), "big")
            e = int.from_bytes(b64url_decode(key["e"]), "big")
            pubkey = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
            pem = pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return pem.decode("utf-8")
        except (
            requests.RequestException,
            ValueError,
            KeyError,
            TypeError,
        ) as e:
            log.error("Failed to fetch public key from JWKS: %s", e)
            return None

    def decode(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Decode the JWT token and return the claims."""
        token = self.parse_token_from_event(event)
        return self.decode_token(token)

    def parse_token_from_event(self, event: Dict[str, Any]) -> str:
        """Extract the Bearer token from the authorization header."""
        log.debug("Parsing JWT token from event")
        
        auth_header = (
            event.get("authorizationToken") or
            event.get("headers", {}).get("Authorization") or
            event.get("headers", {}).get("authorization")
        )
        
        log.debug(
            "Authorization header found: %s",
            "Yes" if auth_header else "No",
        )
        
        if not auth_header:
            log.error("No authorization header found in event")
            raise ValueError("No authorization header found")

        auth_token_parts = auth_header.split(" ")
        log.debug("Authorization header parts: %d", len(auth_token_parts))
        
        if (
            len(auth_token_parts) != 2
            or auth_token_parts[0].lower() != "bearer"
            or not auth_token_parts[1]
        ):
            log.error("Invalid authorization header format")
            raise ValueError("Invalid AuthorizationToken.")
            
        token = auth_token_parts[1]
        log.debug("JWT token extracted successfully, length: %d", len(token))
        return token

    def decode_token(self, token: str) -> Dict[str, Any]:
        """Validate and decode the JWT using the PEM public key."""
        log.debug("Starting JWT token validation and decoding")

        import jwt
        from jwt import (
            InvalidTokenError,
            ExpiredSignatureError,
            InvalidAudienceError,  # type: ignore
        )

        try:
            # First decode without audience enforcement; we'll validate
            # audience against the configured allowed set derived from
            # config.yaml. This supports multi-audience tokens.
            log.debug("Configuring JWT decode options")
            decode_options = {"verify_aud": False}
            decode_args = {
                "algorithms": self.algorithms,
                "options": decode_options,
                "key": self.public_key,
                "token": token,
            }
            
            if self.issuer:
                log.debug("Using issuer validation: %s", self.issuer)
                decode_args["issuer"] = self.issuer
            else:
                log.debug("Skipping issuer validation")
                decode_options["verify_iss"] = False

            if self.allowed_audiences:
                log.debug(
                    "Allowed audiences configured: %s", self.allowed_audiences
                )
            else:
                log.debug("No audience validation configured")
                decode_options["verify_aud"] = False

            log.debug("Decoding JWT token with PyJWT")
            # Extract token from decode_args as it needs to be the first
            # positional argument
            token_arg = decode_args.pop("token")
            decoded_token = jwt.decode(token_arg, **decode_args)
            log.debug("JWT token decoded successfully")
        
            token_aud = decoded_token.get("aud")
            log.debug("Token audience claim: %s", token_aud)
            
            # Normalize token audience to a list for comparison
            token_auds = (
                [token_aud]
                if isinstance(token_aud, str)
                else list(token_aud or [])
            )
            token_auds = [str(a).strip() for a in token_auds if str(a).strip()]
            log.debug("Normalized token audiences: %s", token_auds)
            
            # Validate audience: token must contain at least one allowed aud
            if self.allowed_audiences:
                if not any(a in self.allowed_audiences for a in token_auds):
                    log.error(
                        "Audience validation failed. Required: %s, Found: %s",
                        self.allowed_audiences, token_auds
                    )
                    raise InvalidAudienceError("Audience not allowed")
                    
            log.debug("All JWT validations passed successfully")
            log.debug("Decoded token claims: %s", list(decoded_token.keys()))
            return decoded_token
            
        except ExpiredSignatureError:
            log.error("Token has expired")
            raise
        except InvalidTokenError as e:
            log.error("Token validation failed: %s", e)
            raise

