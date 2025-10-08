"""OAuth2 client_credentials token endpoint Lambda handler.

Features:
- Accepts JSON or application/x-www-form-urlencoded bodies
- Handles base64-encoded payloads from API Gateway
- Supports Basic Authorization header for client auth
- Validates client_secret against config.yaml
- ISSUER configurable via env var (ISSUER)
- Consistent JSON responses with headers
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import logging
import os
from typing import Any, Dict, Optional, Tuple, cast
import urllib.parse

import jwt
import yaml


logging.basicConfig(
    format="%(levelname)s\t%(filename)s:%(lineno)d:%(funcName)s\t%(message)s",
    level=os.environ.get("LOGGING_LEVEL", "DEBUG"),
)
log = logging.getLogger(__name__)
log.setLevel(os.environ.get("LOGGING_LEVEL", "DEBUG"))


def _json_response(status: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
        "body": json.dumps(body),
    }


class TokenAuthorizer:
    def __init__(self, clients: Dict[str, Dict[str, Any]], private_key: str, issuer: str):
        self.clients = clients
        self.private_key = private_key
        self.issuer = issuer

    def _lower_headers(self, event: Dict[str, Any]) -> Dict[str, str]:
        raw_headers: Any = event.get("headers") or {}
        if not isinstance(raw_headers, dict):
            return {}
        out: Dict[str, str] = {}
        raw_headers_typed: Dict[Any, Any] = cast(Dict[Any, Any], raw_headers)
        for k, v in raw_headers_typed.items():
            out[str(k).lower()] = str(v)
        return out

    def _decode_body(self, event: Dict[str, Any]) -> str:
        raw = event.get("body") or ""
        if event.get("isBase64Encoded"):
            try:
                return base64.b64decode(raw).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return ""
        return raw

    def _parse_body(self, event: Dict[str, Any]) -> Dict[str, Any]:
        headers = self._lower_headers(event)
        raw = self._decode_body(event)
        ctype = (
            (headers.get("content-type") or "application/json")
        .split(";")[0]
        .strip()
        )

        if ctype == "application/json":
            try:
                return json.loads(raw or "{}")
            except json.JSONDecodeError as e:
                log.error("Failed to parse JSON body: %s", e)
                return {}
        if ctype == "application/x-www-form-urlencoded":
            parsed: Dict[str, list[str]] = urllib.parse.parse_qs(raw or "")
            return {k: (v[0] if v else "") for k, v in parsed.items()}
        # Fallback try JSON, else empty
        try:
            return json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {}

    def _extract_basic_auth(self, headers: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
        auth = headers.get("authorization")
        if not auth or not auth.lower().startswith("basic "):
            return None, None
        try:
            user_pass = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            client_id, client_secret = user_pass.split(":", 1)
            return client_id, client_secret
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None, None

    def handler(self, event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
        log.info("Received event: %s", event)

        headers = self._lower_headers(event)
        body = self._parse_body(event)
        log.info("Parsed body: %s", body)

        # Pull client credentials
        client_id = body.get("client_id")
        client_secret = body.get("client_secret")
        basic_id, basic_secret = self._extract_basic_auth(headers)
        client_id = client_id or basic_id
        client_secret = client_secret or basic_secret

        audience = body.get("audience")
        grant_type = body.get("grant_type")

        if grant_type != "client_credentials":
            return _json_response(
                400,
                {
                    "error": "unsupported_grant_type",
                    "error_description": "Only client_credentials is supported",
                },
            )

        if not client_id or not client_secret or not audience:
            return _json_response(
                400,
                {
                    "error": "invalid_request",
                    "error_description": (
                        "Missing client_id, client_secret, or audience"
                    ),
                },
            )

        client_data: Optional[Dict[str, Any]] = self.clients.get(client_id)
        if not client_data:
            return _json_response(
                401,
                {
                    "error": "invalid_client",
                    "error_description": "Unknown client",
                },
            )

        expected_secret = client_data.get("client_secret")
        if not expected_secret or expected_secret != client_secret:
            return _json_response(
                401,
                {
                    "error": "invalid_client",
                    "error_description": "Invalid client credentials",
                },
            )

        if audience != client_data.get("audience"):
            return _json_response(
                401,
                {
                    "error": "invalid_audience",
                    "error_description": "Audience does not match",
                },
            )

        # Generate JWT
        try:
            now = dt.datetime.now(dt.timezone.utc)
            payload: Dict[str, Any] = {
                "iss": self.issuer,
                "sub": client_data.get("sub", client_id),
                "aud": client_data.get("audience", audience),
                "iat": now,
                "exp": now + dt.timedelta(hours=24),
                "scope": client_data.get("scope", ""),
                "permissions": client_data.get("permissions", []),
            }
            headers_out: Dict[str, str] = {"kid": "key-id-1"}
            token = jwt.encode(
                payload,
                self.private_key,
                algorithm="RS256",
                headers=headers_out,
            )
        except (FileNotFoundError, OSError) as e:
            log.error("Failed to read private key: %s", e)
            return _json_response(500, {"error": "server_error"})
        except jwt.exceptions.PyJWTError as e:  # type: ignore[attr-defined]
            log.error("Failed to generate token: %s", e)
            return _json_response(500, {"error": "server_error"})

        return _json_response(
            200,
            {
                "token": token,
                "token_type": "Bearer",
                "expires_in": 86400,
            },
        )


def load_clients() -> Dict[str, Dict[str, Any]]: 
    # Load configuration
    with open("config.yaml", "r", encoding="utf-8") as file:
        cfg_any: Dict[str, Any] = cast(Dict[str, Any], yaml.safe_load(file) or {})
        
        clients_any: Dict[str, Any] = cast(
            Dict[str, Any], cfg_any.get("clients") or {}
        )
        
        clients: Dict[str, Dict[str, Any]] = cast(
            Dict[str, Dict[str, Any]], clients_any
        )
        return clients


def load_private_key() -> str:
    with open("private_key.pem", "r", encoding="utf-8") as f:
        return f.read()


authorizer: Optional[TokenAuthorizer] = None
def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    global authorizer
    if not authorizer:
        try:
            clients = load_clients()
            private_key = load_private_key()
            issuer = os.getenv("ISSUER", "https://oauth.local/")
            authorizer = TokenAuthorizer(clients, private_key, issuer)
        except (FileNotFoundError, yaml.YAMLError, OSError, ValueError) as e:
            log.error("Failed to load configuration: %s", e)
            return _json_response(500, {"error": "server_error"})
    return authorizer.handler(event, context)
