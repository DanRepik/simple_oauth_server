# token_validator.py

import os
import json
import re
from typing import Any, Dict
import jwt
from cryptography.hazmat.primitives import serialization
import logging

logging.basicConfig(
    format="%(levelname)s %(filename)s:%(lineno)d %(funcName)s %(message)s",
    level=os.environ.get("LOGGING_LEVEL", "DEBUG"),
)

log = logging.getLogger(__name__)

# Load environment variables
AUTH_MAPPINGS = json.loads(os.getenv("AUTH0_AUTH_MAPPINGS", "{}"))
DEFAULT_ARN = "arn:aws:execute-api:*:*:*/*/*"


class AuthTokenValidator:
    def __init__(self, public_key, issuer: str):
        self.public_key = public_key
        self.issuer = issuer

    def handler(self, event: Dict[str, Any], _) -> Dict[str, Any]:
        """Main Lambda handler."""
        log.info(event)
        try:
            token = self.parse_token_from_event(
                self.check_event_for_error(event)
            )
            decoded_token = self.decode_token(event, token)
            # Enforce scopes with wildcard support
            required_scope = self._required_scope_from_method_arn(
                event["methodArn"]
            )
            scope_str = str(decoded_token.get("scope", "")).strip()
            token_scopes = set(scope_str.split()) if scope_str else set()
            decoded_perms = set(
                decoded_token.get("permissions", []) or []
            )
            action = required_scope.split(":", 1)[0]
            # Enforce scopes only if present; also allow access when
            # permissions explicitly include the required scope.
            scopes_allow = (
                required_scope in token_scopes
                or f"{action}:*" in token_scopes
                or "*" in token_scopes
                or "*:*" in token_scopes
            )
            perms_allow = required_scope in decoded_perms
            if token_scopes and not scopes_allow and not perms_allow:
                return {
                    "statusCode": 401,
                    "body": json.dumps(
                        {
                            "message": "Unauthorized",
                            "error": "insufficient_scope",
                            "required_scope": required_scope,
                        }
                    ),
                }
            return self.get_policy(
                self.build_policy_resource_base(event),
                decoded_token,
                "sec-websocket-protocol" in event["headers"],
            )
        except jwt.InvalidTokenError as e:
            log.error("Token validation failed: %s", e)
            return {
                "statusCode": 401,
                "body": json.dumps({
                    "message": "Unauthorized",
                    "error": str(e)
                })
            }
        except (KeyError, ValueError) as e:
            log.error("Authorization error: %s", e)
            return {
                "statusCode": 500,
                "body": json.dumps({
                    "message": "Internal Server Error",
                    "error": str(e)
                })
            }

    def check_event_for_error(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Check event for errors and prepare headers."""
        if "headers" not in event:
            event["headers"] = {}

        # Normalize headers to lowercase
        # normalize headers; be lenient with types
        headers_any = event["headers"]
        event["headers"] = {str(k).lower(): str(v) for k, v in headers_any.items()}

        # Check if it's a REST request (type TOKEN)
        if event.get("type") == "TOKEN":
            if "methodArn" not in event or "authorizationToken" not in event:
                raise ValueError(
                    "Missing methodArn or authorizationToken."
                )
        # Check if it's a WebSocket request
        elif "sec-websocket-protocol" in event["headers"]:
            protocols = str(
                event["headers"]["sec-websocket-protocol"]
            ).split(", ")
            if len(protocols) != 2 or not protocols[0] or not protocols[1]:
                raise ValueError(
                    "Invalid token, required protocols not found."
                )
            event["authorizationToken"] = f"bearer {protocols[1]}"
        else:
            raise ValueError("Unable to find token in the event.")

        return event

    def parse_token_from_event(self, event: Dict[str, Any]) -> str:
        """Extract the Bearer token from the authorization header."""
        auth_token_parts = event["authorizationToken"].split(" ")
        if (
            len(auth_token_parts) != 2
            or auth_token_parts[0].lower() != "bearer"
            or not auth_token_parts[1]
        ):
            raise ValueError("Invalid AuthorizationToken.")
        log.info("token: %s", auth_token_parts[1])
        return auth_token_parts[1]

    def build_policy_resource_base(self, event: Dict[str, Any]) -> str:
        """Build the policy resource base from the event's methodArn."""
        if not AUTH_MAPPINGS:
            return DEFAULT_ARN

        method_arn = str(event["methodArn"]).rstrip("/")
        slice_where = -2 if event.get("type") == "TOKEN" else -1
        arn_pieces = re.split(":|/", method_arn)[:slice_where]

        if len(arn_pieces) != 7:
            raise ValueError("Invalid methodArn.")

        last_element = f"{arn_pieces[-2]}/{arn_pieces[-1]}/"
        arn_pieces = arn_pieces[:5] + [last_element]
        return ":".join(arn_pieces)

    def decode_token(
        self, event: Dict[str, Any], token: str
    ) -> Dict[str, Any]:
        """Validate and decode the JWT using the PEM public key."""
        log.info("decode_token")
        log.info("method_arn: %s", event["methodArn"])
        audience = (
            str(event["methodArn"]).rstrip("/").split(":")[-1].split("/")[1]
        )
        log.info("audience: %s", audience)
        try:
            # Decode and verify the JWT token
            decoded_token = jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=self.issuer,
            )
            return decoded_token
        except jwt.ExpiredSignatureError:
            log.error("Token has expired.")
            raise
        except jwt.InvalidTokenError as e:
            log.error("Token validation failed: %s", e)
            raise

    def get_policy(
        self, policy_resource_base: str, decoded: Dict[str, Any], is_ws: bool
    ) -> Dict[str, Any]:
        """Create and return the policy for API Gateway."""
        resources: list[str] = []
        user_permissions = decoded.get("permissions", [])

        for perms, endpoints in AUTH_MAPPINGS.items():
            if perms in user_permissions or perms == "principalId":
                for endpoint in endpoints:
                    if (
                        not is_ws
                        and "method" in endpoint
                        and "resourcePath" in endpoint
                    ):
                        url_build = (
                            f"{policy_resource_base}{endpoint['method']}"
                            f"{endpoint['resourcePath']}"
                        )
                    elif is_ws and "routeKey" in endpoint:
                        url_build = (
                            f"{policy_resource_base}{endpoint['routeKey']}"
                        )
                    else:
                        continue
                    resources.append(url_build)

        context: Dict[str, str] = {
            # identity
            "sub": str(decoded.get("sub", "")),
            "scope": str(decoded.get("scope", "")),
            # list-like claims must be strings in API Gateway context
            "roles": json.dumps(decoded.get("roles", [])),
            "groups": json.dumps(decoded.get("groups", [])),
            "permissions": json.dumps(decoded.get("permissions", [])),
        }
        log.info("context: %s", json.dumps(context))

        if policy_resource_base == DEFAULT_ARN:
            resources = [DEFAULT_ARN]

        return {
            "principalId": decoded.get("sub", "unknown"),
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [self.create_statement("Allow", resources)],
            },
            "context": context,
        }

    def _required_scope_from_method_arn(self, method_arn: str) -> str:
        """Map methodArn to required scope using action:entity."""
        # arn:aws:execute-api:region:acct:apiId/stage/VERB/...
        tail = method_arn.rstrip("/").split(":")[-1]
        parts = tail.split("/")
        # parts layout:
        #   [0]=apiId, [1]=stage, [2]=VERB, [3:]=resource path segments
        verb = parts[2].upper() if len(parts) > 2 else "GET"
        path_segments = parts[3:] if len(parts) > 3 else []
        entity = (path_segments[0] if path_segments else "").strip("{}")
        verb_to_action = {
            "GET": "read",
            "POST": "write",
            "PUT": "write",
            "PATCH": "write",
            "DELETE": "delete",
        }
        action = verb_to_action.get(verb, "read")
        return f"{action}:{entity}" if entity else f"{action}:*"

    def create_statement(
        self, effect: str, resource: list[str]
    ) -> Dict[str, Any]:
        """Create a policy statement."""
        return {
            "Effect": effect,
            "Resource": resource,
            "Action": ["execute-api:Invoke"],
        }


authorization_handler_singleton: AuthTokenValidator | None = None


def handler(event: Dict[str, Any], _) -> Dict[str, Any]:
    # Lazy init without using global statement
    if not isinstance(
        globals().get("authorization_handler_singleton"), AuthTokenValidator
    ):
        # Load the public key from the PEM file
        with open("public_key.pem", "rb") as pem_file:
            public_key = serialization.load_pem_public_key(pem_file.read())
            issuer = os.getenv("ISSUER", "https://oauth.local/")
            globals()["authorization_handler_singleton"] = AuthTokenValidator(
                public_key, issuer
            )

    instance = globals()["authorization_handler_singleton"]
    assert isinstance(instance, AuthTokenValidator)
    return instance.handler(event, _)


