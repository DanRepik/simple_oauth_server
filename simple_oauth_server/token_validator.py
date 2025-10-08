# token_validator.py

import os
import json
import re
from typing import Any, Dict
import jwt
from cryptography.hazmat.primitives import serialization
import logging

logging.basicConfig(
    format="%(levelname)s \t %(filename)s:%(lineno)d:%(funcName)s \t %(message)s",
    level=os.environ.get("LOGGING_LEVEL", "DEBUG"),
)

log = logging.getLogger(__name__)

# Load environment variables
AUTH_MAPPINGS = json.loads(os.getenv("AUTH0_AUTH_MAPPINGS", "{}"))
DEFAULT_ARN = "arn:aws:execute-api:*:*:*/*/*"

class AuthTokenValidator():
    def __init__(self, public_key, issuer: str):
        self.public_key = public_key
        self.issuer = issuer

    def handler(self, event: Dict[str, Any], _) -> Dict[str, Any]:
        """Main Lambda handler."""
        log.info(event)
        try:
            token = self.parse_token_from_event(self.check_event_for_error(event))
            decoded_token = self.decode_token(event, token)
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
        event["headers"] = {k.lower(): v for k, v in event["headers"].items()}

        # Check if it's a REST request (type TOKEN)
        if event.get("type") == "TOKEN":
            if "methodArn" not in event or "authorizationToken" not in event:
                raise ValueError(
                    'Missing required fields: "methodArn" or "authorizationToken".'
                )
        # Check if it's a WebSocket request
        elif "sec-websocket-protocol" in event["headers"]:
            protocols = str(event["headers"]["sec-websocket-protocol"]).split(", ")
            if len(protocols) != 2 or not protocols[0] or not protocols[1]:
                raise ValueError("Invalid token, required protocols not found.")
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


    def decode_token(self, event: Dict[str, Any], token: str) -> Dict[str, Any]:
        """
        Validate and decode the JWT token using the public key from the PEM file.
        """
        log.info("decode_token")

        log.info("public_key: %s", public_key)
        log.info("method_arn: %s", event["methodArn"])
        audience = str(event["methodArn"]).rstrip("/").split(":")[-1].split("/")[1]
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

    def get_policy(self, policy_resource_base: str, decoded: Dict[str, Any], is_ws: bool) -> Dict[str, Any]:
        """Create and return the policy for API Gateway."""
        resources: list[str] = []
        user_permissions = decoded.get("permissions", [])

        for perms, endpoints in AUTH_MAPPINGS.items():
            if perms in user_permissions or perms == "principalId":
                for endpoint in endpoints:
                    if not is_ws and "method" in endpoint and "resourcePath" in endpoint:
                        url_build = f"{policy_resource_base}{endpoint['method']}{endpoint['resourcePath']}"
                    elif is_ws and "routeKey" in endpoint:
                        url_build = f"{policy_resource_base}{endpoint['routeKey']}"
                    else:
                        continue
                    resources.append(url_build)

        context: Dict[str, str] = {
            "scope": str(decoded.get("scope", "")),
            "permissions": json.dumps(decoded.get("permissions", [])),
        }
        log.info("context: %s", json.dumps(context))

        if policy_resource_base == DEFAULT_ARN:
            resources = [DEFAULT_ARN]

        return {
            "principalId": decoded["sub"],
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [self.create_statement("Allow", resources)],
            },
            "context": context,
        }

    def create_statement(self, effect: str, resource: list[str]) -> Dict[str, Any]:
        """Create a policy statement."""
        return {
            "Effect": effect,
            "Resource": resource,
            "Action": ["execute-api:Invoke"],
        }


authorization_handler: AuthTokenValidator | None = None


def handler(event: Dict[str, Any], _) -> Dict[str, Any]:
    global authorization_handler
    if authorization_handler is None:
        # Load the public key from the PEM file
        with open("public_key.pem", "rb") as pem_file:
            public_key = serialization.load_pem_public_key(pem_file.read())
            authorization_handler = AuthTokenValidator(public_key, os.getenv("ISSUER"))
    
    return authorization_handler.handler(event, _)


