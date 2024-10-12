# token_validator.py

import os
import json
import re
import jwt
from cryptography.hazmat.primitives import serialization
import logging

logging.basicConfig(
    format="%(levelname)s \t %(filename)s:%(lineno)d:%(funcName)s \t %(message)s",
    level=os.environ.get("LOGGING_LEVEL", "DEBUG"),
)

log = logging.getLogger(__name__)
log.setLevel(os.environ.get("LOGGING_LEVEL", "DEBUG"))

# Load environment variables
AUTH_MAPPINGS = json.loads(os.getenv("AUTH0_AUTH_MAPPINGS", "{}"))
DEFAULT_ARN = "arn:aws:execute-api:*:*:*/*/*"


def handler(event, context):
    """Main Lambda handler."""
    log.info(event)
    try:
        token = parse_token_from_event(check_event_for_error(event))
        decoded_token = decode_token(event, token)
        return get_policy(
            build_policy_resource_base(event),
            decoded_token,
            "sec-websocket-protocol" in event["headers"],
        )
    except jwt.InvalidTokenError as e:
        log.error(f"Token validation failed: {e}")
        return {
            "statusCode": 401,
            "body": json.dumps({
                "message": "Unauthorized",
                "error": str(e)
            })
        }
    except Exception as e:
        log.error(f"Authorization error: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "message": "Internal Server Error",
                "error": str(e)
            })
        }


def check_event_for_error(event: dict) -> dict:
    """Check event for errors and prepare headers."""
    if "headers" not in event:
        event["headers"] = {}

    # Normalize headers to lowercase
    event["headers"] = {k.lower(): v for k, v in event["headers"].items()}

    # Check if it's a REST request (type TOKEN)
    if event.get("type") == "TOKEN":
        if "methodArn" not in event or "authorizationToken" not in event:
            raise Exception(
                'Missing required fields: "methodArn" or "authorizationToken".'
            )
    # Check if it's a WebSocket request
    elif "sec-websocket-protocol" in event["headers"]:
        protocols = event["headers"]["sec-websocket-protocol"].split(", ")
        if len(protocols) != 2 or not protocols[0] or not protocols[1]:
            raise Exception("Invalid token, required protocols not found.")
        event["authorizationToken"] = f"bearer {protocols[1]}"
    else:
        raise Exception("Unable to find token in the event.")

    return event


def parse_token_from_event(event: dict) -> str:
    """Extract the Bearer token from the authorization header."""
    auth_token_parts = event["authorizationToken"].split(" ")
    if (
        len(auth_token_parts) != 2
        or auth_token_parts[0].lower() != "bearer"
        or not auth_token_parts[1]
    ):
        raise Exception("Invalid AuthorizationToken.")
    log.info(f"token: {auth_token_parts[1]}")
    return auth_token_parts[1]


def build_policy_resource_base(event: dict) -> str:
    """Build the policy resource base from the event's methodArn."""
    if not AUTH_MAPPINGS:
        return DEFAULT_ARN

    method_arn = str(event["methodArn"]).rstrip("/")
    slice_where = -2 if event.get("type") == "TOKEN" else -1
    arn_pieces = re.split(":|/", method_arn)[:slice_where]

    if len(arn_pieces) != 7:
        raise Exception("Invalid methodArn.")

    last_element = f"{arn_pieces[-2]}/{arn_pieces[-1]}/"
    arn_pieces = arn_pieces[:5] + [last_element]
    return ":".join(arn_pieces)


def decode_token(event, token: str) -> dict:
    """
    Validate and decode the JWT token using the public key from the PEM file.
    """
    log.info("decode_token")
    # Load the public key from the PEM file
    with open("public_key.pem", "rb") as pem_file:
        public_key = serialization.load_pem_public_key(pem_file.read())

    log.info(f"public_key: {public_key}")
    log.info(f"method_arn: {event['methodArn']}")
    audience = event["methodArn"].rstrip("/").split(":")[-1].split("/")[1]
    log.info(f"audience: {audience}")
    try:
        # Decode and verify the JWT token
        decoded_token = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=os.getenv("ISSUER"),
        )
        return decoded_token
    except jwt.ExpiredSignatureError:
        log.error("Token has expired.")
        raise jwt.InvalidTokenError("Token has expired.")
    except jwt.InvalidTokenError as e:
        log.error(f"Token validation failed: {e}")
        raise


def get_policy(policy_resource_base: str, decoded: dict, is_ws: bool) -> dict:
    """Create and return the policy for API Gateway."""
    resources = []
    user_permissions = decoded.get("permissions", [])
    default_action = "execute-api:Invoke"

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

    context = {
        "scope": decoded.get("scope"),
        "permissions": json.dumps(decoded.get("permissions", [])),
    }
    log.info(f"context: {json.dumps(context)}")

    if policy_resource_base == DEFAULT_ARN:
        resources = [DEFAULT_ARN]

    return {
        "principalId": decoded["sub"],
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [create_statement("Allow", resources, [default_action])],
        },
        "context": context,
    }


def create_statement(effect: str, resource: list, action: list) -> dict:
    """Create a policy statement."""
    return {
        "Effect": effect,
        "Resource": resource,
        "Action": action,
    }
