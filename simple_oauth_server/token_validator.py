# token_validator.py

import os
import json
import re
from jwt import PyJWKClient, decode, get_unverified_header, InvalidTokenError
from logging import Logger

logger = Logger(__name__)

# Load environment variables
AUTH_MAPPINGS = json.loads(os.getenv("AUTH0_AUTH_MAPPINGS", "{}"))
DEFAULT_ARN = "arn:aws:execute-api:*:*:*/*/*"
DECODE_OPTIONS = {"verify_signature": True, "verify_aud": False}

def handler(event, context):
    """Main Lambda handler."""
    logger.info(event)
    try:
        token = parse_token_from_event(check_event_for_error(event))
        return get_policy(
            build_policy_resource_base(event),
            validate_token(token),
            "sec-websocket-protocol" in event["headers"],
        )
    except Exception as e:
        logger.error(e)
        raise Exception("Unauthorized")


def check_event_for_error(event: dict) -> dict:
    """Check event for errors and prepare headers."""
    if "headers" not in event:
        event["headers"] = {}

    # Normalize headers to lowercase
    event["headers"] = {k.lower(): v for k, v in event["headers"].items()}

    # Check if it's a REST request (type TOKEN)
    if event.get("type") == "TOKEN":
        if "methodArn" not in event or "authorizationToken" not in event:
            raise Exception('Missing required fields: "methodArn" or "authorizationToken".')
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
    if len(auth_token_parts) != 2 or auth_token_parts[0].lower() != "bearer" or not auth_token_parts[1]:
        raise Exception("Invalid AuthorizationToken.")
    return auth_token_parts[1]


def build_policy_resource_base(event: dict) -> str:
    """Build the policy resource base from the event's methodArn."""
    if not AUTH_MAPPINGS:
        return DEFAULT_ARN

    method_arn = str(event["methodArn"]).rstrip('/')
    slice_where = -2 if event.get("type") == "TOKEN" else -1
    arn_pieces = re.split(":|/", method_arn)[:slice_where]

    if len(arn_pieces) != 7:
        raise Exception("Invalid methodArn.")

    last_element = f"{arn_pieces[-2]}/{arn_pieces[-1]}/"
    arn_pieces = arn_pieces[:5] + [last_element]
    return ":".join(arn_pieces)


def validate_token(token: str) -> dict:
    """Validate and decode the JWT token using Auth0 JWKS."""
    header = get_unverified_header(token)
    if "kid" not in header:
        raise InvalidTokenError("No kid found in token header.")

    jwks_url = f"{os.getenv('AUTH0_DOMAIN')}/.well-known/jwks.json"
    key = PyJWKClient(jwks_url).get_signing_key(header["kid"]).key

    return decode(
        token,
        key,
        algorithms=[header.get("alg", "RS256")],
        issuer=f'{os.getenv("AUTH0_DOMAIN")}/',
        audience=os.getenv("AUDIENCE"),
        options=DECODE_OPTIONS,
    )


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
    logger.info(f"context: {json.dumps(context)}")

    if policy_resource_base == DEFAULT_ARN:
        resources = [DEFAULT_ARN]

    return create_policy(
        decoded["sub"],
        [create_statement("Allow", resources, [default_action])],
        context,
    )


def create_statement(effect: str, resource: list, action: list) -> dict:
    """Create a policy statement."""
    return {
        "Effect": effect,
        "Resource": resource,
        "Action": action,
    }


def create_policy(principal_id: str, statements: list, context: dict) -> dict:
    """Create the policy document."""
    return {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": statements,
        },
        "context": context,
    }
