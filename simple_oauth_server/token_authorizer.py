# token_authorizer.py
import json
import jwt
import os
import datetime
import yaml
import logging

logging.basicConfig(
    format="%(levelname)s \t %(filename)s:%(lineno)d:%(funcName)s \t %(message)s",
    level=os.environ.get("LOGGING_LEVEL", "DEBUG"),
)

log = logging.getLogger(__name__)
log.setLevel(os.environ.get("LOGGING_LEVEL", "DEBUG"))


def handler(event, context):
    log.info(f"Received event: {event}")

    # Load the YAML configuration
    try:
        # Load the YAML configuration file
        with open("config.yaml", "r") as file:
            config = yaml.safe_load(file)
            log.info("Configuration loaded successfully")
    except Exception as e:
        log.error(f"Failed to load configuration: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal Server Error"}),
        }

    # Parse the incoming request body (expected to be in JSON format)
    try:
        body = json.loads(event.get("body", "{}"))
        log.info(f"Parsed body: {body}")
    except Exception as e:
        log.error(f"Failed to parse request body: {e}")
        return {
            "statusCode": 400,
            "body": json.dumps(
                {"error": "invalid_request", "error_description": "Invalid JSON format"}
            ),
        }

    client_id = body.get("client_id")
    client_secret = body.get("client_secret")
    audience = body.get("audience")
    grant_type = body.get("grant_type")

    log.info(f"client_id: {client_id}, audience: {audience}, grant_type: {grant_type}")

    # Validate the incoming request
    if (
        not client_id
        or not client_secret
        or not audience
        or grant_type != "client_credentials"
    ):
        log.error("Invalid request parameters")
        return {
            "statusCode": 400,
            "body": json.dumps(
                {
                    "error": "invalid_request",
                    "error_description": "Missing or invalid parameters",
                }
            ),
        }

    # Check if the client_id exists in the configuration
    client_data = config["clients"].get(client_id)

    if not client_data:
        log.error("Client ID not found")
        return {
            "statusCode": 401,
            "body": json.dumps(
                {"error": "invalid_client", "error_description": "Client ID not found"}
            ),
        }

    # Check if the audience matches the one defined for the client
    if audience != client_data["audience"]:
        log.error("Audience does not match")
        return {
            "statusCode": 401,
            "body": json.dumps(
                {
                    "error": "invalid_audience",
                    "error_description": "Audience does not match",
                }
            ),
        }

    # Generate the token using the client-specific data from the YAML
    try:
        # Use an RSA private key if using RS256
        private_key = open("private_key.pem", "r").read()
        now = datetime.datetime.utcnow()

        # Prepare the payload using values from the client_data
        payload = {
            "iss": "https://your-oauth-mock-domain/",
            "sub": client_data["sub"],
            "aud": client_data["audience"],
            "iat": now,
            "exp": now + datetime.timedelta(hours=24),  # Token valid for 24 hours
            "scope": client_data["scope"],
            "permissions": client_data["permissions"],
        }

        # Define JWT headers with kid
        headers = {"kid": "your-key-id"}

        # Generate the JWT token
        token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
        log.info("Token generated successfully")
    except Exception as e:
        log.error(f"Failed to generate token: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal Server Error"}),
        }

    # Return the token in the response
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "token": token,
                "token_type": "Bearer",
                "expires_in": 86400,  # Token expires in 24 hours
            }
        ),
        "headers": {"Content-Type": "application/json"},
    }
