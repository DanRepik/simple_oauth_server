# test_gateway.py

import logging
import requests
import time

from test_fixtures import gateway_endpoint

log = logging.getLogger(__name__)

def test_get_request_all(gateway_endpoint):

    client_id = "client1"  # Change as needed to match your config.yaml
    client_secret = "client1-secret"  # Change as needed
    audience = "https://api.yourservice.com"  # Should match the audience in your config.yaml
    grant_type = "client_credentials"

    # Construct the request payload
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience,
        "grant_type": grant_type
    }

    # Make the POST request
    endpoint = gateway_endpoint + "/token"
    log.info(f"request: {endpoint}")
    response = requests.post(endpoint, json=payload)

    # Check the response status and print the result
    if response.status_code == 200:
        token_data = response.json()
        log.info("Access Token: {token_data['access_token']}")
    else:
        log.info(f"Error: {response.status_code}")
        log.info(response.json())    # Define the endpoint
        assert False

    # Make the POST request
    endpoint = gateway_endpoint + "/token/validate"
    log.info(f"request: {endpoint}")
    response = requests.post(endpoint, json=token_data)

    # Check the response status and print the result
    if response.status_code == 200:
        token_data = response.json()
        log.info("Access Token: {token_data['access_token']}")
    else:
        log.info(f"Error: {response.status_code}")
        log.info(response.json())    # Define the endpoint
        assert False


    assert False