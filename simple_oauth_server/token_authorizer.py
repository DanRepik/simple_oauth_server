# token_authorizer.py

import json
import jwt
import datetime
import yaml

# Load the YAML configuration file
def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)

def generate_mock_token(client_data):
    secret_key = "your-mock-secret"

    now = datetime.datetime.utcnow()

    # Prepare the payload using values from the client_data
    payload = {
        'iss': 'https://your-auth0-mock-domain/',
        'sub': client_data['sub'],
        'aud': client_data['audience'],
        'iat': now,
        'exp': now + datetime.timedelta(hours=24),  # Token valid for 24 hours
        'scope': client_data['scope'],
        'permissions': client_data['permissions']
    }

    # Generate the JWT token
    token = jwt.encode(payload, secret_key, algorithm='HS256')

    return token

def handler(event, context):
    # Load the YAML configuration
    config = load_config()

    # Parse the incoming request body (expected to be in JSON format)
    body = json.loads(event.get('body', '{}'))

    client_id = body.get('client_id')
    client_secret = body.get('client_secret')
    audience = body.get('audience')
    grant_type = body.get('grant_type')

    # Validate the incoming request
    if not client_id or not client_secret or not audience or grant_type != 'client_credentials':
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'invalid_request',
                'error_description': 'Missing or invalid parameters'
            })
        }

    # Check if the client_id exists in the configuration
    client_data = config['clients'].get(client_id)
    
    if not client_data:
        return {
            'statusCode': 401,
            'body': json.dumps({
                'error': 'invalid_client',
                'error_description': 'Client ID not found'
            })
        }

    # Check if the audience matches the one defined for the client
    if audience != client_data['audience']:
        return {
            'statusCode': 401,
            'body': json.dumps({
                'error': 'invalid_audience',
                'error_description': 'Audience does not match'
            })
        }

    # Generate the mock token using the client-specific data from the YAML
    token = generate_mock_token(client_data)

    # Return the token in the response, similar to Auth0's response format
    return {
        'statusCode': 200,
        'body': json.dumps({
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': 86400  # Token expires in 24 hours
        }),
        'headers': {
            'Content-Type': 'application/json'
        }
    }
