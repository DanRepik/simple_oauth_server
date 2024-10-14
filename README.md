# Simple OAuth Server

A simple OAuth server deployable to AWS Lambda, designed for development and testing environments. This server offers two primary services: 

1. **Authorization** - Clients can provide their credentials and obtain a bearer token.
2. **Validation** - Validates bearer tokens for authorizing AWS API Gateway requests.

This service is targeted at developers who need a mock OAuth server for testing and development.

## Prerequisites

The deployment uses **Pulumi** for AWS Lambda, and components are deployed using the Pulumi CLI. You can deploy the server as part of a larger Pulumi deployment or separately.

### Requirements

- AWS account credentials
- Pulumi CLI installed
- Python environment

## Set Up

### Step 1: Deployment Script

You can deploy the OAuth server using Pulumi. Below is an example script that starts the OAuth server with the test configuration provided.
You need a configuration that defines test clients with their credentials and permissions.  This configuration is expected to be in YAML format.  When starting a OAuth server configation can be either passed as string inline like the example below or using a file name.


```python
# __main__.py

import simple_oauth_server

test_users = """
clients:
  client1:
    client_secret: "client1-secret"
    audience: "test-api"
    sub: "client1-subject"
    scope: "read:data"
    permissions:
      - "read:data"
  
  client2:
    client_secret: "client2-secret"
    audience: "test-api"
    sub: "client2-subject"
    scope: "write:data"
    permissions:
      - "write:data"
"""

oauth_server = simple_oauth_server.start("oauth", config=test_users)
```

### Step 3: Run Pulumi Deployment

To deploy the server:

```bash
pulumi up
```

Pulumi will use the provided configuration and start the OAuth service on AWS Lambda.

## Usage

### Authorization

To obtain a bearer token, clients must provide their `client_id`, `client_secret`, and the target `audience` (API they want to access). Here's an example of how to request an authorization token:

#### Example Request:

```bash
curl --request POST \
  --url https://your-oauth-server/authorize \
  --header 'Content-Type: application/json' \
  --data '{
    "client_id": "client1",
    "client_secret": "client1-secret",
    "audience": "test-api",
    "grant_type": "client_credentials"
  }'
```

#### Example Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

This token can be used to authenticate subsequent API requests.

### Validation

The validation service can be integrated with **AWS API Gateways** as a authorizer to validate incoming requests using the bearer token.

#### Example AWS API Gateway Integration:

1. Set up a Lambda authorizer in AWS API Gateway.
2. Use the `token_validator.py` Lambda function to validate tokens.
3. Configure API Gateway routes to use the Lambda authorizer.

#### Example Request:

```bash
curl --request POST \
  --url https://your-api-gateway-endpoint/test-api/greet \
  --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
```

The `token_validator.py` function verifies the JWT token, ensuring the request is authenticated before allowing access to your API routes.

### Example Token Validator (Lambda):

```python
import os
import jwt

def validate_token(token):
    public_key = open('public_key.pem').read()  # Load public key from file
    return jwt.decode(token, public_key, algorithms=["RS256"], audience="test-api")
```

