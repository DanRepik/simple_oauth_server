# Simple OAuth Server

A simple OAuth server deployable to AWS, designed to provide authorization services for development and testing environments. This server offers two primary services:

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
You need a configuration that defines test clients with their credentials and permissions. This configuration is expected to be in YAML format. When starting an OAuth server, configuration can be either passed inline as a string (like the example below) or using a file name.


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

### Step 2: Keys and Environment

The token service uses RS256 JWTs and expects an RSA key pair packaged with the function:

- private_key.pem (used by the token issuer)
- public_key.pem (used by the validator)

At runtime, you can set the following environment variables:

- ISSUER: Token issuer (iss) claim to set/validate (e.g., https://oauth.local/)
- AUTH0_AUTH_MAPPINGS: JSON mapping of permissions to allowed API Gateway resources for policies (used by the validator)

### Step 3: Run Pulumi Deployment

To deploy the server:

```bash
pulumi up
```

Pulumi will use the provided configuration and start the OAuth service on AWS Lambda.

## Usage

### Authorization (Token endpoint)

To obtain a bearer token, clients must provide their `client_id`, `client_secret`, the target `audience` (API they want to access), and `grant_type=client_credentials`.

The token endpoint is typically exposed at `POST /token` (or `/oauth/token`). JSON and application/x-www-form-urlencoded bodies are supported, and Basic Authorization is also accepted for client credentials.

#### Example Request (JSON body):

```bash
curl --request POST \
  --url https://your-oauth-server/token \
  --header 'Content-Type: application/json' \
  --data '{
    "client_id": "client1",
    "client_secret": "client1-secret",
    "audience": "test-api",
    "grant_type": "client_credentials"
  }'
```

#### Example Request (form-urlencoded + Basic auth):

```bash
curl --request POST \
  --url https://your-oauth-server/token \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --header 'Authorization: Basic Y2xpZW50MTpjbGllbnQxLXNlY3JldA==' \
  --data 'client_id=client1&audience=test-api&grant_type=client_credentials'
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

The validation service can be integrated with **AWS API Gateway** as an authorizer to validate incoming requests using the bearer token. It supports:

- REST (TOKEN authorizer): expects `authorizationToken` and `methodArn` in the event
- WebSocket: reads the token from the `sec-websocket-protocol` header (second value)

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

The `token_validator.py` function verifies the JWT token (audience derived from `methodArn`, issuer from `ISSUER` env var), ensuring the request is authenticated before allowing access to your API routes. It also returns an IAM policy allowing only the routes mapped to the token's permissions via `AUTH0_AUTH_MAPPINGS`.

### Example: Validating a token in Python

```python
import os
import jwt

def validate_token(token):
    with open('public_key.pem', 'r', encoding='utf-8') as f:
        public_key = f.read()
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience="test-api",
        issuer=os.getenv("ISSUER", "https://oauth.local/")
    )
```

### Lambda handlers

- Token issuance: `simple_oauth_server/token_authorizer.py::handler`
- Token validation (authorizer): `simple_oauth_server/token_validator.py::handler`

## Claims and authorizer context at a glance

Issued RS256 JWTs include these claims relevant to authorization and downstream identity:

- `iss`, `sub`, `aud`, `iat`, `exp` (standard)
- `scope` (string): space-delimited OAuth scopes, e.g., `"read:pets write:pets"`
- `permissions` (array of strings)
- `roles` (array of strings)
- `groups` (array of strings)

Authorizer response fields (strings only due to API Gateway constraints):

- `principalId = sub`
- `context.sub` — subject from the token
- `context.scope` — original scope string
- `context.scopes` — same value as `scope` for compatibility
- `context.roles` — JSON-encoded array of roles
- `context.groups` — JSON-encoded array of groups
- `context.permissions` — JSON-encoded array of permissions

Note: Arrays are JSON-encoded because API Gateway TOKEN authorizers only support string values in context.

## How `sub`, `scope`, and `permissions` work

This server issues RS256 JWTs with the following relevant claims for authorization:

- `sub` (subject):
  - Represents the identity making the request.
  - Comes from the client config `sub` value and is not overridden by roles.
  - Use `roles` and/or `groups` for role/group semantics; keep `sub` as the stable user or service identity.

- `scope` (space-delimited string):
  - Coarse-grained OAuth scopes, e.g. `"read:pets write:pets"`.
  - The validator derives a required scope from the API Gateway `methodArn` as `action:entity`, where action is mapped from the HTTP verb: GET→read, POST/PUT/PATCH→write, DELETE→delete; and `entity` is the first path segment (e.g., `/pets/{id}` → `pets`).
  - Wildcards supported in tokens:
    - `action:*` (e.g., `read:*`) allows that action for any entity.
    - `*` or `*:*` allows all actions/entities.
  - If the token has no `scope` claim, scope enforcement is skipped and permissions still apply (see below).

- `permissions` (array of strings):
  - Fine-grained labels primarily used for policy mapping with `AUTH0_AUTH_MAPPINGS` to produce an IAM policy with allowed resources.
  - The validator also treats a permission equal to the required scope as sufficient (logical OR with scopes). For example, a token with `permissions: ["read:pets"]` is allowed to `GET /pets` even without `scope`.

- `roles` and `groups` (arrays of strings):
  - Optional identity metadata included in the token for downstream use.
  - You may provide them in the client config as a string or a list; they are normalized to arrays.

Putting it together (validator logic overview):

1. Compute `required_scope` from `methodArn` → `action:entity`.
2. Extract `token_scopes` from `scope` (split by spaces) and `decoded_perms` from `permissions`.
3. Allow the request if any is true:
   - `required_scope` is in `token_scopes`.
   - `action:*` is in `token_scopes`.
   - `*` or `*:*` is in `token_scopes`.
   - `required_scope` is in `decoded_perms`.
4. If none match and `token_scopes` is present, return 401 with `error: "insufficient_scope"` and `required_scope` for clarity.
5. Independently, `AUTH0_AUTH_MAPPINGS` maps `permissions` to specific API Gateway resources to populate the Allow policy.

### Client configuration examples

Minimal client using `sub` and `scope` only:

```yaml
clients:
  reader:
    client_secret: "s"
    audience: "dev"
    sub: "reader-1"
    scope: "read:pets"
```

Client with roles/groups, plus a wildcard scope (note: `sub` remains the configured identity):

```yaml
clients:
  writer:
    client_secret: "s2"
    audience: "dev"
    sub: "writer-1"
    roles: ["sales_manager", "sales_associate"]
    groups: ["east", "retail"]
    scope: "write:*"
```

Client relying on `permissions` (no scope) to allow reads via mapping and scope-equivalence:

```yaml
clients:
  auditor:
    client_secret: "s3"
    audience: "dev"
    sub: "auditor-1"
    permissions:
      - "read:pets"
```

With this setup:
- `GET /pets` requires `read:pets` (or `read:*`, `*`, `*:*`), satisfied by either scope or permissions.
- `POST /pets` requires `write:pets` (or `write:*`, `*`, `*:*`).
- `DELETE /pets/{id}` requires `delete:pets` (or `delete:*`, `*`, `*:*`).

### Passing context to backends

The validator includes these string fields in the successful authorizer response:

- `principalId` — set to `sub`
- `context.sub` — the subject
- `context.scope` and `context.scopes` — the raw scope string (space-delimited)
- `context.roles`, `context.groups`, `context.permissions` — JSON-encoded arrays

Backends can use these to implement row-level security and app logic beyond the IAM policy.

### Notes

- `roles` and `groups` are optional, non-standard claims for convenience; they do not affect the `sub` value.
- Scopes are evaluated when present; permissions provide an additional allow path and are always used for policy mapping via `AUTH0_AUTH_MAPPINGS`.
- The validator derives `audience` from `methodArn` (API stage) and validates it along with `iss`.

### Policy mapping example (AUTH0_AUTH_MAPPINGS)

Set `AUTH0_AUTH_MAPPINGS` to a JSON object that maps a permission in the token to API Gateway resources allowed by the authorizer. For example:

```json
{
  "read:pets": [
    {"method": "GET", "resourcePath": "/pets"},
    {"method": "GET", "resourcePath": "/pets/{petId}"}
  ],
  "admin": [
    {"method": "DELETE", "resourcePath": "/pets/{petId}"}
  ],
  "principalId": [
    {"method": "POST", "resourcePath": "/echo"}
  ]
}
```

