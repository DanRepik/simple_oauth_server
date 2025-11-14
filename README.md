# Simple OAuth Server

A lightweight OAuth 2.0 server deployable to AWS Lambda, designed for development and testing environments. Provides RS256 JWT token issuance, validation, and JWKS endpoint support for securing REST APIs.

## Key Features

- **Token Issuance**: Client credentials flow with RS256 JWTs
- **Token Validation**: AWS API Gateway Lambda authorizer integration
- **JWKS Endpoint**: RFC 7517 compliant public key discovery
- **Token Decoder**: Optional JWT validation decorator for Lambda functions
- **DB Auth Enrichment**: Optional Postgres-backed roles/permissions enrichment
- **Automatic Key Generation**: RSA key pairs created during deployment
- **Flexible Configuration**: YAML-based client and permission setup

## Quick Start

### Prerequisites

- AWS account with credentials configured
- Pulumi CLI installed
- Python 3.9+ environment

### Basic Deployment

```python
# __main__.py
import simple_oauth_server

# Define test clients
config = """
clients:
  api_client:
    client_secret: "my-secret-key"
    audience: "my-api"
    sub: "api-user-1"
    scope: "read:data write:data"
    permissions:
      - "read:data"
      - "write:data"
  
  admin_client:
    client_secret: "admin-secret"
    audience: "my-api"
    sub: "admin-user"
    scope: "*:*"
    roles: ["admin"]
    permissions:
      - "admin"
"""

# Deploy OAuth server with explicit audience
oauth_server = simple_oauth_server.start(
    "oauth", config=config, audience="my-api"
)
```

Deploy with Pulumi:

```bash
pulumi up
```

The server automatically generates RSA key pairs and deploys three Lambda functions:
- Token issuer (`POST /token`)
- Token validator (API Gateway authorizer)
- JWKS endpoint (`GET /.well-known/jwks.json`)

## Usage

### Token Issuance

Request bearer tokens using client credentials:

```bash
curl --request POST \
  --url https://your-oauth-server/token \
  --header 'Content-Type: application/json' \
  --data '{
    "client_id": "api_client",
    "client_secret": "my-secret-key",
    "audience": "my-api",
    "grant_type": "client_credentials"
  }'
```

Response:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

### JWKS Endpoint

Public key discovery for token validation:

```bash
curl --request GET \
  --url https://your-oauth-server/.well-known/jwks.json
```

Returns RSA public keys in JWK format for signature verification.

### API Gateway Integration

Configure the token validator as a Lambda authorizer in AWS API Gateway:

1. Create Lambda authorizer using the deployed validator function
2. Configure API routes to use the authorizer
3. Clients include tokens in requests:

```bash
curl --request GET \
  --url https://your-api-gateway/my-api/data \
  --header 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
```

The validator checks token signature, expiration, audience, and scopes, then returns an IAM policy allowing access to authorized resources.

### Token Decoder (Optional)

For Lambda functions that need to validate JWTs directly:

```python
from simple_oauth_server.token_decoder import token_decoder

@token_decoder(
    jwks_url="https://your-oauth-server/.well-known/jwks.json",
    audience="my-api",
    issuer="https://oauth.local/"
)
def my_lambda_handler(event, context):
    # JWT claims available in event['requestContext']['authorizer']
    authorizer = event.get('requestContext', {}).get('authorizer', {})
    user_id = authorizer.get('sub', 'unknown')
    scopes = authorizer.get('scope', '').split()
    
    return {
        'statusCode': 200,
        'body': f'Hello {user_id}, scopes: {scopes}'
    }
```

#### DB Authorization Enrichment (Optional)

You can enrich decoded JWT claims with roles, permissions, and groups
from a PostgreSQL database by setting `AUTHZ_DB_ENABLED=true`.
Enrichment runs only after successful JWT validation; if disabled, the
decoder returns raw JWT claims.

Environment variables:

```bash
export AUTHZ_DB_ENABLED=true                # Toggle feature (default: false)
export AUTHZ_FAIL_MODE=fail_closed          # Or fail_open
export AUTHZ_CACHE_TTL_SECONDS=300          # Per-sub/tenant cache TTL

# Connection settings (standard PG env vars)
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=authz
export PGUSER=app
export PGPASSWORD=secret
export PGSSLMODE=prefer

# SQL (use :sub and :tenant placeholders)
export AUTHZ_SQL_VALIDATE_SUB='SELECT 1 FROM users WHERE sub = :sub'
export AUTHZ_SQL_ROLES='SELECT role FROM user_roles WHERE sub = :sub'
export AUTHZ_SQL_PERMISSIONS='SELECT perm FROM user_perms WHERE sub = :sub'
export AUTHZ_SQL_GROUPS='SELECT grp FROM user_groups WHERE sub = :sub'
```

Behavior:
- Validation query: if present and yields no row
  - `fail_closed` -> raises PermissionError (handler returns 500)
  - `fail_open` -> failure logged; role/permission/group queries still run
- DB driver/connect errors: logged & skipped in `fail_open`; raise in `fail_closed`.
- Roles / permissions / groups only merged if non-empty.
- Cache key: `(sub, tenant)`; TTL controlled by `AUTHZ_CACHE_TTL_SECONDS`.
- Placeholders `:sub` / `:tenant` converted to positional `%s`.

## Configuration

### Client Configuration

Define clients in YAML format with credentials and permissions:

```yaml
clients:
  client_name:
    client_secret: "secret-key"      # Required: client authentication
    audience: "api-identifier"       # Required: target API
    sub: "user-identity"            # Required: subject claim
    scope: "read:data write:data"   # Optional: OAuth scopes
    permissions:                    # Optional: fine-grained permissions
      - "read:data"
      - "write:data"
    roles: ["user", "admin"]        # Optional: role metadata
    groups: ["team-a"]              # Optional: group metadata
```

### Environment Variables

Configure at runtime:

```bash
# Token issuer/validator settings
export ISSUER="https://oauth.local/"
export AUDIENCE="my-api"  # Optional: default audience for validation

# Permission-to-resource mapping for IAM policies
export AUTH0_AUTH_MAPPINGS='{
  "read:data": [{"method": "GET", "resourcePath": "/data"}],
  "admin": [{"method": "*", "resourcePath": "*"}]
}'
```

DB enrichment environment variables are described in the
[Token Decoder > DB Authorization Enrichment](#db-authorization-enrichment-optional)
section above.

### JWT Claims

Issued tokens include:

**Standard Claims:**
- `iss`: Issuer (from ISSUER env var)
- `sub`: Subject (from client config)
- `aud`: Audience (from client config)
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp

**Custom Claims:**
- `scope`: Space-delimited OAuth scopes
- `permissions`: Array of permission strings
- `roles`: Array of role strings
- `groups`: Array of group strings

### Scope Validation

The validator derives required scopes from API Gateway method ARN:
- `GET /data` → requires `read:data`
- `POST /data` → requires `write:data`
- `DELETE /data/{id}` → requires `delete:data`

Wildcards supported: `read:*`, `write:*`, `*:*`

### Authorizer Context

Successful validation provides context to backend APIs:

```json
{
  "principalId": "user-identity",
  "context": {
    "sub": "user-identity",
    "scope": "read:data write:data",
    "scopes": "read:data write:data",
    "roles": "[\"user\", \"admin\"]",
    "groups": "[\"team-a\"]",
    "permissions": "[\"read:data\", \"write:data\"]"
  }
}
```

## Development & Testing

### Running Tests

```bash
# Install test dependencies and run tests
hatch run test:pytest

# Run with coverage
hatch run test:pytest --cov=simple_oauth_server

# Run specific test categories
hatch run test:pytest tests/test_authorizer.py
hatch run test:pytest tests/test_validator.py
```

### Local Development

For testing without AWS deployment:

```bash
# Generate RSA keys manually (optional - deployment auto-generates)
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Set environment variables
export ISSUER="https://oauth.local/"
export AUTH0_AUTH_MAPPINGS='{"read:pets": [{"method": "GET", "resourcePath": "/pets"}]}'
```

### LocalStack Integration

The project includes LocalStack support for testing AWS Lambda deployment locally without AWS costs.

### Test Environment

Uses Hatch for dependency management with dedicated test environment including:
- pytest for test execution
- pytest-cov for coverage reporting
- requests for HTTP client testing
- AsymmetricKeyPair utility for ephemeral test keys
 - test_authz_db.py covers DB enrichment (disabled, missing sub, validation modes, caching)

## API Reference

### Lambda Handlers

- **Token Issuer**: `simple_oauth_server.token_authorizer::handler`
- **Token Validator**: `simple_oauth_server.token_validator::handler`
- **JWKS Endpoint**: `simple_oauth_server.jwks_handler::handler`

### Key Modules

- `token_decoder.py`: JWT validation decorator for Lambda functions
- `asymmetric_key_pair.py`: RSA key pair generation utilities
- Configuration files: YAML client definitions with credentials and permissions

### Deployment Components

The `simple_oauth_server.start()` function creates:
1. Lambda functions for token issuance, validation, and JWKS
2. API Gateway endpoints with proper routing
3. RSA key pair generation and packaging
4. IAM roles and policies for Lambda execution

For complete examples and advanced configuration options, see the test files in the `tests/` directory.

## Troubleshooting

**500 Internal error**
- Check JWKS host reachability and issuer/audience env vars.
- If enrichment enabled, verify Postgres driver installed (psycopg or psycopg2).

**Enrichment silently skipped**
- Ensure `AUTHZ_DB_ENABLED` is one of: true, 1, yes, on.
- Confirm validation query returns a row or switch to `fail_open`.

**Changed roles not reflected**
- Decrease `AUTHZ_CACHE_TTL_SECONDS` or restart service to clear cache.

**Audience mismatch**
- Provide all acceptable audiences via `JWT_ALLOWED_AUDIENCES` (comma separated).
