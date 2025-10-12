# AI Coding Agent Instructions — Simple OAuth Server

Simple OAuth Server provides a minimal OAuth 2.0 style token issuer and an AWS API Gateway Lambda authorizer for development and testing. It issues RS256 JWTs and validates them to produce IAM policies.

## Architecture
- Token Issuer: `simple_oauth_server/token_authorizer.py`
  - Token endpoint handler (POST /token)
  - Accepts JSON or x-www-form-urlencoded; supports Basic auth for client auth
  - Loads clients from `config.yaml`; signs tokens with `private_key.pem`
- Token Validator (Authorizer): `simple_oauth_server/token_validator.py`
  - Validates JWT (iss, aud, exp)
  - Enforces scopes (with wildcards) OR permissions
  - Builds IAM policy from `AUTH0_AUTH_MAPPINGS`
  - Returns `principalId=sub` and context for backends
- Keys: `public_key.pem` for validator; `private_key.pem` for issuer

## Claims and Context
- Issued token claims:
  - Standard: `iss`, `sub`, `aud`, `iat`, `exp`
  - Custom: `scope` (space-delimited), `permissions` (list), `roles` (list), `groups` (list)
- Authorizer returns:
  - `principalId = sub`
  - `context` strings:
    - `sub`
    - `scope` and `scopes` (same value for compatibility)
    - `roles`, `groups`, `permissions` (JSON-encoded arrays)

## Scope & Permission Enforcement
- Required scope is derived from API Gateway `methodArn`:
  - Action mapping: GET→read, POST/PUT/PATCH→write, DELETE→delete
  - Entity: first path segment (e.g., /pets → `pets`)
  - Required scope: `action:entity` (e.g., `read:pets`)
- Allow if any is true:
  - Token has exact scope (e.g., `read:pets`)
  - Token has wildcard: `action:*`, `*`, or `*:*`
  - Permissions include `required_scope`
- If token contains no `scope`, scope check is skipped; permissions still apply

## Configuration
- Clients are read from `config.yaml` with fields:
  - `client_secret` (string), `audience` (string), `sub` (user id)
  - Optional: `scope` (string), `permissions` (list), `roles` (str|list), `groups` (str|list)
- Environment variables:
  - `ISSUER` (defaults to `https://oauth.local/`)
  - `AUTH0_AUTH_MAPPINGS` — JSON mapping from permission→allowed resources

## Tests
- Test suite under `tests/` uses `AsymmetricKeyPair` for ephemeral keys
- Key tests:
  - `test_authorizer.py` — token issuance, basic auth, subject behavior
  - `test_validator.py` — policy building, ws/rest flows, error paths
  - `test_scopes.py` — scope exact/wildcard and insufficient scope
- Run: `pytest -q`

## Coding Guidance
- Keep token field names stable: `token`, `token_type`, `expires_in`
- Authorizer context must be strings; JSON-encode arrays
- For new features, update README and add unit tests covering:
  - token claims shape
  - authorizer context shape
  - scope/permission allow/deny cases

## Common Pitfalls
- Wrong `audience`: validator derives `aud` from methodArn (`/stage`) and will 401
- Missing `ISSUER`: ensure issuer matches both issuer env and token claim
- API Gateway TOKEN authorizer only returns strings in `context`

