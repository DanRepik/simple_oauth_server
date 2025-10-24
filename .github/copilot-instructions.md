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
- JWKS Handler: `simple_oauth_server/jwks_handler.py`
  - Exposes public keys at `/.well-known/jwks.json` (RFC 7517)
  - Converts RSA public key to JWK format with key ID (`kid`)
  - Supports CORS and caching headers (1 hour TTL)
- Token Decoder: `simple_oauth_server/token_decoder.py`
  - `@token_decoder()` decorator for Lambda functions
  - Automatic JWT validation with JWKS key fetching and caching
  - Flexible configuration (JWKS URL, audience, issuer, algorithms)
- Keys: `public_key.pem` for validator/JWKS; `private_key.pem` for issuer

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
- Hatch test environment with isolated dependencies (pytest, pytest-cov, requests)
- Key tests:
  - `test_authorizer.py` — token issuance, basic auth, subject behavior
  - `test_validator.py` — policy building, ws/rest flows, error paths
  - `test_scopes.py` — scope exact/wildcard and insufficient scope
  - `test_jwks_handler.py` — JWKS endpoint, JWK format, caching, CORS
  - `test_token_decoder.py` — decorator functionality, JWKS integration, error handling
- Pytest config excludes `temp/` directory and focuses on `tests/`
- Run: `hatch run test:pytest` or `pytest -q` (if dependencies installed)

## Coding Guidance
- Keep token field names stable: `token`, `token_type`, `expires_in`
- Authorizer context must be strings; JSON-encode arrays
- JWKS endpoint must follow RFC 7517 format with proper `kid` values
- Token decoder should handle JWKS caching and key rotation gracefully
- Use Hatch environments for dependency isolation: `hatch run test:pytest`
- For new features, update README and add unit tests covering:
  - token claims shape
  - authorizer context shape
  - scope/permission allow/deny cases
  - JWKS format compliance and caching behavior

## Common Pitfalls
- Wrong `audience`: validator derives `aud` from methodArn (`/stage`) and will 401
- Missing `ISSUER`: ensure issuer matches both issuer env and token claim
- API Gateway TOKEN authorizer only returns strings in `context`
- JWKS caching: respect TTL headers and handle key rotation properly
- Test isolation: use `hatch run test:pytest` to avoid dependency conflicts
- URI schemes: ensure `pkg://` schemes are properly formatted (no extra colons)

