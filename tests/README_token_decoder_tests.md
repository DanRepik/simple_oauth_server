# Token Decoder Test Fixture

This test fixture (`test_token_decoder.py`) demonstrates how to test the `token_decoder` decorator by creating an authorized greet function and testing it directly.

## Overview

The test fixture focuses on testing the `token_decoder` decorator functionality by:

1. **Creating test fixtures for token generation and validation**
2. **Implementing an authorized greet function that uses the decorator**
3. **Testing various scenarios including valid tokens, invalid tokens, and error cases**

## Key Test Fixtures

### `authorized_greet_handler`
Creates a greet function decorated with `@token_decoder()` that:
- Extracts JWT claims from the `requestContext.authorizer`
- Returns personalized greetings based on user information
- Demonstrates accessing `sub`, `scope`, and `roles` from the token

### `test_token_authorizer`
Provides a `TokenAuthorizer` instance for creating valid JWT tokens during tests.

### `mock_jwks_response`
Creates a mock JWKS (JSON Web Key Set) response for JWT validation.

### `valid_jwt_token`
Generates a valid JWT token for testing purposes.

## Test Scenarios

1. **Valid Token Test** - Verifies that a valid JWT token is properly decoded and the greet function returns the expected personalized message.

2. **Missing Token Test** - Ensures the decorator handles missing Authorization headers gracefully.

3. **Invalid Token Test** - Tests behavior with malformed or invalid JWT tokens.

4. **Skip JWT Processing** - Verifies that JWT processing is skipped when `JWKS_HOST` is not configured.

5. **Existing Authorizer Context** - Tests that existing authorizer context is preserved and not overwritten.

6. **Metadata Preservation** - Ensures the decorator preserves the original handler's metadata.

7. **Singleton Behavior** - Verifies that the JWTDecoder instance is reused across multiple calls.

8. **Direct Call Comparison** - Shows the difference between a decorated and non-decorated handler.

## Usage Example

```python
@token_decoder()
def my_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Example handler using token_decoder."""
    # Access JWT claims through standard authorizer context
    authorizer = event.get('requestContext', {}).get('authorizer', {})
    user_sub = authorizer.get('sub', 'unknown')
    user_scope = authorizer.get('scope', '')
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': f'Hello {user_sub}!',
            'scope': user_scope
        })
    }
```

## Running the Tests

```bash
# Run all token decoder tests
python -m pytest tests/test_token_decoder.py -v

# Run a specific test
python -m pytest tests/test_token_decoder.py::test_authorized_greet_with_valid_token -v
```

## Environment Variables

The tests use the following environment variables to configure JWT processing:
- `JWKS_HOST`: The host for JWKS endpoint (e.g., 'oauth.local')
- `JWT_ISSUER`: The JWT issuer (e.g., 'https://oauth.local/')
- `JWT_ALLOWED_AUDIENCES`: Comma-separated list of allowed audiences

When `JWKS_HOST` is not set, JWT processing is skipped entirely.