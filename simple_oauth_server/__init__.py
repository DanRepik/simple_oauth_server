import os
import logging
import pkgutil
from cloud_foundry import python_function, rest_api, Function, RestAPI
from typing import Optional, Dict, Union
from pulumi import Output
from simple_oauth_server.asymmetric_key_pair import AsymmetricKeyPair

log = logging.Logger(__name__, os.environ.get("LOGGING_LEVEL", logging.DEBUG))


class SimpleOAuth:
    _validator: Function
    _authorizer: Function
    _jwks_handler: Function
    _server: RestAPI

    def __init__(
        self,
        name: str,
        config: str,
        path_prefix: Optional[str] = "/auth",
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        public_key_pem: Optional[str] = None,
    ):
        self.name = name
        self.config = config
        self._issuer = issuer or "https://oauth.local/"
        self._audience = audience
        self.path_prefix = path_prefix
        
        # Use provided keys or generate new ones
        if private_key_pem and public_key_pem:
            # Keys provided (from Secrets Manager, etc.)
            # Check if they are Pulumi Outputs or plain strings
            from pulumi import Output
            
            if isinstance(private_key_pem, Output) or isinstance(public_key_pem, Output):
                # Pass keys via environment variables (cloud_foundry supports Output in environment)
                self._use_env_keys = True
                self._private_key_pem = private_key_pem
                self._public_key_pem = public_key_pem
            else:
                # Plain strings - can be used as file sources
                self._use_env_keys = False
                self._private_key_pem = private_key_pem
                self._public_key_pem = public_key_pem
        else:
            # Generate new ephemeral keys (for testing)
            self._use_env_keys = False
            key_pair = AsymmetricKeyPair()
            self._private_key_pem = key_pair.private_key_pem
            self._public_key_pem = key_pair.public_key_pem
            
        self.environment: Dict[str, Union[str, Output[str]]] = {
            "ISSUER": self.issuer,
        }
        if self._audience:
            self.environment["AUDIENCE"] = self._audience

    @property
    def issuer(self) -> str:
        return self._issuer

    def validator(self) -> Function:
        if not hasattr(self, "_validator"):
            # Build sources dict
            sources = {
                "app.py": "pkg://simple_oauth_server/token_validator.py",
            }
            
            # Build environment dict
            env = dict(self.environment)
            
            # Add keys based on mode
            if self._use_env_keys:
                # Pass keys via environment variables
                env["PUBLIC_KEY_PEM"] = self._public_key_pem
            else:
                # Pass key as file
                sources["public_key.pem"] = self._public_key_pem
            
            self._validator = python_function(
                f"{self.name}-validator",
                timeout=12,
                memory_size=128,
                sources=sources,
                requirements=["requests==2.27.1", "PyJWT", "cryptography"],
                environment=env,
            )
        return self._validator

    def authorizer(self) -> Function:
        if not hasattr(self, "_authorizer"):
            # Build sources dict
            sources = {
                "app.py": "pkg://simple_oauth_server/token_authorizer.py",
                "config.yaml": self.config,
            }
            
            # Build environment dict
            env = dict(self.environment)
            
            # Add keys based on mode
            if self._use_env_keys:
                # Pass keys via environment variables
                env["PRIVATE_KEY_PEM"] = self._private_key_pem
            else:
                # Pass key as file
                sources["private_key.pem"] = self._private_key_pem
            
            self._authorizer = python_function(
                f"{self.name}-authorizer",
                timeout=12,
                sources=sources,
                requirements=[
                    "PyJWT",
                    "requests==2.27.1",
                    "PyYAML",
                    "cryptography",
                ],
                environment=env,
            )
        return self._authorizer

    def jwks_handler(self) -> Function:
        if not hasattr(self, "_jwks_handler"):
            # Build sources dict
            sources = {
                "app.py": "pkg://simple_oauth_server/jwks_handler.py",
            }
            
            # Build environment dict
            env = dict(self.environment)
            
            # Add keys based on mode
            if self._use_env_keys:
                # Pass keys via environment variables
                env["PUBLIC_KEY_PEM"] = self._public_key_pem
            else:
                # Pass key as file
                sources["public_key.pem"] = self._public_key_pem
            
            self._jwks_handler = python_function(
                f"{self.name}-jwks",
                timeout=12,
                memory_size=128,
                sources=sources,
                requirements=["cryptography"],
                environment=env,
            )
        return self._jwks_handler

    @property
    def validator_api_spec(self) -> str:
        return pkgutil.get_data(
            "simple_oauth_server", "validate_api_spec.yaml"
        ).decode("utf-8")

    @property
    def authorizer_api_spec(self) -> str:
        return pkgutil.get_data(
            "simple_oauth_server", "authorize_api_spec.yaml"
        ).decode("utf-8")

    @property
    def jwks_api_spec(self) -> str:
        return pkgutil.get_data(
            "simple_oauth_server", "jwks_api_spec.yaml"
        ).decode("utf-8")

    @property
    def domain(self) -> str:
        return self.server.domain

    @property
    def server(self) -> RestAPI:
        if not hasattr(self, "_server"):
            self._server = rest_api(
                f"{self.name}-rest-api",
                path_prefix=self.path_prefix,
                specification=[
                    self.validator_api_spec,
                    self.authorizer_api_spec,
                    self.jwks_api_spec
                ],
                integrations=[
                    {
                        "path": "/token",
                        "method": "post",
                        "function": self.authorizer()
                    },
                    {
                        "path": "/token/validate",
                        "method": "post",
                        "function": self.validator(),
                    },
                    {
                        "path": "/.well-known/jwks.json",
                        "method": "get",
                        "function": self.jwks_handler(),
                    },
                ],
            )
        return self._server


def start(
    name: str,
    config: str,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
):
    issuer = issuer or os.environ.get("ISSUER", "https://oauth.local/")
    audience = audience or os.environ.get("AUDIENCE")
    # Trigger construction of the API by accessing the property
    _ = SimpleOAuth(name, config, issuer, audience).server
