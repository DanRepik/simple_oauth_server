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
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
    ):
        self.name = name
        self.config = config
        self._issuer = issuer or "https://oauth.local/"
        self._audience = audience
        self.asymmetic_key_pair = AsymmetricKeyPair()
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
            self._validator = python_function(
                f"{self.name}-validator",
                timeout=12,
                memory_size=128,
                sources={
                    "app.py": "pkg://simple_oauth_server/token_validator.py",
                    "public_key.pem": self.asymmetic_key_pair.public_key_pem,
                },
                requirements=["requests==2.27.1", "PyJWT", "cryptography"],
                environment=self.environment,
            )
        return self._validator

    def authorizer(self) -> Function:
        if not hasattr(self, "_authorizer"):
            self._authorizer = python_function(
                f"{self.name}-authorizer",
                timeout=12,
                sources={
                    "app.py": "pkg://simple_oauth_server/token_authorizer.py",
                    "config.yaml": self.config,
                    "private_key.pem": self.asymmetic_key_pair.private_key_pem,
                },
                requirements=["PyJWT", "requests==2.27.1", "PyYAML", "cryptography"],
            )
        return self._authorizer

    def jwks_handler(self) -> Function:
        if not hasattr(self, "_jwks_handler"):
            self._jwks_handler = python_function(
                f"{self.name}-jwks",
                timeout=12,
                memory_size=128,
                sources={
                    "app.py": "pkg://simple_oauth_server/jwks_handler.py",
                    "public_key.pem": self.asymmetic_key_pair.public_key_pem,
                },
                requirements=["cryptography"],
                environment=self.environment,
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
        return self.server().domain

    @property
    def server(self) -> RestAPI:
        if not hasattr(self, "_server"):
            self._server = rest_api(
                f"{self.name}-rest-api",
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
    SimpleOAuth(name, config, issuer, audience).server()
