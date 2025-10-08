import pulumi
import pkgutil
import os
import logging
import cloud_foundry
from cloud_foundry import python_function, Function, RestAPI
from simple_oauth_server.asymmetric_key_pair import AsymmetricKeyPair

log = logging.Logger(__name__, os.environ.get("LOGGING_LEVEL", logging.DEBUG))


class SimpleOAuth:
    _validator: Function
    _autorizer: Function
    _server: RestAPI

    def __init__(self, name: str, config: str):
        self.name = name
        self.config = config
        self.asymmetic_key_pair = AsymmetricKeyPair()

    def validator(self) -> Function:
        if not hasattr(self, "_validator"):
            self._validator = python_function(
                f"{self.name}-validator",
                timeout=12,
                memory_size=128,
                sources={
                    "app.py": pkgutil.get_data("simple_oauth_server", "token_validator.py").decode("utf-8"),  # type: ignore
                    "public_key.pem": self.asymmetic_key_pair.public_key_pem,
                },
                requirements=["requests==2.27.1", "PyJWT", "cryptography"],
            )
        return self._validator

    def authorizer(self) -> Function:
        if not hasattr(self, "_authorizer"):
            self._authorizer = cloud_foundry.python_function(
                f"{self.name}-authorizer",
                timeout=12,
                sources={
                    "app.py": pkgutil.get_data(
                        "simple_oauth_server", "token_authorizer.py"
                    ).decode("utf-8"),
                    "config.yaml": self.config,
                    "private_key.pem": self.asymmetic_key_pair.private_key_pem,
                },
                requirements=["PyJWT", "requests==2.27.1", "PyYAML", "cryptography"],
            )
        return self._authorizer

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

    def server(self) -> RestAPI:
        if not hasattr(self, "_server"):
            self._server = cloud_foundry.rest_api(
                f"{self.name}-rest-api",
                specification=[self.validator_api_spec, self.authorizer_api_spec],
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
                ],
            )
        return self._server


def start(name: str, config: str):
    SimpleOAuth(name, config).server()
