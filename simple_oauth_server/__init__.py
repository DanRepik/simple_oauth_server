import pulumi
import pkgutil
import os
import logging
import cloud_foundry
from cloud_foundry import python_function, Function
from simple_oauth_server.openapi_editor import OpenAPISpecEditor

log = logging.Logger(__name__, os.environ.get("LOGGING_LEVEL", logging.DEBUG))
        
def validator() -> Function:
    return python_function(
        "validator",
        timeout=12,
        memory_size=128,
        environment={
            "AUTH0_DOMAIN": "auth0_domain",
            "AUDIENCE": "auth0_audience",
            "LOGGING_LEVEL": "DEBUG",
        },
        sources={
            "app.py": pkgutil.get_data("simple_oauth_server", "token_validator.py").decode("utf-8"),  # type: ignore
        },
        requirements=[
            "requests==2.27.1",
            "PyJWT",
        ],
    )

def authorizer(config_loc: str) -> Function:
    return cloud_foundry.python_function(
        "authorizer",
        timeout=12,
        sources={
            "app.py": pkgutil.get_data("simple_oauth_server", "token_authorizer.py").decode("utf-8"),
            "config.yaml": config_loc
        },
        requirements=[
            "PyJWT",
            "requests==2.27.1",
            "PyYAML"
        ],
    )


def run(config_loc: str):

    log.info(f"config_loc: {config_loc}")
                        
    cloud_foundry.rest_api(
        "rest-api",
        body=[
            pkgutil.get_data("simple_oauth_server", "authorize_api_spec.yaml").decode("utf-8"),
            pkgutil.get_data("simple_oauth_server", "validate_api_spec.yaml").decode("utf-8"),
        ],
        integrations=[
            { "path":"/token", "method":"post", "function":authorizer(config_loc)},
            { "path":"/token/validate", "method":"post", "function":validator()}
        ],
    )

    
    
