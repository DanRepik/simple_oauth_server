import pkgutil
import cloud_foundry
from openapi_editor import OpenAPISpecParser


def run(auth0_domain: str = "auth0_domain", auth0_audience: str = "auth0_audience"):

    validator = cloud_foundry.python_function(
        "validator",
        timeout=12,
        memory_size=128,
        environment={
            "AUTH0_DOMAIN": auth0_domain,
            "AUDIENCE": auth0_audience,
            "LOGGING_LEVEL": "DEBUG",
        },
        sources={
            "app.py": pkgutil.get_data("simple_oath_server", "token_validator.py").decode("utf-8"),  # type: ignore
        },
        requirements=[
            "jsonschema==4.4.0",
            "moto==3.1.6",
            "pytest==7.1.1",
            "requests==2.27.1",
        ],
    )

    authorizer = cloud_foundry.python_function(
        "authorizer",
        timeout=12,
        sources={
            "app.py": pkgutil.get_data("simple_oath_server", "token_authorizer.py").decode("utf-8"),  # type: ignore
        },
        requirements=[
            "jwt",
            "requests==2.27.1",
        ],
    )

    cloud_foundry.rest_api(
        "rest-api",
        body=OpenAPISpecParser(
            pkgutil.get_data("simple_oath_server", "api_spec.yaml").decode("utf-8")
        )
        .add_operation_attribute(
            path="/token",
            method="post",
            attibute="x-function-name",
            value=authorizer.name,
        )
        .add_operation_attribute(
            path="/token",
            method="post",
            attribute="x-amazon-apigateway-integration",
            value={
                "type": "aws_proxy",
                "uri": authorizer.invoke_arn,
                "httpMethod": "POST",
            },
        )
        .add_operation_attribute(
            path="/token/validate",
            method="post",
            attibute="x-function-name",
            value=validator.function_name,
        )
        .add_operation_attribute(
            path="/token/validate",
            method="post",
            attribute="x-amazon-apigateway-integration",
            value={
                "type": "aws_proxy",
                "uri": validator.invoke_arn,
                "httpMethod": "POST",
            },
        )
        .to_yaml(),
    )
