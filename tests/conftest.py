import os
import pytest

os.environ["PULUMI_BACKEND_URL"] = "file://~"


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("localstack")
    group.addoption(
        "--localstack-services",
        action="store",
        default="logs,iam,lambda,secretsmanager,apigateway,cloudwatch",
        help="Comma-separated list of LocalStack services to start",
    )
