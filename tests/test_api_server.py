"""Deploy OAuth server to LocalStack and test issuing a token."""
from typing import Dict, Generator
import os
import requests

import pytest  # type: ignore

import pulumi
import simple_oauth_server

from fixture_foundry import deploy, to_localstack_url, localstack, container_network

os.environ["PULUMI_BACKEND_URL"] = "file://."


def pytest_addoption(parser: pytest.Parser) -> None:
	group = parser.getgroup("localstack")
	group.addoption(
		"--localstack-services",
		action="store",
		default="logs,iam,lambda,secretsmanager,apigateway,cloudwatch",
		help="Comma-separated list of LocalStack services to start",
	)


def pulumi_program(config_yaml: str):
    def program():
        oauth = simple_oauth_server.SimpleOAuth(
            "oauth", config=config_yaml, audience="test-api"
        )
        # Export identifiers needed to construct the LocalStack URL
        pulumi.export("endpoint", oauth.server.domain)  # type: ignore

    return program


def _test_users_yaml() -> str:
    # Minimal config for one client
    return (
        "clients:\n"
        "  client1:\n"
        "    client_secret: \"client1-secret\"\n"
        "    audience: \"test-api\"\n"
        "    sub: \"client1-subject\"\n"
        "    scope: \"read:data\"\n"
        "    permissions:\n"
        "      - \"read:data\"\n"
    )


@pytest.fixture(scope="session")
def simple_oauth(localstack: Dict[str, str]) -> Generator[str, None, None]:  # noqa: F811
    config_yaml = _test_users_yaml()

    with deploy(
        project_name="simple-oauth",
        stack_name="test",
        pulumi_program=pulumi_program(config_yaml),
        localstack=localstack,
        teardown=True,
    ) as outputs:
        yield to_localstack_url(outputs["endpoint"], int(localstack["port"]))

def test_simple_oauth_server_issues_token(simple_oauth: str):  # noqa: F811
        url = f"{simple_oauth}/token"
        payload = {
            "client_id": "client1",
            "client_secret": "client1-secret",
            "audience": "test-api",
            "grant_type": "client_credentials",
        }

        resp = requests.post(url, json=payload, timeout=10)
        assert resp.status_code == 200, resp.text

        data = resp.json()
        assert data.get("token_type") == "Bearer"
        token = data.get("token")
        assert isinstance(token, str) and token.count(".") == 2
