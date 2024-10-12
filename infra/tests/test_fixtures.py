import pytest
import logging

log = logging.Logger(__name__)

api_id: str = None
@pytest.fixture
def gateway_endpoint():
    global api_id
    if not api_id:
        from pulumi import automation as auto

        stack = auto.select_stack(
            stack_name="local",
            work_dir=".",
        )

        stack.refresh(on_output=print)
        outputs = stack.outputs()
        log.info(f"outputs: {outputs}")

        api_id = outputs["rest-api-id"].value if "rest-api-id" in outputs else None
    return (
        f"http://{api_id}.execute-api.localhost.localstack.cloud:4566/rest-api"

    )