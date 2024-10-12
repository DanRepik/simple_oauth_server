
from simple_oauth_server.token_authorizer import handler
import simple_oauth_server.token_authorizer

def test_handler():
  resutl = handler({}, {})
  assert False