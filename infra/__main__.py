# __main.py__

import simple_oauth_server

test_users = """
clients:
  client1:
    client_secret: "client1-secret"
    audience: "test-api"
    sub: "client1-subject"
    scope: "read:data"
    permissions:
      - "read:data"
  
  client2:
    client_secret: "client2-secret"
    audience: "test-api"
    sub: "client2-subject"
    scope: "write:data"
    permissions:
      - "write:data"
  
  client3:
    client_secret: "client3-secret"
    audience: "test-api"
    sub: "client3-subject"
    scope: "read:data write:data"
    permissions:
      - "read:data"
      - "write:data"

  client4:
    client_secret: "client4-secret"
    audience: "test-api"
    sub: "client4-subject"
    scope: "admin"
    permissions:
      - "read:data"
      - "write:data"
      - "delete:data"
"""

oauth_server = simple_oauth_server.start("oauth", config=test_users)


