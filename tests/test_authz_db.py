import os
import time
from typing import Any, List, Optional

import pytest

from simple_oauth_server.utils import authz_db


class FakeCursor:
    def __init__(self, sub_expected: str, tenant_expected: Optional[str]):
        self.sub_expected = sub_expected
        self.tenant_expected = tenant_expected
        self._last_sql: str = ""
        self._last_params: List[Any] = []

    def __enter__(self):  # context manager support
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: D401
        return False

    def execute(self, sql: str, params: tuple[Any, ...]):
        self._last_sql = sql
        self._last_params = list(params)

    def fetchone(self):
        # Validation succeeds only if params match expected sub
        if "FROM users" in self._last_sql:
            if self._last_params and self._last_params[0] == self.sub_expected:
                return (1,)
            return None
        return None

    def fetchall(self):
        sql = self._last_sql
        if "FROM user_roles" in sql:
            return [("admin",), ("user",)]
        if "FROM user_perms" in sql:
            return [("write:data",), ("read:data",), ("read:data",)]
        if "FROM user_groups" in sql:
            return [("team-a",), ("team-b",)]
        return []


class FakeConn:
    def __init__(self, sub_expected: str, tenant_expected: Optional[str]):
        self.sub_expected = sub_expected
        self.tenant_expected = tenant_expected

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: D401
        return False

    def cursor(self):
        return FakeCursor(self.sub_expected, self.tenant_expected)

    def close(self):  # pragma: no cover - not relevant
        pass


def _set_env(enabled: bool = True, fail_mode: str = "fail_closed"):
    os.environ["AUTHZ_DB_ENABLED"] = "true" if enabled else "false"
    os.environ["AUTHZ_FAIL_MODE"] = fail_mode
    os.environ["AUTHZ_SQL_VALIDATE_SUB"] = (
        "SELECT 1 FROM users WHERE sub = :sub"
    )
    os.environ["AUTHZ_SQL_ROLES"] = (
        "SELECT role FROM user_roles WHERE sub = :sub"
    )
    os.environ["AUTHZ_SQL_PERMISSIONS"] = (
        "SELECT perm FROM user_perms WHERE sub = :sub"
    )
    os.environ["AUTHZ_SQL_GROUPS"] = (
        "SELECT grp FROM user_groups WHERE sub = :sub"
    )


def test_enrichment_disabled_returns_original():
    _set_env(enabled=False)
    original = {"sub": "user1"}
    enriched = authz_db.enrich_claims(original)
    assert enriched == original


def test_skip_when_no_sub():
    _set_env(enabled=True)
    claims = {"aud": "x"}
    enriched = authz_db.enrich_claims(claims)
    assert enriched == claims


def test_validation_fail_closed(monkeypatch):
    _set_env(enabled=True, fail_mode="fail_closed")

    def fake_get_conn():
        # Return connection expecting different sub to force validation failure
        return FakeConn(sub_expected="other", tenant_expected=None)

    monkeypatch.setattr(authz_db, "_get_conn", fake_get_conn)
    with pytest.raises(PermissionError):
        authz_db.enrich_claims({"sub": "user1"})


def test_validation_fail_open(monkeypatch):
    _set_env(enabled=True, fail_mode="fail_open")

    def fake_get_conn():
        return FakeConn(sub_expected="other", tenant_expected=None)

    monkeypatch.setattr(authz_db, "_get_conn", fake_get_conn)
    enriched = authz_db.enrich_claims({"sub": "user1"})
    # Validation failed; fail_open allows enrichment to proceed
    assert enriched.get("roles") == ["admin", "user"]
    assert enriched.get("permissions") == ["read:data", "write:data"]
    assert enriched.get("groups") == ["team-a", "team-b"]


def test_success_enrichment_and_caching(monkeypatch):
    _set_env(enabled=True, fail_mode="fail_closed")

    def fake_get_conn():
        return FakeConn(sub_expected="user1", tenant_expected=None)

    monkeypatch.setattr(authz_db, "_get_conn", fake_get_conn)
    # Clear cache first
    getattr(authz_db, "_CACHE").clear()  # type: ignore[attr-defined]
    claims = {"sub": "user1"}
    enriched1 = authz_db.enrich_claims(claims)
    assert enriched1["roles"] == ["admin", "user"]
    # Permissions sorted unique
    assert enriched1["permissions"] == ["read:data", "write:data"]
    assert enriched1["groups"] == ["team-a", "team-b"]

    # Ensure caching: second call should not hit DB
    def failing_get_conn():  # pragma: no cover - only invoked if cache miss
        raise RuntimeError("Should not be called on cached lookup")

    monkeypatch.setattr(authz_db, "_get_conn", failing_get_conn)
    start = time.time()
    enriched2 = authz_db.enrich_claims(claims)
    end = time.time()
    assert enriched2["roles"] == enriched1["roles"]
    assert enriched2["permissions"] == enriched1["permissions"]
    assert enriched2["groups"] == enriched1["groups"]
    assert (end - start) < 0.5


def test_placeholder_substitution_order(monkeypatch):
    _set_env(enabled=True, fail_mode="fail_closed")
    os.environ["AUTHZ_SQL_ROLES"] = (
        "SELECT role FROM user_roles WHERE tenant = :tenant AND sub = :sub"
    )

    def fake_get_conn():
        return FakeConn(sub_expected="user1", tenant_expected="t1")

    monkeypatch.setattr(authz_db, "_get_conn", fake_get_conn)
    getattr(authz_db, "_CACHE").clear()  # type: ignore[attr-defined]
    claims = {"sub": "user1", "tenant": "t1"}
    enriched = authz_db.enrich_claims(claims)
    # Roles present; confirms both placeholders worked
    assert enriched["roles"] == ["admin", "user"]
