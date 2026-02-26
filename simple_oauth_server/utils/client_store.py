import json
import logging
import os
from typing import Any, Dict, Optional

def _get_conn():
    """Connect to Postgres using environment variables.
    Tries psycopg (v3) then psycopg2.
    """
    try:
        import psycopg  # type: ignore

        return psycopg.connect(
            host=os.getenv("PGHOST"),
            port=os.getenv("PGPORT"),
            dbname=os.getenv("PGDATABASE"),
            user=os.getenv("PGUSER"),
            password=os.getenv("PGPASSWORD"),
            sslmode=os.getenv("PGSSLMODE"),
            connect_timeout=int(os.getenv("PGCONNECT_TIMEOUT", "5")),
        )
    except ImportError:
        import psycopg2  # type: ignore

        return psycopg2.connect(
            host=os.getenv("PGHOST"),
            port=os.getenv("PGPORT"),
            dbname=os.getenv("PGDATABASE"),
            user=os.getenv("PGUSER"),
            password=os.getenv("PGPASSWORD"),
            sslmode=os.getenv("PGSSLMODE"),
            connect_timeout=int(os.getenv("PGCONNECT_TIMEOUT", "5")),
        )
        

log = logging.getLogger(__name__)


def _truthy(val: Optional[str]) -> bool:
    if val is None:
        return False
    return val.strip().lower() in ("1", "true", "yes", "on")


def db_clients_enabled() -> bool:
    # Reuse AUTHZ_DB_ENABLED unless explicitly overridden
    flag = os.getenv("OAUTH_CLIENTS_DB_ENABLED") or os.getenv(
        "AUTHZ_DB_ENABLED"
    )
    return _truthy(flag)


def get_client_from_db(client_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch client configuration from farm_market.oauth_clients by id.
        Expected columns:
            id (uuid), client_secret (text, optional),
            secret_hash (text, optional), audience (jsonb or text),
            scope (text), permissions (jsonb), roles (jsonb),
            groups (jsonb), sub (uuid or text), tier (text), status (text)
    Returns a dict compatible with the authorizer's client config schema.
    """
    sql = (
        "SELECT id::text, client_secret, secret_hash, audience::text, scope, "
        "permissions::text, roles::text, groups::text, "
        "COALESCE(sub::text, '') AS sub, tier, status "
        "FROM farm_market.oauth_clients "
        "WHERE id::text = %s AND status = 'active'"
    )
    conn = _get_conn()
    with conn:
        with conn.cursor() as cur:
            cur.execute(sql, (client_id,))
            row = cur.fetchone()
            if not row:
                return None
            (
                _id,
                client_secret,
                secret_hash,
                audience_text,
                scope_text,
                perms_text,
                roles_text,
                groups_text,
                sub_text,
                tier,
                status,
            ) = row

            def _parse_json(txt: Optional[str]) -> Optional[Any]:
                if not txt:
                    return None
                try:
                    return json.loads(txt)
                except json.JSONDecodeError:
                    return None

            audience = _parse_json(audience_text) or audience_text
            permissions = _parse_json(perms_text) or []
            roles = _parse_json(roles_text) or []
            groups = _parse_json(groups_text) or []

            client: Dict[str, Any] = {
                "client_secret": client_secret,
                "secret_hash": secret_hash,
                "audience": audience,
                "scope": scope_text or "",
                "permissions": permissions,
                "roles": roles,
                "groups": groups,
                "sub": sub_text or client_id,
                "tier": tier,
                "status": status,
            }
            return client
