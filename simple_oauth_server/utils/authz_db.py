import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _truthy(val: Optional[str]) -> bool:
    if val is None:
        return False
    return val.strip().lower() in ("1", "true", "yes", "on")


def is_enabled() -> bool:
    return _truthy(os.getenv("AUTHZ_DB_ENABLED"))


def _fail_mode() -> str:
    mode = (os.getenv("AUTHZ_FAIL_MODE") or "fail_closed").strip().lower()
    return "fail_open" if mode == "fail_open" else "fail_closed"


def _cache_ttl() -> int:
    try:
        return int(os.getenv("AUTHZ_CACHE_TTL_SECONDS", "300"))
    except (TypeError, ValueError):
        return 300


def _cache_key(sub: str, tenant: Optional[str]) -> str:
    return f"sub:{sub}|tenant:{tenant or ''}"


def _get_conn():
    try:
        # Prefer psycopg (v3), fallback to psycopg2
        import psycopg  # type: ignore

        conn = psycopg.connect(
            host=os.getenv("PGHOST"),
            port=os.getenv("PGPORT"),
            dbname=os.getenv("PGDATABASE"),
            user=os.getenv("PGUSER"),
            password=os.getenv("PGPASSWORD"),
            sslmode=os.getenv("PGSSLMODE"),
            connect_timeout=int(os.getenv("PGCONNECT_TIMEOUT", "5")),
        )
        return conn
    except Exception as e1:  # noqa: BLE001
        log.debug("psycopg unavailable or connect failed: %s", e1)
        try:
            import psycopg2  # type: ignore

            conn = psycopg2.connect(
                host=os.getenv("PGHOST"),
                port=os.getenv("PGPORT"),
                dbname=os.getenv("PGDATABASE"),
                user=os.getenv("PGUSER"),
                password=os.getenv("PGPASSWORD"),
                sslmode=os.getenv("PGSSLMODE"),
                connect_timeout=int(os.getenv("PGCONNECT_TIMEOUT", "5")),
            )
            return conn
        except Exception as e2:  # noqa: BLE001
            log.debug("psycopg2 unavailable or connect failed: %s", e2)
            raise RuntimeError(
                "No PostgreSQL client available or connection failed"
            ) from e2


def _prepare_sql(
    sql: str, sub: str, tenant: Optional[str]
) -> Tuple[str, Tuple[Any, ...]]:
    """
    Support a simple named parameter style with :sub and :tenant and
    convert to %s placeholders.
    If a name is absent, it is not included in the param tuple.
    """
    if sql is None:
        return "", tuple()
    params: List[Any] = []
    ordered: List[str] = []
    # Determine order by appearance
    idx_sub = sql.find(":sub")
    idx_tenant = sql.find(":tenant")
    for name, idx in sorted(
        [(":sub", idx_sub), (":tenant", idx_tenant)],
        key=lambda x: (x[1] if x[1] >= 0 else 10**9),
    ):
        if idx >= 0:
            ordered.append(name)
    for name in ordered:
        if name == ":sub":
            params.append(sub)
        elif name == ":tenant":
            params.append(tenant)
    sql_prepared = sql.replace(":sub", "%s").replace(":tenant", "%s")
    return sql_prepared, tuple(params)


def _fetch_single_column(cur, sql: str, params: Tuple[Any, ...]) -> List[str]:
    cur.execute(sql, params)
    rows = cur.fetchall() or []
    results: List[str] = []
    for r in rows:
        if isinstance(r, (list, tuple)) and r:
            if r[0] is None:
                continue
            results.append(str(r[0]))
        else:
            results.append(str(r))
    # Normalize: unique + sorted for determinism
    return sorted(list({x.strip() for x in results if str(x).strip()}))


def _validate(cur, sql: str, params: Tuple[Any, ...]) -> bool:
    if not sql:
        return True
    cur.execute(sql, params)
    return cur.fetchone() is not None


def enrich_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run configured SQL against Postgres to validate/enrich claims.
    Environment:
      - AUTHZ_DB_ENABLED=true|false
      - AUTHZ_FAIL_MODE=fail_closed|fail_open
      - AUTHZ_CACHE_TTL_SECONDS=300
            - AUTHZ_SQL_VALIDATE_SUB, AUTHZ_SQL_ROLES,
                AUTHZ_SQL_PERMISSIONS, AUTHZ_SQL_GROUPS
    Params supported in SQL: :sub, :tenant
    """
    if not is_enabled():
        return claims

    sub = str(claims.get("sub")) if claims.get("sub") is not None else None
    tenant = claims.get("tenant") or claims.get("tenant_id")
    if not sub:
        log.warning(
            "DB auth enabled but no 'sub' in claims; skipping enrichment"
        )
        return claims

    key = _cache_key(sub, tenant)
    ttl = _cache_ttl()
    now = time.time()
    cached = _CACHE.get(key)
    if cached and (now - cached[0]) < ttl:
        log.debug("Using cached DB auth enrichment for %s", key)
        merged = dict(claims)
        merged.update(cached[1])
        return merged

    validate_sql = os.getenv("AUTHZ_SQL_VALIDATE_SUB", "").strip()
    roles_sql = os.getenv("AUTHZ_SQL_ROLES", "").strip()
    perms_sql = os.getenv("AUTHZ_SQL_PERMISSIONS", "").strip()
    groups_sql = os.getenv("AUTHZ_SQL_GROUPS", "").strip()

    try:
        conn = _get_conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    v_sql, v_params = _prepare_sql(validate_sql, sub, tenant)
                    if v_sql:
                        ok = _validate(cur, v_sql, v_params)
                        if not ok:
                            if _fail_mode() == "fail_closed":
                                raise PermissionError(
                                    "DB auth validation failed"
                                )
                            log.warning(
                                "DB auth validation failed (fail_open)"
                            )

                    roles: List[str] = []
                    perms: List[str] = []
                    groups: List[str] = []

                    if roles_sql:
                        r_sql, r_params = _prepare_sql(roles_sql, sub, tenant)
                        roles = _fetch_single_column(cur, r_sql, r_params)
                    if perms_sql:
                        p_sql, p_params = _prepare_sql(perms_sql, sub, tenant)
                        perms = _fetch_single_column(cur, p_sql, p_params)
                    if groups_sql:
                        g_sql, g_params = _prepare_sql(groups_sql, sub, tenant)
                        groups = _fetch_single_column(cur, g_sql, g_params)

                    enrichment: Dict[str, Any] = {}
                    if roles:
                        enrichment["roles"] = roles
                    if perms:
                        enrichment["permissions"] = perms
                    if groups:
                        enrichment["groups"] = groups

                    merged = dict(claims)
                    merged.update(enrichment)

                    _CACHE[key] = (now, enrichment)
                    return merged
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except PermissionError:
        raise
    except Exception as e:  # noqa: BLE001
        if _fail_mode() == "fail_closed":
            raise PermissionError(f"DB auth error: {e}") from e
        log.warning("DB auth error (fail_open): %s", e)
        return claims


def enrich_authorizer_if_enabled(authorizer: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return enrich_claims(authorizer)
    except PermissionError:
        # Propagate as a generic 403/401 trigger for callers
        raise
    except Exception as e:  # noqa: BLE001
        # Defensive: do not break caller on unexpected errors
        log.debug("Unexpected error enriching authorizer: %s", e)
        return authorizer
