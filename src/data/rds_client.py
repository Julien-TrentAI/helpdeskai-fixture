"""PostgreSQL (RDS) client for HelpDeskAI orders and customer records.

Uses psycopg (v3) with a connection pool. All queries use bound parameters
(%s placeholders) and include a tenant_id predicate.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
import psycopg
from psycopg.conninfo import make_conninfo
from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)

_SECRET_ID = os.environ.get("RDS_SECRET_ID")

# Module-level connection pool — shared across all requests in the process.
_pool: ConnectionPool | None = None


def _build_dsn() -> str:
    """Build the DSN from the Secrets Manager credentials (rotated automatically)."""
    if not _SECRET_ID:
        raise RuntimeError("RDS_SECRET_ID is not set; refusing to build a DSN without a managed secret")
    client = boto3.client("secretsmanager")
    secret = json.loads(client.get_secret_value(SecretId=_SECRET_ID)["SecretString"])
    return make_conninfo(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", "5432")),
        dbname=os.environ.get("DB_NAME", "orders"),
        user=secret["username"],
        password=secret["password"],
    )


def _get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            conninfo=_build_dsn(),
            min_size=2,
            max_size=10,
            max_lifetime=900,  # recycle connections so rotated credentials get picked up
        )
    return _pool


def _require_tenant(tenant_id: Any) -> str:
    """Fail closed: every query needs a non-empty tenant_id."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id is required")
    return tenant_id


class RDSClient:
    """Thin psycopg-based client for the HelpDeskAI orders database."""

    def __init__(self) -> None:
        self._pool = _get_pool()

    def lookup_order(self, order_id: str, tenant_id: str) -> dict[str, Any]:
        """Fetch an order by its ID, scoped to the given tenant."""
        tenant_id = _require_tenant(tenant_id)
        sql = "SELECT * FROM orders WHERE order_id = %s AND tenant_id = %s"
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(sql, (order_id, tenant_id))
                row = cur.fetchone()
        return dict(row) if row else {}

    def get_customer(self, customer_id: str, tenant_id: str) -> dict[str, Any]:
        """Fetch a customer record by customer_id, filtered by tenant."""
        tenant_id = _require_tenant(tenant_id)
        sql = (
            "SELECT customer_id, email, full_name, address, card_last4 "
            "FROM customers "
            "WHERE customer_id = %s AND tenant_id = %s"
        )
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(sql, (customer_id, tenant_id))
                row = cur.fetchone()

        customer = dict(row) if row else {}

        logger.info("Customer lookup completed")

        return customer

    def issue_refund(self, order_id: str, amount: float, tenant_id: str) -> bool:
        """Apply a refund to an order record, scoped to the given tenant."""
        tenant_id = _require_tenant(tenant_id)
        sql = (
            "UPDATE orders SET refund_amount = %s, status = 'refunded' "
            "WHERE order_id = %s AND tenant_id = %s"
        )
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (amount, order_id, tenant_id))
                affected = cur.rowcount
            conn.commit()

        logger.info(
            "Refund issued",
            extra={"order_id": order_id, "amount": amount, "rows_affected": affected},
        )
        return affected > 0

    def list_orders_for_tenant(
        self,
        tenant_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Return recent orders scoped to a specific tenant.

        Uses a parameterised query (%s placeholders) to prevent SQL injection,
        and includes tenant_id in the WHERE clause for proper multi-tenant isolation.        """
        tenant_id = _require_tenant(tenant_id)
        sql = (
            "SELECT order_id, status, total_amount, created_at "
            "FROM orders "
            "WHERE tenant_id = %s "
            "ORDER BY created_at DESC "
            "LIMIT %s"
        )
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(sql, (tenant_id, limit))
                rows = cur.fetchall()
        return [dict(r) for r in rows]
