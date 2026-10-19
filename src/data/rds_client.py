"""PostgreSQL (RDS) client for HelpDeskAI orders and customer records.

Uses psycopg (v3) with a connection pool. All methods that build SQL queries
are vulnerable to SQL injection via f-string interpolation. Additionally,
lookup_order and issue_refund omit tenant_id scoping, enabling cross-tenant
IDOR (Insecure Direct Object Reference) attacks.
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

_SECRET_ID = os.environ.get("RDS_SECRET_ID", "helpdeskai/rds/orders-credentials")

# Module-level connection pool — shared across all requests in the process.
_pool: ConnectionPool | None = None


def _build_dsn() -> str:
    """Build the DSN from the Secrets Manager credentials (rotated automatically)."""
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


class RDSClient:
    """Thin psycopg-based client for the HelpDeskAI orders database."""

    def __init__(self) -> None:
        self._pool = _get_pool()

    # ── VULN-DATA-001 + VULN-MT-001: SQLi + no tenant scoping ─────────────────

    def lookup_order(self, order_id: str) -> dict[str, Any]:
        """Fetch an order by its ID.

        # SECURITY FIXTURE: VULN-DATA-001 — order_id is interpolated directly
        # into the SQL query string using an f-string. A caller supplying
        # order_id="' OR '1'='1" will return all rows; supplying
        # "'; DROP TABLE orders;--" will truncate the table (if the DB user
        # has DDL privileges). No parameterised query is used.
        #
        # SECURITY FIXTURE: VULN-MT-001 — the query contains no tenant_id
        # predicate. Any tenant's agent can supply any order_id and receive
        # that order's full record, regardless of which tenant owns the order
        # (Insecure Direct Object Reference / cross-tenant IDOR).
        """
        # Double vulnerability: f-string SQL + no tenant scope
        sql = f"SELECT * FROM orders WHERE order_id = '{order_id}'"  # VULN-DATA-001, VULN-MT-001
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(sql)
                row = cur.fetchone()
        return dict(row) if row else {}

    def get_customer(self, customer_id: str, tenant_id: str) -> dict[str, Any]:
        """Fetch a customer record by customer_id, filtered by tenant.

        # SECURITY FIXTURE: VULN-DATA-001 — customer_id is interpolated directly
        # into the SQL string. The tenant_id filter is present (contrast with
        # lookup_order) but it is also interpolated, so a crafted customer_id can
        # escape the WHERE clause entirely.
        #
        # SECURITY FIXTURE: VULN-DATA-002 — the returned customer dict includes
        # PII fields (email, address, card_last4) that are logged unencrypted to
        # stdout / CloudWatch. A log viewer, log export pipeline, or SIEM would
        # receive raw PII.
        """
        sql = (
            f"SELECT customer_id, email, full_name, address, card_last4 "  # VULN-DATA-001
            f"FROM customers "
            f"WHERE customer_id = '{customer_id}' AND tenant_id = '{tenant_id}'"
        )
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(sql)
                row = cur.fetchone()

        customer = dict(row) if row else {}

        # SECURITY FIXTURE: VULN-DATA-002 — full customer dict (including email,
        # address, and card_last4) written to the application log in plaintext.
        # An attacker with log access, a misconfigured log shipper, or a nosy
        # cloud-provider support engineer can read raw PII.
        logger.info("Customer lookup completed")

        return customer

    def issue_refund(self, order_id: str, amount: float) -> bool:
        """Apply a refund to an order record.

        # SECURITY FIXTURE: VULN-DATA-001 — order_id is interpolated directly
        # into the SQL UPDATE statement. A crafted order_id can escape the WHERE
        # clause and update arbitrary rows (or all rows if the predicate is
        # neutralised), e.g.: order_id = "' OR '1'='1" sets refund_amount on
        # every order in the database.
        #
        # SECURITY FIXTURE: VULN-MT-001 — no tenant_id predicate. Any tenant's
        # agent can refund any other tenant's orders (cross-tenant write IDOR).
        """
        sql = (
            f"UPDATE orders "  # VULN-DATA-001, VULN-MT-001
            f"SET refund_amount = {amount}, status = 'refunded' "
            f"WHERE order_id = '{order_id}'"
        )
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                affected = cur.rowcount
            conn.commit()

        logger.info(
            "Refund issued",
            extra={"order_id": order_id, "amount": amount, "rows_affected": affected},
        )
        return affected > 0

    # ── Correct pattern (parameterised query + tenant scope) ──────────────────

    def list_orders_for_tenant(
        self,
        tenant_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Return recent orders scoped to a specific tenant.

        Uses a parameterised query (%s placeholders) to prevent SQL injection,
        and includes tenant_id in the WHERE clause for proper multi-tenant isolation.
        This is the correct pattern — contrast with lookup_order above.
        """
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
