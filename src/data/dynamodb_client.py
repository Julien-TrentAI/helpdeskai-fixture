"""DynamoDB client for HelpDeskAI conversations, tickets, and tenant config.

Table layout:
  helpdeskAI-tickets
    PK: tenant_id (S)  — partition key, scopes data to a single tenant
    SK: ticket_id  (S) — sort key, unique per ticket within a tenant

Multi-tenant isolation requires that ALL reads and writes include the tenant_id
in the KeyConditionExpression (for Query) or as the PK in PutItem / GetItem.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)

_DEFAULT_TABLE = "helpdeskAI-tickets"
_TENANT_CONFIG_TABLE = "helpdeskAI-tenant-config"


class DynamoDBClient:
    """Thin wrapper around a single DynamoDB table with helper methods."""

    def __init__(
        self,
        table_name: str = _DEFAULT_TABLE,
        region: str = "us-east-1",
    ) -> None:
        self._dynamodb = boto3.resource("dynamodb", region_name=region)
        self._table = self._dynamodb.Table(table_name)
        self._config_table = self._dynamodb.Table(_TENANT_CONFIG_TABLE)

    # ── Positive control: tenant-scoped write ─────────────────────────────────

    def create_ticket(
        self,
        tenant_id: str,
        subject: str,
        body: str,
        customer_email: str,
    ) -> dict[str, Any]:
        """Create a support ticket scoped to the tenant's partition.

        # SECURITY FIXTURE: CTRL-DATA-001 — create_ticket CORRECTLY uses the
        # tenant_id (sourced from the verified JWT) as the DynamoDB partition key.
        # This ensures the ticket is written to and readable only within the
        # tenant's own slice of the table.
        # Ticket reads must use get_tickets_for_tenant (Query), never Scan.
        """
        ticket_id = str(uuid.uuid4())
        item = {
            "tenant_id": tenant_id,   # PK — enforces partition isolation
            "ticket_id": ticket_id,   # SK
            "subject": subject,
            "body": body,
            "customer_email": customer_email,
            "status": "open",
        }
        self._table.put_item(Item=item)
        logger.info(
            "Ticket created",
            extra={"tenant_id": tenant_id, "ticket_id": ticket_id},
        )
        return item

    # ── Correct: tenant-scoped Query ──────────────────────────────────────────

    def get_tickets_for_tenant(
        self,
        tenant_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return tickets for a tenant using a properly scoped Query.

        Uses KeyConditionExpression so DynamoDB constrains the scan to the
        tenant's partition at the storage layer — no cross-tenant reads.
        """
        response = self._table.query(
            KeyConditionExpression=Key("tenant_id").eq(tenant_id),
            Limit=limit,
            ScanIndexForward=False,
        )
        return response.get("Items", [])

    def get_ticket(self, tenant_id: str, ticket_id: str) -> dict[str, Any] | None:
        """Fetch a single ticket by composite key (tenant_id + ticket_id)."""
        response = self._table.get_item(
            Key={"tenant_id": tenant_id, "ticket_id": ticket_id}
        )
        return response.get("Item")

    def get_tenant_config(self, tenant_id: str) -> dict[str, Any] | None:
        """Load tenant configuration (plan, feature flags, branding).

        Uses GetItem by primary key — correctly scoped to the single tenant.
        """
        response = self._config_table.get_item(
            Key={"tenant_id": tenant_id}
        )
        return response.get("Item")
