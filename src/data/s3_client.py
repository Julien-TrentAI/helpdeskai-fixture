"""S3 client for HelpDeskAI knowledge base documents and customer attachments.

Two logical buckets:
  helpdeskai-kb-docs         — shared KB documents under {tenant_id}/ (private, SSE-KMS)
  helpdeskAI-attachments     — shared attachments bucket (secure: SSE-KMS, no public access)

The KB bucket is managed by Terraform (see infra/main.tf); its name comes from the
KB_BUCKET setting, matching the Terraform `kb_bucket_name` variable.
The attachments bucket is the positive control (CTRL-CLOUD-001).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
_ATTACHMENTS_BUCKET = os.environ.get("ATTACHMENTS_BUCKET", "helpdeskAI-attachments")
_KB_BUCKET = os.environ.get("KB_BUCKET", "helpdeskai-kb-docs")
_PRESIGNED_URL_EXPIRY = 604800  # 7 days — VULN-DATA-004
_TENANT_SESSION_SECONDS = 900  # 15 minutes


class S3Client:
    """S3 client wrapper for KB documents and file attachments."""

    def __init__(self, region: str = _AWS_REGION) -> None:
        self._region = region
        self._s3 = boto3.client("s3", region_name=region)

    def _tenant_kb_client(self, tenant_id: str) -> Any:
        """Build an S3 client whose credentials can only reach the tenant's KB prefix.

        Assumes the application role with an inline session policy, so storage
        refuses out-of-tenant keys even if a path traversal reaches it.
        """
        if not tenant_id or "/" in tenant_id or "*" in tenant_id or "?" in tenant_id:
            raise PermissionError("Invalid tenant scope")
        role_arn = os.environ.get("APP_ROLE_ARN")
        if not role_arn:
            raise RuntimeError("APP_ROLE_ARN is not configured")

        bucket_arn = f"arn:aws:s3:::{_KB_BUCKET}"
        session_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": f"{bucket_arn}/{tenant_id}/*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": bucket_arn,
                    "Condition": {"StringLike": {"s3:prefix": f"{tenant_id}/*"}},
                },
            ],
        }
        sts = boto3.client("sts", region_name=self._region)
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"kb-{tenant_id}"[:64],
            DurationSeconds=_TENANT_SESSION_SECONDS,
            Policy=json.dumps(session_policy),
        )["Credentials"]
        return boto3.client(
            "s3",
            region_name=self._region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def search_kb(self, tenant_id: str, document_prefix: str) -> list[dict[str, Any]]:
        """List KB documents matching a prefix inside the caller's tenant folder.

        The listing prefix is always f"{tenant_id}/{document_prefix}", matching the
        key layout of upload_kb_document, and returned keys are re-checked against
        that tenant prefix.
        """
        if not tenant_id or "/" in tenant_id:
            raise PermissionError("Invalid tenant scope")
        if (
            not isinstance(document_prefix, str)
            or document_prefix.startswith("/")
            or "\\" in document_prefix
            or "\x00" in document_prefix
            or ".." in document_prefix.split("/")
        ):
            raise PermissionError("document_prefix is outside the authenticated tenant's scope")

        kb_bucket = _KB_BUCKET
        tenant_prefix = f"{tenant_id}/"
        scoped_prefix = f"{tenant_prefix}{document_prefix}"

        paginator = self._tenant_kb_client(tenant_id).get_paginator("list_objects_v2")
        results: list[dict[str, Any]] = []

        for page in paginator.paginate(Bucket=kb_bucket, Prefix=scoped_prefix):
            for obj in page.get("Contents", []):
                if not obj["Key"].startswith(tenant_prefix):
                    continue
                results.append(
                    {
                        "key": obj["Key"],
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                    }
                )

        return results

    def upload_kb_document(
        self,
        tenant_id: str,
        document_key: str,
        content: bytes,
    ) -> str:
        """Upload a document to the tenant's KB bucket with a namespaced key.

        The key is prefixed with tenant_id so documents are stored under the
        tenant's own path (correct pattern for write operations).
        """
        kb_bucket = _KB_BUCKET
        scoped_key = f"{tenant_id}/{document_key}"  # tenant-scoped prefix
        self._tenant_kb_client(tenant_id).put_object(Bucket=kb_bucket, Key=scoped_key, Body=content)
        logger.info(
            "KB document uploaded",
            extra={"tenant_id": tenant_id, "key": scoped_key},
        )
        return scoped_key

    # ── VULN-DATA-004: presigned URL with 7-day expiry and no tenant scoping ──

    def get_document_url(self, tenant_id: str, document_key: str) -> str:
        """Generate a presigned URL for a KB document.

        # SECURITY FIXTURE: VULN-DATA-004 — presigned URL is generated with a
        # 7-day (604800 second) expiry. A leaked or shared URL remains valid for a
        # week, giving an attacker ample time to exfiltrate the document. Industry
        # best practice for short-lived access is 15 minutes or less.
        #
        # Additionally, document_key is taken from the caller with no per-tenant
        # scoping check. Any caller who knows (or guesses) another tenant's document
        # key can obtain a valid presigned URL for it.
        """
        if not tenant_id or "/" in tenant_id:
            raise PermissionError("Invalid tenant scope")
        parts = document_key.split("/")
        if (
            parts[0] != tenant_id
            or len(parts) < 2
            or any(part in ("", ".", "..") for part in parts)
            or "\\" in document_key
            or "\x00" in document_key
        ):
            raise PermissionError("document_key is outside the authenticated tenant's scope")

        url = self._tenant_kb_client(tenant_id).generate_presigned_url(
            "get_object",
            Params={
                "Bucket": _KB_BUCKET,  # shared bucket; tenant isolation via key prefix
                "Key": document_key,             # VULN-DATA-004
            },
            ExpiresIn=_PRESIGNED_URL_EXPIRY,    # VULN-DATA-004: 7 days
        )
        return url

    # ── CTRL-CLOUD-001: attachments bucket enforces SSE-KMS ──────────────────

    def upload_attachment(
        self,
        tenant_id: str,
        filename: str,
        content: bytes,
    ) -> str:
        """Upload a customer attachment to the SSE-KMS-protected attachments bucket.

        # SECURITY FIXTURE: CTRL-CLOUD-001 — attachments bucket enforces SSE-KMS
        # at the bucket level (see infra/main.tf aws_s3_bucket_server_side_encryption_configuration).
        # This client also passes ServerSideEncryption='aws:kms' explicitly so uploads
        # fail if the bucket policy is ever relaxed. This is the correct pattern:
        # encrypt at rest with a customer-managed KMS key, store under a tenant-scoped
        # key prefix, and use the secure (non-public) attachments bucket.
        # The KB bucket is likewise private and SSE-KMS encrypted.
        """
        scoped_key = f"attachments/{tenant_id}/{filename}"

        self._s3.put_object(
            Bucket=_ATTACHMENTS_BUCKET,
            Key=scoped_key,
            Body=content,
            ServerSideEncryption="aws:kms",  # CTRL-CLOUD-001 — explicit SSE-KMS
        )
        logger.info(
            "Attachment uploaded",
            extra={"tenant_id": tenant_id, "key": scoped_key},
        )
        return scoped_key

    def get_attachment(self, tenant_id: str, filename: str) -> bytes:
        """Fetch an attachment from the secure attachments bucket.

        Key is constructed with the tenant prefix to prevent cross-tenant reads.
        """
        scoped_key = f"attachments/{tenant_id}/{filename}"
        try:
            response = self._s3.get_object(Bucket=_ATTACHMENTS_BUCKET, Key=scoped_key)
            return response["Body"].read()
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code == "NoSuchKey":
                raise FileNotFoundError(f"Attachment not found: {filename}") from exc
            raise
