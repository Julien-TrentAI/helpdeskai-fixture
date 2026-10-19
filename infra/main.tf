# SECURITY FIXTURE — DELIBERATELY VULNERABLE INFRASTRUCTURE-AS-CODE
# This Terraform defines the AWS backbone for HelpDeskAI. It contains deliberately
# planted cloud/storage/IAM misconfigurations for Trent's threat-model analysis to
# detect, alongside one positive control for contrast. Do NOT use as a template.
#
# PLANTED FINDINGS:
#   VULN-DATA-003 (High):     KB bucket is public-read and has no server-side encryption
#   VULN-CLOUD-001 (Critical): IAM policy grants s3:* and dynamodb:* on Resource "*"
#   VULN-CLOUD-002 (High):     hardcoded AWS access key / secret in the provider block
#   VULN-CLOUD-003 (Medium):   RDS instance with storage_encrypted = false (no KMS)
# POSITIVE CONTROLS:
#   CTRL-CLOUD-001: attachments bucket enforces SSE-KMS + full public-access block

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# SECURITY FIXTURE: VULN-CLOUD-002 — static, long-lived AWS credentials hardcoded
# directly in the provider block (and committed to the repo). These should come from
# an assumed role / OIDC / environment, never be checked in. A leaked repo leaks the
# keys; the CI coding agents (see .github/workflows) run with repo access and could
# read these via prompt injection (see cross-surface CHAIN-2 in EXPECTED_FINDINGS.md).
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"                         # VULN-CLOUD-002
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"     # VULN-CLOUD-002
}

# ─────────────────────────────────────────────────────────────────────────────
# Knowledge-base bucket — INSECURE (VULN-DATA-003)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "kb_docs" {
  bucket = "helpdeskai-kb-docs"
}

# SECURITY FIXTURE: VULN-DATA-003 — public-read ACL on the KB bucket. Any anonymous
# internet user can list and download every tenant's knowledge-base documents.
resource "aws_s3_bucket_acl" "kb_docs" {
  bucket = aws_s3_bucket.kb_docs.id
  acl    = "public-read" # VULN-DATA-003
}

# SECURITY FIXTURE: VULN-DATA-003 — public access block explicitly DISABLED, so the
# public-read ACL above takes effect (no account/bucket guard rail).
resource "aws_s3_bucket_public_access_block" "kb_docs" {
  bucket                  = aws_s3_bucket.kb_docs.id
  block_public_acls       = false # VULN-DATA-003
  block_public_policy     = false # VULN-DATA-003
  ignore_public_acls      = false # VULN-DATA-003
  restrict_public_buckets = false # VULN-DATA-003
}

# NOTE the ABSENCE of an aws_s3_bucket_server_side_encryption_configuration for
# kb_docs — VULN-DATA-003: KB documents are stored unencrypted at rest.

# ─────────────────────────────────────────────────────────────────────────────
# Attachments bucket — SECURE (CTRL-CLOUD-001)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_kms_key" "attachments" {
  description             = "CMK for HelpDeskAI customer attachments"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_s3_bucket" "attachments" {
  bucket = "helpdeskai-attachments"
}

# SECURITY FIXTURE: CTRL-CLOUD-001 — attachments bucket enforces SSE-KMS at rest with
# a customer-managed key. Contrast with the KB bucket (VULN-DATA-003).
resource "aws_s3_bucket_server_side_encryption_configuration" "attachments" {
  bucket = aws_s3_bucket.attachments.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.attachments.arn
    }
  }
}

# SECURITY FIXTURE: CTRL-CLOUD-001 — full public-access block on the attachments bucket.
resource "aws_s3_bucket_public_access_block" "attachments" {
  bucket                  = aws_s3_bucket.attachments.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─────────────────────────────────────────────────────────────────────────────
# DynamoDB + RDS data stores
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "tickets" {
  name         = "helpdeskAI-tickets"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tenant_id"
  range_key    = "ticket_id"

  attribute {
    name = "tenant_id"
    type = "S"
  }
  attribute {
    name = "ticket_id"
    type = "S"
  }
}

# SECURITY FIXTURE: VULN-CLOUD-003 — RDS instance holding customer orders + PII with
# storage_encrypted = false: no encryption at rest, no KMS. PII (see VULN-DATA-002)
# sits unencrypted on disk and in snapshots.
resource "aws_db_instance" "orders" {
  identifier        = "helpdeskai-orders"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  allocated_storage = 50
  username          = "helpdeskAI_app"
  password          = "changeme" # also weak/committed, compounds VULN-CLOUD-002
  storage_encrypted = false      # VULN-CLOUD-003
  publicly_accessible = true     # VULN-CLOUD-003: DB reachable from the internet
  skip_final_snapshot = true
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM role for the application — OVER-PERMISSIONED (VULN-CLOUD-001)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "app" {
  name = "helpdeskai-app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

# SECURITY FIXTURE: VULN-CLOUD-001 — the application role is granted s3:* and
# dynamodb:* on Resource "*". A compromise of the app (e.g. via the agent's RCE
# tool, or a CI agent reading these creds) yields full read/write/delete over EVERY
# bucket and table in the account, across all tenants. The least-privilege version
# would scope actions to the specific buckets/tables and to GetObject/PutObject /
# Query/PutItem only.
resource "aws_iam_role_policy" "app" {
  name = "helpdeskai-app-policy"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::helpdeskai-kb-docs",
          "arn:aws:s3:::helpdeskai-kb-docs/*",
          "arn:aws:s3:::*-kb-docs",
          "arn:aws:s3:::*-kb-docs/*",
          "arn:aws:s3:::helpdeskai-attachments",
          "arn:aws:s3:::helpdeskai-attachments/*",
        ]
      },
      {
        Effect = "Allow"
        Action = ["dynamodb:Query", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Scan"]
        Resource = [
          "arn:aws:dynamodb:us-east-1:*:table/helpdeskAI-tickets",
          "arn:aws:dynamodb:us-east-1:*:table/helpdeskAI-tenant-config",
        ]
      },
    ]
  })
}
