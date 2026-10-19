# SECURITY FIXTURE — DELIBERATELY VULNERABLE INFRASTRUCTURE-AS-CODE
# This Terraform defines the AWS backbone for HelpDeskAI. It contains deliberately
# planted cloud/storage/IAM misconfigurations for Trent's threat-model analysis to
# detect, alongside one positive control for contrast. Do NOT use as a template.
#
# PLANTED FINDINGS:
#   VULN-DATA-003 (High):     KB bucket is public-read and has no server-side encryption
#   VULN-CLOUD-001 (Critical): IAM policy grants s3:* and dynamodb:* on Resource "*"
# POSITIVE CONTROLS:
#   CTRL-CLOUD-001: attachments bucket enforces SSE-KMS + full public-access block

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# No static credentials. The provider resolves temporary credentials from the standard
# AWS chain: in CI, AWS OIDC (the workflow's role-to-assume exports a web identity token /
# session credentials); locally, an assumed IAM role (set `deploy_role_arn`, or use an
# AWS SSO / `aws sso login` profile). Nothing secret is stored on disk or in the repo.
variable "deploy_role_arn" {
  description = "IAM role Terraform assumes for local development (leave null in CI, where OIDC supplies the role)"
  type        = string
  default     = null
}

provider "aws" {
  region = "us-east-1"

  dynamic "assume_role" {
    for_each = var.deploy_role_arn == null ? [] : [var.deploy_role_arn]
    content {
      role_arn     = assume_role.value
      session_name = "terraform-local"
    }
  }
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

resource "aws_kms_key" "rds" {
  description             = "CMK for HelpDeskAI RDS storage encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "rds" {
  name          = "alias/helpdeskai-rds-key"
  target_key_id = aws_kms_key.rds.key_id
}

resource "random_password" "rds_password" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "rds_credentials" {
  name       = "helpdeskai/rds/orders-credentials"
  kms_key_id = aws_kms_key.rds.arn
}

resource "aws_secretsmanager_secret_version" "rds_credentials" {
  secret_id = aws_secretsmanager_secret.rds_credentials.id
  secret_string = jsonencode({
    username = "helpdeskAI_app"
    password = random_password.rds_password.result
  })
}

variable "private_subnet_ids" {
  description = "Private subnet IDs (no route to an internet gateway) for the RDS subnet group"
  type        = list(string)
}

variable "vpc_id" {
  description = "VPC that hosts the RDS instance"
  type        = string
}

variable "app_security_group_id" {
  description = "Security group of the application tasks allowed to reach the database"
  type        = string
}

resource "aws_db_subnet_group" "orders" {
  name       = "helpdeskai-orders-private"
  subnet_ids = var.private_subnet_ids
}

# No internet-facing rules: Postgres is reachable only from the application security group.
resource "aws_security_group" "rds_orders" {
  name        = "helpdeskai-orders-rds"
  description = "RDS orders database - private access from the app only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Postgres from the application"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.app_security_group_id]
  }
}

resource "aws_db_instance" "orders" {
  identifier          = "helpdeskai-orders"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 50
  username            = "helpdeskAI_app"
  password            = random_password.rds_password.result
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.rds.arn
  publicly_accessible = false
  db_subnet_group_name   = aws_db_subnet_group.orders.name
  vpc_security_group_ids = [aws_security_group.rds_orders.id]
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

# Least-privilege: actions are limited to GetObject/PutObject/ListBucket and
# Query/GetItem/PutItem, scoped to the specific buckets and tables below.
data "aws_caller_identity" "current" {}

resource "aws_iam_role_policy" "app" {
  name = "helpdeskai-app-policy"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject"]
        Resource = [
          "${aws_s3_bucket.kb_docs.arn}/*",
          "${aws_s3_bucket.attachments.arn}/*",
        ]
      },
      {
        Effect = "Allow"
        Action = ["s3:ListBucket"]
        Resource = [
          aws_s3_bucket.kb_docs.arn,
          aws_s3_bucket.attachments.arn,
        ]
      },
      {
        # Query-only access keyed on tenant_id; no Scan.
        Effect = "Allow"
        Action = ["dynamodb:Query", "dynamodb:GetItem", "dynamodb:PutItem"]
        Resource = [
          aws_dynamodb_table.tickets.arn,
          "arn:aws:dynamodb:us-east-1:${data.aws_caller_identity.current.account_id}:table/helpdeskAI-tenant-config",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.attachments.arn]
      },
    ]
  })
}
