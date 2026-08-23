# ─────────────────────────────────────────────────────────────────────────────
# RDS Module — PostgreSQL Database & Secrets Manager Setup
# ─────────────────────────────────────────────────────────────────────────────

# ── Random Password Generation ───────────────────────────────────────────────
resource "random_password" "db_password" {
  length  = 24
  special = false
}

# ── Subnet Group ───────────────────────────────────────────────────────────
resource "aws_db_subnet_group" "main" {
  name       = "threatlens-db-subnet-group-${var.environment}"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "threatlens-db-subnet-group-${var.environment}"
  }
}

# ── PostgreSQL RDS Instance ────────────────────────────────────────────────
resource "aws_db_instance" "postgres" {
  identifier           = "threatlens-postgres-${var.environment}"
  allocated_storage    = 20
  max_allocated_storage = 100
  engine               = "postgres"
  engine_version       = "15.5"
  instance_class       = var.db_instance_class
  db_name              = var.db_name
  username             = var.db_username
  password             = random_password.db_password.result
  db_subnet_group_name = aws_db_subnet_group.main.name
  vpc_security_group_ids = [var.rds_security_group_id]

  skip_final_snapshot    = true
  deletion_protection    = false
  publicly_accessible    = false
  storage_encrypted      = true
  auto_minor_version_upgrade = true
  backup_retention_period = 7

  tags = {
    Name = "threatlens-db-${var.environment}"
  }
}

# ── Store Database Credentials securely in AWS Secrets Manager ──────────────
resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "threatlens/db-credentials-${var.environment}"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_credentials_version" {
  secret_id     = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    engine   = "postgres"
    host     = aws_db_instance.postgres.address
    port     = aws_db_instance.postgres.port
    username = var.db_username
    password = random_password.db_password.result
    database = var.db_name
  })
}
