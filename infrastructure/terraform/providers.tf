# ─────────────────────────────────────────────────────────────────────────────
# ThreatLens AI — Terraform Providers & Backend Configuration
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # For production, enable remote S3 state storage:
  # backend "s3" {
  #   bucket         = "threatlens-tf-state-bucket"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "threatlens-tf-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ThreatLens AI"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
