variable "aws_region" {
  description = "AWS Region to deploy resources into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "VPC IPv4 CIDR Block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability Zones for High Availability"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "db_instance_class" {
  description = "RDS PostgreSQL Instance Class"
  type        = string
  default     = "db.t4g.micro"
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "threatlens"
}

variable "db_username" {
  description = "Master database user"
  type        = string
  default     = "threatlens_admin"
}

variable "backend_image" {
  description = "Docker image for backend"
  type        = string
  default     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/threatlens-backend:latest"
}

variable "frontend_image" {
  description = "Docker image for frontend"
  type        = string
  default     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/threatlens-frontend:latest"
}

variable "jwt_secret_key" {
  description = "JWT Secret Key for FastAPI token signing"
  type        = string
  sensitive   = true
}
