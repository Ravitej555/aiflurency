# ─────────────────────────────────────────────────────────────────────────────
# ThreatLens AI — Main Infrastructure Orchestration Module
# ─────────────────────────────────────────────────────────────────────────────

# 1. Networking (VPC, Subnets, Gateways, SGs)
module "networking" {
  source             = "./modules/networking"
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
  environment        = var.environment
}

# 2. Application Load Balancer
module "alb" {
  source                = "./modules/alb"
  vpc_id                = module.networking.vpc_id
  public_subnet_ids     = module.networking.public_subnet_ids
  alb_security_group_id = module.networking.alb_security_group_id
  environment           = var.environment
}

# 3. RDS PostgreSQL Database
module "rds" {
  source                = "./modules/rds"
  vpc_id                = module.networking.vpc_id
  private_subnet_ids    = module.networking.private_subnet_ids
  rds_security_group_id = module.networking.rds_security_group_id
  db_instance_class     = var.db_instance_class
  db_name               = var.db_name
  db_username           = var.db_username
  environment           = var.environment
}

# 4. CloudWatch Monitoring & Logging
module "monitoring" {
  source                = "./modules/monitoring"
  environment           = var.environment
  ecs_cluster_name      = module.ecs.cluster_name
  backend_service_name  = module.ecs.backend_service_name
  frontend_service_name = module.ecs.frontend_service_name
}

# 5. ECS Fargate Cluster & Services
module "ecs" {
  source                   = "./modules/ecs"
  aws_region               = var.aws_region
  environment              = var.environment
  vpc_id                   = module.networking.vpc_id
  private_subnet_ids       = module.networking.private_subnet_ids
  ecs_security_group_id    = module.networking.ecs_security_group_id
  backend_target_group_arn  = module.alb.backend_target_group_arn
  frontend_target_group_arn = module.alb.frontend_target_group_arn
  backend_image            = var.backend_image
  frontend_image           = var.frontend_image
  db_address               = module.rds.db_address
  db_name                  = var.db_name
  db_username              = var.db_username
  db_password              = module.rds.db_password
  jwt_secret_key           = var.jwt_secret_key
  backend_log_group_name   = module.monitoring.backend_log_group_name
  frontend_log_group_name  = module.monitoring.frontend_log_group_name
}
