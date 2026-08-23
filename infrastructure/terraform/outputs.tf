output "alb_dns_name" {
  description = "Public DNS Name of the Application Load Balancer"
  value       = module.alb.alb_dns_name
}

output "ecs_cluster_name" {
  description = "Name of the ECS Cluster"
  value       = module.ecs.cluster_name
}

output "rds_endpoint" {
  description = "Connection endpoint for RDS PostgreSQL"
  value       = module.rds.db_endpoint
  sensitive   = true
}

output "cloudwatch_log_group_backend" {
  description = "CloudWatch log group for backend tasks"
  value       = module.monitoring.backend_log_group_name
}

output "cloudwatch_log_group_frontend" {
  description = "CloudWatch log group for frontend tasks"
  value       = module.monitoring.frontend_log_group_name
}
