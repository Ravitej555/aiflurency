# ─────────────────────────────────────────────────────────────────────────────
# Monitoring Module — CloudWatch Log Groups & Alarms
# ─────────────────────────────────────────────────────────────────────────────

# ── CloudWatch Log Groups ──────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "backend" {
  name              = "/ecs/threatlens-backend-${var.environment}"
  retention_in_days = 30

  tags = {
    Name = "threatlens-backend-logs-${var.environment}"
  }
}

resource "aws_cloudwatch_log_group" "frontend" {
  name              = "/ecs/threatlens-frontend-${var.environment}"
  retention_in_days = 30

  tags = {
    Name = "threatlens-frontend-logs-${var.environment}"
  }
}

# ── CloudWatch Alarms for ECS High CPU Usage ────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "backend_cpu_high" {
  alarm_name          = "threatlens-backend-high-cpu-${var.environment}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Triggered when backend CPU utilization exceeds 80%"

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = var.backend_service_name
  }
}

resource "aws_cloudwatch_metric_alarm" "backend_memory_high" {
  alarm_name          = "threatlens-backend-high-memory-${var.environment}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Average"
  threshold           = 85
  alarm_description   = "Triggered when backend memory utilization exceeds 85%"

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = var.backend_service_name
  }
}
