# ─────────────────────────────────────────────────────────────────────────────
# Networking Module — VPC, Subnets, Gateways, Route Tables & Security Groups
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "threatlens-vpc-${var.environment}"
  }
}

# ── Public Subnets (for ALB) ───────────────────────────────────────────────
resource "aws_subnet" "public" {
  count                   = length(var.availability_zones)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "threatlens-public-subnet-${count.index + 1}-${var.environment}"
  }
}

# ── Private Subnets (for ECS Tasks & RDS) ──────────────────────────────────
resource "aws_subnet" "private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "threatlens-private-subnet-${count.index + 1}-${var.environment}"
  }
}

# ── Internet Gateway ───────────────────────────────────────────────────────
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "threatlens-igw-${var.environment}"
  }
}

# ── NAT Gateway & Elastic IP ───────────────────────────────────────────────
resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "threatlens-nat-${var.environment}"
  }

  depends_on = [aws_internet_gateway.gw]
}

# ── Route Tables ───────────────────────────────────────────────────────────
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "threatlens-public-rt-${var.environment}"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(var.availability_zones)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "threatlens-private-rt-${var.environment}"
  }
}

resource "aws_route_table_association" "private" {
  count          = length(var.availability_zones)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ── Security Groups ────────────────────────────────────────────────────────
# 1. ALB Security Group (Public internet facing)
resource "aws_security_group" "alb" {
  name        = "threatlens-alb-sg-${var.environment}"
  description = "Controls traffic to the Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 2. ECS Tasks Security Group (Strict: accepts traffic ONLY from ALB)
resource "aws_security_group" "ecs" {
  name        = "threatlens-ecs-sg-${var.environment}"
  description = "Controls access to ECS tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow HTTP from ALB on port 8000 (Backend)"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "Allow HTTP from ALB on port 3000 (Frontend)"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. RDS PostgreSQL Security Group (Strict: accepts traffic ONLY from ECS tasks)
resource "aws_security_group" "rds" {
  name        = "threatlens-rds-sg-${var.environment}"
  description = "Controls access to PostgreSQL RDS"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow PostgreSQL access from ECS tasks"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
