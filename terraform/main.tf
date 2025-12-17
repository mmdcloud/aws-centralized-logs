# -----------------------------------------------------------------------------------------
# Registering vault provider
# -----------------------------------------------------------------------------------------
data "vault_generic_secret" "opensearch" {
  path = "secret/opensearch"
}

resource "random_id" "random" {
  byte_length = 8
}

data "vault_generic_secret" "rds" {
  path = "secret/rds"
}

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------------------
# VPC Configuration
# -----------------------------------------------------------------------------------------
module "carshub_vpc" {
  source                  = "./modules/vpc"
  vpc_name                = "carshub-vpc"
  vpc_cidr                = "10.0.0.0/16"
  azs                     = var.azs
  public_subnets          = var.public_subnets
  private_subnets         = var.private_subnets
  enable_dns_hostnames    = true
  enable_dns_support      = true
  create_igw              = true
  map_public_ip_on_launch = true
  enable_nat_gateway      = true
  single_nat_gateway      = false
  one_nat_gateway_per_az  = true
  tags = {
    Environment = "${var.env}"
    Project     = "carshub"
  }
}

# Security Group
module "carshub_frontend_lb_sg" {
  source = "./modules/security-groups"
  name   = "carshub-frontend-lb-sg"
  vpc_id = module.carshub_vpc.vpc_id
  ingress_rules = [
    {
      description = "HTTP Traffic"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "HTTPS Traffic"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  egress_rules = [
    {
      description = "Allow all outbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  tags = {
    Name = "carshub-frontend-lb-sg"
  }
}

module "carshub_backend_lb_sg" {
  source = "./modules/security-groups"
  name   = "carshub-backend-lb-sg"
  vpc_id = module.carshub_vpc.vpc_id
  ingress_rules = [
    {
      description = "HTTP Traffic"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "HTTPS Traffic"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  egress_rules = [
    {
      description = "Allow all outbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  tags = {
    Name = "carshub-backend-lb-sg"
  }
}

module "carshub_asg_frontend_sg" {
  source = "./modules/security-groups"
  name   = "carshub-asg-frontend-sg"
  vpc_id = module.carshub_vpc.vpc_id
  ingress_rules = [
    {
      description = "ASG Frontend Traffic"
      from_port   = 3000
      to_port     = 3000
      protocol    = "tcp"
      security_groups = [module.carshub_frontend_lb_sg.id]
      cidr_blocks = []
    }
  ]
  egress_rules = [
    {
      description = "Allow all outbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  tags = {
    Name = "carshub-asg-frontend-sg"
  }
}

module "carshub_asg_backend_sg" {
  source = "./modules/security-groups"
  name   = "carshub-asg-backend-sg"
  vpc_id = module.carshub_vpc.vpc_id
  ingress_rules = [
    {
      description = "ASG Backend Traffic"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      security_groups = [module.carshub_backend_lb_sg.id]
      cidr_blocks = []
    }
  ]
  egress_rules = [
    {
      description = "Allow all outbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  tags = {
    Name = "carshub-asg-backend-sg"
  }
}

module "carshub_rds_sg" {
  source = "./modules/security-groups"
  name   = "carshub-rds-sg"
  vpc_id = module.carshub_vpc.vpc_id
  ingress_rules = [
    {
      description = "RDS Traffic"
      from_port   = 3306
      to_port     = 3306
      protocol    = "tcp"
      security_groups = [module.carshub_asg_backend_sg.id]
      cidr_blocks = []
    }
  ]
  egress_rules = [
    {
      description = "Allow all outbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  tags = {
    Name = "carshub-rds-sg"
  }
}

# -----------------------------------------------------------------------------------------
# Secrets Manager
# -----------------------------------------------------------------------------------------
module "carshub_db_credentials" {
  source                  = "./modules/secrets-manager"
  name                    = "carshub-rds-secrets"
  description             = "carshub-rds-secrets"
  recovery_window_in_days = 0
  secret_string = jsonencode({
    username = tostring(data.vault_generic_secret.rds.data["username"])
    password = tostring(data.vault_generic_secret.rds.data["password"])
  })
}

# -----------------------------------------------------------------------------------------
# VPC Flow Logs
# -----------------------------------------------------------------------------------------
module "flow_logs_role" {
  source             = "./modules/iam"
  role_name          = "carshub-flow-logs-role"
  role_description   = "carshub-flow-logs-role"
  policy_name        = "carshub-flow-logs-policy"
  policy_description = "carshub-flow-logs-policy"
  assume_role_policy = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "vpc-flow-logs.amazonaws.com"
                },
                "Effect": "Allow",
                "Sid": ""
            }
        ]
    }
    EOF
  policy             = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                  "logs:CreateLogGroup",
                  "logs:CreateLogStream",
                  "logs:PutLogEvents",
                  "logs:DescribeLogGroups",
                  "logs:DescribeLogStreams"
                ],
                "Resource": "*",
                "Effect": "Allow"
            }
        ]
    }
    EOF
}

module "carshub_flow_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/carshub/application"
  retention_in_days = 365
}

# Add VPC Flow Logs for security monitoring
resource "aws_flow_log" "carshub_vpc_flow_log" {
  iam_role_arn    = module.flow_logs_role.arn
  log_destination = module.carshub_flow_log_group.arn
  traffic_type    = "ALL"
  vpc_id          = module.carshub_vpc.vpc_id
}

# -----------------------------------------------------------------------------------------
# RDS Instance
# -----------------------------------------------------------------------------------------
resource "aws_iam_role" "rds_monitoring_role" {
  name = "carshub-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_policy" {
  role       = aws_iam_role.rds_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

module "carshub_db" {
  source                          = "./modules/rds"
  db_name                         = "carshubdb${var.env}useast1"
  allocated_storage               = 100
  storage_type                    = "gp3"
  engine                          = "mysql"
  engine_version                  = "8.0.40"
  instance_class                  = "db.r6g.large"
  multi_az                        = true
  username                        = tostring(data.vault_generic_secret.rds.data["username"])
  password                        = tostring(data.vault_generic_secret.rds.data["password"])
  subnet_group_name               = "carshub-rds-subnet-group"
  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
  backup_retention_period         = 35
  backup_window                   = "03:00-06:00"
  subnet_group_ids = [
    module.carshub_vpc.private_subnets[0],
    module.carshub_vpc.private_subnets[1],
    module.carshub_vpc.private_subnets[2]
  ]
  vpc_security_group_ids                = [module.carshub_rds_sg.id]
  publicly_accessible                   = false
  deletion_protection                   = false
  skip_final_snapshot                   = true
  max_allocated_storage                 = 500
  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_monitoring_role.arn
  parameter_group_name                  = "carshub-db-pg"
  parameter_group_family                = "mysql8.0"
  parameters = [
    {
      name  = "max_connections"
      value = "1000"
    },
    {
      name  = "innodb_buffer_pool_size"
      value = "{DBInstanceClassMemory*3/4}"
    },
    {
      name  = "slow_query_log"
      value = "1"
    }
  ]
}

# -----------------------------------------------------------------------------------------
# S3 Configuration
# -----------------------------------------------------------------------------------------
module "carshub_media_bucket" {
  source      = "./modules/s3"
  bucket_name = "carshub-media-bucket${var.env}-${var.region}"
  objects = [
    {
      key    = "images/"
      source = ""
    },
    {
      key    = "documents/"
      source = ""
    }
  ]
  versioning_enabled = "Enabled"
  cors = [
    {
      allowed_headers = ["${module.carshub_media_cloudfront_distribution.domain_name}"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    },
    {
      allowed_headers = ["${module.carshub_frontend_lb.lb_dns_name}"]
      allowed_methods = ["PUT"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  bucket_policy = jsonencode({
    "Version" : "2012-10-17",
    "Id" : "PolicyForCloudFrontPrivateContent",
    "Statement" : [
      {
        "Sid" : "AllowCloudFrontServicePrincipal",
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "cloudfront.amazonaws.com"
        },
        "Action" : "s3:GetObject",
        "Resource" : "${module.carshub_media_bucket.arn}/*",
        "Condition" : {
          "StringEquals" : {
            "AWS:SourceArn" : "${module.carshub_media_cloudfront_distribution.arn}"
          }
        }
      }
    ]
  })
  # Note: Lifecycle policies should be configured in the S3 module
  # or as separate aws_s3_bucket_lifecycle_configuration resources
  force_destroy = true
  bucket_notification = {
    queue = [
      {
        queue_arn = module.carshub_media_events_queue.arn
        events    = ["s3:ObjectCreated:*"]
      }
    ]
    lambda_function = []
  }
}

module "carshub_media_update_function_code" {
  source      = "./modules/s3"
  bucket_name = "carshub-media-updatefunctioncode${var.env}-${var.region}"
  objects = [
    {
      key    = "lambda.zip"
      source = "../../../files/lambda.zip"
    }
  ]
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = true
}

module "carshub_frontend_lb_logs" {
  source        = "./modules/s3"
  bucket_name   = "carshub-frontend-lb-logs"
  objects       = []
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    },
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = true
}

module "carshub_backend_lb_logs" {
  source        = "./modules/s3"
  bucket_name   = "carshub-backend-lb-logs"
  objects       = []
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    },
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = true
}

# -----------------------------------------------------------------------------------------
# Signing Profile
# -----------------------------------------------------------------------------------------
module "carshub_media_update_function_code_signed" {
  source             = "./modules/s3"
  bucket_name        = "carshub-media-update-function-code-signed${var.env}-${var.region}"
  versioning_enabled = "Enabled"
  force_destroy      = true
  bucket_policy      = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
}

# Signing profile
module "carshub_signing_profile" {
  source                           = "./modules/signing-profile"
  platform_id                      = "AWSLambda-SHA384-ECDSA"
  signature_validity_value         = 5
  signature_validity_type          = "YEARS"
  ignore_signing_job_failure       = true
  untrusted_artifact_on_deployment = "Warn"
  s3_bucket_key                    = "lambda.zip"
  s3_bucket_source                 = module.carshub_media_update_function_code.bucket
  s3_bucket_version                = module.carshub_media_update_function_code.objects[0].version_id
  s3_bucket_destination            = module.carshub_media_update_function_code_signed.bucket
}

# -----------------------------------------------------------------------------------------
# SQS Config
# -----------------------------------------------------------------------------------------
resource "aws_lambda_event_source_mapping" "sqs_event_trigger" {
  event_source_arn                   = module.carshub_media_events_queue.arn
  function_name                      = module.carshub_media_update_function.arn
  enabled                            = true
  batch_size                         = 10
  maximum_batching_window_in_seconds = 60
}

# SQS Queue for buffering S3 events
module "carshub_media_events_queue" {
  source                        = "./modules/sqs"
  queue_name                    = "carshub-media-events-queue"
  delay_seconds                 = 0
  maxReceiveCount               = 3
  dlq_message_retention_seconds = 86400
  dlq_name                      = "carshub-media-events-dlq"
  max_message_size              = 262144
  message_retention_seconds     = 345600
  visibility_timeout_seconds    = 180
  receive_wait_time_seconds     = 20
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = "arn:aws:sqs:${var.region}:*:carshub-media-events-queue"
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = module.carshub_media_bucket.arn
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------------------
# Lambda Config
# -----------------------------------------------------------------------------------------
module "carshub_media_update_function_iam_role" {
  source             = "./modules/iam"
  role_name          = "carshub-media-update-function-iam-role"
  role_description   = "carshub-media-update-function-iam-role"
  policy_name        = "carshub-media-update-function-iam-policy"
  policy_description = "carshub-media-update-function-iam-policy"
  assume_role_policy = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "lambda.amazonaws.com"
                },
                "Effect": "Allow",
                "Sid": ""
            }
        ]
    }
    EOF
  policy             = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                  "logs:CreateLogGroup",
                  "logs:CreateLogStream",
                  "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:*",
                "Effect": "Allow"
            },
            {
              "Effect": "Allow",
              "Action": "secretsmanager:GetSecretValue",
              "Resource": "${module.carshub_db_credentials.arn}"
            },
            {
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Effect": "Allow",
                "Resource": "${module.carshub_media_bucket.arn}/*"
            },
            {
              "Action": [
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes"
              ],
              "Effect"   : "Allow",
              "Resource" : "${module.carshub_media_events_queue.arn}"
            }
        ]
    }
    EOF
}

# Lambda Layer for storing dependencies
resource "aws_lambda_layer_version" "python_layer" {
  filename            = "../../../files/python.zip"
  layer_name          = "python"
  compatible_runtimes = ["python3.12"]
}

# Lambda function to update media metadata in RDS database
module "carshub_media_update_function" {
  source        = "./modules/lambda"
  function_name = "carshub-media-update"
  role_arn      = module.carshub_media_update_function_iam_role.arn
  permissions   = []
  env_variables = {
    SECRET_NAME = module.carshub_db_credentials.name
    DB_HOST     = tostring(split(":", module.carshub_db.endpoint)[0])
    DB_NAME     = var.db_name
    REGION      = var.region
  }
  handler                 = "lambda.lambda_handler"
  runtime                 = "python3.12"
  s3_bucket               = module.carshub_media_update_function_code.bucket
  s3_key                  = "lambda.zip"
  layers                  = [aws_lambda_layer_version.python_layer.arn]
  code_signing_config_arn = module.carshub_signing_profile.config_arn
}

# -----------------------------------------------------------------------------------------
# Cloudfront distribution
# -----------------------------------------------------------------------------------------
module "carshub_media_cloudfront_distribution" {
  source                                = "./modules/cloudfront"
  distribution_name                     = "carshub-media-cdn"
  oac_name                              = "carshub-media-cdn-oac"
  oac_description                       = "carshub-media-cdn-oac"
  oac_origin_access_control_origin_type = "s3"
  oac_signing_behavior                  = "always"
  oac_signing_protocol                  = "sigv4"
  enabled                               = true
  origin = [
    {
      origin_id           = "carshub-media-bucket-${var.env}"
      domain_name         = "carshub-media-bucket-${var.env}.s3.${var.region}.amazonaws.com"
      connection_attempts = 3
      connection_timeout  = 10
    }
  ]
  compress                       = true
  smooth_streaming               = false
  target_origin_id               = "carshub-media-bucket-${var.env}"
  allowed_methods                = ["GET", "HEAD"]
  cached_methods                 = ["GET", "HEAD"]
  viewer_protocol_policy         = "redirect-to-https"
  min_ttl                        = 0
  default_ttl                    = 86400
  max_ttl                        = 31536000
  price_class                    = "PriceClass_100"
  forward_cookies                = "all"
  cloudfront_default_certificate = true
  geo_restriction_type           = "none"
  query_string                   = true
}

# -----------------------------------------------------------------------------------------
# EC2 Configuration
# -----------------------------------------------------------------------------------------
module "iam_instance_profile_role" {
  source             = "./modules/iam"
  role_name          = "iam-instance-profile-role"
  role_description   = "iam-instance-profile-role"
  policy_name        = "iam-instance-profile-policy"
  policy_description = "iam-instance-profile-policy"
  assume_role_policy = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "ec2.amazonaws.com"
                },
                "Effect": "Allow",
                "Sid": ""
            }
        ]
    }
    EOF
  policy             = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                  "s3:*"
                ],
                "Resource": "*",
                "Effect": "Allow"
            }
        ]
    }
    EOF
}

resource "aws_iam_instance_profile" "iam_instance_profile" {
  name = "iam-instance-profile"
  role = module.iam_instance_profile_role.name
}

# Carshub frontend instance template
module "carshub_frontend_launch_template" {
  source                               = "./modules/launch_template"
  name                                 = "carshub_frontend_launch_template_${var.env}"
  description                          = "carshub_frontend_launch_template_${var.env}"
  ebs_optimized                        = false
  image_id                             = "ami-005fc0f236362e99f"
  instance_type                        = "t2.micro"
  instance_initiated_shutdown_behavior = "stop"
  instance_profile_name                = aws_iam_instance_profile.iam_instance_profile.name
  key_name                             = "madmaxkeypair"
  network_interfaces = [
    {
      associate_public_ip_address = true
      security_groups             = [module.carshub_asg_frontend_sg.id]
    }
  ]
  user_data = base64encode(templatefile("${path.module}/../../../scripts/user_data_frontend.sh", {
    BASE_URL = "http://${module.carshub_backend_lb.lb_dns_name}"
    CDN_URL  = module.carshub_media_cloudfront_distribution.domain_name
  }))
}

# Carshub backend instance template
module "carshub_backend_launch_template" {
  source                               = "./modules/launch_template"
  name                                 = "carshub_backend_launch_template_${var.env}"
  description                          = "carshub_backend_launch_template_${var.env}"
  ebs_optimized                        = false
  image_id                             = "ami-005fc0f236362e99f"
  instance_type                        = "t2.micro"
  instance_initiated_shutdown_behavior = "stop"
  instance_profile_name                = aws_iam_instance_profile.iam_instance_profile.name
  key_name                             = "madmaxkeypair"
  network_interfaces = [
    {
      associate_public_ip_address = true
      security_groups             = [module.carshub_asg_backend_sg.id]
    }
  ]
  user_data = base64encode(templatefile("${path.module}/../../../scripts/user_data_backend.sh", {
    DB_PATH = tostring(split(":", module.carshub_db.endpoint)[0])
    UN      = tostring(data.vault_generic_secret.rds.data["username"])
    CREDS   = tostring(data.vault_generic_secret.rds.data["password"])
    DB_NAME = module.carshub_db.name
  }))
}

# Auto Scaling Group for Frontend Template
module "carshub_frontend_asg" {
  source                    = "./modules/auto_scaling_group"
  name                      = "carshub_frontend_asg_${var.env}"
  min_size                  = 3
  max_size                  = 50
  desired_capacity          = 3
  health_check_grace_period = 300
  health_check_type         = "ELB"
  force_delete              = true
  target_group_arns         = [module.carshub_frontend_lb.target_groups[0].arn]
  vpc_zone_identifier       = module.carshub_vpc.private_subnets
  launch_template_id        = module.carshub_frontend_launch_template.id
  launch_template_version   = "$Latest"
}

# Auto Scaling Group for Backend Template
module "carshub_backend_asg" {
  source                    = "./modules/auto_scaling_group"
  name                      = "carshub_backend_asg_${var.env}"
  min_size                  = 3
  max_size                  = 50
  desired_capacity          = 3
  health_check_grace_period = 300
  health_check_type         = "ELB"
  force_delete              = true
  target_group_arns         = [module.carshub_backend_lb.target_groups[0].arn]
  vpc_zone_identifier       = module.carshub_vpc.private_subnets
  launch_template_id        = module.carshub_backend_launch_template.id
  launch_template_version   = "$Latest"
}

# -----------------------------------------------------------------------------------------
# Load Balancer Configuration
# -----------------------------------------------------------------------------------------
module "carshub_frontend_lb" {
  source                     = "terraform-aws-modules/alb/aws"
  name                       = "carshub-frontend-lb"
  load_balancer_type         = "application"
  vpc_id                     = module.carshub_vpc.vpc_id
  subnets                    = module.carshub_vpc.public_subnets
  enable_deletion_protection = false
  drop_invalid_header_fields = true
  ip_address_type            = "ipv4"
  internal                   = false
  security_groups = [
    module.frontend_lb_sg.id
  ]
  access_logs = {
    bucket = "${module.carshub_frontend_lb_logs.bucket}"
  }
  listeners = {
    carshub_frontend_lb_http_listener = {
      port     = 80
      protocol = "HTTP"
      forward = {
        target_group_key = "carshub_frontend_lb_target_group"
      }
    }
  }
  target_groups = {
    carshub_frontend_lb_target_group = {
      backend_protocol = "HTTP"
      backend_port     = 3000
      target_type      = "ip"
      health_check = {
        enabled             = true
        healthy_threshold   = 3
        interval            = 30
        path                = "/auth/signin"
        port                = 3000
        protocol            = "HTTP"
        unhealthy_threshold = 3
      }
      create_attachment = false
    }
  }
  tags = {
    Project = "carshub"
  }
}

module "carshub_backend_lb" {
  source                     = "terraform-aws-modules/alb/aws"
  name                       = "carshub-backend-lb"
  load_balancer_type         = "application"
  vpc_id                     = module.carshub_vpc.vpc_id
  subnets                    = module.carshub_vpc.public_subnets
  enable_deletion_protection = false
  drop_invalid_header_fields = true
  ip_address_type            = "ipv4"
  internal                   = false
  security_groups = [
    module.backend_lb_sg.id
  ]
  access_logs = {
    bucket = "${module.carshub_backend_lb_logs.bucket}"
  }
  listeners = {
    carshub_backend_lb_http_listener = {
      port     = 80
      protocol = "HTTP"
      forward = {
        target_group_key = "carshub_backend_lb_target_group"
      }
    }
  }
  target_groups = {
    carshub_backend_lb_target_group = {
      backend_protocol = "HTTP"
      backend_port     = 80
      target_type      = "ip"
      health_check = {
        enabled             = true
        healthy_threshold   = 3
        interval            = 30
        path                = "/"
        port                = 80
        protocol            = "HTTP"
        unhealthy_threshold = 3
      }
      create_attachment = false
    }
  }
  tags = {
    Project = "carshub"
  }
}

# -----------------------------------------------------------------------------------------
# Cloudwath Alarm Configuration
# -----------------------------------------------------------------------------------------
module "carshub_alarm_notifications" {
  source     = "./modules/sns"
  topic_name = "carshub_cloudwatch_alarm_notification_topic"
  subscriptions = [
    {
      protocol = "email"
      endpoint = "madmaxcloudonline@gmail.com"
    }
  ]
}

# Target Response Time Alarm (if using ALB)
module "carshub_frontend_alb_high_response_time" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "${module.carshub_frontend_lb.arn}-high-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Average"
  extended_statistic  = "p95"
  threshold           = "1" # 1 second response time
  alarm_description   = "This metric monitors ALB target response time (p95)"
  alarm_actions       = [module.carshub_alarm_notifications.topic_arn]
  ok_actions          = [module.carshub_alarm_notifications.topic_arn]

  dimensions = {
    TargetGroup  = module.carshub_frontend_lb.target_groups[0].arn
    LoadBalancer = "${module.carshub_frontend_lb.arn}"
  }
}

# HTTP 5XX Error Rate Alarm (if using ALB)
module "carshub_frontend_lb_high_5xx_errors" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "${module.carshub_frontend_lb.arn}-high-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Sum"
  threshold           = "10" # Adjust based on your traffic pattern
  alarm_description   = "This metric monitors number of 5XX errors"
  alarm_actions       = [module.carshub_alarm_notifications.topic_arn]
  ok_actions          = [module.carshub_alarm_notifications.topic_arn]

  dimensions = {
    TargetGroup  = module.carshub_frontend_lb.target_groups[0].arn
    LoadBalancer = "${module.carshub_frontend_lb.arn}"
  }
}

# # -------------------------------------------------------------------------------------------------------------------------

# Target Response Time Alarm (if using ALB)
module "carshub_backend_lb_high_response_time" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "${module.carshub_backend_lb.arn}-high-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  extended_statistic  = "p95"
  statistic           = "Average"
  threshold           = "1" # 1 second response time
  alarm_description   = "This metric monitors ALB target response time (p95)"
  alarm_actions       = [module.carshub_alarm_notifications.topic_arn]
  ok_actions          = [module.carshub_alarm_notifications.topic_arn]

  dimensions = {
    TargetGroup  = module.carshub_backend_lb.target_groups[0].arn
    LoadBalancer = "${module.carshub_backend_lb.arn}"
  }
}

# HTTP 5XX Error Rate Alarm (if using ALB)
module "carshub_backend_lb_high_5xx_errors" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "${module.carshub_backend_lb.arn}-high-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Sum"
  threshold           = "10" # Adjust based on your traffic pattern
  alarm_description   = "This metric monitors number of 5XX errors"
  alarm_actions       = [module.carshub_alarm_notifications.topic_arn]
  ok_actions          = [module.carshub_alarm_notifications.topic_arn]

  dimensions = {
    TargetGroup  = module.carshub_backend_lb.target_groups[0].arn
    LoadBalancer = "${module.carshub_backend_lb.arn}"
  }
}

module "lambda_errors" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "carshub-media-update-lambda-errors-${var.env}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alarm when Lambda function errors > 0 in 5 minutes"
  alarm_actions       = [module.carshub_alarm_notifications.topic_arn]
  ok_actions          = [module.carshub_alarm_notifications.topic_arn]

  dimensions = {
    FunctionName = module.carshub_media_update_function.function_name
  }
}

module "sqs_queue_depth" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "carshub-media-events-queue-depth-${var.env}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Average"
  threshold           = 100
  alarm_description   = "Alarm when SQS queue depth > 100"
  alarm_actions       = [module.carshub_alarm_notifications.topic_arn]
  ok_actions          = [module.carshub_alarm_notifications.topic_arn]

  dimensions = {
    QueueName = module.carshub_media_events_queue.name
  }
}

module "rds_high_cpu" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "carshub-rds-high-cpu-${var.env}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when RDS CPU utilization > 80% for 10 minutes"
  alarm_actions       = [module.carshub_alarm_notifications.topic_arn]
  ok_actions          = [module.carshub_alarm_notifications.topic_arn]
  dimensions = {
    DBInstanceIdentifier = module.carshub_db.name
  }
}

module "rds_low_storage" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "carshub-rds-low-storage-${var.env}"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 10737418240 # 10 GB in bytes
  alarm_description   = "Alarm when RDS free storage < 10 GB"
  alarm_actions       = [module.carshub_alarm_notifications.topic_arn]
  ok_actions          = [module.carshub_alarm_notifications.topic_arn]
  dimensions = {
    DBInstanceIdentifier = module.carshub_db.name
  }
}

module "rds_high_connections" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "carshub-rds-high-connections-${var.env}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 100
  alarm_description   = "Alarm when RDS connections exceed 80% of max"
  alarm_actions       = [module.carshub_alarm_notifications.topic_arn]
  ok_actions          = [module.carshub_alarm_notifications.topic_arn]
  dimensions = {
    DBInstanceIdentifier = module.carshub_db.name
  }
}

# -----------------------------------------------------------------------------------------
# Cloudwatch log groups
# -----------------------------------------------------------------------------------------
module "carshub_frontend_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/ecs/carshub-frontend"
  retention_in_days = 30
}

module "carshub_backend_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/lambda/carshub-backend"
  retention_in_days = 30
}

# -----------------------------------------------------------------------------------------
# Kinesis & Firehose configuration
# -----------------------------------------------------------------------------------------
module "kinesis_stream" {
  source           = "./modules/kinesis"
  name             = "kinesis-stream"
  retention_period = 48
  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
  ]
  stream_mode = "ON_DEMAND"
}

# -----------------------------------------------------------------------------------------
# Opensearch configuration
# -----------------------------------------------------------------------------------------
module "opensearch" {
  source                          = "./modules/opensearch"
  domain_name                     = "opensearchdestination"
  engine_version                  = "OpenSearch_2.17"
  instance_type                   = "t3.small.search"
  instance_count                  = 1
  ebs_enabled                     = true
  volume_size                     = 10
  encrypt_at_rest_enabled         = true
  security_options_enabled        = true
  anonymous_auth_enabled          = true
  internal_user_database_enabled  = true
  master_user_name                = tostring(data.vault_generic_secret.opensearch.data["username"])
  master_user_password            = tostring(data.vault_generic_secret.opensearch.data["password"])
  node_to_node_encryption_enabled = true
}

# -----------------------------------------------------------------------------------------
# Firehose delivery stream configuration
# -----------------------------------------------------------------------------------------
module "firehose_backup" {
  source      = "./modules/s3"
  bucket_name = "firehose-opensearch-backup-${random_id.random.hex}"
  objects = []
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = true
}

module "firehose_role" {
  source             = "./modules/iam"
  role_name          = "firehose_role"
  role_description   = "firehose_role"
  policy_name        = "firehose_iam_policy"
  policy_description = "firehose_iam_policy"
  assume_role_policy = <<EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Principal": {
            "Service": "firehose.amazonaws.com"
          },
          "Effect": "Allow",
          "Sid": ""
        }
      ]
    }
    EOF
  policy             = <<EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "",
          "Effect": "Allow",
          "Action": [
              "es:DescribeDomain",
              "es:DescribeDomains",
              "es:DescribeDomainConfig",
              "es:ESHttpPost",
              "es:ESHttpPut"
          ],
          "Resource": [
              "${module.opensearch.domain_arn}",
              "${module.opensearch.domain_arn}/*"
          ]
        },
        {
          "Effect": "Allow",
          "Action": [
              "s3:AbortMultipartUpload",
              "s3:GetBucketLocation",
              "s3:GetObject",
              "s3:ListBucket",
              "s3:ListBucketMultipartUploads",
              "s3:PutObject"
          ],
          "Resource": [
            "${module.firehose_backup.arn}",
            "${module.firehose_backup.arn}/*"
          ]
        },
        {
          "Sid": "",
          "Effect": "Allow",
          "Action": [
              "logs:CreateLogStream",
              "logs:PutLogEvents"
          ],
          "Resource": [
              "arn:aws:logs:*:*:*"
          ]
        }
      ]
    }
    EOF
}

# Kinesis Data Firehose delivery stream
resource "aws_kinesis_firehose_delivery_stream" "opensearch_stream" {
  name        = "opensearch-delivery-stream"
  destination = "opensearch"
  kinesis_source_configuration {
    kinesis_stream_arn = module.kinesis_stream.arn
    role_arn           = module.firehose_role.arn
  }
  opensearch_configuration {
    domain_arn            = module.opensearch.domain_arn
    role_arn              = module.firehose_role.arn
    index_name            = "firehose-index"
    index_rotation_period = "OneDay"
    s3_configuration {
      role_arn           = module.firehose_role.arn
      bucket_arn         = module.firehose_backup.arn
      compression_format = "GZIP"
    }
    # vpc_config {
    #   subnet_ids         = [aws_subnet.example.id]
    #   security_group_ids = [aws_security_group.example.id]
    #   role_arn           = module.firehose_role.arn
    # }

    s3_backup_mode = "AllDocuments"
  }
  depends_on = [module.opensearch]
}

# -----------------------------------------------------------------------------------------
# Cloudwatch logs subscription filter
# -----------------------------------------------------------------------------------------
module "cloudwatch_to_kinesis_role" {
  source             = "./modules/iam"
  role_name          = "cloudwatch-to-kinesis-role"
  role_description   = "cloudwatch-to-kinesis-role"
  policy_name        = "cloudwatch-to-kinesis-policy"
  policy_description = "cloudwatch-to-kinesis-policy"
  assume_role_policy = <<EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Principal": {
            "Service": "logs.amazonaws.com"
          },
          "Effect": "Allow",
          "Sid": ""
        }
      ]
    }
    EOF
  policy             = <<EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "",
          "Effect": "Allow",
          "Action": [
              "kinesis:PutRecord",
              "kinesis:PutRecords"
          ],
          "Resource": [
              "${module.kinesis_stream.arn}"
          ]
        }
      ]
    }
    EOF
}

resource "aws_cloudwatch_log_subscription_filter" "carshub_frontend_log_subscription" {
  name            = "carshub-frontend-log-subscription"
  log_group_name  = module.carshub_frontend_log_group.name
  filter_pattern  = ""
  destination_arn = module.kinesis_stream.arn
  role_arn        = module.cloudwatch_to_kinesis_role.arn
  distribution    = "ByLogStream"
}

resource "aws_cloudwatch_log_subscription_filter" "carshub_backend_log_subscription" {
  name            = "carshub-backend-log-subscription"
  log_group_name  = module.carshub_backend_log_group.name
  filter_pattern  = ""
  destination_arn = module.kinesis_stream.arn
  role_arn        = module.cloudwatch_to_kinesis_role.arn
  distribution    = "ByLogStream"
}