# Registering vault provider
data "vault_generic_secret" "opensearch" {
  path = "secret/opensearch"
}

resource "random_id" "random" {
  byte_length = 8
}

# VPC Configuration
module "vpc" {
  source                = "./modules/vpc/vpc"
  vpc_name              = "vpc"
  vpc_cidr_block        = "10.0.0.0/16"
  enable_dns_hostnames  = true
  enable_dns_support    = true
  internet_gateway_name = "vpc_igw"
}

# Security Group
module "ecs_lb_sg" {
  source = "./modules/vpc/security_groups"
  vpc_id = module.vpc.vpc_id
  name   = "ecs_lb_sg"
  ingress = [
    {
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      self            = "false"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      description     = "any"
    }
  ]
  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

module "ecs_sg" {
  source = "./modules/vpc/security_groups"
  vpc_id = module.vpc.vpc_id
  name   = "ecs_lb_sg"
  ingress = [
    {
      from_port       = 3000
      to_port         = 3000
      protocol        = "tcp"
      self            = "false"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      description     = "any"
    }
  ]
  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

module "asg_lb_sg" {
  source = "./modules/vpc/security_groups"
  vpc_id = module.vpc.vpc_id
  name   = "asg-lb-sg"
  ingress = [
    {
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      self            = "false"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      description     = "any"
    }
  ]
  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

module "asg_sg" {
  source = "./modules/vpc/security_groups"
  vpc_id = module.vpc.vpc_id
  name   = "asg-sg"
  ingress = [
    {
      from_port       = 3000
      to_port         = 3000
      protocol        = "tcp"
      self            = "false"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      description     = "any"
    }
  ]
  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

# Public Subnets
module "public_subnets" {
  source = "./modules/vpc/subnets"
  name   = "public-subnet"
  subnets = [
    {
      subnet = "10.0.1.0/24"
      az     = "us-east-1a"
    },
    {
      subnet = "10.0.2.0/24"
      az     = "us-east-1b"
    },
    {
      subnet = "10.0.3.0/24"
      az     = "us-east-1c"
    }
  ]
  vpc_id                  = module.vpc.vpc_id
  map_public_ip_on_launch = true
}

# Private Subnets
module "private_subnets" {
  source = "./modules/vpc/subnets"
  name   = "private-subnet"
  subnets = [
    {
      subnet = "10.0.6.0/24"
      az     = "us-east-1a"
    },
    {
      subnet = "10.0.5.0/24"
      az     = "us-east-1b"
    },
    {
      subnet = "10.0.4.0/24"
      az     = "us-east-1c"
    }
  ]
  vpc_id                  = module.vpc.vpc_id
  map_public_ip_on_launch = false
}

# Public Route Table
module "public_rt" {
  source  = "./modules/vpc/route_tables"
  name    = "public-route-table"
  subnets = module.public_subnets.subnets[*]
  routes = [
    {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = ""
      gateway_id     = module.vpc.igw_id
    }
  ]
  vpc_id = module.vpc.vpc_id
}

# Private Route Table
module "private_rt" {
  source  = "./modules/vpc/route_tables"
  name    = "private-route-table"
  subnets = module.private_subnets.subnets[*]
  routes  = []
  vpc_id  = module.vpc.vpc_id
}

# Lambda Function Code Bucket
module "lambda_function_code_bucket" {
  source      = "./modules/s3"
  bucket_name = "lambda-function-code-${random_id.random.hex}"
  objects = [
    {
      key    = "lambda_function.zip"
      source = "./files/lambda_function.zip"
    }
  ]
  versioning_enabled = "Enabled"
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT", "POST", "GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  force_destroy = true
}

# Lambda IAM  Role
module "lambda_function_iam_role" {
  source             = "./modules/iam"
  role_name          = "lambda-function-iam-role"
  role_description   = "lambda-function-iam-role"
  policy_name        = "lambda-function-iam-policy"
  policy_description = "lambda-function-iam-policy"
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
            }
        ]
    }
    EOF
}

# Lambda function to process media files
module "lambda_function" {
  source        = "./modules/lambda"
  function_name = "lambda-function"
  role_arn      = module.lambda_function_iam_role.arn
  permissions   = []
  env_variables = {}
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  s3_bucket     = module.lambda_function_code_bucket.bucket
  s3_key        = "lambda_function.zip"
  depends_on    = [module.lambda_function_code_bucket]
}

# -----------------------------------------------------------------------------------------
# ECR Configuration
# -----------------------------------------------------------------------------------------
module "ecr_container_registry" {
  source               = "./modules/ecr"
  force_delete         = true
  scan_on_push         = false
  image_tag_mutability = "IMMUTABLE"
  bash_command         = "bash ${path.cwd}/../src/nodeapp/artifact_push.sh nodeapp ${var.region}"
  name                 = "nodeapp"
}

# -----------------------------------------------------------------------------------------
# Load Balancer Configuration
# -----------------------------------------------------------------------------------------

# ECS Load Balancer
module "ecs_lb" {
  source                     = "./modules/load-balancer"
  lb_name                    = "ecs-lb"
  lb_is_internal             = false
  lb_ip_address_type         = "ipv4"
  load_balancer_type         = "application"
  enable_deletion_protection = true
  security_groups            = [module.ecs_lb_sg.id]
  subnets                    = module.public_subnets.subnets[*].id
  target_groups = [
    {
      target_group_name                = "ecs-lb-tg"
      target_port                      = 3000
      target_ip_address_type           = "ipv4"
      target_protocol                  = "HTTP"
      target_type                      = "ip"
      target_vpc_id                    = module.vpc.vpc_id
      health_check_interval            = 30
      health_check_path                = "/"
      health_check_enabled             = true
      health_check_protocol            = "HTTP"
      health_check_timeout             = 5
      health_check_healthy_threshold   = 3
      health_check_unhealthy_threshold = 3
      health_check_port                = 3000

    }
  ]
  listeners = [
    {
      listener_port     = 80
      listener_protocol = "HTTP"
      certificate_arn   = null
      default_actions = [
        {
          type             = "forward"
          target_group_arn = module.ecs_lb.target_groups[0].arn
        }
      ]
    }
  ]
}

# -----------------------------------------------------------------------------------------
# ECS Configuration
# -----------------------------------------------------------------------------------------

resource "aws_ecs_cluster" "ecs_cluster" {
  name = "ecs_cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Cloudwatch log groups for ecs service logs
module "ecs_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/ecs/nodeapp"
  retention_in_days = 30
}

module "lambda_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/lambda/nodeapp"
  retention_in_days = 30
}

module "ec2_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/ec2/nodeapp"
  retention_in_days = 30
}

data "aws_iam_policy_document" "s3_put_object_policy_document" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "s3_put_policy" {
  name        = "s3_put_policy"
  description = "Policy for allowing PutObject action"
  policy      = data.aws_iam_policy_document.s3_put_object_policy_document.json
}

# ECR-ECS IAM Role
resource "aws_iam_role" "ecs_task_execution_role" {
  name               = "ecs-task-execution-role"
  assume_role_policy = <<EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Principal": {
            "Service": "ecs-tasks.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
        }
    ]
    }
    EOF
}

# ECR-ECS policy attachment 
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy_attachment" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# X-Ray tracing
resource "aws_iam_role_policy_attachment" "ecs_task_xray" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy_attachment" "s3_put_object_role_policy_attachment" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = aws_iam_policy.s3_put_policy.arn
}

# Frontend ECS Configuration
module "ecs" {
  source                                   = "./modules/ecs"
  task_definition_family                   = "nodeapp"
  task_definition_requires_compatibilities = ["FARGATE"]
  task_definition_cpu                      = 2048
  task_definition_memory                   = 4096
  task_definition_execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_definition_task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  task_definition_network_mode             = "awsvpc"
  task_definition_cpu_architecture         = "X86_64"
  task_definition_operating_system_family  = "LINUX"
  task_definition_container_definitions = jsonencode(
    [
      {
        "name" : "nodeapp",
        "image" : "${module.ecr_container_registry.repository_url}:latest",
        "cpu" : 1024,
        "memory" : 2048,
        "essential" : true,
        "healthCheck" : {
          "command" : ["CMD-SHELL", "curl -f http://localhost:3000/ || exit 1"],
          "interval" : 30,
          "timeout" : 5,
          "retries" : 3,
          "startPeriod" : 60
        },
        "ulimits" : [
          {
            "name" : "nofile",
            "softLimit" : 65536,
            "hardLimit" : 65536
          }
        ]
        "portMappings" : [
          {
            "containerPort" : 3000,
            "hostPort" : 3000,
            "name" : "nodeapp"
          }
        ],
        "logConfiguration" : {
          "logDriver" : "awslogs",
          "options" : {
            "awslogs-group" : "${module.ecs_log_group.name}",
            "awslogs-region" : "${var.region}",
            "awslogs-stream-prefix" : "ecs"
          }
        },
        environment = []
      },
      {
        "name" : "xray-daemon",
        "image" : "amazon/aws-xray-daemon",
        "cpu" : 32,
        "memoryReservation" : 256,
        "portMappings" : [
          {
            "containerPort" : 2000,
            "protocol" : "udp"
          }
        ]
      },
  ])

  service_name                = "nodeapp"
  service_cluster             = aws_ecs_cluster.ecs_cluster.id
  service_launch_type         = "FARGATE"
  service_scheduling_strategy = "REPLICA"
  service_desired_count       = 1

  deployment_controller_type = "ECS"
  load_balancer_config = [{
    container_name   = "nodeapp"
    container_port   = 3000
    target_group_arn = module.ecs_lb.target_groups[0].arn
  }]

  security_groups = [module.ecs_sg.id]
  subnets = [
    module.public_subnets.subnets[0].id,
    module.public_subnets.subnets[1].id,
    module.public_subnets.subnets[2].id
  ]
  assign_public_ip = true
}

# EC2 IAM Instance Profile
data "aws_iam_policy_document" "instance_profile_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "instance_profile_iam_role" {
  name               = "instance-profile-role"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.instance_profile_assume_role.json
}

data "aws_iam_policy_document" "instance_profile_policy_document" {
  statement {
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "instance_profile_s3_policy" {
  role   = aws_iam_role.instance_profile_iam_role.name
  policy = data.aws_iam_policy_document.instance_profile_policy_document.json
}

resource "aws_iam_instance_profile" "iam_instance_profile" {
  name = "iam-instance-profile"
  role = aws_iam_role.instance_profile_iam_role.name
}

module "asg_launch_template" {
  source                               = "./modules/launch_template"
  name                                 = "asg-launch-template"
  description                          = "asg-launch-template"
  ebs_optimized                        = false
  image_id                             = "ami-005fc0f236362e99f"
  instance_type                        = "t2.micro"
  instance_initiated_shutdown_behavior = "stop"
  instance_profile_name                = aws_iam_instance_profile.iam_instance_profile.name
  key_name                             = "madmaxkeypair"
  network_interfaces = [
    {
      associate_public_ip_address = true
      security_groups             = [module.asg_sg.id]
    }
  ]
  user_data = base64encode(templatefile("${path.module}/scripts/asg_user_data.sh", {}))
}

module "asg" {
  source                    = "./modules/auto_scaling_group"
  name                      = "asg-nodeapp"
  min_size                  = 3
  max_size                  = 50
  desired_capacity          = 3
  health_check_grace_period = 300
  health_check_type         = "ELB"
  force_delete              = true
  target_group_arns         = [module.asg_lb.target_groups[0].arn]
  vpc_zone_identifier       = module.public_subnets.subnets[*].id
  launch_template_id        = module.asg_launch_template.id
  launch_template_version   = "$Latest"
}

module "asg_lb" {
  source                     = "./modules/load-balancer"
  lb_name                    = "asg-lb"
  lb_is_internal             = false
  lb_ip_address_type         = "ipv4"
  load_balancer_type         = "application"
  enable_deletion_protection = true
  security_groups            = [module.asg_lb_sg.id]
  subnets                    = module.public_subnets.subnets[*].id
  target_groups = [
    {
      target_group_name                = "nodeapp"
      target_port                      = 80
      target_ip_address_type           = "ipv4"
      target_protocol                  = "HTTP"
      target_type                      = "instance"
      target_vpc_id                    = module.vpc.vpc_id
      health_check_interval            = 30
      health_check_path                = "/"
      health_check_enabled             = true
      health_check_protocol            = "HTTP"
      health_check_timeout             = 5
      health_check_healthy_threshold   = 3
      health_check_unhealthy_threshold = 3
      health_check_port                = 80
    }
  ]
  listeners = [
    {
      listener_port     = 80
      listener_protocol = "HTTP"
      certificate_arn   = null
      default_actions = [
        {
          type             = "forward"
          target_group_arn = module.asg_lb.target_groups[0].arn
        }
      ]
    }
  ]
}

# Kinesis module
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

# Firehose Role
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
            "${aws_s3_bucket.firehose_backup.arn},
            "${aws_s3_bucket.firehose_backup.arn}/*"
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

# Opensearch module
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

resource "aws_s3_bucket" "firehose_backup" {
  bucket = "firehose-opensearch-backup-${random_id.random.hex}"
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
      bucket_arn         = aws_s3_bucket.firehose_backup.arn
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

resource "aws_cloudwatch_log_subscription_filter" "lambda_log_subscription" {
  name            = "lambda-log-subscription"
  log_group_name  = module.lambda_log_group.name
  filter_pattern  = ""
  destination_arn = module.kinesis_stream.arn
  role_arn        = aws_iam_role.cloudwatch_to_kinesis.arn
  distribution    = "ByLogStream"
}

resource "aws_cloudwatch_log_subscription_filter" "ecs_log_subscription" {
  name            = "ecs-log-subscription"
  log_group_name  = module.ecs_log_group.name
  filter_pattern  = ""
  destination_arn = module.kinesis_stream.arn
  role_arn        = aws_iam_role.cloudwatch_to_kinesis.arn
  distribution    = "ByLogStream"
}

resource "aws_cloudwatch_log_subscription_filter" "ec2_log_subscription" {
  name            = "ec2-log-subscription"
  log_group_name  = module.ec2_log_group.name
  filter_pattern  = ""
  destination_arn = module.kinesis_stream.arn
  role_arn        = aws_iam_role.cloudwatch_to_kinesis.arn
  distribution    = "ByLogStream"
}
