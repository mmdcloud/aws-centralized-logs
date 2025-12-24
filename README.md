# Centralized Logs

A production-grade, highly available AWS infrastructure for the CarsHub application, built with Terraform and following AWS best practices for scalability, security, and observability.

## 🏗️ Architecture Overview

CarsHub is deployed as a three-tier architecture on AWS:

- **Frontend Layer**: React application running on EC2 instances behind an Application Load Balancer
- **Backend Layer**: API servers on EC2 instances with ALB for load distribution
- **Data Layer**: RDS MySQL with Multi-AZ deployment, S3 for media storage, and OpenSearch for log analytics

### Key Components

- **Compute**: Auto Scaling Groups with Launch Templates for both frontend and backend
- **Database**: RDS MySQL 8.0 with Multi-AZ, automated backups, and enhanced monitoring
- **Storage**: S3 buckets with versioning, CloudFront CDN for media delivery
- **Networking**: VPC with public/private subnets across 3 AZs, NAT Gateways, VPC Flow Logs
- **Serverless**: Lambda function for media metadata processing with SQS buffering
- **Monitoring**: CloudWatch alarms, log aggregation via Kinesis and OpenSearch
- **Security**: Secrets Manager, IAM roles, Security Groups, Code Signing

## 📋 Prerequisites

- **Terraform**: >= 1.0
- **AWS CLI**: Configured with appropriate credentials
- **Vault**: HashiCorp Vault for secrets management
- **SSH Key**: AWS key pair named `madmaxkeypair` (or update in configuration)

### Required Secrets in Vault

```bash
# RDS credentials
vault kv put secret/rds username=<db_username> password=<db_password>

# OpenSearch credentials
vault kv put secret/opensearch username=<os_username> password=<os_password>
```

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd carshub-infrastructure/terraform/environments/prod
```

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Configure Variables

Create a `terraform.tfvars` file:

```hcl
env             = "prod"
region          = "us-east-1"
azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
public_subnets  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
private_subnets = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
db_name         = "carshubdb"
```

### 4. Review the Plan

```bash
terraform plan
```

### 5. Deploy Infrastructure

```bash
terraform apply
```

## 📦 Infrastructure Components

### Networking

| Component | Configuration |
|-----------|--------------|
| VPC CIDR | 10.0.0.0/16 |
| Availability Zones | 3 (us-east-1a, us-east-1b, us-east-1c) |
| Public Subnets | 3 across AZs |
| Private Subnets | 3 across AZs |
| NAT Gateways | 1 per AZ (high availability) |
| Internet Gateway | Yes |

### Compute Resources

#### Frontend Auto Scaling Group
- **Min/Max/Desired**: 3/50/3 instances
- **Instance Type**: t2.micro
- **AMI**: ami-005fc0f236362e99f (Ubuntu)
- **Health Check**: ELB, 300s grace period
- **Target Port**: 3000

#### Backend Auto Scaling Group
- **Min/Max/Desired**: 3/50/3 instances
- **Instance Type**: t2.micro
- **AMI**: ami-005fc0f236362e99f (Ubuntu)
- **Health Check**: ELB, 300s grace period
- **Target Port**: 80

### Database

#### RDS MySQL Configuration
- **Engine**: MySQL 8.0.40
- **Instance Class**: db.r6g.large
- **Multi-AZ**: Enabled
- **Storage**: 100 GB (gp3), auto-scaling to 500 GB
- **Backups**: 35-day retention, daily automated backups
- **Monitoring**: Enhanced monitoring (60s intervals)
- **Performance Insights**: Enabled (7-day retention)
- **Logs**: Audit, error, general, slow query

#### Database Parameters
- **max_connections**: 1000
- **innodb_buffer_pool_size**: 75% of instance memory
- **slow_query_log**: Enabled

### Storage & CDN

#### S3 Buckets
1. **carshub-media-bucket**: Primary media storage with CloudFront OAC
2. **carshub-media-updatefunctioncode**: Lambda deployment packages
3. **carshub-frontend-lb-logs**: Frontend ALB access logs
4. **carshub-backend-lb-logs**: Backend ALB access logs
5. **firehose-opensearch-backup**: OpenSearch delivery backup

#### CloudFront Distribution
- **Origin**: S3 media bucket
- **Cache Behavior**: GET, HEAD methods cached
- **Price Class**: PriceClass_100 (US, Canada, Europe)
- **Protocol**: Redirect HTTP to HTTPS
- **TTL**: Min 0s, Default 24h, Max 1 year

### Serverless Components

#### Lambda Function: carshub-media-update
- **Runtime**: Python 3.12
- **Trigger**: SQS (carshub-media-events-queue)
- **Batch Size**: 10 messages
- **Timeout**: Configurable via module
- **Code Signing**: Enabled via AWS Signer
- **Layer**: Python dependencies layer

#### SQS Configuration
- **Main Queue**: carshub-media-events-queue
  - Message retention: 4 days
  - Visibility timeout: 180s
  - Dead Letter Queue: After 3 attempts
- **DLQ**: carshub-media-events-dlq
  - Message retention: 1 day

### Security

#### Security Groups

| Security Group | Purpose | Inbound Rules |
|---------------|---------|---------------|
| carshub-frontend-lb-sg | Frontend ALB | 80, 443 from 0.0.0.0/0 |
| carshub-backend-lb-sg | Backend ALB | 80, 443 from 0.0.0.0/0 |
| carshub-asg-frontend-sg | Frontend instances | 3000 from frontend-lb-sg |
| carshub-asg-backend-sg | Backend instances | 80 from backend-lb-sg |
| carshub-rds-sg | RDS database | 3306 from asg-backend-sg |

#### IAM Roles
- **flow-logs-role**: VPC Flow Logs to CloudWatch
- **rds-monitoring-role**: RDS Enhanced Monitoring
- **iam-instance-profile-role**: EC2 instance S3 access
- **carshub-media-update-function-iam-role**: Lambda execution
- **firehose_role**: Kinesis Firehose to OpenSearch
- **cloudwatch-to-kinesis-role**: CloudWatch Logs to Kinesis

#### Secrets Management
- **carshub-rds-secrets**: Database credentials stored in AWS Secrets Manager
- Recovery window: 0 days (immediate deletion on destroy)

### Monitoring & Logging

#### CloudWatch Alarms

| Alarm | Metric | Threshold | Evaluation Period |
|-------|--------|-----------|-------------------|
| Frontend ALB Response Time | TargetResponseTime (p95) | > 1s | 3 periods of 60s |
| Frontend ALB 5XX Errors | HTTPCode_Target_5XX_Count | > 10 | 1 period of 60s |
| Backend ALB Response Time | TargetResponseTime (p95) | > 1s | 3 periods of 60s |
| Backend ALB 5XX Errors | HTTPCode_Target_5XX_Count | > 10 | 1 period of 60s |
| Lambda Errors | Errors | > 0 | 1 period of 300s |
| SQS Queue Depth | ApproximateNumberOfMessagesVisible | > 100 | 1 period of 300s |
| RDS High CPU | CPUUtilization | > 80% | 2 periods of 300s |
| RDS Low Storage | FreeStorageSpace | < 10 GB | 2 periods of 300s |
| RDS High Connections | DatabaseConnections | > 100 | 2 periods of 300s |

**Notifications**: All alarms send notifications to `madmaxcloudonline@gmail.com` via SNS

#### Log Aggregation Pipeline
1. **CloudWatch Log Groups**
   - `/ecs/carshub-frontend` (30-day retention)
   - `/lambda/carshub-backend` (30-day retention)
   - `/carshub/application` (VPC Flow Logs, 365-day retention)

2. **Kinesis Data Stream**
   - Mode: ON_DEMAND (automatic scaling)
   - Retention: 48 hours
   - Metrics: IncomingBytes, OutgoingBytes

3. **Kinesis Firehose**
   - Destination: OpenSearch
   - Index rotation: Daily
   - Backup: S3 with GZIP compression

4. **OpenSearch**
   - Version: 2.17
   - Instance: t3.small.search
   - Storage: 10 GB EBS (encrypted)
   - Authentication: Internal user database

## 🔧 Configuration Files

### User Data Scripts

#### Frontend (`scripts/user_data_frontend.sh`)
```bash
#!/bin/bash
# Install Node.js, clone repo, configure environment
# Variables: BASE_URL, CDN_URL
```

#### Backend (`scripts/user_data_backend.sh`)
```bash
#!/bin/bash
# Install dependencies, configure database connection
# Variables: DB_PATH, UN, CREDS, DB_NAME
```

### Lambda Package Structure
```
files/
├── lambda.zip          # Lambda function code
└── python.zip          # Python dependencies layer
```

## 🔐 Security Best Practices

✅ **Implemented Security Features**:
- VPC with private subnets for compute and database
- Security groups with least-privilege access
- RDS in private subnets with encryption at rest
- Secrets stored in AWS Secrets Manager and Vault
- VPC Flow Logs enabled for network monitoring
- CloudFront with HTTPS redirect
- Lambda code signing enabled
- S3 bucket versioning and encryption
- IAM roles with minimal required permissions
- Multi-AZ deployment for high availability

⚠️ **Security Considerations**:
- Update `madmaxcloudonline@gmail.com` to your monitoring email
- Review and restrict `0.0.0.0/0` CIDR blocks for load balancers based on your requirements
- Enable AWS GuardDuty and Security Hub for additional threat detection
- Implement AWS WAF rules for the ALBs
- Enable MFA delete for S3 buckets in production
- Rotate credentials regularly

## 📊 Outputs

After successful deployment, Terraform outputs:

```hcl
frontend_lb_dns_name    = "carshub-frontend-lb-XXXXXXXX.us-east-1.elb.amazonaws.com"
backend_lb_dns_name     = "carshub-backend-lb-XXXXXXXX.us-east-1.elb.amazonaws.com"
cloudfront_domain_name  = "XXXXXXXXXXXXXX.cloudfront.net"
rds_endpoint           = "carshubdbproduseast1.XXXXXXXXXXXX.us-east-1.rds.amazonaws.com:3306"
opensearch_endpoint    = "opensearchdestination-XXXXXXXXXXXXXXXXXXXX.us-east-1.es.amazonaws.com"
```

## 🧪 Testing

### Health Checks

```bash
# Frontend health
curl http://<frontend_lb_dns_name>/auth/signin

# Backend health
curl http://<backend_lb_dns_name>/

# CloudFront
curl https://<cloudfront_domain_name>/images/
```

### Database Connection

```bash
mysql -h <rds_endpoint> -u <username> -p<password> carshubdb
```

## 📈 Scaling

### Auto Scaling Policies

Both frontend and backend ASGs are configured with:
- **Scale Out**: Manually add policies based on CPU/Memory metrics
- **Scale In**: Gradually reduce instances during low traffic

### Cost Optimization
- Review CloudWatch metrics to right-size EC2 instances
- Implement S3 lifecycle policies for old logs and media
- Consider Reserved Instances or Savings Plans for predictable workloads
- Use AWS Cost Explorer to identify optimization opportunities

## 🔄 CI/CD Integration

This infrastructure supports CI/CD pipelines. Recommended flow:

1. **Build**: Application containers/artifacts
2. **Deploy**: Update Launch Template with new AMI
3. **Rolling Update**: Trigger ASG instance refresh
4. **Validation**: Health check monitoring
5. **Rollback**: Previous Launch Template version if needed

## 🐛 Troubleshooting

### Common Issues

**Issue**: Instances not passing health checks
```bash
# Check target group health
aws elbv2 describe-target-health --target-group-arn <tg_arn>

# Review instance logs
aws logs tail /ecs/carshub-frontend --follow
```

**Issue**: Lambda function errors
```bash
# Check CloudWatch logs
aws logs tail /aws/lambda/carshub-media-update --follow

# Check SQS dead letter queue
aws sqs receive-message --queue-url <dlq_url>
```

**Issue**: High RDS CPU
```bash
# Check slow query log
aws rds download-db-log-file-portion \
  --db-instance-identifier carshubdbproduseast1 \
  --log-file-name slowquery/mysql-slowquery.log
```

## 🗑️ Cleanup

To destroy all resources:

```bash
# Review what will be destroyed
terraform plan -destroy

# Destroy infrastructure
terraform destroy
```

**Note**: Some resources have deletion protection enabled (RDS). Disable before destroying:
```hcl
deletion_protection = false
```

## 📚 Module Documentation

Detailed documentation for custom modules:

- [VPC Module](./modules/vpc/README.md)
- [Security Groups Module](./modules/security-groups/README.md)
- [RDS Module](./modules/rds/README.md)
- [S3 Module](./modules/s3/README.md)
- [Lambda Module](./modules/lambda/README.md)
- [ALB Module](./modules/alb/README.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Support

For issues and questions:
- **Email**: madmaxcloudonline@gmail.com
- **Issues**: [GitHub Issues](https://github.com/your-org/carshub-infrastructure/issues)

## 🎯 Roadmap

- [ ] Implement AWS WAF rules for ALBs
- [ ] Add Route53 DNS configuration
- [ ] Implement automated disaster recovery
- [ ] Add ECS/EKS alternative deployment
- [ ] Integrate with AWS Systems Manager for patching
- [ ] Implement cost allocation tags
- [ ] Add AWS Config rules for compliance

---

**Version**: 1.0.0  
**Last Updated**: December 2025  
**Maintained By**: DevOps Team
