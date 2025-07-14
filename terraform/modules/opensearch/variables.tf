variable "domain_name" {}
variable "engine_version" {}

variable "instance_type" {}
variable "instance_count" {}

variable "ebs_enabled" {}
variable "volume_size" {}

variable "encrypt_at_rest_enabled" {}

variable "security_options_enabled" {}
variable "anonymous_auth_enabled" {}
variable "internal_user_database_enabled" {}
variable "master_user_name" {}
variable "master_user_password" {}

variable "node_to_node_encryption_enabled" {}