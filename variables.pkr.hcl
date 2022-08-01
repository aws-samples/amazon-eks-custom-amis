variable "aws_region" {
  description = "Region where AMI will be created"
  type        = string
  default     = "us-west-2"
}

variable "data_volume_size" {
  description = "Size of the AMI data EBS volume"
  type        = number
  default     = 50
}

variable "root_volume_size" {
  description = "Size of the AMI root EBS volume"
  type        = number
  default     = 10
}

variable "eks_version" {
  description = "The EKS cluster version associated with the AMI created"
  type        = string
  default     = "1.22"
}

variable "http_proxy" {
  description = "The HTTP proxy to set on the AMI created"
  type        = string
  default     = ""
}

variable "https_proxy" {
  description = "The HTTPS proxy to set on the AMI created"
  type        = string
  default     = ""
}

variable "no_proxy" {
  description = "Disables proxying on the AMI created"
  type        = string
  default     = ""
}

variable "source_ami_arch" {
  description = "The architecture of the source AMI. Either `x86_64` or `arm64`"
  type        = string
  default     = "x86_64"
}

variable "source_ami_owner" {
  description = "The owner of the source AMI"
  type        = string
  default     = "amazon"
}

variable "source_ami_owner_govcloud" {
  description = "The owner of the source AMI in the GovCloud region"
  type        = string
  default     = "219670896067"
}

variable "source_ami_ssh_user" {
  description = "The SSH user used when connecting to the AMI for provisioning"
  type        = string
  default     = "ec2-user"
}

variable "subnet_id" {
  description = "The subnet ID where the AMI can be created. Required if a default VPC is not present in the `aws_region`"
  type        = string
  default     = null
}

variable "instance_type" {
  description = "The instance type to use when creating the AMI. Note: this should be adjusted based on the `source_ami_arch` provided"
  type        = string
  default     = "c6i.large"
}

variable "ami_name_prefix" {
  description = "The prefix to use when creating the AMI name. i.e. - `<ami_name_prefix>-<eks_version>-<timestamp>"
  type        = string
  default     = "amazon-eks-node"
}
