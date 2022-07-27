variable "region" {
  description = "AWS region where VPC resources will be created"
  type        = string
  default     = "us-west-2"
}

variable "name" {
  description = "Name given to the VPC as well as the EKS cluster name (one in the same)"
  type        = string
  default     = "eks-ami-e2e"
}
