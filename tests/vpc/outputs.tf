output "id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "public_subnets" {
  description = "VPC public subnet IDs"
  value       = module.vpc.public_subnets
}
