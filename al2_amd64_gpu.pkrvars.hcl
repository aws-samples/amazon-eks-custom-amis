ami_name_prefix = "amazon-eks-gpu"
ami_type        = "amazon-linux-2"
ami_description = "Amazon EKS Kubernetes GPU AMI based on AmazonLinux2 OS"
instance_type   = "g4dn.8xlarge"

ami_block_device_mappings = [
  {
    device_name = "/dev/xvda"
    volume_size = 20
  },
]

launch_block_device_mappings = [
  {
    device_name = "/dev/xvda"
    volume_size = 20
  },
]

shell_provisioner1 = {
  scripts = [
    "scripts/nvidia-gpu-install.sh",
    "scripts/cleanup.sh",
  ]
}
