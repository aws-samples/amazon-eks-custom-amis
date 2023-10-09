ami_name_prefix = "amazon-eks-arm64"
ami_type        = "amazon-linux-2-arm64"
ami_description = "Amazon EKS Kubernetes arm64 AMI based on AmazonLinux2 OS"
instance_type   = "c6g.large"

ami_block_device_mappings = [
  {
    device_name = "/dev/xvda"
    volume_size = 10
  },
]

launch_block_device_mappings = [
  {
    device_name = "/dev/xvda"
    volume_size = 10
  },
  {
    device_name = "/dev/xvdb"
    volume_size = 64
  },
]

shell_provisioner1 = {
  expect_disconnect = true
  scripts = [
    "scripts/update.sh"
  ]
}

shell_provisioner2 = {
  expect_disconnect = true
  // Pass in values below if enabling proxy support
  // environment_vars = [
  //     "HTTP_PROXY=xxx",
  //     "HTTPS_PROXY=xxx",
  //     "NO_PROXY=xxx",
  //   ]
  scripts = [
    "scripts/partition-disks.sh",
    "scripts/configure-proxy.sh",
    "scripts/configure-containers.sh",
  ]
}

shell_provisioner3 = {
  expect_disconnect = true
  scripts = [
    "scripts/cis-benchmark.sh",
    "scripts/cis-eks.sh",
    "scripts/cleanup.sh",
    "scripts/cis-benchmark-tmpmount.sh",
  ]
}
