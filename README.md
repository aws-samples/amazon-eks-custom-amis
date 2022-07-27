# Amazon EKS Custom AMIs

This repository contains [Packer](https://packer.io/) configurations to create custom AMIs based on the [Amazon EKS optimized AMI](https://github.com/awslabs/amazon-eks-ami). The Amazon EKS Optimized AMI remains the preferred way to deploy containers on Amazon EKS and the configurations provided here are intended to provide a starting point for customers looking to implement custom EKS Optimized AMIs to meet additional security and compliance requirements.

This project applies the Docker CIS Benchmark and Amazon EKS CIS Benchmark to all AMIs. It also provides a number of additional hardening benchmarks such as DISA STIG, PCI-DSS, and HIPAA. These are based on [OpenSCAP](https://www.open-scap.org/) and other open source hardening guidelines.

_Scripts and artifacts created by this repository do not guarantee compliance nor are these AMIs are not officially supported by AWS. It is up to users to review and validate for their individual use cases._

## Supported Distributions

The following AMI distributions are supported by this repository. This repository is not officially supported by AWS or Amazon EKS.

| Distribution | Version | Architecture |     Available      | Supported Hardening |
| :----------- | :-----: | :----------: | :----------------: | ------------------- |
| Amazon Linux |    2    |    x86_64    | :white_check_mark: | CIS Benchmark       |
| Amazon Linux |    2    |    arm64     | :white_check_mark: | CIS Benchmark       |

The Amazon Linux 2 EKS Optmized AMI is used as the base for this image. This image extends the EKS Optimized AMI to apply the Amazon Linux 2 CIS Benchmark, Docker CIS Benchmark, and Amazon EKS CIS Benchmark. These benchmarks are typically used to meet NIST 800-53 controls. Hardening is provided as a "best effort" and does not guarantee compliance with the above frameworks.

## Prerequisites

- [Packer](https://packer.io/) v1.7+ - [installation instructions](https://learn.hashicorp.com/tutorials/packer/get-started-install-cli)

## Build an AMI

Users will need to have a default VPC in the region where the AMI will be created, or provide a subnet ID via the `subnet_id` variable. The remaining variables are optional and can be modified to suit; either through the appropriate `*.pkrvars.hcl` file or by passing via `-var 'key=value'` on the Packer CLI. See the `variables.pkr.hcl` file for variables that are available for customization.

First, inialize the project:

```sh
packer init -upgrade .
```

To build an x86_64 based archicture AMI:

```sh
packer build -var-file=al2_x86_64.pkrvars.hcl -var 'subnet_id=subnet-01abc23' .
```

To build an arm64 based archicture AMI:

```sh
packer build -var-file=al2_arm64.pkrvars.hcl -var 'subnet_id=subnet-01abc23' .
```

## Use AMI

The AMI can be used with [self-managed node groups](https://docs.aws.amazon.com/eks/latest/userguide/worker.html) and [EKS managed node groups](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html) within EKS. The AMIs built in this repository use the same [bootstrap script](https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh) used in the EKS Optimized AMI. To join the cluster, run the following command on boot:

```bash
/etc/eks/bootstrap.sh <cluster name> --kubelet-extra-args '--node-labels=eks.amazonaws.com/nodegroup=<node group name>,eks.amazonaws.com/nodegroup-image=<ami id>'
```

## License

This library is licensed under the MIT-0 License. See the [LICENSE file](./LICENSE).
