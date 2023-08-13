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

<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_amazon-ami"></a> [amazon-ami](#provider\_amazon-ami) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [amazon-ami_amazon-ami.this](https://registry.terraform.io/providers/hashicorp/amazon-ami/latest/docs/data-sources/amazon-ami) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_ami_name_prefix"></a> [ami\_name\_prefix](#input\_ami\_name\_prefix) | The prefix to use when creating the AMI name. i.e. - `<ami_name_prefix>-<eks_version>-<timestamp>` | `string` | `"amazon-eks-node"` | no |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | Region where AMI will be created | `string` | `"us-west-2"` | no |
| <a name="input_data_volume_size"></a> [data\_volume\_size](#input\_data\_volume\_size) | Size of the AMI data EBS volume | `number` | `50` | no |
| <a name="input_eks_version"></a> [eks\_version](#input\_eks\_version) | The EKS cluster version associated with the AMI created | `string` | `"1.22"` | no |
| <a name="input_http_proxy"></a> [http\_proxy](#input\_http\_proxy) | The HTTP proxy to set on the AMI created | `string` | `""` | no |
| <a name="input_https_proxy"></a> [https\_proxy](#input\_https\_proxy) | The HTTPS proxy to set on the AMI created | `string` | `""` | no |
| <a name="input_instance_type"></a> [instance\_type](#input\_instance\_type) | The instance type to use when creating the AMI. Note: this should be adjusted based on the `source_ami_arch` provided | `string` | `"c6i.large"` | no |
| <a name="input_no_proxy"></a> [no\_proxy](#input\_no\_proxy) | Disables proxying on the AMI created | `string` | `""` | no |
| <a name="input_root_volume_size"></a> [root\_volume\_size](#input\_root\_volume\_size) | Size of the AMI root EBS volume | `number` | `10` | no |
| <a name="input_source_ami_arch"></a> [source\_ami\_arch](#input\_source\_ami\_arch) | The architecture of the source AMI. Either `x86_64` or `arm64` | `string` | `"x86_64"` | no |
| <a name="input_source_ami_owner"></a> [source\_ami\_owner](#input\_source\_ami\_owner) | The owner of the source AMI | `string` | `"amazon"` | no |
| <a name="input_source_ami_owner_govcloud"></a> [source\_ami\_owner\_govcloud](#input\_source\_ami\_owner\_govcloud) | The owner of the source AMI in the GovCloud region | `string` | `"219670896067"` | no |
| <a name="input_source_ami_ssh_user"></a> [source\_ami\_ssh\_user](#input\_source\_ami\_ssh\_user) | The SSH user used when connecting to the AMI for provisioning | `string` | `"ec2-user"` | no |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | The subnet ID where the AMI can be created. Required if a default VPC is not present in the `aws_region` | `string` | `null` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->

## License

This library is licensed under the MIT-0 License. See the [LICENSE file](./LICENSE).
