# Amazon EKS Sample Custom AMIs

This repository contains [Packer](https://packer.io/) scripts and definitions to create custom AMIs for use with [Amazon EKS via self-managed Auto Scaling Groups](https://docs.aws.amazon.com/eks/latest/userguide/worker.html) and [Managed Node Groups](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html).  Many organizations require running custom AMIs for security, compliance, or internal policy requirements. **The Amazon EKS Optimized AMI remains the preferred way to deploy containers on Amazon EKS, these AMIs aim to provide a starting place for customers looking to implement custom AMIs with operating systems other than Amazon Linux.** The AMIs built in this repository are based on the [Amazon EKS optimized AMI published by AWS](https://github.com/awslabs/amazon-eks-ami).

| Distribution | Version | CIS Benchmark (cis) | NIST 800-171 (nist) | ACSC (acsc) | HIPAA (hipaa) | OSPP (ospp) | PCI-DSS (pci-dss) | DISA STIG (stig) |
|--------------|:-------:|:----------------:|:--------------------:|:-----------------:|:---------:|:---------:|:---------:|:---------:|
| Amazon Linux             | 2 | :white_check_mark: | :x: | :x: | :x: | :x: | :x: | :x: |
| Ubuntu                   | 18.04 | :x: | :x: | :x: | :x: | :x: | :x: | :x: |
| Red Hat Enterprise Linux | 7 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Red Hat Enterprise Linux | 8 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |

## Installing Dependencies

This repository uses [Packer](https://packer.io/) to build AMIs. You can install these tools from their respective websites or via [Homebrew](https://brew.sh/).

```bash
brew install packer
```

You will also need to provision a VPC with a single public Subnet. You can leverage an existing VPC and Subnet or create one via the console. You will need the VPC ID and Subnet ID for the builds.

## Usage

The Packer commands are encapsulated in Make commands. Packer handles provisioning the instance, the temporary ssh key, temporary security group, and creating the AMI. Below are the variables accepted by the `build` command. This repository also offers convenience commands listed below.

| Parameter | Default | Description |
|-----------|:-------:|-------------|
| `AWS_REGION` | | The AWS Region to use for the packer instance |
| `VPC_ID` | | The AWS VPC to use for the packer instance |
| `SUBNET_ID`| | The AWS Subnet to use for the packer instance |
| `eks_version`| `1.18.8` | The version of Kubernetes to install. See blow for information on how to get this value. |
| `eks_build_date`| `2020-09-18` | The build date of the Kubernetes build |
| `cni_plugin_version`| `v0.8.6` | The version of the Kubernetes Container Networking Interface (CNI) plugin to install |
| `http_proxy` |  | Specify an HTTP Proxy to use when running commands on the server. This will set the `http_proxy` and `HTTP_PROXY` environment variables on the server while commands are running. |
| `https_proxy` |  | Specify an HTTPS Proxy to use when running commands on the server. This will set the `https_proxy` and `HTTPS_PROXY` environment variables on the server while commands are running. |
| `no_proxy` |  | Specify the no proxy configuration to use when running commands on the server. This will set the `no_proxy` and `NO_PROXY` environment variables on the server while commands are running. |

```bash

# build amazon linux 2 images
make build-al2-1.15
make build-al2-1.16
make build-al2-1.17
make build-al2-1.18

# build ubuntu 18.04 images
make build-ubuntu1804-1.15
make build-ubuntu1804-1.16
make build-ubuntu1804-1.17
make build-ubuntu1804-1.18

# build rhel 7 images
make build-rhel7-1.15
make build-rhel7-1.16
make build-rhel7-1.17
make build-rhel7-1.18

# build rhel 8 images
make build-rhel8-1.15
make build-rhel8-1.16
make build-rhel8-1.17
make build-rhel8-1.18

```

### Considerations

- This repository leverages the latest version of [Docker CE](https://docs.docker.com/install/) available from Docker. The version of Docker that comes with RHEL 7 is out of date and overidden with the Docker CE repository.
- Custom AMIs are only supported in the bring your own Auto Scaling Group configuration of Amazon EKS worker nodes.
- Hardening is provided as a "best effort" baseline and should still be independently validated by your organization's security team.

### Hardening

This repository supports standard Container and Operating System (OS) hardening guides. The frameworks can be applied by appending the `hardening_flag` parameter to your build script, for example:

```bash
make build-rhel8-1.18 hardening_flag=stig
```

You can find the full list of supported hardening scripts in the table above. The value of the hardening flag is found in parentheses in the header.

#### CIS Benchmark for Docker

Sections 1, 2, and 3 of the [CIS Benchmark for Docker](https://www.cisecurity.org/benchmark/docker/) are applied during image build. Sections 4, 5, 6, 7, and 8 do not apply to Amazon EKS deployments or apply directly to container images. In order to support Amazon EKS we have made a few modifications:

- `2.8 - Enable user namespace support` is not supported by the AWS VPC CNI Driver because it needs to access the host. This can be mitigated via Kubernetes Pod configuration.

To see the implementation visit the `cis-docker.sh` [script](./scripts/shared/cis-docker.sh).

#### CIS Benchmark for EKS

The worker node sections of the [Amazon EKS CIS Benchmark](https://aws.amazon.com/about-aws/whats-new/2020/07/announcing-cis-benchmark-for-amazon-eks/) are applied during image build.

To see the implementation visit the `cis-eks.sh` [script](./scripts/shared/cis-eks.sh).

#### DoD Security Technical Implementation Guides (STIG)

*Only applies to Red Hat Enterprise Linux AMIs.*

This repository also supports applying the [STIG from DISA](https://public.cyber.mil/stigs/). The Red Hat Enterprise Linux STIG scripts are generated using [OpenSCAP](https://www.open-scap.org/) based on the [NIST Checklist](https://nvd.nist.gov/ncp/checklist/811). **These images are reference implementations and still needs to be validated by your security organization. These images are designed to be starting place for regulated environments.**

To see the implementation visit the `hardening.sh` [RHEL 7](./scripts/rhel7/hardening.sh) and [RHEL 8](./scripts/rhel8/hardening.sh) scripts.

#### Hardening Notes

The following changes are made during the build process to the hardened image in order to support Amazon EC2 and Kubernetes:

- The `boot=UUID=<disk uuid>` from the grub boot configuration has been revmoed. This prevents instances from being stuck booting when FIPS mode is enabled
- `firewalld` service is disabled.
- The SELinux boolean `container_manage_cgroup` is enabled to support containers.

### Fetching the Kubernetes Build Information

Amazon EKS builds and tests specific versions of Kubernetes together for compatability. It is important that you use versions that have been tested together. 

| Kubernetes Version | Build Date | CNI Plugins Version |
|--------------------|------------|---------------------|
| 1.18.8 | 2020-09-18 | v0.8.6 |
| 1.17.11 | 2020-09-18 | v0.8.6 |
| 1.16.13 | 2020-09-18 | v0.8.6 |
| 1.15.11 | 2020-09-18 | v0.8.6 |
| 1.14.9 | 2020-09-18 | v0.8.6 |

To get the list of support Kubernetes versions run the following command:

```bash
aws s3 ls amazon-eks --region=us-west-2
# ...
# PRE 1.14.9/
# PRE 1.15.10/
# ...
```

Once you select a version you will need to get the build date:

```bash
aws s3 ls s3://amazon-eks/1.15.10/ --region=us-west-2
# PRE 2020-02-22/
```

## License

This library is licensed under the MIT-0 License. See the [LICENSE file](./LICENSE).
