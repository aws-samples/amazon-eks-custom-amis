# Amazon EKS Sample Custom AMIs

This repository contains [Ansible](https://www.ansible.com/) playbooks along with [Packer](https://packer.io/) definitions to create custom AMIs for use with [Amazon EKS via "bring your own" Auto Scaling Groups](https://docs.aws.amazon.com/eks/latest/userguide/worker.html).  Many organizations require running custom AMIs for security, compliance, or internal policy requirements. **The Amazon EKS Optimized AMI remains the preferred way to deploy containers on Amazon EKS, these AMIs aim to provide a starting place for customers looking to implement custom AMIs with operating systems other than Amazon Linux.** The AMIs built in this repository are based on the [Amazon EKS optimized AMI published by AWS](https://github.com/awslabs/amazon-eks-ami).

| Distribution | Version | Supported | Make | STIG Available |
|--------------|:-----------:|:---------:|------|:------:|
| Debian                   | Stretch | :white_check_mark: | `build-debian-stretch`              | |
| Debian                   | Buster  | :x:                |                                     | |
| Ubuntu                   | 16.04   | :white_check_mark: | `build-ubuntu-1604`                 | |
| Ubuntu                   | 18.04   | :white_check_mark: | `build-ubuntu-1804`                 | |
| CentOS                   | 7       | :white_check_mark: | `build-centos-7`                    | |
| CentOS                   | 8       | :x:                |                                     | |
| Red Hat Enterprise Linux | 7       | :white_check_mark: | `build-rhel-7`, `build-rhel-7-stig` | :white_check_mark: |
| Red Hat Enterprise Linux | 8       | :x:                |                                     |  |

## Installing Dependencies

This repository uses [Packer](https://packer.io/) and [Ansible](https://www.ansible.com/) to build AMIs. You can install these tools from their respective websites or via [Homebrew](https://brew.sh/).

```bash
brew install packer ansible
```

You will also need to provision a VPC with a single public Subnet. You can leverage an existing VPC and Subnet or create one via the console. You will need the VPC ID and Subnet ID for the builds.

## Usage

The Packer commands are encapsulated in Make commands. Packer handles provisioning the instance, the temporary ssh key, temporary security group, and running the Ansible playbooks via the Packer SSH proxy. The Make command names can be found in the table above.

```bash
make AWS_REGION=us-east-2 AWS_VPC_ID=vpc-123456789abcdefgh AWS_SUBNET_ID=subnet-123456789abcdefgh build-centos-7
```

| Parameter | Default | Description |
|-----------|:-------:|-------------|
| `AWS_REGION` | | The AWS Region to use for the packer instance |
| `AWS_VPC_ID` | | The AWS VPC to use for the packer instance |
| `AWS_SUBNET_ID`| | The AWS Subnet to use for the packer instance |
| `K8S_VERSION`| `1.15.10` | The version of Kubernetes to install. See blow for information on how to get this value. |
| `K8S_BUILD_DATE`| `2020-02-22` | The build date of the Kubernetes build |
| `CNI_VERSION`| `v0.6.0` | The version of the Kubernetes Container Networking Interface (CNI) to install |
| `CNI_PLUGIN_VERSION`| `v0.7.5` | The version of the Kubernetes Container Networking Interface (CNI) plugin to install |
| `HTTP_PROXY` |  | Specify an HTTP Proxy to use when running commands on the server. This will set the `http_proxy` and `HTTP_PROXY` environment variables on the server while commands are running. |
| `HTTPS_PROXY` |  | Specify an HTTPS Proxy to use when running commands on the server. This will set the `https_proxy` and `HTTPS_PROXY` environment variables on the server while commands are running. |
| `NO_PROXY` |  | Specify the no proxy configuration to use when running commands on the server. This will set the `no_proxy` and `NO_PROXY` environment variables on the server while commands are running. |

#### Getting the Kubernetes Build Information

Amazon EKS builds and tests specific versions of Kubernetes together for compatability. It is important that you use versions that have been tested together. To get the list of support Kubernetes versions run the following command:

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

### Considerations

- This repository leverages the latest version of [Docker CE](https://docs.docker.com/install/) available from Docker. The version of Docker that comes with RHEL 7 is out of date and overidden with the Docker CE repository.
- Custom AMIs are only supported in the bring your own Auto Scaling Group configuration of Amazon EKS worker nodes.

### CIS Benchmark for Docker

Sections 1, 2, and 3 of the [CIS Benchmark for Docker](https://www.cisecurity.org/benchmark/docker/) are applied during image build. Sections 4, 5, 6, 7, and 8 do not apply to Amazon EKS deployments or apply directly to container images. In order to support Amazon EKS we have made a few modifications:

- `2.8 - Enable user namespace support` is not supported by the AWS VPC CNI Driver because it needs to access the host. This can be mitigated via Kubernetes Pod configuration.

### DoD Security Technical Implementation Guides (STIGs)

This repository also supports that have approved [STIGs from DISA](https://public.cyber.mil/stigs/). Currently, the only supported OS is Red Hat Enterprise Linux 7. To apply the STIG to the Red Hat Enterprise Linux base image, install the [Red Hat official STIG playbook](https://github.com/RedHatOfficial/ansible-role-rhel7-stig) from [Ansible Galaxy](https://galaxy.ansible.com/). There is a preconfigured Packer configuration for the STIG image. **These images are reference implementations and still needs to be validated by your security organization. These images are designed to be starting place for regulated environments.**

To get started with the STIG images you will need to install the RHEL 7 STIG:

```bash
cd ./ansible
ansible-galaxy install RedHatOfficial.rhel7_stig
```

Next, in the repositories root directory:

```bash
make AWS_REGION=us-east-2 AWS_VPC_ID=vpc-123456789abcdefgh AWS_SUBNET_ID=subnet-123456789abcdefgh build-rhel-7-stig
```

The follow changes are made to the image in order to support Kubernetes:

- The `net.ipv4.ip_forward=0` set by the STIG is overridden based on Kubernetes requirements to `net.ipv4.ip_forward=1`
- The SELinux boolean `container_manage_cgroup` is enabled to support containers


## License

This library is licensed under the MIT-0 License. See the [LICENSE file](./LICENSE).
