# Amazon EKS Sample Custom AMIs

This repository contains [Packer](https://packer.io/) scripts and definitions to create custom AMIs for use with [Amazon EKS via self-managed Auto Scaling Groups](https://docs.aws.amazon.com/eks/latest/userguide/worker.html) and [Managed Node Groups](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html).  Many organizations require running custom AMIs for security, compliance, or internal policy requirements. **The Amazon EKS Optimized AMI remains the preferred way to deploy containers on Amazon EKS, these AMIs aim to provide a starting place for customers looking to implement custom AMIs with operating systems other than Amazon Linux.** The AMIs built in this repository are based on the [Amazon EKS optimized AMI published by AWS](https://github.com/awslabs/amazon-eks-ami).

This repository also applies the Docker CIS Benchmark and Amazon EKS CIS Benchmark to all AMIs. We also support a number of optional hardening benchmarks such as DISA STIG, PCI-DSS, and HIPAA. These are based on [OpenSCAP](https://www.open-scap.org/) and other open source hardening guidelines.

*Scripts and artifacts created by this repository do not guarantee compliance and these AMIs are not officially supported by AWS. Ensure your security and compliance teams thoroughly review these scripts before moving AMIs into production.*

Lack of support in this repository does not indicate that you can't meet compliance with Amazon EKS, it simply means it is not supported by this repository. We welcome pull requests!

| Distribution | Version | Supported | Supported Hardening |
|:---|:---:|:---:|:---:|
| Amazon Linux | 2 | :white_check_mark: | CIS Benchmark |
| Ubuntu | 18.04 | :white_check_mark: | |
| Ubuntu | 20.04 | :white_check_mark: | |
| Red Hat Enterprise Linux | 7 | :white_check_mark: | CIS Benchmark, NIST 800-171, ACSC, HIPAA, OSPP, PCI-DSS, DISA STIG |
| Red Hat Enterprise Linux | 8 | :white_check_mark: | CIS Benchmark, NIST 800-171, ACSC, HIPAA, OSPP, PCI-DSS, DISA STIG |
| CentOS | 7 | :warning: ([Changing to CentOS Stream](https://blog.centos.org/2020/12/future-is-centos-stream/)) | CIS Benchmark, NIST 800-171, ACSC, HIPAA, OSPP, PCI-DSS |
| CentOS | 8 | :warning: ([Changing to CentOS Stream](https://blog.centos.org/2020/12/future-is-centos-stream/)) | CIS Benchmark, NIST 800-171, ACSC, HIPAA, OSPP, PCI-DSS|

## Installing Dependencies

This repository uses [Packer](https://packer.io/) to build AMIs. You can install these tools from their respective websites or via [Homebrew](https://brew.sh/).

```bash
brew install packer
```

You will also need to provision a VPC with a single public Subnet. You can leverage an existing VPC and Subnet or create one via the console. You will need the VPC ID and Subnet ID for the builds.

## Usage

The Packer commands are encapsulated in Make commands. Packer handles provisioning the instance, the temporary ssh key, temporary security group, and creating the AMI. Below are the variables accepted by the `build` command. The Make commands folllow the following naming convention:

```bash
make build-<operating system>-<eks major version>
```

| Parameter | Default | Description |
|-----------|:-------:|-------------|
| `AWS_REGION` | | The AWS Region to use for the packer instance |
| `VPC_ID` | | The AWS VPC to use for the packer instance |
| `SUBNET_ID`| | The AWS Subnet to use for the packer instance |
| `eks_version`| `1.18.9` | The version of Kubernetes to install. See blow for information on how to get this value. |
| `eks_build_date`| `2020-11-02` | The build date of the Kubernetes build |
| `cni_plugin_version`| `v0.8.6` | The version of the Kubernetes Container Networking Interface (CNI) plugin to install |
| `http_proxy` |  | Specify an HTTP Proxy to use when running commands on the server. This will set the `http_proxy` and `HTTP_PROXY` environment variables on the server while commands are running. |
| `https_proxy` |  | Specify an HTTPS Proxy to use when running commands on the server. This will set the `https_proxy` and `HTTPS_PROXY` environment variables on the server while commands are running. |
| `no_proxy` |  | Specify the no proxy configuration to use when running commands on the server. This will set the `no_proxy` and `NO_PROXY` environment variables on the server while commands are running. |
| `hardening_flag` | `false` | This flag specifies the hardening to apply to the instance. The default is only the Docker and EKS benchmark. |
| `root_volume_size` | `10` | The size of the root volume on the host. |
| `data_volume_size` | `50` | The size of the data volume that is attached to those. This volume houses docker, var, and logs. |

### Using the AMI

The AMI can be used with [self-managed node groups](https://docs.aws.amazon.com/eks/latest/userguide/worker.html) and [managed node groups](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html) within EKS. The AMIs built in this repository use the same [bootstrap script](https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh) used in the EKS Optimized AMI. To join the cluster, run the following command on boot:

```bash
/etc/eks/bootstrap.sh <cluster name> --kubelet-extra-args '--node-labels=eks.amazonaws.com/nodegroup=<node group name>,eks.amazonaws.com/nodegroup-image=<ami id>'
```

This can also be used with [eksctl](https://eksctl.io/) to create a managed node group with a custom AMI. To use with managed node groups, you will first need to create a Launch Template. You need to create a Launch Template because eksctl uses a type of UserData that only support Amazon Linux 2 so we must provide our own.

```bash
./helpers/eksctl-lt.sh --cluster custom-ami --name ng-1 --ami ami-123456789abcdefgh --instance-type t3.xlarge
# lt-123456789abcdefgh
```

The excerpt from a `cluster.yml` shows how to supply a Launch Template ID:

```yaml
managedNodeGroups:
  - name: ng-1
    ami: <id of created AMI>
    instanceType: t3.xlarge
    minSize: 3
    desiredCapacity: 3
    maxSize: 6
    privateNetworking: true
    labels:
      role: worker
    tags:
      k8s.io/cluster-autoscaler/enabled: "true"
      k8s.io/cluster-autoscaler/<cluster name>: "true"
    launchTemplate:
      id: lt-123456789abcdefgh
```

### Supported Operating Systems

The following operating systems are supported by this repository. This repository is not officially supported by AWS or Amazon EKS.

#### Amazon Linux

| Distribution | Version | Build Command | CIS Benchmark |
|:---|:---:|:---:|:---:|
| Amazon Linux | 2 | `build-al2-<eks major version>` | `hardening_flag=cis` |

The Amazon Linux 2 EKS Optmized AMI is used as the base for this image. This image extends the EKS Optimized AMI to apply the Amazon Linux 2 CIS Benchmark, Docker CIS Benchmark, and Amazon EKS CIS Benchmark. These benchmarks are typically used to meet NIST 800-53 controls. Hardening is provided as a "best effort" and does not guarantee compliance with the above frameworks.

```bash
# build amazon linux 2 for amazon eks 1.15
make build-al2-1.15

# build amazon linux 2 for amazon eks 1.16
make build-al2-1.16

# build amazon linux 2 for amazon eks 1.17
make build-al2-1.17

# build amazon linux 2 for amazon eks 1.18
make build-al2-1.18
```

#### Ubuntu

| Distribution | Version | Supported |
|:---|:---:|:---:|
| Ubuntu | 18.04 | `build-ubuntu1804-<eks major version>` |
| Ubuntu | 20.04 | `build-ubuntu2004-<eks major version>` |

Ubuntu AMIs are aimed to provide a similar experience to the EKS Optimized AMI. This reposiroty installs Docker and the Amazon EKS components.

```bash
# build ubuntu 18.04 for amazon eks 1.15
make build-ubuntu1804-1.15

# build ubuntu 18.04 for amazon eks 1.16
make build-ubuntu1804-1.16

# build ubuntu 18.04 for amazon eks 1.17
make build-ubuntu1804-1.17

# build ubuntu 18.04 for amazon eks 1.18
make build-ubuntu1804-1.18
```

```bash
# build ubuntu 20.04 for amazon eks 1.15
make build-ubuntu2004-1.15

# build ubuntu 20.04 for amazon eks 1.16
make build-ubuntu2004-1.16

# build ubuntu 20.04 for amazon eks 1.17
make build-ubuntu2004-1.17

# build ubuntu 20.04 for amazon eks 1.18
make build-ubuntu2004-1.18
```

#### Red Hat Enterprise Linux

| Distribution | Version | Build Command  | CIS Benchmark | NIST 800-171 | E8 | HIPAA | OSPP | PCI | DISA STIG |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Red Hat Enterprise Linux | 7 | `build-rhel7-<eks major version>` | `hardening_flag=cis` | `hardening_flag=cui` | `hardening_flag=e8` | `hardening_flag=hipaa` | `hardening_flag=ospp` | `hardening_flag=pci-dss` | `hardening_flag=stig` |
| Red Hat Enterprise Linux | 8 | `build-rhel8-<eks major version>` | `hardening_flag=cis` | `hardening_flag=cui` | `hardening_flag=e8` | `hardening_flag=hipaa` | `hardening_flag=ospp` | `hardening_flag=pci-dss` | `hardening_flag=stig` |

Red Hat Enterprise Linux 7/8 are aimed to provide a similar experience to the EKS Optimized AMI. This reposiroty installs Docker and the Amazon EKS components. OpenSCAP is used to apply the above hardening frameworks. Hardening is provided as a "best effort" and does not guarantee compliance with the above frameworks. Certain adjustments are made in order to work with Amazon EKS:

- This repository leverages the latest version of [Docker CE](https://docs.docker.com/install/) available from Docker. The version of Docker that comes with RHEL 7 is out of date and overidden with the Docker CE repository.
- The `firewalld` serivce is disable to support Docker and Kubernetes.
- When FIPS 140-2 mode is enabled, `boot=<UUID>` is not added as the `/boot` folder is not on a separate partition.
- The SELinux boolean `container_manage_cgroup` is enabled to support containers.
- **Hardening frameworks such as the DISA STIG that enable SELinux require the VPC CNI `aws-node` container be run in privileged mode.**
- Packer does not support RHEL 8 in FIPS mode. SSH authentication breaks once FIPS is enabled. This repository enables FIPS as the last step as a workaround.

```bash
# Red Hat Enterprise Linux 7
################################

# build red hat enterprise linux 7 for amazon eks 1.15
make build-rhel7-1.15

# build red hat enterprise linux 7 for amazon eks 1.16
make build-rhel7-1.16

# build red hat enterprise linux 7 for amazon eks 1.17
make build-rhel7-1.17

# build red hat enterprise linux 7 for amazon eks 1.18
make build-rhel7-1.18

# Red Hat Enterprise Linux 8
################################

# build red hat enterprise linux 8 for amazon eks 1.15
make build-rhel8-1.15

# build red hat enterprise linux 8 for amazon eks 1.16
make build-rhel8-1.16

# build red hat enterprise linux 8 for amazon eks 1.17
make build-rhel8-1.17

# build red hat enterprise linux 8 for amazon eks 1.18
make build-rhel8-1.18
```

#### CentOS

| Distribution | Version | Build Command  | CIS Benchmark | NIST 800-171 | E8 | HIPAA | OSPP | PCI |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| CentOS | 7 | `build-centos7-<eks major version>` | `hardening_flag=cis` | `hardening_flag=cui` | `hardening_flag=e8` | `hardening_flag=hipaa` | `hardening_flag=ospp` | `hardening_flag=pci-dss` |
| CentOS | 8 | `build-centos8-<eks major version>` | `hardening_flag=cis` | `hardening_flag=cui` | `hardening_flag=e8` | `hardening_flag=hipaa` | `hardening_flag=ospp` | `hardening_flag=pci-dss` |

CentOS 7/8 are aimed to provide a similar experience to the EKS Optimized AMI. This reposiroty installs Docker and the Amazon EKS components. OpenSCAP is used to apply the above hardening frameworks. Hardening is provided as a "best effort" and does not guarantee compliance with the above frameworks. Certain adjustments are made in order to work with Amazon EKS:

- The `firewalld` serivce is disable to support Docker and Kubernetes.
- While FIPS 140-2 modules can be applied to CentOS, CentOS has not been formally validated.
- The SELinux boolean `container_manage_cgroup` is enabled to support containers.
- Hardening is applied using RHEL hardening guides.

```bash
# CentOS 7
################################

# build centos 7 for amazon eks 1.15
make build-centos7-1.15

# build centos 7 for amazon eks 1.16
make build-centos7-1.16

# build centos 7 for amazon eks 1.17
make build-centos7-1.17

# build centos 7 for amazon eks 1.18
make build-centos7-1.18

# CentOS 8
################################

# build centos 8 for amazon eks 1.15
make build-centos8-1.15

# build centos 8 for amazon eks 1.16
make build-centos8-1.16

# build centos 8 for amazon eks 1.17
make build-centos8-1.17

# build centos 8 for amazon eks 1.18
make build-centos8-1.18
```

### Fetching the Kubernetes Build Information

Amazon EKS builds and tests specific versions of Kubernetes together for compatability. It is important that you use versions that have been tested together.

| Kubernetes Version | Build Date |
|---|:---:|
| 1.18.9 | 2020-11-02 |
| 1.17.12 | 2020-11-02 |
| 1.16.15 | 2020-11-02 |
| 1.15.12 | 2020-11-02 |

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
