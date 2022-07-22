# Amazon EKS Custom AMIs

This repository contains [Packer](https://packer.io/) configurations to create custom AMIs based on the [Amazon EKS optimized AMI](https://github.com/awslabs/amazon-eks-ami). The Amazon EKS Optimized AMI remains the preferred way to deploy containers on Amazon EKS and the configurations provided here are intended to provide a starting point for customers looking to implement custom EKS Optimized AMIs to meet additional security and compliance requirements.

This project applies the Docker CIS Benchmark and Amazon EKS CIS Benchmark to all AMIs. It also provides a number of additional hardening benchmarks such as DISA STIG, PCI-DSS, and HIPAA. These are based on [OpenSCAP](https://www.open-scap.org/) and other open source hardening guidelines.

_Scripts and artifacts created by this repository do not guarantee compliance nor are these AMIs are not officially supported by AWS. It is up to users to review and validate for their individual use cases._

| Distribution | Version | Architecture |     Available      | Supported Hardening |
| :----------- | :-----: | :----------: | :----------------: | ------------------- |
| Amazon Linux |    2    |    x86_64    | :white_check_mark: | CIS Benchmark       |
| Amazon Linux |    2    |    arm64     | :white_check_mark: | CIS Benchmark       |

## Prerequisites

- [Packer](https://packer.io/) v1.7+ - [installation instructions](https://learn.hashicorp.com/tutorials/packer/get-started-install-cli)

## Usage

The Packer commands are encapsulated in Make commands. Packer handles provisioning the instance, the temporary ssh key, temporary security group, and creating the AMI. Below are the variables accepted by the `build` command. The Make commands folllow the following naming convention:

```bash
make build-<operating system>-<eks major version>
```

| Parameter            |   Default    | Description                                                                                                                                                                                |
| -------------------- | :----------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `AWS_REGION`         |              | The AWS Region to use for the packer instance                                                                                                                                              |
| `VPC_ID`             |              | The AWS VPC to use for the packer instance                                                                                                                                                 |
| `SUBNET_ID`          |              | The AWS Subnet to use for the packer instance                                                                                                                                              |
| `eks_version`        |   `1.18.9`   | The version of Kubernetes to install. See blow for information on how to get this value.                                                                                                   |
| `eks_build_date`     | `2020-11-02` | The build date of the Kubernetes build                                                                                                                                                     |
| `cni_plugin_version` |   `v0.8.6`   | The version of the Kubernetes Container Networking Interface (CNI) plugin to install                                                                                                       |
| `http_proxy`         |              | Specify an HTTP Proxy to use when running commands on the server. This will set the `http_proxy` and `HTTP_PROXY` environment variables on the server while commands are running.          |
| `https_proxy`        |              | Specify an HTTPS Proxy to use when running commands on the server. This will set the `https_proxy` and `HTTPS_PROXY` environment variables on the server while commands are running.       |
| `no_proxy`           |              | Specify the no proxy configuration to use when running commands on the server. This will set the `no_proxy` and `NO_PROXY` environment variables on the server while commands are running. |
| `hardening_flag`     |   `false`    | This flag specifies the hardening to apply to the instance. The default is only the Docker and EKS benchmark.                                                                              |
| `root_volume_size`   |     `10`     | The size of the root volume on the host.                                                                                                                                                   |
| `data_volume_size`   |     `50`     | The size of the data volume that is attached to those. This volume houses docker, var, and logs.                                                                                           |

### Using the AMI

The AMI can be used with [self-managed node groups](https://docs.aws.amazon.com/eks/latest/userguide/worker.html) and [EKS managed node groups](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html) within EKS. The AMIs built in this repository use the same [bootstrap script](https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh) used in the EKS Optimized AMI. To join the cluster, run the following command on boot:

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

| Distribution | Version |          Build Command          |    CIS Benchmark     |
| :----------- | :-----: | :-----------------------------: | :------------------: |
| Amazon Linux |    2    | `build-al2-<eks major version>` | `hardening_flag=cis` |

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

### Fetching the Kubernetes Build Information

Amazon EKS builds and tests specific versions of Kubernetes together for compatability. It is important that you use versions that have been tested together.

| Kubernetes Version | Build Date |
| ------------------ | :--------: |
| 1.18.9             | 2020-11-02 |
| 1.17.12            | 2020-11-02 |
| 1.16.15            | 2020-11-02 |
| 1.15.12            | 2020-11-02 |

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
