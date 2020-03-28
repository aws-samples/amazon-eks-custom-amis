# Amazon EKS Sample Custom AMIs

This repository contains Ansible playbooks along with Packer definitions to create custom AMIs for use with Amazon EKS via "bring your own" Auto Scaling Groups.  Many organizations require running custom AMIs for security, compliance, or internal policy requirements. **The Amazon EKS Optimized AMI remains the preferred way to deploy containers on Amazon EKS**, these AMIs aim to provide a starting place for customers looking to implement custom AMIs. The AMIs built in this repository are based on the [Amazon EKS optimized AMI published by AWS](https://github.com/awslabs/amazon-eks-ami).

| Distribution | Versions(s) | Supported | Make | STIG Available |
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
| `AWS_REGION` | `` | The AWS region to build and save the AMI |
| `AWS_VPC_ID` | `` | The AWS VPC to build the AMI |
| `AWS_SUBNET_ID`| `` | The AWS Subnet to build the AMI |
| `K8S_VERSION`| `1.15.10` | The version of Kubernetes to install. See blow for information on how to get this value. |
| `K8S_BUILD_DATE`| `2020-02-22` | The build date of the Kubernetes build |
| `CNI_VERSION`| `v0.6.0` | The version of the Kubernetes Container Networking Interface (CNI) to install |
| `CNI_PLUGIN_VERSION`| `v0.7.5` | The version of the Kubernetes Container Networking Interface (CNI) plugin to install |

#### Getting the Kubernetes Build Information

Amazon EKS builds and tests specific versions of Kubernetes together for compatability. It is important that you use versions that have been tested together. To get the list of support Kubernetes versions run the following command:

```bash
aws s3 ls amazon-eks --region=us-west-2
# PRE 1.10.11/
# PRE 1.10.13/
# PRE 1.10.3/
# PRE 1.11.10/
# PRE 1.11.5/
# PRE 1.11.8/
# PRE 1.11.9/
# PRE 1.12.10/
# PRE 1.12.7/
# PRE 1.12.9/
# PRE 1.13.11/
# PRE 1.13.12/
# PRE 1.13.7/
# PRE 1.13.8/
# PRE 1.14.6/
# PRE 1.14.7/
# PRE 1.14.8/
# PRE 1.14.9/
# PRE 1.15.10/
# PRE cloudformation/
# PRE manifests/
```

Once you select a version you will need to get the build date:

```bash
aws s3 ls s3://amazon-eks/1.15.10/ --region=us-west-2
# PRE 2020-02-22/
```


### Considerations

- This repository leverages the latest version of Docker CE available from Docker. The version of Docker that comes with RHEL 7 is out of date and overidden with the Docker CE repository.
- Custom AMIs are only supported in the bring your own Auto Scaling Group configuration of Amazon EKS worker nodes.
- If you are adding additional agents to the host you may want to edit the CPU and Memory reservations set on the kubelet by editing the [bootstrap.sh script](https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh#L297-L306).

### DoD Security Technical Implementation Guides (STIGs)

This repository also contains images that can be STIGed based on Red Hat Enterprise Linux (RHEL) 7. We achieve this by using Red Hat's official RHEL STIG Ansible Playbook. **This images are reference implementations and still needs to be validated by your security organization.** The goal of these implementations is to provide a starting point for building compliant Amazon EKS AMIs.

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


## License

This library is licensed under the MIT-0 License. See the [LICENSE file](./LICENSE).
