
PACKER_VARIABLES := binary_bucket_name binary_bucket_region eks_version eks_build_date cni_plugin_version hardening_flag http_proxy https_proxy no_proxy
VPC_ID := vpc-20477248
SUBNET_ID := subnet-e81b4980
AWS_REGOIN := ap-south-1
PACKER_FILE := 

EKS_BUILD_DATE := 2020-11-02
EKS_115_VERSION := 1.15.12
EKS_116_VERSION := 1.16.15
EKS_117_VERSION := 1.17.12
EKS_118_VERSION := 1.18.9

build:
	packer build \
		--var 'aws_region=$(AWS_REGOIN)' \
		--var 'vpc_id=$(VPC_ID)' \
		--var 'subnet_id=$(SUBNET_ID)' \
		$(foreach packerVar,$(PACKER_VARIABLES), $(if $($(packerVar)),--var $(packerVar)='$($(packerVar))',)) \
		$(PACKER_FILE)

# Amazon Linux 2
#-----------------------------------------------------
build-al2-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-al2.json eks_version=1.15

build-al2-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-al2.json eks_version=1.16

build-al2-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-al2.json eks_version=1.17

build-al2-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-al2.json eks_version=1.18

# Ubuntu 18.04
#-----------------------------------------------------
build-ubuntu1804-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu1804.json eks_version=$(EKS_115_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-ubuntu1804-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu1804.json eks_version=$(EKS_116_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-ubuntu1804-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu1804.json eks_version=$(EKS_117_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-ubuntu1804-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu1804.json eks_version=$(EKS_118_VERSION) eks_build_date=$(EKS_BUILD_DATE)

# Ubuntu 20.04
#-----------------------------------------------------
build-ubuntu2004-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu2004.json eks_version=$(EKS_115_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-ubuntu2004-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu2004.json eks_version=$(EKS_116_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-ubuntu2004-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu2004.json eks_version=$(EKS_117_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-ubuntu2004-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu2004.json eks_version=$(EKS_118_VERSION) eks_build_date=$(EKS_BUILD_DATE)

# RHEL 7
#-----------------------------------------------------
build-rhel7-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel7.json eks_version=$(EKS_115_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-rhel7-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel7.json eks_version=$(EKS_116_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-rhel7-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel7.json eks_version=$(EKS_117_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-rhel7-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel7.json eks_version=$(EKS_118_VERSION) eks_build_date=$(EKS_BUILD_DATE)

# RHEL 8
#-----------------------------------------------------
build-rhel8-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel8.json eks_version=$(EKS_115_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-rhel8-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel8.json eks_version=$(EKS_116_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-rhel8-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel8.json eks_version=$(EKS_117_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-rhel8-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel8.json eks_version=$(EKS_118_VERSION) eks_build_date=$(EKS_BUILD_DATE)

# CentOS 7
#-----------------------------------------------------
build-centos7-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos7.json eks_version=$(EKS_115_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-centos7-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos7.json eks_version=$(EKS_116_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-centos7-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos7.json eks_version=$(EKS_117_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-centos7-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos7.json eks_version=$(EKS_118_VERSION) eks_build_date=$(EKS_BUILD_DATE)

# CentOS 8
#-----------------------------------------------------
build-centos8-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos8.json eks_version=$(EKS_115_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-centos8-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos8.json eks_version=$(EKS_116_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-centos8-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos8.json eks_version=$(EKS_117_VERSION) eks_build_date=$(EKS_BUILD_DATE)

build-centos8-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos8.json eks_version=$(EKS_118_VERSION) eks_build_date=$(EKS_BUILD_DATE)


