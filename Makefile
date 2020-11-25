
PACKER_VARIABLES := binary_bucket_name binary_bucket_region eks_version eks_build_date cni_plugin_version hardening_flag http_proxy https_proxy no_proxy
VPC_ID := vpc-0e8cf1ce122b1b059
SUBNET_ID := subnet-0eddf1d7d0f9f9772
AWS_REGOIN := us-east-2
PACKER_FILE := 

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
	$(MAKE) build PACKER_FILE=amazon-eks-node-al2.json eks_version=1.15.11 eks_build_date=2020-09-18

build-al2-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-al2.json eks_version=1.16.13 eks_build_date=2020-09-18

build-al2-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-al2.json eks_version=1.17.11 eks_build_date=2020-09-18

build-al2-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-al2.json eks_version=1.18.8 eks_build_date=2020-09-18

# Ubuntu 18.04
#-----------------------------------------------------
build-ubuntu1804-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu1804.json eks_version=1.15.11 eks_build_date=2020-09-18

build-ubuntu1804-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu1804.json eks_version=1.16.13 eks_build_date=2020-09-18

build-ubuntu1804-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu1804.json eks_version=1.17.11 eks_build_date=2020-09-18

build-ubuntu1804-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-ubuntu1804.json eks_version=1.18.8 eks_build_date=2020-09-18

# RHEL 7
#-----------------------------------------------------
build-rhel7-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel7.json eks_version=1.15.11 eks_build_date=2020-09-18

build-rhel7-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel7.json eks_version=1.16.13 eks_build_date=2020-09-18

build-rhel7-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel7.json eks_version=1.17.11 eks_build_date=2020-09-18

build-rhel7-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel7.json eks_version=1.18.8 eks_build_date=2020-09-18

# RHEL 8
#-----------------------------------------------------
build-rhel8-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel8.json eks_version=1.15.11 eks_build_date=2020-09-18

build-rhel8-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel8.json eks_version=1.16.13 eks_build_date=2020-09-18

build-rhel8-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel8.json eks_version=1.17.11 eks_build_date=2020-09-18

build-rhel8-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-rhel8.json eks_version=1.18.8 eks_build_date=2020-09-18

# CentOS 7
#-----------------------------------------------------
build-centos7-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos7.json eks_version=1.15.11 eks_build_date=2020-09-18

build-centos7-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos7.json eks_version=1.16.13 eks_build_date=2020-09-18

build-centos7-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos7.json eks_version=1.17.11 eks_build_date=2020-09-18

build-centos7-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos7.json eks_version=1.18.8 eks_build_date=2020-09-18

# CentOS 8
#-----------------------------------------------------
build-centos8-1.15:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos8.json eks_version=1.15.11 eks_build_date=2020-09-18

build-centos8-1.16:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos8.json eks_version=1.16.13 eks_build_date=2020-09-18

build-centos8-1.17:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos8.json eks_version=1.17.11 eks_build_date=2020-09-18

build-centos8-1.18:
	$(MAKE) build PACKER_FILE=amazon-eks-node-centos8.json eks_version=1.18.8 eks_build_date=2020-09-18


