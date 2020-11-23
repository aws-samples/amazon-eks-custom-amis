
PACKER_VARIABLES := binary_bucket_name binary_bucket_region eks_version eks_build_date cni_plugin_version hardening_flag
VPC_ID := vpc-0e8cf1ce122b1b059
SUBNET_ID := subnet-0eddf1d7d0f9f9772
AWS_REGOIN := us-east-2

# Amazon Linux 2
#-----------------------------------------------------
build-al2:
	packer build \
		--var 'aws_region=$(AWS_REGOIN)' \
		--var 'vpc_id=$(VPC_ID)' \
		--var 'subnet_id=$(SUBNET_ID)' \
		$(foreach packerVar,$(PACKER_VARIABLES), $(if $($(packerVar)),--var $(packerVar)='$($(packerVar))',)) \
		./amazon-eks-node-al2.json

build-al2-1.15:
	$(MAKE) build-al2 eks_version=1.15.11 eks_build_date=2020-09-18

build-al2-1.16:
	$(MAKE) build-al2 eks_version=1.16.13 eks_build_date=2020-09-18

build-al2-1.17:
	$(MAKE) build-al2 eks_version=1.17.11 eks_build_date=2020-09-18

build-al2-1.18:
	$(MAKE) build-al2 eks_version=1.18.8 eks_build_date=2020-09-18

build-al2-1.15-nist: 
	$(MAKE) build-al2 eks_version=1.15.11 eks_build_date=2020-09-18 hardening_flag=nist

build-al2-1.16-nist:
	$(MAKE) build-al2 eks_version=1.16.13 eks_build_date=2020-09-18 hardening_flag=nist

build-al2-1.17-nist:
	$(MAKE) build-al2 eks_version=1.17.11 eks_build_date=2020-09-18 hardening_flag=nist

build-al2-1.18-nist:
	$(MAKE) build-al2 eks_version=1.18.8 eks_build_date=2020-09-18 hardening_flag=nist

# Ubuntu 18.04
#-----------------------------------------------------
build-ubuntu1804:
	packer build \
		--var 'aws_region=$(AWS_REGOIN)' \
		--var 'vpc_id=$(VPC_ID)' \
		--var 'subnet_id=$(SUBNET_ID)' \
		$(foreach packerVar,$(PACKER_VARIABLES), $(if $($(packerVar)),--var $(packerVar)='$($(packerVar))',)) \
		./amazon-eks-node-ubuntu1804.json

build-ubuntu1804-1.15:
	$(MAKE) build-ubuntu1804 eks_version=1.15.11 eks_build_date=2020-09-18

build-ubuntu1804-1.16:
	$(MAKE) build-ubuntu1804 eks_version=1.16.13 eks_build_date=2020-09-18

build-ubuntu1804-1.17:
	$(MAKE) build-ubuntu1804 eks_version=1.17.11 eks_build_date=2020-09-18

build-ubuntu1804-1.18:
	$(MAKE) build-ubuntu1804 eks_version=1.18.8 eks_build_date=2020-09-18

# RHEL 7
#-----------------------------------------------------
build-rhel7:
	packer build \
		--var 'aws_region=$(AWS_REGOIN)' \
		--var 'vpc_id=$(VPC_ID)' \
		--var 'subnet_id=$(SUBNET_ID)' \
		$(foreach packerVar,$(PACKER_VARIABLES), $(if $($(packerVar)),--var $(packerVar)='$($(packerVar))',)) \
		./amazon-eks-node-rhel7.json

build-rhel7-1.15:
	$(MAKE) build-rhel7 eks_version=1.15.11 eks_build_date=2020-09-18

build-rhel7-1.16:
	$(MAKE) build-rhel7 eks_version=1.16.13 eks_build_date=2020-09-18

build-rhel7-1.17:
	$(MAKE) build-rhel7 eks_version=1.17.11 eks_build_date=2020-09-18

build-rhel7-1.18:
	$(MAKE) build-rhel7 eks_version=1.18.8 eks_build_date=2020-09-18

build-rhel7-1.15-stig:
	$(MAKE) build-rhel7 eks_version=1.15.11 eks_build_date=2020-09-18 hardening_flag=stig

build-rhel7-1.16-stig:
	$(MAKE) build-rhel7 eks_version=1.16.13 eks_build_date=2020-09-18 hardening_flag=stig

build-rhel7-1.17-stig:
	$(MAKE) build-rhel7 eks_version=1.17.11 eks_build_date=2020-09-18 hardening_flag=stig

build-rhel7-1.18-stig:
	$(MAKE) build-rhel7 eks_version=1.18.8 eks_build_date=2020-09-18 hardening_flag=stig

# RHEL 8
#-----------------------------------------------------
build-rhel8:
	packer build \
		--var 'aws_region=$(AWS_REGOIN)' \
		--var 'vpc_id=$(VPC_ID)' \
		--var 'subnet_id=$(SUBNET_ID)' \
		$(foreach packerVar,$(PACKER_VARIABLES), $(if $($(packerVar)),--var $(packerVar)='$($(packerVar))',)) \
		./amazon-eks-node-rhel8.json

build-rhel8-1.15:
	$(MAKE) build-rhel8 eks_version=1.15.11 eks_build_date=2020-09-18

build-rhel8-1.16:
	$(MAKE) build-rhel8 eks_version=1.16.13 eks_build_date=2020-09-18

build-rhel8-1.17:
	$(MAKE) build-rhel8 eks_version=1.17.11 eks_build_date=2020-09-18

build-rhel8-1.18:
	$(MAKE) build-rhel8 eks_version=1.18.8 eks_build_date=2020-09-18

build-rhel8-1.15-stig:
	$(MAKE) build-rhel8 eks_version=1.15.11 eks_build_date=2020-09-18 hardening_flag=stig

build-rhel8-1.16-stig:
	$(MAKE) build-rhel8 eks_version=1.16.13 eks_build_date=2020-09-18 hardening_flag=stig

build-rhel8-1.17-stig:
	$(MAKE) build-rhel8 eks_version=1.17.11 eks_build_date=2020-09-18 hardening_flag=stig

build-rhel8-1.18-stig:
	$(MAKE) build-rhel8 eks_version=1.18.8 eks_build_date=2020-09-18 hardening_flag=stig



