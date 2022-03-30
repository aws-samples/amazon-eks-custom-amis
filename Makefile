
PACKER_VARIABLES := binary_bucket_name binary_bucket_region eks_version eks_version_withminor eks_build_date cni_plugin_version root_volume_size data_volume_size hardening_flag http_proxy https_proxy no_proxy
VPC_ID := vpc-04421521831249174
SUBNET_ID := subnet-049ea2459d1e821a1
SECURITY_GROUP := sg-0d2795ad6a120d9ff
INSTANCE_PROFILE := ManagedInstanceSSM
AWS_REGION := us-east-2
PACKER_FILE := 
PACKER_OPTIONS = 

EKS_119_VERSION := 1.19.15
EKS_119_BUILD_DATE := 2021-11-10

eks_version = 1.19
eks_build_date = ${EKS_$(subst .,,$(eks_version))_BUILD_DATE}
eks_version_withminor = ${EKS_$(subst .,,$(eks_version))_VERSION}

MAKEFLAGS += -j8

# Backward compatibility target
all-1.19: eks_version = 1.19
all-1.19: $(linux_amis) $(windows_amis)
build-al2-1.19: amazon-eks-node-linux-al2
build-ubuntu1804-1.19: amazon-eks-node-linux-ubuntu1804
build-ubuntu2004-1.19: amazon-eks-node-linux-ubuntu1804
build-rhel7-1.19: amazon-eks-node-linux-rhel7
build-rhel8-1.19: amazon-eks-node-linux-rhel8
build-windows1809full-1.19: amazon-eks-node-windows-1809full
build-windows1809core-1.19: amazon-eks-node-windows-1809core
build-windows2004core-1.19: amazon-eks-node-windows-2004core


linux_amis := amazon-eks-node-linux-al2 amazon-eks-node-linux-ubuntu1804 amazon-eks-node-linux-ubuntu1804 amazon-eks-node-linux-rhel7 amazon-eks-node-linux-rhel8
windows_amis :=  amazon-eks-node-windows-1809full amazon-eks-node-windows-1809core amazon-eks-node-windows-2004core

define build_ami
	packer build \
		$(PACKER_OPTIONS) \
		--var 'aws_region=$(AWS_REGION)' \
		--var 'vpc_id=$(VPC_ID)' \
		--var 'subnet_id=$(SUBNET_ID)' \
		--var 'security_group_id=$(SECURITY_GROUP)' \
		--var 'iam_instance_profile=$(INSTANCE_PROFILE)' \
		$(foreach packerVar,$(PACKER_VARIABLES), $(if $($(packerVar)),--var $(packerVar)='$($(packerVar))',)) \
		$(1)
endef

.PHONY: amazon-eks-node-linux%
amazon-eks-node-%: amazon-eks-node-%.json
	#Dynamic fetching of build-date : aws s3 ls amazon-eks/1.19.13/2021-09-02/bin/linux/amd64/ --region=us-west-2
	$(call build_ami,$<)