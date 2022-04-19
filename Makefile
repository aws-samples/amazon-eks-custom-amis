packer_variables := binary_bucket_name binary_bucket_region EKS_VERSION eks_version_withminor eks_build_date cni_plugin_version root_volume_size data_volume_size hardening_flag http_proxy https_proxy no_proxy
VPC_ID := vpc-04421521831249174
SUBNET_ID := subnet-049ea2459d1e821a1
SECURITY_GROUP := sg-0d2795ad6a120d9ff
INSTANCE_PROFILE := ManagedInstanceSSM
AWS_REGION := us-east-2
PACKER_OPTIONS = 

EKS_VERSION = 1.19
# Definition should be dynamically fetch
eks_119_version := 1.19.15
eks_119_build_date := 2021-11-10

eks_build_date = ${eks_$(subst .,,$(EKS_VERSION))_build_date}
eks_version_withminor = ${eks_(subst .,,$(EKS_VERSION))_version}

MAKEFLAGS += -j8

# Backward compatibility target
all-1.19: EKS_VERSION = 1.19
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
		$(foreach packerVar,$(packer_variables), $(if $($(packerVar)),--var $(packerVar)='$($(packerVar))',)) \
		$(1)
endef

GET_LATEST_EKS = $(shell aws s3 ls amazon-eks --region=us-west-2 | grep $(EKS_VERSION) | sort -V -r | head -n 1 | sed 's|PRE \(.*\)/|\1|')
set_eks_version_minor = $(eval eks_version_withminor=$(GET_LATEST_EKS))

.PHONY: amazon-eks-node-linux%
amazon-eks-node-%: amazon-eks-node-%.json
	$(set_eks_version_minor)
	@echo $(eks_version_withminor)
	$(call build_ami,$<)