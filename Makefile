
PACKER_VARIABLES := binary_bucket_name binary_bucket_region eks_version eks_build_date cni_plugin_version root_volume_size data_volume_size hardening_flag http_proxy https_proxy no_proxy
VPC_ID := vpc-0e8cf1ce122b1b059
SUBNET_ID := subnet-0eddf1d7d0f9f9772
AWS_REGION := us-east-2
PACKER_FILE :=

EKS_BUILD_DATE := 2020-11-02
EKS_115_VERSION := 1.15.12
EKS_116_VERSION := 1.16.15
EKS_117_VERSION := 1.17.12
EKS_118_VERSION := 1.18.9
EKS_119_VERSION := 1.19.6

build:
	packer build \
		--var 'aws_region=$(AWS_REGION)' \
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

build-al2-1.19:
	$(MAKE) build PACKER_FILE=amazon-eks-node-al2.json eks_version=1.19
