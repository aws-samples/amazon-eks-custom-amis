AWS_VPC_ID := none
AWS_SUBNET_ID := none
AWS_REGION := us-east-2

K8S_VERSION := 1.15.10
K8S_BUILD_DATE := 2020-02-22
CNI_VERSION := v0.6.0
CNI_PLUGIN_VERSION := v0.7.5

define packer_build
	@echo "Starting Packer Build"
	@echo "VPC ID: $(AWS_VPC_ID)"
	@echo "SUBNET ID: $(AWS_SUBNET_ID)"
	@echo "REGION: $(AWS_REGION)"
	@echo "CONFIG: $1"

	cd ./packer; \
		packer build -var "vpc_id=$(AWS_VPC_ID)" \
			-var "subnet_id=$(AWS_SUBNET_ID)" \
			-var "aws_region=$(AWS_REGION)" \
			-var "k8s_version=$(K8S_VERSION)" \
			-var "k8s_build_date=$(K8S_BUILD_DATE)" \
			-var "cni_version=$(CNI_VERSION)" \
			-var "cni_plugin_version=$(CNI_PLUGIN_VERSION)" \
			$1
endef

install:
	brew install ansible packer
	cd ./ansible; ansible-galaxy install RedHatOfficial.rhel7_stig

build-ubuntu-1604:
	$(call packer_build,"ubuntu-1604.json")

build-ubuntu-1804:
	$(call packer_build,"ubuntu-1804.json")

build-debian-stretch:
	$(call packer_build,"debian-stretch.json")

build-centos-7:
	$(call packer_build,"centos-7.json")

build-rhel-7:
	$(call packer_build,"rhel-7.json")

build-rhel-7-stig:
	$(call packer_build,"rhel-7-stig.json")
