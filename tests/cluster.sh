#!/usr/bin/env bash

set -e

CLUSTER_NAME="custom-amis"
AWS_REGION="us-east-2"

create_lt() {
  local lt_name=$1
  local lt_ami=$2

  if [ "$(aws ec2 describe-launch-templates --launch-template-names eksctl-custom-amis-nodegroup-${lt_name} | jq '.LaunchTemplates | length')" -gt "0" ]; then
    aws ec2 describe-launch-templates --launch-template-names "eksctl-custom-amis-nodegroup-${lt_name}" --query "LaunchTemplates[0].LaunchTemplateId"
  else
    ./helpers/eksctl-lt.sh --cluster custom-amis --name $lt_name --ami $lt_ami
  fi

}

LT_CENTOS_7=$(create_lt ng-centos7-1 ami-044d1dbe037917005)
LT_CENTOS_8=$(create_lt ng-centos8-1 ami-0b2572c575f1c35d8)
LT_RHEL_7=$(create_lt ng-rhel7-1 ami-0ea018c3f542649eb)
LT_RHEL_8=$(create_lt ng-rhel8-1 ami-03586b0f3ba5eb19a)
LT_UBUNTU_1804=$(create_lt ng-ubuntu1804-1 ami-05697729b7648add6)

cat > ./tests/test-cluster.yml <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: custom-amis
  region: $AWS_REGION

managedNodeGroups:
  - name: ng-centos8-1
    minSize: 1
    desiredCapacity: 1
    maxSize: 1
    privateNetworking: true
    iam:
      attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM
    launchTemplate:
      id: $LT_CENTOS_8

  - name: ng-centos7-1
    minSize: 1
    desiredCapacity: 1
    maxSize: 1
    privateNetworking: true
    iam:
      attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM
    launchTemplate:
      id: $LT_CENTOS_7

  - name: ng-rhel7-1
    minSize: 1
    desiredCapacity: 1
    maxSize: 1
    privateNetworking: true
    iam:
      attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM
    launchTemplate:
      id: $LT_RHEL_7

  - name: ng-rhel8-1
    minSize: 1
    desiredCapacity: 1
    maxSize: 1
    privateNetworking: true
    iam:
      attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM
    launchTemplate:
      id: $LT_RHEL_8

  - name: ng-ubuntu1804-1
    minSize: 1
    desiredCapacity: 1
    maxSize: 1
    privateNetworking: true
    iam:
      attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM
    launchTemplate:
      id: $LT_UBUNTU_1804
  
EOF
