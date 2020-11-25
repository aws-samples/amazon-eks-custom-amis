#!/usr/bin/env bash

set -e

PARAMS=""
CLUSTER_NAME=""
NODE_GROUP_NAME=""
AMI_ID=""
INSTANCE_TYPE="t3.xlarge"

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        --cluster)
            CLUSTER_NAME="$2"
            shift # past argument
            shift # past value
            ;;
        --name)
            NODE_GROUP_NAME="$2"
            shift # past argument
            shift # past value
            ;;
        --ami)
            AMI_ID="$2"
            shift # past argument
            shift # past value
            ;;
        --instance-type)
            INSTANCE_TYPE="$2"
            shift # past argument
            shift # past value
            ;;
        *)    # unknown option
            POSITIONAL+=("$1") # save it in an array for later
            shift # past argument
            ;;
    esac
done

if [ -z "${CLUSTER_NAME}" ]; then
    echo "You must specify --cluster flag with the name of the cluster"
    exit 1
fi

if [ -z "${NODE_GROUP_NAME}" ]; then
    echo "You must specify --name flag with the name of the node group"
    exit 1
fi

if [ -z "${AMI_ID}" ]; then
    echo "You must specify --ami flag with the ID of the AMI"
    exit 1
fi

TMP_USER_DATA_FILE=$(pwd)/tmp_userdata.sh
TMP_LT_FILE=$(pwd)/tmp_lt.json

echo -e '#!/bin/bash' >> ${TMP_USER_DATA_FILE}
echo "/etc/eks/bootstrap.sh ${CLUSTER_NAME} --kubelet-extra-args '--node-labels=eks.amazonaws.com/nodegroup=${NODE_GROUP_NAME},eks.amazonaws.com/nodegroup-image=${AMI_ID}'" >> ${TMP_USER_DATA_FILE}

cat > ${TMP_LT_FILE} <<EOF
{
    "ImageId":"${AMI_ID}",
    "InstanceType":"${INSTANCE_TYPE}",
    "UserData":"$(cat $TMP_USER_DATA_FILE | base64)",
    "TagSpecifications":[
        {
            "ResourceType":"instance",
            "Tags":[
                {
                    "Key":"Name",
                    "Value":"${CLUSTER_NAME}-ng-${NODE_GROUP_NAME}-Node"
                },
                {
                    "Key":"kubernetes.io/cluster/${CLUSTER_NAME}",
                    "Value":"owned"
                },
                {
                    "Key":"alpha.eksctl.io/nodegroup-name",
                    "Value":"${NODE_GROUP_NAME}"
                },
                {
                    "Key":"alpha.eksctl.io/nodegroup-type",
                    "Value":"managed"
                }
            ]
        }
    ]
}
EOF

LT_ID=$(aws ec2 create-launch-template --launch-template-name="eksctl-${CLUSTER_NAME}-nodegroup-${NODE_GROUP_NAME}" --launch-template-data=file://$TMP_LT_FILE --output=text --query="LaunchTemplate.LaunchTemplateId")
rm -f ${TMP_LT_FILE} ${TMP_USER_DATA_FILE}

echo "${LT_ID}"
