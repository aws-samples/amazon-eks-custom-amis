#!/usr/bin/env

CLUSTER_NAME=custom-amis

function create_cluster() {
   eksctl create cluster -f ./cluster.yml 
}

function delete_cluster() {
   eksctl delete cluster -f ./cluster.yml 
}

function deploy_load_balancer_controller() {
    local aws_account_id=$(aws sts get-caller-identity --output text --query "Account")
    local service_account_name="aws-load-balancer-controller"
    local service_account_namespace="kube-system"
    local policy_name="AWSLoadBalancerControllerIAMPolicy"
    local policy_arn="arn:aws:iam::${aws_account_id}:policy/${policy_name}"

    if ! aws iam get-policy --policy-arn $policy_arn; then
        curl -sL -o iam-policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json
        aws iam create-policy \
            --policy-name ${policy_name} \
            --policy-document file://iam-policy.json
        rm -f iam-policy.json
    fi

    eksctl create iamserviceaccount --cluster=$CLUSTER_NAME \
        --namespace=$service_account_namespace \
        --name=$service_account_name \
        --attach-policy-arn=$policy_arn \
        --approve

    helm upgrade -i aws-load-balancer-controller eks/aws-load-balancer-controller \
        -n kube-system \
        --set clusterName=$CLUSTER_NAME \
        --set serviceAccount.create=false \
        --set serviceAccount.name=$service_account_name
}

function deploy_cluster_autoscaler() {
    local aws_account_id=$(aws sts get-caller-identity --output text --query "Account")
    local service_account_name="cluster-autoscaler"
    local service_account_namespace="kube-system"
    local policy_name="ClusterAutoscalerPolicy"
    local policy_arn="arn:aws:iam::${aws_account_id}:policy/${policy_name}"

    if ! aws iam get-policy --policy-arn $policy_arn; then
       
        cat > iam-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeAutoScalingInstances",
                "autoscaling:DescribeLaunchConfigurations",
                "autoscaling:DescribeTags",
                "autoscaling:SetDesiredCapacity",
                "autoscaling:TerminateInstanceInAutoScalingGroup",
                "ec2:DescribeLaunchTemplateVersions"
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}
EOF

        aws iam create-policy \
            --policy-name ${policy_name} \
            --policy-document file://iam-policy.json
        rm -f iam-policy.json
    fi

    eksctl create iamserviceaccount --cluster=$CLUSTER_NAME \
        --namespace=$service_account_namespace \
        --name=$service_account_name \
        --attach-policy-arn=$policy_arn \
        --approve

    kubectl apply -f https://raw.githubusercontent.com/kubernetes/autoscaler/master/cluster-autoscaler/cloudprovider/aws/examples/cluster-autoscaler-autodiscover.yaml
    
}

function deploy_csi_drivers() {
    local aws_account_id=$(aws sts get-caller-identity --output text --query "Account")
    local service_account_name="ebs-csi-controller-sa"
    local service_account_namespace="kube-system"
    local policy_name="AmazonEBSCSIDriver"
    local policy_arn="arn:aws:iam::${aws_account_id}:policy/${policy_name}"

    if ! aws iam get-policy --policy-arn $policy_arn; then
        curl -sL -o iam-policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-ebs-csi-driver/v0.8.0/docs/example-iam-policy.json
        aws iam create-policy \
            --policy-name ${policy_name} \
            --policy-document file://iam-policy.json
        rm -f iam-policy.json
    fi

    eksctl create iamserviceaccount --cluster=$CLUSTER_NAME \
        --namespace=$service_account_namespace \
        --name=$service_account_name \
        --attach-policy-arn=$policy_arn \
        --approve

    kubectl apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=master"
}

function deploy_tekton() {


    kubectl create configmap config-artifact-pvc \
        --from-literal=size=5Gi \
        --from-literal=storageClassName=ebs \
        -o yaml -n tekton-pipelines \
        --dry-run=client | kubectl replace -f -

}
