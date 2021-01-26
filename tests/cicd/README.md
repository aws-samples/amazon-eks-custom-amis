
```bash
curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-ebs-csi-driver/v0.8.0/docs/example-iam-policy.json

aws iam create-policy --policy-name AmazonEBSCSIDriver \
    --policy-document file://example-iam-policy.json

eksctl create iamserviceaccount \
    --cluster=cicd \
    --namespace=kube-system \
    --name=ebs-csi-controller-sa \
    --attach-policy-arn=arn:aws:iam::858922139614:policy/AmazonEBSCSIDriver \
    --approve

kubectl apply -k "github.com/kubernetes-sigs/aws-ebs-csi-driver/deploy/kubernetes/overlays/stable/?ref=master"
```

```bash
curl -o iam-policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json

aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://iam-policy.json

eksctl create iamserviceaccount \
    --cluster=cicd \
    --namespace=kube-system \
    --name=aws-load-balancer-controller \
    --attach-policy-arn=arn:aws:iam::858922139614:policy/AWSLoadBalancerControllerIAMPolicy \
    --approve
```
