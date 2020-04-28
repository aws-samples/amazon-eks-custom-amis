#!/bin/bash -e

echo "=> Deleting all of the AMIs prefixed with eks-"
AMIS=($(aws ec2 describe-images --owners="self" --filters "Name=name,Values=eks-*" --query="Images[].ImageId" --output=text))

for id in "${AMIS[@]}"
do
    image_name=$(aws ec2 describe-images --image-id=$id --query="Images[0].Name" --output=text)
    echo "Deleting - $id - $image_name"
    aws ec2 deregister-image --image-id=$id
    
done

echo "=> Complete!"
