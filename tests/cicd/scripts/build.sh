#!/usr/bin/env

# import the common scripts
source ./scripts/common.sh

# create the cluster
create_cluster

# deploy the aws load balancer controller
deploy_load_balancer_controller

# deploy the cluster autoscaler
deploy_cluster_autoscaler

# deploy the csi drivers
deploy_csi_drivers
