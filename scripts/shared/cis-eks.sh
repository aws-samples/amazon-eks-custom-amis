#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

echo "1 - control plane configuration"
echo "[not scored] - not applicable for worker node"

echo "2 - control plane configuration"
echo "[not scored] - not applicable for worker node"

echo "3.1.1 - ensure that the kubeconfig file permissions are set to 644 or more restrictive"
chmod 644 /var/lib/kubelet/kubeconfig

echo "3.1.2 - ensure that the kubelet kubeconfig file ownership is set to root:root"
chown root:root /var/lib/kubelet/kubeconfig

echo "3.1.3 - ensure that the kubelet configuration file permissions are set to 644 or more restrictive"
chmod 644 /etc/kubernetes/kubelet/kubelet-config.json

echo "3.1.4 - ensure that the kubelet configuration file ownership is set to root:root"
chown root:root /etc/kubernetes/kubelet/kubelet-config.json

echo "3.2 - kubelet"
cat > /etc/kubernetes/kubelet/kubelet-config.json <<EOF
{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "address": "0.0.0.0",
  "authentication": {
    "anonymous": {
      "enabled": false
    },
    "webhook": {
      "cacheTTL": "2m0s",
      "enabled": true
    },
    "x509": {
      "clientCAFile": "/etc/kubernetes/pki/ca.crt"
    }
  },
  "authorization": {
    "mode": "Webhook",
    "webhook": {
      "cacheAuthorizedTTL": "5m0s",
      "cacheUnauthorizedTTL": "30s"
    }
  },
  "clusterDomain": "cluster.local",
  "hairpinMode": "hairpin-veth",
  "readOnlyPort": 0,
  "cgroupDriver": "cgroupfs",
  "cgroupRoot": "/",
  "featureGates": {
    "RotateKubeletServerCertificate": true
  },
  "protectKernelDefaults": true,
  "serializeImagePulls": false,
  "serverTLSBootstrap": true,
  "streamingConnectionIdleTimeout": "4h0m0s",
  "makeIPTablesUtilChains": true,
  "eventRecordQPS": 5,
  "RotateCertificate": true,
  "tlsCipherSuites": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256"]
}
EOF
