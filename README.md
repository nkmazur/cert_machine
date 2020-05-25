cert_machine
====

Cert_machine utility for generating certificate bundle for Kubernetes.

Cert_machine provides functionality for creating and manage certificate authorities for Kubernetes clusters.

----
# Configuration example
```toml
cluster_name = "Test kubernetes cluster"  # Common name for certificate authority
validity_days = 365  # Validity in days for non CA certificates
master_san = ["10.0.21.1", "10.0.21.2", "10.0.21.3", "10.96.0.1", "m1-test", "m2-test", "m3-test"]  # SAN for kube-apiserver certificate
apiserver_internal_address = "10.0.21.1:6443"  # Apiserver address which will be writen in all kubeconfig files exclude admin.kubeconfig
apiserver_external_address = "192.0.2.1:6443"  # Apiserver address which will be writen in admin and user kubeconfigs
etcd_users = ["calico"]  # Additional user certs for etcd. Optional

[[worker]]  # Worker node section
hostname = "s1.test" # Hostname of worker node
san = ["10.0.22.2", "s1", "s1.test"]  # SAN for kubelet server certificate

[[worker]]
hostname = "s2.test"
san = ["10.0.22.3", "s2", "s2.test"]

[[etcd_server]]  # Etcd node section
filename = "etcd1.test"  # Directory name where certificates for this instance will be stored. Optional
hostname = "etcd1-test"  # Hostname of etcd node
san = ["10.0.23.1", "etcd1-test", "etcd1-test.novalocal"]  # SAN for etcd server and peer certificate

[ca]  # Certificate authority section
country = "RU"  # Country code can be presented in main CA cert. Optional
organization = "Wonderful Technologies inc."  # Organization name can be presented in main CA cert. Optional
organization_unit = "Container Ops"  # Organization unit can be presented in main CA cert. Optional
locality = "Moscow"  # Locality can be presented in main CA cert. Optional
validity_days = 1000  # Validity in days for all CA certs
```
Full example see in [config.toml](/config.toml)

----
# Usage example
Create new ca and all certificates defined in config:
```bash
cert-machine new  # Create new ca and all certificates defined in config file
cert-machine gen-cert apiserver  # Create new certificate for apiserver
cert-machine gen-cert kubelet s1.test  # Create new certificates for node 's1.test'
cert-machine -c my-cluster.toml -o my_cluster new # Create new CA and certs using
# config file 'my-cluster.toml' and write to directory my_cluster
cert-machine gen-cert etcd-user calico  # Create cert for etcd user
cert-machine refresh-all # Create new certificates for masters, etcd and workers
```
