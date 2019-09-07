#!/bin/sh

echo "Enter the path to the p8 file: "
read K8FILE
echo "Hi $K8FILE"
kubectl create secret generic k8key.p8 --from-file=$K8FILE
echo "Enter the path to config.yaml file:"
read CONFIG
echo "Config file: $CONFIG"
kubectl create secret generic config.yaml --from-file=$CONFIG