#  Kubernetes deployment for gorush push server

## Switching aws EKS clusters

Check if AWS IAM Authenticator for Kubernetes is installed on your localhost:

```bash
aws sts get-caller-identity
```

Update kubeconfig for cluster:
```
aws eks --region us-east-1 update-kubeconfig --name gorush-push
```

[Resource](https://docs.aws.amazon.com/eks/latest/userguide/create-kubeconfig.html)


Set default kubernetes namespace
```bash
kubectl config set-context --current --namespace=gorush
# Validate it
kubectl config view | grep namespace:
```