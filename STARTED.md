# Getting started

For a proper installation you should use tagged images and your own implementation of kubernetes manifests, for a quick start however feel free to follow the instruction below.

## Installing proxy

The following command is going to install the proxy component, while adding a webhook that disables normal kubectl exec.

```
kustomize build manifests/ | kubectl -n kube-system apply -f -
```

## Installing the plugin

Ensure that you go bin directory is in the path.

```
go install github.com/adyen/kubectl-rexec@latest
```

## Observe events 

Tail the logs of the proxy to see audit events, and ideally set up a logshipping setup that suits you to store them.

```
kubectl -n kube-system logs -l app=rexec -f
```

## Use the plugin

The rexec plugin has the same params as the upstream exec command.

```
kubectl rexec exec -ti some-pod -- bash
```