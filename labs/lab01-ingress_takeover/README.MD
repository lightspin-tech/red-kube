Red Kube Lab 01: Ingress Takeover
==============================

The lab demonstrates how an exploited ingress or unauthorized access to the ingress controller can lead to taking over the k8s cluster.

The lab uses several commands from red-kube to create the attack chain.

**Lab Motivation:**

In Kubernetes the users, service accounts and application secrets are stored in the same secret management.
The mixture between secrets related to the control plane and secrets related to the data plane generates a high risk.

The lab takes advantage of that design flaw to steal the admin secret from the ingress controller with list all secrets permission.
Any user or service account with the ability to list all secrets is a 'Shadow Admin' in the Kubernetes Cluster.

```
-------------       -------------       --------------------        -----------------
|           |       |           |       |                  |        |               |
| Attacker  | --->  |  Ingress  | --->  |   Admin Secret   |  --->  | K8S Takeover  |
|           |       |           |       |                  |        |               |
-------------       -------------       --------------------        -----------------
                       rk-ds07
                       rk-ca04              rk-ca06
```

The steps for reproducing the lab is in the attached yaml file.

**Warning: You should NOT use the labs on a Kubernetes cluster that you don't own!**
