
Red Team KubeCTL Cheat Sheet
==============================

Red Kube is a red team cheat sheet based on kubectl commands.


**Warning: You should NOT use red-kube commands on a Kubernetes cluster that you don't own!**

## Prerequisites:
kubectl
```
sudo apt-get update && sudo apt-get install -y apt-transport-https gnupg2 curl
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubectlsudo apt-get update -y
```

jq
```
sudo apt-get update -y
sudo apt-get install -y jq
```

### Available Tactics
| Tactic | Count |
|-------|---------|
| Initial Access  | 0 |
| Execution | 0 |
| Persistence | 0 |
| Privilege Escalation | 1 |
| Defense Evasion | 0 |
| Credential Access | 7 |
| Discovery | 12 |
| Lateral Movement | 0 |
| Collection | 0 |
| Command and Control | 1 |
| Exfiltration | 0 |
| Impact | 0 |
