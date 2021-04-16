![red-kube](https://github.com/lightspin-tech/red-kube/blob/main/redcube.png)


Red Team Kubernetes Analysis Based on kubectl
==============================

Red Kube is a collection of kubectl commands to be used in k8s penetration testing or k8s security audit.
The project helps achieve the right point of view for your Kubernetes Security Posture from the attacker's perspective by leveraging the extensive capabilities in kubectl and linux commands.

The commands are either active or passive with mapping to the MITRE ATT&CK Matrix.

The project uses python3 to orchestrate the running commands in linux.

**Warning: You should NOT use red-kube commands on a Kubernetes cluster that you don't own!**

## Prerequisites:

python3 requirements
```bash
pip3 install -r requirements.txt
```

kubectl (Ubuntu / Debian)
```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl
sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubectl
```

kubectl (Red Hat based)
```bash
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
yum install -y kubectl
```

jq
```bash
sudo apt-get update -y
sudo apt-get install -y jq
```

### Commands by MITRE ATT&CK Tactics
| Tactic | Count |
|-------|---------|
| Initial Access  | 0 |
| Execution | 0 |
| Persistence | 2 |
| Privilege Escalation | 4 |
| Defense Evasion | 0 |
| Credential Access | 8 |
| Discovery | 16 |
| Lateral Movement | 0 |
| Collection | 3 |
| Command and Control | 2 |
| Exfiltration | 1 |
| Impact | 0 |

## Webinars
#1 First Workshop with Lab01 and Lab02 [Webinar Link](https://www.lightspin.io/kubernetes-security-concepts-workshop)

#2 Second Workshop with Lab03 and Lab04 [Webinar Link](https://www.lightspin.io/webishop-specific-container-security-in-kubernetes)

## TODO

Defense Evasion: Delete API Audit Logs

Collection: Dump all configmaps and env to a file

## License
This repository is available under the [Apache License 2.0](https://github.com/lightspin-tech/red-kube/blob/main/LICENSE).
