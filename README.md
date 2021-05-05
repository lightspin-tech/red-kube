![red-kube](https://github.com/lightspin-tech/red-kube/blob/main/redcube.png)


Red Team K8S Adversary Emulation Based on kubectl
==============================

Red Kube is a collection of kubectl commands written to evaluate the security posture of Kubernetes clusters from the attacker's perspective.

The commands are either passive for data collection and information disclosure or active for performing real actions that affect the cluster.

The commands are mapped to MITRE ATT&CK Tactics to help get a sense of where we have most of our gaps and prioritize our findings.

The current version is wrapped with a python orchestration module to run several commands in one run based on different scenarios or tactics.

Please use with care as some commands are active and actively deploy new containers or change the role-based access control configuration.


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

## Usage
```bash
usage: python3 main.py [-h] [--mode active/passive/all] [--tactic TACTIC_NAME] [--show_tactics] [--cleanup]

required arguments:
--mode            run kubectl commands which are active / passive / all modes
--tactic          choose tactic

other arguments:
-h --help         show this help message and exit
--show_tactics    show all tactics

```

### Commands by MITRE ATT&CK Tactics
| Tactic | Count |
|-------|---------|
| Reconnaissance  | 2 |
| Initial Access  | 0 |
| Execution | 0 |
| Persistence | 2 |
| Privilege Escalation | 4 |
| Defense Evasion | 1 |
| Credential Access | 8 |
| Discovery | 15 |
| Lateral Movement | 0 |
| Collection | 1 |
| Command and Control | 2 |
| Exfiltration | 1 |
| Impact | 0 |

## Webinars
**1 First Workshop with Lab01 and Lab02 [Webinar Link](https://www.lightspin.io/kubernetes-security-concepts-workshop)**

**2 Second Workshop with Lab03 and Lab04 [Webinar Link](https://www.lightspin.io/webishop-specific-container-security-in-kubernetes)**

## Presentations
**[BlackHat Asia 2021](https://www.blackhat.com/asia-21/arsenal/schedule/#red-kube-22401)**

## Q&A
**Why choosing kubectl and not using the kubernetes api in python?**
When performing red team assessments and adversary emulations, the quick manipulations and tweaks for the tools used in the arsenal are critical.

The ability to run such assessments and combine the k8s attack techniques based on kubectl and powerful Linux commands reduces the time and effort significantly.


### Contact Us
This research was held by Lightspin's Security Research Team.
For more information, contact us at support@lightspin.io.

### License
This repository is available under the [Apache License 2.0](https://github.com/lightspin-tech/red-kube/blob/main/LICENSE).
