# Pattern matching against three lists:
- Fingerprint patterns: `/.dockerenv`, `/proc/1/cgroup`, `systemd-detect-virt`, `dmidecode` etc

These are the commands that check for virtualization

- Recon patterns: `whoami`, `id`, `netstat`, `/etc/passwd` etc, standard enumeration.
- Exploit patterns: `chmod +s`, `pty.spawn`, `/dev/tcp/`, `curl|bash` etc, privilege escalation and reverse shells.

# Returns a category and a suspicion weight.