package analyzer

import (
	"regexp"
	"strings"
)

type Category string

const (
	CategoryFingerprint Category = "fingerprint"
	CategoryRecon       Category = "recon"
	CategoryExploit     Category = "exploit"
	CategoryUnknown     Category = "unknown"
)

var ansiEscape = regexp.MustCompile(`(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]|\x1B\][^\x07]*\x07|\x1B[()][AB]|\r`)

type ClassificationResult struct {
	Category        Category
	SuspicionWeight int
	Reason          string
}

var fingerprintPatterns = []struct {
	pattern string
	weight  int
	reason  string
}{
	{"/.dockerenv", 40, "checking for docker environment file"},
	{"/proc/1/cgroup", 35, "reading cgroup to detect containerization"},
	{"/proc/self/cgroup", 35, "reading cgroup to detect containerization"},
	{"/proc/self/status", 20, "reading process status for VM detection"},
	{"systemd-detect-virt", 40, "explicit virtualization detection tool"},
	{"virt-what", 40, "explicit virtualization detection tool"},
	{"dmidecode", 30, "reading DMI data for hardware fingerprinting"},
	{"dmesg", 25, "reading kernel messages for environment clues"},
	{"/proc/version", 20, "checking kernel version for fingerprinting"},
	{"/proc/cpuinfo", 20, "reading CPU info for VM detection"},
	{"container=", 30, "checking container environment variable"},
}

var reconPatterns = []struct {
	pattern string
	weight  int
	reason  string
}{
	{"whoami", 5, "checking current user"},
	{"id", 5, "checking user identity"},
	{"uname", 5, "checking OS info"},
	{"hostname", 5, "checking hostname"},
	{"ifconfig", 8, "network interface reconnaissance"},
	{"ip a", 8, "network interface reconnaissance"},
	{"ip addr", 8, "network interface reconnaissance"},
	{"netstat", 10, "checking network connections"},
	{"ps ", 8, "listing running processes"},
	{"ps\n", 8, "listing running processes"},
	{"w ", 5, "checking logged in users"},
	{"who", 5, "checking logged in users"},
	{"uptime", 3, "checking system uptime"},
	{"env", 5, "dumping environment variables"},
	{"printenv", 5, "dumping environment variables"},
	{"/etc/passwd", 15, "reading password file"},
	{"/etc/shadow", 20, "attempting to read shadow file"},
	{"cat /etc/", 10, "reading system config files"},
	{"ls -la", 5, "detailed directory listing"},
	{"find /", 12, "filesystem search"},
}

var exploitPatterns = []struct {
	pattern string
	weight  int
	reason  string
}{
	{"chmod +s", 50, "setuid bit — privilege escalation attempt"},
	{"chmod 777", 30, "world-writable permission change"},
	{"/bin/bash -p", 50, "privileged bash shell attempt"},
	{"python3 -c", 30, "python code execution"},
	{"python -c", 30, "python code execution"},
	{"pty.spawn", 40, "PTY shell spawning via python"},
	{"nc -e", 50, "netcat reverse shell"},
	{"ncat -e", 50, "netcat reverse shell"},
	{"bash -i", 40, "interactive bash — likely reverse shell"},
	{"bash -c", 25, "bash command execution"},
	{"curl | bash", 60, "remote code execution via curl pipe"},
	{"wget | sh", 60, "remote code execution via wget pipe"},
	{"curl|bash", 60, "remote code execution via curl pipe"},
	{"wget|sh", 60, "remote code execution via wget pipe"},
	{"> /etc/", 40, "writing to system config files"},
	{"dd if=", 35, "disk read/write operation"},
	{"/dev/tcp/", 45, "bash TCP redirect — reverse shell attempt"},
}

func Classify(cmd string) ClassificationResult {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	lower = ansiEscape.ReplaceAllString(lower, "")
	for _, p := range exploitPatterns {
		if strings.Contains(lower, p.pattern) {
			return ClassificationResult{
				Category:        CategoryExploit,
				SuspicionWeight: p.weight,
				Reason:          p.reason,
			}
		}
	}

	for _, p := range fingerprintPatterns {
		if strings.Contains(lower, p.pattern) {
			return ClassificationResult{
				Category:        CategoryFingerprint,
				SuspicionWeight: p.weight,
				Reason:          p.reason,
			}
		}
	}

	for _, p := range reconPatterns {
		if strings.Contains(lower, p.pattern) {
			return ClassificationResult{
				Category:        CategoryRecon,
				SuspicionWeight: p.weight,
				Reason:          p.reason,
			}
		}
	}

	return ClassificationResult{
		Category:        CategoryUnknown,
		SuspicionWeight: 1,
		Reason:          "no pattern matched",
	}
}
