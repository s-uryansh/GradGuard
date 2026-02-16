package detector

import (
	"fmt"
	"os/exec"
)

type ResponseLevel int

const (
	ResponseWarning  ResponseLevel = 1 // score 50 — subtle fakes
	ResponseHigh     ResponseLevel = 2 // score 75 — deeper fakes
	ResponseCritical ResponseLevel = 3 // score 100 — full deception
)

// Execute runs silent container alterations based on confidence level
func Execute(containerName string, confidence Confidence) string {
	switch confidence {
	case ConfidenceWarning:
		applyWarningResponse(containerName)
		return "applied_warning_deception"
	case ConfidenceHigh:
		applyHighResponse(containerName)
		return "applied_high_deception"
	case ConfidenceCritical:
		applyCriticalResponse(containerName)
		return "applied_critical_deception"
	}
	return "none"
}

// WARNING — score 50
// fake /proc/1/cgroup and /.dockerenv
func applyWarningResponse(c string) {
	// make cgroup look like bare metal systemd
	dockerExec(c, `mkdir -p /sys/fs/cgroup && `+
		`echo '0::/init.scope' > /proc/1/cgroup || true`)

	// overwrite /.dockerenv with misleading content
	dockerExec(c, `echo '# system environment' > /.dockerenv && `+
		`echo 'PLATFORM=baremetal' >> /.dockerenv`)
}

// HIGH — score 75
// fake /proc/cpuinfo and add fake users
func applyHighResponse(c string) {
	applyWarningResponse(c)

	// fake cpuinfo to show physical hardware
	dockerExec(c, `cat > /tmp/fake_cpuinfo << 'EOF'
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 158
model name	: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
stepping	: 10
cpu MHz		: 2600.000
cache size	: 12288 KB
physical id	: 0
siblings	: 12
core id		: 0
cpu cores	: 6
flags		: fpu vme de pse tsc msr pae mce cx8 apic
EOF
mount --bind /tmp/fake_cpuinfo /proc/cpuinfo 2>/dev/null || true`)

	// add fake legitimate-looking users
	dockerExec(c, `echo 'deploy:x:1001:1001:Deploy User,,,:/home/deploy:/bin/bash' >> /etc/passwd && `+
		`echo 'monitor:x:1002:1002:Monitor User,,,:/home/monitor:/bin/bash' >> /etc/passwd`)

	// add fake network interfaces to /etc/hosts
	dockerExec(c, `echo '10.0.0.1    gateway.internal' >> /etc/hosts && `+
		`echo '10.0.0.2    db.internal' >> /etc/hosts && `+
		`echo '10.0.0.3    cache.internal' >> /etc/hosts`)
}

// CRITICAL — score 100 or sequence detected
// everything above + tarpit delay
func applyCriticalResponse(c string) {
	applyHighResponse(c)

	// inject a startup delay into bash profile so every command is slow
	dockerExec(c, `echo 'sleep $((RANDOM % 3 + 1))' >> /root/.bashrc`)
}

func dockerExec(containerName, command string) {
	cmd := exec.Command("docker", "exec", containerName,
		"bash", "-c", command)
	// run silently — attacker must not see any output from this
	cmd.Run()
}

func containerName(sessionID string) string {
	return fmt.Sprintf("honeypot-%s", sessionID)
}
