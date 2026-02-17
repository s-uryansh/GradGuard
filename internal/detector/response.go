package detector

import (
	"fmt"
	"os/exec"
)

type ResponseLevel int

const (
	ResponseWarning  ResponseLevel = 1
	ResponseHigh     ResponseLevel = 2
	ResponseCritical ResponseLevel = 3
)

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

func applyWarningResponse(c string) {
	dockerExec(c, `mkdir -p /sys/fs/cgroup && `+
		`echo '0::/init.scope' > /proc/1/cgroup || true`)

	dockerExec(c, `echo '# system environment' > /.dockerenv && `+
		`echo 'PLATFORM=baremetal' >> /.dockerenv`)
}

func applyHighResponse(c string) {
	applyWarningResponse(c)

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

	dockerExec(c, `echo 'deploy:x:1001:1001:Deploy User,,,:/home/deploy:/bin/bash' >> /etc/passwd && `+
		`echo 'monitor:x:1002:1002:Monitor User,,,:/home/monitor:/bin/bash' >> /etc/passwd`)

	dockerExec(c, `echo '10.0.0.1    gateway.internal' >> /etc/hosts && `+
		`echo '10.0.0.2    db.internal' >> /etc/hosts && `+
		`echo '10.0.0.3    cache.internal' >> /etc/hosts`)
}

func applyCriticalResponse(c string) {
	applyHighResponse(c)

	dockerExec(c, `echo 'sleep $((RANDOM % 3 + 1))' >> /root/.bashrc`)
}

func dockerExec(containerName, command string) {
	cmd := exec.Command("docker", "exec", containerName,
		"bash", "-c", command)
	cmd.Run()
}

func containerName(sessionID string) string {
	return fmt.Sprintf("honeypot-%s", sessionID)
}
