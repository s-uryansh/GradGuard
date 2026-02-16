package shell

import (
	"GradGuard/JSON/logger"
	sshsession "GradGuard/internal/Session"
	"GradGuard/internal/analyzer"
	"GradGuard/internal/detector"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"

	"golang.org/x/crypto/ssh"
)

func RunRealShell(
	channel ssh.Channel,
	requests <-chan *ssh.Request,
	session *sshsession.SessionState,
	pty ptyInfo,
) {
	defer channel.Close()

	containerName := "honeypot-" + session.ID

	prep := exec.Command("docker", "run", "-d",
		"--name", containerName,
		"--network", "none",
		"--memory", "128m",
		"--pids-limit", "64",
		"honeypot-base",
		"sleep", "infinity",
	)
	if out, err := prep.CombinedOutput(); err != nil {
		logger.LogCommand(session.ID, session.RemoteAddr, "[container-start-failed] "+string(out), 0, 0, "unknown", 0, "container failed to start")
		channel.Write([]byte("System error\r\n"))
		return
	}

	defer exec.Command("docker", "rm", "-f", containerName).Run()

	logger.LogCommand(session.ID, session.RemoteAddr, "[container-started]", 0, 0, "unknown", 0, "container started successfully")

	cmd := exec.Command("docker", "exec", "-i",
		fmt.Sprintf("--env=COLUMNS=%d", pty.cols),
		fmt.Sprintf("--env=LINES=%d", pty.rows),
		"--env=TERM=xterm",
		containerName,
		"script", "-q", "-c",
		"/bin/bash --login",
		"/dev/null",
	)

	logWriter := &sessionLogger{
		sessionID:  session.ID,
		remoteAddr: session.RemoteAddr,
		session:    session,
		detector:   detector.New(session),
	}

	cmd.Stdin = channel
	cmd.Stdout = io.MultiWriter(channel, logWriter)
	cmd.Stderr = channel

	if err := cmd.Start(); err != nil {
		channel.Write([]byte("System error\r\n"))
		return
	}

	go func() {
		for req := range requests {
			if req.Type == "window-change" && len(req.Payload) >= 8 {
				cols := binary.BigEndian.Uint32(req.Payload[:4])
				rows := binary.BigEndian.Uint32(req.Payload[4:])
				exec.Command("docker", "exec", containerName,
					"stty", fmt.Sprintf("cols %d rows %d", cols, rows),
				).Run()
			}
			req.Reply(false, nil)
		}
	}()

	cmd.Wait()
	analyzer.WriteReport(session)
	logger.LogCommand(session.ID, session.RemoteAddr, "[session-ended]", 0, session.CommandCount, "unknown", session.SuspicionScore, "session ended")
}
