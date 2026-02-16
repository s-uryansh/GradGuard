package shell

import (
	"GradGuard/JSON/logger"
	sshsession "GradGuard/internal/Session"
	"GradGuard/internal/analyzer"
	"GradGuard/internal/detector"
	"bytes"
	"regexp"
	"strings"
	"time"
)

var ansiEscape = regexp.MustCompile(`(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]|\x1B\][^\x07]*\x07|\x1B[()][AB]`)

var promptPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[^#$]*[#$]\s*`)

type sessionLogger struct {
	sessionID  string
	remoteAddr string
	session    *sshsession.SessionState
	buf        bytes.Buffer
	detector   *detector.Detector
}

func (l *sessionLogger) Write(p []byte) (n int, err error) {
	l.buf.Write(p)

	for {
		idx := bytes.IndexByte(l.buf.Bytes(), '\n')
		if idx < 0 {
			break
		}

		raw := string(l.buf.Next(idx + 1))

		clean := ansiEscape.ReplaceAllString(raw, "")
		clean = strings.ReplaceAll(clean, "\r", "")
		clean = strings.ReplaceAll(clean, "\x07", "")
		clean = strings.TrimSpace(clean)

		if clean == "" || isPureControlSequence(clean) {
			continue
		}

		isCommand := promptPattern.MatchString(clean)
		if !isCommand {
			continue
		}

		cmd := promptPattern.ReplaceAllString(clean, "")

		cmd = replayBackspaces(cmd)
		cmd = strings.TrimSpace(cmd)

		if cmd == "" || cmd == "clear" || cmd == "logout" {
			continue
		}

		if len([]rune(cmd)) <= 1 {
			continue
		}

		now := time.Now()
		delay := time.Duration(0)
		if !l.session.LastCommandTime.IsZero() {
			delay = now.Sub(l.session.LastCommandTime)
		}
		l.session.LastCommandTime = now
		l.session.CommandCount++

		result := analyzer.Analyze(l.session, cmd)

		logger.LogCommand(
			l.session.ID,
			l.session.RemoteAddr,
			cmd,
			delay.Milliseconds(),
			l.session.CommandCount,
			string(result.Category),
			l.session.SuspicionScore,
			result.Reason,
		)
		l.detector.Check(cmd, string(result.Category), delay.Milliseconds())

	}

	return len(p), nil
}

func replayBackspaces(s string) string {
	var buf []rune
	for _, r := range s {
		if r == '\x08' || r == '\x7f' {
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		} else {
			buf = append(buf, r)
		}
	}
	return string(buf)
}

func isPureControlSequence(s string) bool {
	for _, r := range s {
		if r >= 32 && r != 127 {
			return false
		}
	}
	return true
}
