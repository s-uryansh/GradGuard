package sshserver

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func generateSessionId(sshConn *ssh.ServerConn) string {
	raw := fmt.Sprintf("%s-%d",
		sshConn.RemoteAddr().String(),
		time.Now().UnixNano(),
	)
	safe := strings.NewReplacer(
		":", "_",
		"[", "",
		"]", "",
		"/", "_",
		".", "_",
	).Replace(raw)
	return safe
}
