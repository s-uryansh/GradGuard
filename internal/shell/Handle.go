package shell

import (
	sshsession "GradGuard/internal/Session"
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

type ptyInfo struct {
	cols uint32
	rows uint32
}

func Handle(channel ssh.Channel, requests <-chan *ssh.Request, session *sshsession.SessionState) {
	var pty ptyInfo

	for req := range requests {
		switch req.Type {

		case "pty-req":
			if len(req.Payload) >= 8 {
				termLen := binary.BigEndian.Uint32(req.Payload[:4])
				if len(req.Payload) >= int(4+termLen+8) {
					pty.cols = binary.BigEndian.Uint32(req.Payload[4+termLen:])
					pty.rows = binary.BigEndian.Uint32(req.Payload[4+termLen+4:])
				}
			}
			if pty.cols == 0 {
				pty.cols = 80
			}
			if pty.rows == 0 {
				pty.rows = 24
			}
			req.Reply(true, nil)

		case "env":
			req.Reply(true, nil)

		case "window-change":
			req.Reply(true, nil)

		case "shell":
			req.Reply(true, nil)
			RunRealShell(channel, requests, session, pty)
			return

		default:
			req.Reply(false, nil)
		}
	}
}
