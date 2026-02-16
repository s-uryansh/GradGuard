package sshserver

import (
	"GradGuard/internal/Session"
	"GradGuard/internal/shell"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func handleConn(nConn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	sessionID := generateSessionId(sshConn)
	session := Session.NewSession(sessionID, sshConn.RemoteAddr().String())

	log.Printf("New Session %s from %s", sessionID, sshConn.RemoteAddr())

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go shell.Handle(channel, requests, session)
	}
}
