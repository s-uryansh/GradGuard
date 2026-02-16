package sshserver

import (
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func Start(addr string) {
	config := &ssh.ServerConfig{
		PasswordCallback: passwordCallback,
	}

	config.AddHostKey(generateHostKey())

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("SSH Honeypot listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, config)
	}
}
