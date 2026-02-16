package sshserver

import (
	"log"

	"golang.org/x/crypto/ssh"
)

func passwordCallback(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	log.Printf("Login attempted by user = %s, pass = %s, ip = %s", conn.User(), string(pass), conn.RemoteAddr())
	return nil, nil
}
