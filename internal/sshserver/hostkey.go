package sshserver

import (
	"crypto/rand"
	"crypto/rsa"
	"log"

	"golang.org/x/crypto/ssh"
)

func generateHostKey() ssh.Signer {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	return signer
}
