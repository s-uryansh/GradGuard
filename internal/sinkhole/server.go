package sinkhole

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func StartSinkhole() {
	mux := http.NewServeMux()

	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		fmt.Fprint(w, "AQAAAFAKE_TOKEN_xyz123==")
	})

	mux.HandleFunc("/latest/meta-data/iam/security-credentials/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest/meta-data/iam/security-credentials/" {
			fmt.Fprint(w, "prod-db-role")
			return
		}

		if strings.Contains(r.URL.Path, "prod-db-role") {
			w.Header().Set("Content-Type", "application/json")
			creds := map[string]string{
				"Code":            "Success",
				"LastUpdated":     "2026-04-13T12:00:00Z",
				"Type":            "AWS-HMAC",
				"AccessKeyId":     "AKIAIOSFODNN7HONEYPOT",
				"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYPOT",
				"Token":           "IQoJb3JpZ2luX2VjEFAaCXVzLWVhc3QtMS...",
				"Expiration":      "2030-04-14T12:00:00Z",
			}
			json.NewEncoder(w).Encode(creds)
			log.Printf("[SINKHOLE] AWS IAM Credentials accessed by %s", r.RemoteAddr)
			return
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[SINKHOLE] Intercepted request for: %s from %s", r.URL.Path, r.RemoteAddr)
		w.Header().Set("Content-Type", "text/x-shellscript")
		fmt.Fprint(w, `#!/bin/bash
echo "Loading environment..."
sleep 2
echo "Initializing exploit module..."
sleep 1
echo "Error: Target architecture mismatch. Aborting."
exit 1
`)
	})

	server := &http.Server{Addr: ":80", Handler: mux}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[SINKHOLE] Server failed: %v", err)
		}
	}()
}
