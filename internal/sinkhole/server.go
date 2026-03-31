package sinkhole

import (
	"fmt"
	"log"
	"net/http"
)

func StartSinkhole() {
	mux := http.NewServeMux()
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
			log.Fatalf("[SINKHOLE] Server failed to start (are you running as root?): %v", err)
		}
	}()
}
