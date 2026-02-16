package main

import (
	"GradGuard/internal/cli"
	sshserver "GradGuard/internal/sshserver"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		sshserver.Start(":2222")
		return
	}

	switch os.Args[1] {
	case "analyze":
		sessionID := ""
		for i, arg := range os.Args[2:] {
			if arg == "--session" && i+1 < len(os.Args[2:]) {
				sessionID = os.Args[i+3]
			}
		}
		if sessionID != "" {
			cli.ShowSession(sessionID)
		} else {
			cli.ShowSummary()
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		fmt.Fprintf(os.Stderr, "usage:\n")
		fmt.Fprintf(os.Stderr, "  honeypot                          start the honeypot\n")
		fmt.Fprintf(os.Stderr, "  honeypot analyze                  show all sessions summary\n")
		fmt.Fprintf(os.Stderr, "  honeypot analyze --session ID     show full session detail\n")
		os.Exit(1)
	}
}
