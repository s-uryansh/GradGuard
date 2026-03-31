package main

import (
	"GradGuard/internal/cli"
	"GradGuard/internal/ml"
	"GradGuard/internal/sinkhole"
	"GradGuard/internal/sshserver"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("[*] Starting Internal DNS/HTTP Sinkhole on port 80...")
		go sinkhole.StartSinkhole()

		fmt.Println("[*] Booting GradGuard SSH Deception Engine...")
		sshserver.Start(":2222")
		return
	}

	switch os.Args[1] {
	case "train":
		fmt.Println("[*] Training ML models on Dataset/training_samples.json...")
		model := ml.NewModel()
		trainAcc, testAcc, _ := model.Train()
		fmt.Printf("[+] Training Complete. Train Acc: %.1f%% | Test Acc: %.1f%%\n", trainAcc*100, testAcc*100)

		err := model.SaveWeights("Dataset/trained_model.bin")
		if err != nil {
			fmt.Printf("[-] Error saving weights: %v\n", err)
		} else {
			fmt.Println("[+] Model weights successfully serialized to Dataset/trained_model.bin!")
		}

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
		fmt.Fprintf(os.Stderr, "  honeypot train                    train ML & export weights (.bin)\n")
		fmt.Fprintf(os.Stderr, "  honeypot analyze                  show all sessions summary\n")
		fmt.Fprintf(os.Stderr, "  honeypot analyze --session ID     show full session detail\n")
		os.Exit(1)
	}
}
