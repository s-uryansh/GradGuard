package main

import (
	"GradGuard/internal/analyzer"
	"GradGuard/internal/cli"
	"GradGuard/internal/ml"
	"GradGuard/internal/monitor"
	"GradGuard/internal/sinkhole"
	"GradGuard/internal/sshserver"
	"GradGuard/internal/webshell"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("[*] Starting DNS/HTTP Sinkhole...")
		go sinkhole.StartSinkhole()

		fmt.Println("[*] Starting Web-Shell Gateway...")
		go webshell.StartGateway()

		fmt.Println("[*] Starting eBPF Monitor...")
		go monitor.StartEBPF()

		go func() {
			for alert := range monitor.Alerts {
				res := analyzer.Classify(alert.Command)
				log.Printf("[ML-KERNEL-HOOK] Hidden binary executed: %s | Classification: %s | Suspicion: %d", alert.Command, res.Category, res.SuspicionWeight)

				if res.Category == analyzer.CategoryExploit {
					log.Printf("[!] CRITICAL: Kernel-level exploit detected (PID %d). Initiating isolation protocol.", alert.PID)
				}
			}
		}()

		fmt.Println("[*] Booting SSH Deception Engine...")
		sshserver.Start(":2222")
		return
	}

	switch os.Args[1] {
	case "train":
		model := ml.NewModel()
		model.Train()
		model.SaveWeights("Dataset/trained_model.bin")
	case "analyze":
		cli.ShowSummary()
	default:
		os.Exit(1)
	}
}
