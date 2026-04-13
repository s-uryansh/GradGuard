package webshell

import (
	"GradGuard/internal/analyzer"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
)

var (
	activeSessions = make(map[string]string)
	mu             sync.Mutex
)

func StartGateway() {
	http.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		cmd := r.URL.Query().Get("cmd")

		if cmd == "" {
			fmt.Fprint(w, `{"status": "alive"}`)
			return
		}

		mu.Lock()
		containerName, exists := activeSessions[ip]
		mu.Unlock()

		if !exists {
			res := analyzer.Classify(cmd)
			containerName = "web-honey-" + strings.ReplaceAll(ip, ":", "_")
			bootHoneypot(containerName)
			mu.Lock()
			activeSessions[ip] = containerName
			mu.Unlock()
			if res.Category == analyzer.CategoryExploit || res.Category == analyzer.CategoryRecon {
				log.Printf("[WEB-TRAP] IP %s isolated.", ip)
			}
		}

		out, _ := exec.Command("docker", "exec", containerName, "bash", "-c", cmd).CombinedOutput()
		log.Printf("[WEB-SHELL] %s executed: %s", ip, cmd)
		fmt.Fprint(w, string(out))
	})

	log.Println("[*] Web-to-Shell Gateway on :8080")
	go http.ListenAndServe(":8080", nil)
}

func bootHoneypot(name string) {
	exec.Command("docker", "run", "-d",
		"--name", name,
		"--network", "gradguard-net",
		"--dns", "172.19.0.1",
		"--memory", "128m",
		"--cap-add", "SYS_ADMIN",
		"honeypot-base",
		"sleep", "infinity",
	).Run()
}
