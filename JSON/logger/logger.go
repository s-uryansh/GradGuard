package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var mu sync.Mutex

type CommandEvent struct {
	Timestamp      string `json:"timestamp"`
	SessionID      string `json:"session"`
	RemoteAddr     string `json:"remote_addr"`
	Command        string `json:"command"`
	DelayMs        int64  `json:"delay_ms"`
	CommandIndex   int    `json:"command_index"`
	Category       string `json:"category"`
	SuspicionScore int    `json:"suspicion_score"`
	Reason         string `json:"reason"`
}

func LogCommand(
	sessionID string,
	remoteAddr string,
	cmd string,
	delayMs int64,
	index int,
	category string,
	suspicionScore int,
	reason string,
) {
	mu.Lock()
	defer mu.Unlock()

	dir := "logs/sessions"
	_ = os.MkdirAll(dir, 0755)

	path := filepath.Join(dir, sessionID+".json")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	event := CommandEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		SessionID:      sessionID,
		RemoteAddr:     remoteAddr,
		Command:        cmd,
		DelayMs:        delayMs,
		CommandIndex:   index,
		Category:       category,
		SuspicionScore: suspicionScore,
		Reason:         reason,
	}

	json.NewEncoder(file).Encode(event)
}
