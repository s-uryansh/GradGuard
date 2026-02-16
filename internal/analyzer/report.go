package analyzer

import (
	Session "GradGuard/internal/Session"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var reportMu sync.Mutex

type SessionReport struct {
	SessionID           string         `json:"session_id"`
	RemoteAddr          string         `json:"remote_addr"`
	StartTime           string         `json:"start_time"`
	EndTime             string         `json:"end_time"`
	DurationSeconds     float64        `json:"duration_seconds"`
	TotalCommands       int            `json:"total_commands"`
	FinalSuspicionScore int            `json:"final_suspicion_score"`
	Verdict             string         `json:"verdict"`
	CategoryBreakdown   map[string]int `json:"category_breakdown"`
	FlaggedCommands     []string       `json:"flagged_commands"`
}

func WriteReport(session *Session.SessionState) {
	reportMu.Lock()
	defer reportMu.Unlock()

	dir := "logs/reports"
	_ = os.MkdirAll(dir, 0755)

	endTime := time.Now()
	report := SessionReport{
		SessionID:           session.ID,
		RemoteAddr:          session.RemoteAddr,
		StartTime:           session.StartTime.UTC().Format(time.RFC3339),
		EndTime:             endTime.UTC().Format(time.RFC3339),
		DurationSeconds:     endTime.Sub(session.StartTime).Seconds(),
		TotalCommands:       session.CommandCount,
		FinalSuspicionScore: session.SuspicionScore,
		Verdict:             Verdict(session),
		CategoryBreakdown:   session.CategoryCounts,
		FlaggedCommands:     session.FlaggedCommands,
	}

	path := filepath.Join(dir, session.ID+"-report.json")
	file, err := os.Create(path)
	if err != nil {
		return
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	enc.Encode(report)
}
