package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

type commandEvent struct {
	Timestamp      string `json:"timestamp"`
	Command        string `json:"command"`
	DelayMs        int64  `json:"delay_ms"`
	CommandIndex   int    `json:"command_index"`
	Category       string `json:"category"`
	SuspicionScore int    `json:"suspicion_score"`
	Reason         string `json:"reason"`
}

type detectionEvent struct {
	Timestamp      string `json:"timestamp"`
	Signal         string `json:"signal"`
	Confidence     string `json:"confidence"`
	Details        string `json:"details"`
	CommandIndex   int    `json:"command_index"`
	TriggerCommand string `json:"trigger_command"`
	ResponseTaken  string `json:"response_taken"`
}

func ShowSession(sessionID string) {
	report := loadReport(sessionID)
	commands := loadSessionCommands(sessionID)
	detections := loadSessionDetections(sessionID)

	if report == nil {
		red.Printf("Session not found: %s\n", sessionID)
		return
	}

	fmt.Println()
	cyan.Printf("  SESSION: %s\n", sessionID)
	dimmed.Printf("  %s → %s (%.1fs)\n", report.StartTime, report.EndTime, report.DurationSeconds)
	fmt.Println()

	_, vc := verdictBadge(report.Verdict)
	vc.Printf("  VERDICT: %s", strings.ToUpper(report.Verdict))
	fmt.Printf("  (score: %d/100)\n\n", report.FinalSuspicionScore)

	bold.Println("  ┌─ ATTACKER INTEL ──────────────────────┐")
	ipInfo := LookupIP(report.RemoteAddr)
	printIPInfo(ipInfo)
	bold.Println("  └───────────────────────────────────────┘")
	fmt.Println()

	bold.Println("  ┌─ CATEGORY BREAKDOWN ──────────┐")
	green.Printf("  │  recon      : %d\n", report.CategoryBreakdown["recon"])
	red.Printf("  │  fingerprint: %d\n", report.CategoryBreakdown["fingerprint"])
	red.Printf("  │  exploit    : %d\n", report.CategoryBreakdown["exploit"])
	dimmed.Printf("  │  unknown    : %d\n", report.CategoryBreakdown["unknown"])
	bold.Println("  └───────────────────────────────┘")
	fmt.Println()

	if len(detections) > 0 {
		bold.Println("  ┌─ DETECTION EVENTS ────────────────────────────────────────┐")
		for _, d := range detections {
			confColor := confidenceColor(d.Confidence)
			confColor.Printf("  │  [%s]", strings.ToUpper(d.Confidence))
			fmt.Printf(" %s\n", d.Signal)
			dimmed.Printf("  │    trigger : %s\n", d.TriggerCommand)
			dimmed.Printf("  │    response: %s\n", d.ResponseTaken)
			dimmed.Printf("  │    at cmd  : #%d — %s\n", d.CommandIndex, d.Timestamp)
			fmt.Println("  │")
		}
		bold.Println("  └───────────────────────────────────────────────────────────┘")
		fmt.Println()
	}

	bold.Println("  ┌─ COMMAND TIMELINE ──────────────────────────────────────────────────┐")
	for _, cmd := range commands {
		if strings.HasPrefix(cmd.Command, "[") {
			continue
		}
		categoryColor := categoryColor(cmd.Category)
		categoryColor.Printf("  │  [%-11s]", cmd.Category)
		fmt.Printf(" #%-3d  score:%-3d  +%dms\n",
			cmd.CommandIndex,
			cmd.SuspicionScore,
			cmd.DelayMs,
		)
		white.Printf("  │         > %s\n", cmd.Command)
		dimmed.Printf("  │           %s\n", cmd.Reason)
		fmt.Println("  │")
	}
	bold.Println("  └────────────────────────────────────────────────────────────────────┘")
	fmt.Println()
}

func confidenceColor(confidence string) *color.Color {
	switch confidence {
	case "critical":
		return red
	case "high":
		return yellow
	default:
		return green
	}
}

func categoryColor(category string) *color.Color {
	switch category {
	case "fingerprint":
		return red
	case "exploit":
		return color.New(color.FgMagenta, color.Bold)
	case "recon":
		return yellow
	default:
		return dimmed
	}
}

func loadReport(sessionID string) *reportFile {
	path := filepath.Join("logs/reports", sessionID+"-report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var r reportFile
	if err := json.Unmarshal(data, &r); err != nil {
		return nil
	}
	return &r
}

func loadSessionCommands(sessionID string) []commandEvent {
	var commands []commandEvent
	path := filepath.Join("logs/sessions", sessionID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var c commandEvent
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}
		commands = append(commands, c)
	}
	return commands
}

func loadSessionDetections(sessionID string) []detectionEvent {
	var detections []detectionEvent
	path := filepath.Join("logs/detections", sessionID+"-detections.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var d detectionEvent
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			continue
		}
		detections = append(detections, d)
	}
	return detections
}
