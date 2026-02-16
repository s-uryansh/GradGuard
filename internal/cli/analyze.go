package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

type reportFile struct {
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

type detectionFile struct {
	Signal         string `json:"signal"`
	Confidence     string `json:"confidence"`
	TriggerCommand string `json:"trigger_command"`
	ResponseTaken  string `json:"response_taken"`
}

var (
	bold   = color.New(color.Bold)
	red    = color.New(color.FgRed, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	cyan   = color.New(color.FgCyan, color.Bold)
	white  = color.New(color.FgWhite)
	dimmed = color.New(color.FgHiBlack)
)

func ShowSummary() {
	reports := loadAllReports()
	if len(reports) == 0 {
		yellow.Println("No sessions found in logs/reports/")
		return
	}

	detections := loadAllDetections()

	sort.Slice(reports, func(i, j int) bool {
		return reports[i].StartTime > reports[j].StartTime
	})

	printBanner()
	printSummaryStats(reports, detections)
	printTopFlaggedCommands(reports)
	printDetectionBreakdown(detections)
	printSessionList(reports)
}

func printBanner() {
	fmt.Println()
	cyan.Println("  ██████╗ ██████╗  █████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ")
	cyan.Println("  ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗")
	cyan.Println("  ██║  ███╗██████╔╝███████║██║  ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║")
	cyan.Println("  ██║   ██║██╔══██╗██╔══██║██║  ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║")
	cyan.Println("  ╚██████╔╝██║  ██║██║  ██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝")
	cyan.Println("   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ")
	fmt.Println()
	dimmed.Printf("  Honeypot Analysis Report — %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()
}

func printSummaryStats(reports []reportFile, detections []detectionFile) {
	counts := map[string]int{
		"clean":                 0,
		"suspicious":            0,
		"likely_fingerprinting": 0,
		"exploit_attempt":       0,
	}
	for _, r := range reports {
		counts[r.Verdict]++
	}

	bold.Println("  ┌─ SUMMARY ──────────────────────────────┐")
	fmt.Printf("  │  Total Sessions       : %s\n", bold.Sprintf("%d", len(reports)))
	green.Printf("  │  Clean                : %d\n", counts["clean"])
	yellow.Printf("  │  Suspicious           : %d\n", counts["suspicious"])
	yellow.Printf("  │  Likely Fingerprinting: %d\n", counts["likely_fingerprinting"])
	red.Printf("  │  Exploit Attempts     : %d\n", counts["exploit_attempt"])
	fmt.Printf("  │  Total Detections     : %s\n", bold.Sprintf("%d", len(detections)))
	bold.Println("  └────────────────────────────────────────┘")
	fmt.Println()
}

func printTopFlaggedCommands(reports []reportFile) {
	counts := map[string]int{}
	for _, r := range reports {
		for _, cmd := range r.FlaggedCommands {
			counts[cmd]++
		}
	}
	if len(counts) == 0 {
		return
	}

	// sort by frequency
	type kv struct {
		cmd   string
		count int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	bold.Println("  ┌─ TOP FLAGGED COMMANDS ─────────────────┐")
	limit := 8
	if len(sorted) < limit {
		limit = len(sorted)
	}
	for _, kv := range sorted[:limit] {
		red.Printf("  │  %-40s ×%d\n", truncate(kv.cmd, 38), kv.count)
	}
	bold.Println("  └────────────────────────────────────────┘")
	fmt.Println()
}

func printDetectionBreakdown(detections []detectionFile) {
	if len(detections) == 0 {
		return
	}

	signals := map[string]int{}
	responses := map[string]int{}
	for _, d := range detections {
		signals[d.Signal]++
		responses[d.ResponseTaken]++
	}

	bold.Println("  ┌─ DETECTIONS ───────────────────────────┐")
	for sig, count := range signals {
		yellow.Printf("  │  %-35s ×%d\n", sig, count)
	}
	fmt.Println("  │")
	bold.Println("  │  Responses Applied:")
	for resp, count := range responses {
		dimmed.Printf("  │    %-33s ×%d\n", resp, count)
	}
	bold.Println("  └────────────────────────────────────────┘")
	fmt.Println()
}

func printSessionList(reports []reportFile) {

	bold.Println("  ┌─ SESSIONS (most recent first) ─────────────────────────────────────┐")
	for _, r := range reports {
		ip := extractIP(r.RemoteAddr)

		badge, badgeColor := verdictBadge(r.Verdict)
		badgeColor.Printf("  │  [%-8s]", badge)
		fmt.Printf(" score:%-3d  cmds:%-3d  dur:%-5s  ip %-18s  %s\n",
			r.FinalSuspicionScore,
			r.TotalCommands,
			formatDuration(r.DurationSeconds),
			ip,
			dimmed.Sprintf("%s", truncate(r.SessionID, 25)),
		)
	}
	bold.Println("  └────────────────────────────────────────────────────────────────────┘")
	fmt.Println()
	dimmed.Println("  Run with --session SESSION_ID for full breakdown")
	fmt.Println()
}
func verdictBadge(verdict string) (string, *color.Color) {
	switch verdict {
	case "exploit_attempt":
		return "EXPLOIT", red
	case "likely_fingerprinting":
		return "FINGERP", yellow
	case "suspicious":
		return "SUSPIC", yellow
	default:
		return "CLEAN", green
	}
}

func formatDuration(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(seconds))
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func loadAllReports() []reportFile {
	var reports []reportFile
	files, _ := filepath.Glob("logs/reports/*.json")
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var r reportFile
		if err := json.Unmarshal(data, &r); err != nil {
			continue
		}
		reports = append(reports, r)
	}
	return reports
}

func loadAllDetections() []detectionFile {
	var detections []detectionFile
	files, _ := filepath.Glob("logs/detections/*.json")
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		// each file has multiple JSON lines
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var d detectionFile
			if err := json.Unmarshal([]byte(line), &d); err != nil {
				continue
			}
			detections = append(detections, d)
		}
	}
	return detections
}
