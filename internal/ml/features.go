package ml

import (
	sshsession "GradGuard/internal/Session"
	"GradGuard/internal/analyzer"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
)

type SessionFeatures struct {
	FingerprintRatio float64
	ReconRatio       float64
	ExploitRatio     float64
	SuspicionScore   float64
	AvgDelayMs       float64
	MinDelayMs       float64
	SessionDurationS float64
	UniqueCommands   float64
	CommandCount     float64
	DetectionCount   float64
	SequenceDetected float64
	TimingDetected   float64
}

const (
	LabelLegitimate     = 0
	LabelBruteForce     = 1
	LabelFingerprinting = 2
	LabelExploit        = 3
)

type LabeledSample struct {
	Features SessionFeatures
	Label    int
}

func (f SessionFeatures) ToSlice() []float64 {
	return []float64{
		f.FingerprintRatio,
		f.ReconRatio,
		f.ExploitRatio,
		f.SuspicionScore,
		f.AvgDelayMs,
		f.MinDelayMs,
		f.SessionDurationS,
		f.UniqueCommands,
		f.CommandCount,
		f.DetectionCount,
		f.SequenceDetected,
		f.TimingDetected,
	}
}

func ExtractFromSession(session *sshsession.SessionState, detectionCount int, sequenceDetected, timingDetected bool) SessionFeatures {
	total := float64(session.CommandCount)
	if total == 0 {
		return SessionFeatures{}
	}

	fp := float64(session.CategoryCounts[string(analyzer.CategoryFingerprint)])
	rc := float64(session.CategoryCounts[string(analyzer.CategoryRecon)])
	ex := float64(session.CategoryCounts[string(analyzer.CategoryExploit)])

	seq := 0.0
	if sequenceDetected {
		seq = 1.0
	}
	tim := 0.0
	if timingDetected {
		tim = 1.0
	}

	return SessionFeatures{
		FingerprintRatio: fp / total,
		ReconRatio:       rc / total,
		ExploitRatio:     ex / total,
		SuspicionScore:   float64(session.SuspicionScore) / 100.0,
		CommandCount:     total,
		DetectionCount:   float64(detectionCount),
		SequenceDetected: seq,
		TimingDetected:   tim,
	}
}

type commandLogEntry struct {
	Command        string `json:"command"`
	DelayMs        int64  `json:"delay_ms"`
	Category       string `json:"category"`
	SuspicionScore int    `json:"suspicion_score"`
}

type reportEntry struct {
	Verdict             string         `json:"verdict"`
	DurationSeconds     float64        `json:"duration_seconds"`
	TotalCommands       int            `json:"total_commands"`
	FinalSuspicionScore int            `json:"final_suspicion_score"`
	CategoryBreakdown   map[string]int `json:"category_breakdown"`
	FlaggedCommands     []string       `json:"flagged_commands"`
	SessionID           string         `json:"session_id"`
}

type detectionEntry struct {
	Signal string `json:"signal"`
}

func ExtractFromLogs(sessionID string) (*LabeledSample, error) {
	reportPath := filepath.Join("logs/reports", sessionID+"-report.json")
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, err
	}
	var report reportEntry
	if err := json.Unmarshal(reportData, &report); err != nil {
		return nil, err
	}

	cmdPath := filepath.Join("logs/sessions", sessionID+".json")
	cmdData, err := os.ReadFile(cmdPath)
	if err != nil {
		return nil, err
	}

	var delays []float64
	var uniqueCmds = map[string]bool{}
	for _, line := range strings.Split(string(cmdData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry commandLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.DelayMs > 0 {
			delays = append(delays, float64(entry.DelayMs))
		}
		if entry.Command != "" && !strings.HasPrefix(entry.Command, "[") {
			uniqueCmds[entry.Command] = true
		}
	}

	detectionPath := filepath.Join("logs/detections", sessionID+"-detections.json")
	detectionData, _ := os.ReadFile(detectionPath)
	var detectionCount int
	var sequenceDetected, timingDetected float64
	for _, line := range strings.Split(string(detectionData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var d detectionEntry
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			continue
		}
		detectionCount++
		if d.Signal == "sequence_detection" {
			sequenceDetected = 1.0
		}
		if d.Signal == "timing_analysis" {
			timingDetected = 1.0
		}
	}

	total := float64(report.TotalCommands)
	if total == 0 {
		total = 1
	}

	avgDelay := 0.0
	minDelay := math.MaxFloat64
	for _, d := range delays {
		avgDelay += d
		if d < minDelay {
			minDelay = d
		}
	}
	if len(delays) > 0 {
		avgDelay /= float64(len(delays))
	}
	if minDelay == math.MaxFloat64 {
		minDelay = 0
	}

	features := SessionFeatures{
		FingerprintRatio: float64(report.CategoryBreakdown["fingerprint"]) / total,
		ReconRatio:       float64(report.CategoryBreakdown["recon"]) / total,
		ExploitRatio:     float64(report.CategoryBreakdown["exploit"]) / total,
		SuspicionScore:   float64(report.FinalSuspicionScore) / 100.0,
		AvgDelayMs:       avgDelay,
		MinDelayMs:       minDelay,
		SessionDurationS: report.DurationSeconds,
		UniqueCommands:   float64(len(uniqueCmds)),
		CommandCount:     total,
		DetectionCount:   float64(detectionCount),
		SequenceDetected: sequenceDetected,
		TimingDetected:   timingDetected,
	}

	label := verdictToLabel(report.Verdict)

	return &LabeledSample{Features: features, Label: label}, nil
}

func verdictToLabel(verdict string) int {
	switch verdict {
	case "likely_fingerprinting":
		return LabelFingerprinting
	case "exploit_attempt":
		return LabelExploit
	case "suspicious":
		return LabelBruteForce
	default:
		return LabelLegitimate
	}
}
