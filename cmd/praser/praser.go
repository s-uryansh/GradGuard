package main

import (
	"GradGuard/internal/analyzer"
	"GradGuard/internal/ml"
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type TrainingSample struct {
	Features ml.SessionFeatures `json:"features"`
	Label    int                `json:"label"`
	Source   string             `json:"source"`
}

type sessionData struct {
	CommandCount   int
	FingerprintCmd int
	ReconCmd       int
	ExploitCmd     int
	SuspicionScore int
	Duration       float64
}

func main() {
	var allSamples []TrainingSample
	fmt.Println("Starting GradGuard Universal Dataset Parser...")

	fmt.Println("[*] Mining Cowrie Logs...")
	filepath.Walk("Dataset/logs", func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.Contains(info.Name(), "cowrie.json") {
			samples := parseCowrie(path)
			allSamples = append(allSamples, samples...)
		}
		return nil
	})

	fmt.Println("[*] Mining CIC-IDS-2017 CSVs...")
	filepath.Walk("Dataset/MachineLearningCVE", func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".csv") {
			samples := parseCIC(path)
			allSamples = append(allSamples, samples...)
		}
		return nil
	})

	fmt.Println("[*] Mining NSL-KDD txt files...")
	filepath.Walk("Dataset/nsl-kdd", func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".txt") {
			samples := parseNSL(path)
			allSamples = append(allSamples, samples...)
		}
		return nil
	})

	outFile, err := os.Create("Dataset/training_samples.json")
	if err != nil {
		fmt.Printf("Failed to create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	enc := json.NewEncoder(outFile)
	enc.SetIndent("", "  ")
	enc.Encode(allSamples)

	fmt.Printf("\nSuccess! %d unified samples saved to Dataset/training_samples.json\n", len(allSamples))
}

func parseCowrie(path string) []TrainingSample {
	var samples []TrainingSample
	sessions := make(map[string]*sessionData)

	file, err := os.Open(path)
	if err != nil {
		return samples
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event struct {
			EventID  string  `json:"eventid"`
			Session  string  `json:"session"`
			Input    string  `json:"input"`
			Duration float64 `json:"duration"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		if _, exists := sessions[event.Session]; !exists {
			sessions[event.Session] = &sessionData{}
		}
		data := sessions[event.Session]

		if event.EventID == "cowrie.command.input" {
			data.CommandCount++
			result := analyzer.Classify(event.Input)
			data.SuspicionScore += result.SuspicionWeight
			if data.SuspicionScore > 100 {
				data.SuspicionScore = 100
			}
			switch result.Category {
			case analyzer.CategoryFingerprint:
				data.FingerprintCmd++
			case analyzer.CategoryRecon:
				data.ReconCmd++
			case analyzer.CategoryExploit:
				data.ExploitCmd++
			}
		}
		if event.EventID == "cowrie.session.closed" {
			data.Duration = event.Duration
		}
	}

	for _, data := range sessions {
		if data.CommandCount == 0 && data.Duration < 2 {
			continue
		}
		totalCmds := float64(data.CommandCount)
		if totalCmds == 0 {
			totalCmds = 1
		}

		features := ml.SessionFeatures{
			FingerprintRatio: float64(data.FingerprintCmd) / totalCmds,
			ReconRatio:       float64(data.ReconCmd) / totalCmds,
			ExploitRatio:     float64(data.ExploitCmd) / totalCmds,
			SuspicionScore:   float64(data.SuspicionScore) / 100.0,
			SessionDurationS: data.Duration,
			CommandCount:     float64(data.CommandCount),
			UniqueCommands:   float64(data.CommandCount),
			AvgDelayMs:       (data.Duration * 1000) / totalCmds,
		}

		label := ml.LabelBruteForce
		if features.ExploitRatio > 0 {
			label = ml.LabelExploit
		} else if features.FingerprintRatio > 0 {
			label = ml.LabelFingerprinting
		}

		samples = append(samples, TrainingSample{Features: features, Label: label, Source: "cowrie_logs"})
	}
	return samples
}

func parseCIC(path string) []TrainingSample {
	var samples []TrainingSample
	file, err := os.Open(path)
	if err != nil {
		return samples
	}
	defer file.Close()

	reader := csv.NewReader(file)
	header, err := reader.Read()
	if err != nil {
		return samples
	}

	idxDur, idxPkts, idxIAT, idxLabel := -1, -1, -1, -1
	for i, h := range header {
		cleanH := strings.TrimSpace(h)
		if cleanH == "Flow Duration" {
			idxDur = i
		}
		if cleanH == "Total Fwd Packets" {
			idxPkts = i
		}
		if cleanH == "Flow IAT Mean" {
			idxIAT = i
		}
		if cleanH == "Label" {
			idxLabel = i
		}
	}

	if idxDur == -1 || idxLabel == -1 {
		return samples
	}

	count := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		labelStr := strings.TrimSpace(record[idxLabel])
		label := ml.LabelLegitimate
		if strings.Contains(labelStr, "SSH-Patator") {
			label = ml.LabelBruteForce
		} else if labelStr != "BENIGN" {
			continue
		}

		dur, _ := strconv.ParseFloat(record[idxDur], 64)
		pkts, _ := strconv.ParseFloat(record[idxPkts], 64)
		iat, _ := strconv.ParseFloat(record[idxIAT], 64)

		features := ml.SessionFeatures{
			SessionDurationS: dur / 1000000.0,
			CommandCount:     pkts,
			AvgDelayMs:       iat / 1000.0,
		}

		samples = append(samples, TrainingSample{Features: features, Label: label, Source: "cic_ids_2017"})

		count++
		if count > 5000 {
			break
		}
	}
	return samples
}

func parseNSL(path string) []TrainingSample {
	var samples []TrainingSample
	file, err := os.Open(path)
	if err != nil {
		return samples
	}
	defer file.Close()

	reader := csv.NewReader(file)
	count := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 42 {
			continue
		}

		dur, _ := strconv.ParseFloat(record[0], 64)
		pkts, _ := strconv.ParseFloat(record[22], 64)

		labelStr := record[41]
		label := ml.LabelLegitimate
		if labelStr == "guess_passwd" {
			label = ml.LabelBruteForce
		} else if labelStr != "normal" {
			continue
		}

		features := ml.SessionFeatures{
			SessionDurationS: dur,
			CommandCount:     pkts,
			SuspicionScore:   0,
		}

		samples = append(samples, TrainingSample{Features: features, Label: label, Source: "nsl_kdd"})

		count++
		if count > 5000 {
			break
		}
	}
	return samples
}
