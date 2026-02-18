package ml

import (
	"encoding/json"
	"os"
	"sync"
)

var feedbackMu sync.Mutex

func Ingest(sessionID string) error {
	sample, err := ExtractFromLogs(sessionID)
	if err != nil {
		return err
	}

	feedbackMu.Lock()
	defer feedbackMu.Unlock()

	path := "Dataset/training_samples.json"
	var existing []externalSample

	data, err := os.ReadFile(path)
	if err == nil {
		json.Unmarshal(data, &existing)
	}

	existing = append(existing, externalSample{
		Features: sample.Features,
		Label:    sample.Label,
		Source:   "live_honeypot",
	})

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(existing)
}
