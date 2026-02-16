// internal/ml/dataset.go
package ml

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

func GenerateSyntheticData(rng *rand.Rand) []LabeledSample {
	var samples []LabeledSample

	for i := 0; i < 200; i++ {
		samples = append(samples, LabeledSample{
			Label: LabelLegitimate,
			Features: SessionFeatures{
				FingerprintRatio: rng.Float64() * 0.05,
				ReconRatio:       rng.Float64() * 0.3,
				ExploitRatio:     0,
				SuspicionScore:   rng.Float64() * 0.2,
				AvgDelayMs:       800 + rng.Float64()*4000,
				MinDelayMs:       300 + rng.Float64()*1000,
				SessionDurationS: 30 + rng.Float64()*600,
				UniqueCommands:   5 + rng.Float64()*20,
				CommandCount:     5 + rng.Float64()*30,
				DetectionCount:   0,
				SequenceDetected: 0,
				TimingDetected:   0,
			},
		})
	}

	for i := 0; i < 200; i++ {
		samples = append(samples, LabeledSample{
			Label: LabelBruteForce,
			Features: SessionFeatures{
				FingerprintRatio: 0,
				ReconRatio:       0,
				ExploitRatio:     0,
				SuspicionScore:   rng.Float64() * 0.05,
				AvgDelayMs:       rng.Float64() * 100,
				MinDelayMs:       rng.Float64() * 50,
				SessionDurationS: rng.Float64() * 5,
				UniqueCommands:   rng.Float64() * 2,
				CommandCount:     rng.Float64() * 2,
				DetectionCount:   0,
				SequenceDetected: 0,
				TimingDetected:   0,
			},
		})
	}

	for i := 0; i < 200; i++ {
		seqDetected := 0.0
		if rng.Float64() > 0.4 {
			seqDetected = 1.0
		}
		timDetected := 0.0
		if rng.Float64() > 0.6 {
			timDetected = 1.0
		}
		samples = append(samples, LabeledSample{
			Label: LabelFingerprinting,
			Features: SessionFeatures{
				FingerprintRatio: 0.4 + rng.Float64()*0.5,
				ReconRatio:       rng.Float64() * 0.3,
				ExploitRatio:     0,
				SuspicionScore:   0.6 + rng.Float64()*0.4,
				AvgDelayMs:       200 + rng.Float64()*2000,
				MinDelayMs:       50 + rng.Float64()*500,
				SessionDurationS: 20 + rng.Float64()*200,
				UniqueCommands:   3 + rng.Float64()*15,
				CommandCount:     4 + rng.Float64()*20,
				DetectionCount:   1 + rng.Float64()*4,
				SequenceDetected: seqDetected,
				TimingDetected:   timDetected,
			},
		})
	}

	for i := 0; i < 200; i++ {
		samples = append(samples, LabeledSample{
			Label: LabelExploit,
			Features: SessionFeatures{
				FingerprintRatio: rng.Float64() * 0.2,
				ReconRatio:       0.1 + rng.Float64()*0.4,
				ExploitRatio:     0.3 + rng.Float64()*0.6,
				SuspicionScore:   0.7 + rng.Float64()*0.3,
				AvgDelayMs:       100 + rng.Float64()*1000,
				MinDelayMs:       50 + rng.Float64()*300,
				SessionDurationS: 10 + rng.Float64()*300,
				UniqueCommands:   3 + rng.Float64()*10,
				CommandCount:     4 + rng.Float64()*15,
				DetectionCount:   2 + rng.Float64()*5,
				SequenceDetected: 0,
				TimingDetected:   0,
			},
		})
	}

	return samples
}

func LoadRealSamples() []LabeledSample {
	var samples []LabeledSample
	files, _ := filepath.Glob("logs/reports/*.json")
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var r reportEntry
		if err := json.Unmarshal(data, &r); err != nil {
			continue
		}
		sample, err := ExtractFromLogs(r.SessionID)
		if err != nil {
			continue
		}
		samples = append(samples, *sample)
	}
	return samples
}

func NormalizeSamples(samples []LabeledSample) ([]LabeledSample, []float64, []float64) {
	if len(samples) == 0 {
		return samples, nil, nil
	}

	numFeatures := 12
	mins := make([]float64, numFeatures)
	maxs := make([]float64, numFeatures)

	first := samples[0].Features.ToSlice()
	copy(mins, first)
	copy(maxs, first)

	for _, s := range samples[1:] {
		v := s.Features.ToSlice()
		for i, val := range v {
			if val < mins[i] {
				mins[i] = val
			}
			if val > maxs[i] {
				maxs[i] = val
			}
		}
	}

	normalized := make([]LabeledSample, len(samples))
	for i, s := range samples {
		v := s.Features.ToSlice()
		norm := make([]float64, numFeatures)
		for j, val := range v {
			rng := maxs[j] - mins[j]
			if rng == 0 {
				norm[j] = 0
			} else {
				norm[j] = (val - mins[j]) / rng
			}
		}
		normalized[i] = LabeledSample{
			Features: sliceToFeatures(norm),
			Label:    s.Label,
		}
	}

	return normalized, mins, maxs
}

func sliceToFeatures(v []float64) SessionFeatures {
	return SessionFeatures{
		FingerprintRatio: v[0],
		ReconRatio:       v[1],
		ExploitRatio:     v[2],
		SuspicionScore:   v[3],
		AvgDelayMs:       v[4],
		MinDelayMs:       v[5],
		SessionDurationS: v[6],
		UniqueCommands:   v[7],
		CommandCount:     v[8],
		DetectionCount:   v[9],
		SequenceDetected: v[10],
		TimingDetected:   v[11],
	}
}

func SplitTrainTest(samples []LabeledSample, rng *rand.Rand) ([]LabeledSample, []LabeledSample) {
	rng.Shuffle(len(samples), func(i, j int) {
		samples[i], samples[j] = samples[j], samples[i]
	})
	split := int(float64(len(samples)) * 0.8)
	return samples[:split], samples[split:]
}

var _ = strings.TrimSpace
