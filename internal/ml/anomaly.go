package ml

import "math"

type AnomalyDetector struct {
	Centroid  []float64
	Threshold float64
}

func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		Centroid:  make([]float64, 12),
		Threshold: 0,
	}
}

func (a *AnomalyDetector) Train(samples []LabeledSample) {
	var legitimate []LabeledSample
	for _, s := range samples {
		if s.Label == LabelLegitimate {
			legitimate = append(legitimate, s)
		}
	}
	if len(legitimate) == 0 {
		return
	}

	centroid := make([]float64, 12)
	for _, s := range legitimate {
		v := s.Features.ToSlice()
		for i, val := range v {
			centroid[i] += val
		}
	}
	for i := range centroid {
		centroid[i] /= float64(len(legitimate))
	}
	a.Centroid = centroid

	distances := make([]float64, len(legitimate))
	for i, s := range legitimate {
		distances[i] = euclidean(s.Features.ToSlice(), centroid)
	}

	mean := 0.0
	for _, d := range distances {
		mean += d
	}
	mean /= float64(len(distances))

	variance := 0.0
	for _, d := range distances {
		diff := d - mean
		variance += diff * diff
	}
	variance /= float64(len(distances))
	std := math.Sqrt(variance)

	a.Threshold = mean + 2*std
}

func (a *AnomalyDetector) Score(f SessionFeatures) float64 {
	return euclidean(f.ToSlice(), a.Centroid)
}

func (a *AnomalyDetector) IsAnomaly(f SessionFeatures) bool {
	return a.Score(f) > a.Threshold
}

func euclidean(a, b []float64) float64 {
	sum := 0.0
	for i := range a {
		diff := a[i] - b[i]
		sum += diff * diff
	}
	return math.Sqrt(sum)
}
