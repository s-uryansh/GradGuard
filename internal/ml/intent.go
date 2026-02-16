package ml

import "math"

type NaiveBayesClassifier struct {
	ClassPriors    map[int]float64
	FeatureMeans   map[int][]float64
	FeatureStdDevs map[int][]float64
	NumFeatures    int
}

func NewNaiveBayesClassifier() *NaiveBayesClassifier {
	return &NaiveBayesClassifier{
		ClassPriors:    map[int]float64{},
		FeatureMeans:   map[int][]float64{},
		FeatureStdDevs: map[int][]float64{},
		NumFeatures:    12,
	}
}

func (nb *NaiveBayesClassifier) Train(samples []LabeledSample) {
	byLabel := map[int][]LabeledSample{}
	for _, s := range samples {
		byLabel[s.Label] = append(byLabel[s.Label], s)
	}

	total := float64(len(samples))

	for label, group := range byLabel {
		nb.ClassPriors[label] = float64(len(group)) / total

		means := make([]float64, nb.NumFeatures)
		for _, s := range group {
			v := s.Features.ToSlice()
			for i, val := range v {
				means[i] += val
			}
		}
		for i := range means {
			means[i] /= float64(len(group))
		}
		nb.FeatureMeans[label] = means

		stds := make([]float64, nb.NumFeatures)
		for _, s := range group {
			v := s.Features.ToSlice()
			for i, val := range v {
				diff := val - means[i]
				stds[i] += diff * diff
			}
		}
		for i := range stds {
			variance := stds[i] / float64(len(group))
			stds[i] = math.Sqrt(variance) + 1e-9
		}
		nb.FeatureStdDevs[label] = stds
	}
}

func gaussianLogProb(x, mean, std float64) float64 {
	return -math.Log(std*math.Sqrt(2*math.Pi)) -
		((x-mean)*(x-mean))/(2*std*std)
}

func (nb *NaiveBayesClassifier) Predict(f SessionFeatures) int {
	features := f.ToSlice()
	bestLabel := 0
	bestScore := math.Inf(-1)

	for label, prior := range nb.ClassPriors {
		score := math.Log(prior)
		means := nb.FeatureMeans[label]
		stds := nb.FeatureStdDevs[label]
		for i, val := range features {
			score += gaussianLogProb(val, means[i], stds[i])
		}
		if score > bestScore {
			bestScore = score
			bestLabel = label
		}
	}

	return bestLabel
}

func LabelName(label int) string {
	switch label {
	case LabelLegitimate:
		return "legitimate"
	case LabelBruteForce:
		return "brute_force"
	case LabelFingerprinting:
		return "fingerprinting"
	case LabelExploit:
		return "exploit"
	default:
		return "unknown"
	}
}
