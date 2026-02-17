package ml

import (
	"math/rand"
	"time"
)

type Model struct {
	Classifier  *LogisticClassifier
	Intent      *NaiveBayesClassifier
	Anomaly     *AnomalyDetector
	FeatureMins []float64
	FeatureMaxs []float64
	Trained     bool
}

type Prediction struct {
	IsFingerprintingProb float64
	IsFingerprinting     bool
	Intent               string
	IsAnomaly            bool
	AnomalyScore         float64
}

func NewModel() *Model {
	return &Model{
		Classifier: NewLogisticClassifier(),
		Intent:     NewNaiveBayesClassifier(),
		Anomaly:    NewAnomalyDetector(),
	}
}

func (m *Model) Train() (trainAcc, testAcc float64, cm *ConfusionMatrix) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	all := LoadExternalDataset()

	normalized, mins, maxs := NormalizeSamples(all)
	m.FeatureMins = mins
	m.FeatureMaxs = maxs

	train, test := SplitTrainTest(normalized, rng)

	m.Classifier.Train(train, 1000)
	m.Intent.Train(train)
	m.Anomaly.Train(train)
	m.Trained = true

	labels := []int{LabelLegitimate, LabelBruteForce, LabelFingerprinting, LabelExploit}
	cm = NewConfusionMatrix(labels)

	correct := 0
	for _, s := range test {
		pred := m.Intent.Predict(s.Features)
		cm.Add(s.Label, pred)
		if pred == s.Label {
			correct++
		}
	}
	testAcc = float64(correct) / float64(len(test))

	correctTrain := 0
	for _, s := range train {
		pred := m.Intent.Predict(s.Features)
		if pred == s.Label {
			correctTrain++
		}
	}
	trainAcc = float64(correctTrain) / float64(len(train))

	return trainAcc, testAcc, cm
}

func (m *Model) Predict(f SessionFeatures) Prediction {
	if !m.Trained {
		return Prediction{}
	}

	normalized := normalizeFeatures(f, m.FeatureMins, m.FeatureMaxs)

	prob := m.Classifier.PredictProb(normalized)
	intent := m.Intent.Predict(normalized)
	anomalyScore := m.Anomaly.Score(normalized)
	isAnomaly := m.Anomaly.IsAnomaly(normalized)

	return Prediction{
		IsFingerprintingProb: prob,
		IsFingerprinting:     prob >= 0.5,
		Intent:               LabelName(intent),
		IsAnomaly:            isAnomaly,
		AnomalyScore:         anomalyScore,
	}
}

func normalizeFeatures(f SessionFeatures, mins, maxs []float64) SessionFeatures {
	v := f.ToSlice()
	norm := make([]float64, len(v))
	for i, val := range v {
		rng := maxs[i] - mins[i]
		if rng == 0 {
			norm[i] = 0
		} else {
			norm[i] = (val - mins[i]) / rng
		}
	}
	return sliceToFeatures(norm)
}
