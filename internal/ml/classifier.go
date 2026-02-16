package ml

import "math"

type LogisticClassifier struct {
	Weights []float64
	Bias    float64
	LR      float64
}

func NewLogisticClassifier() *LogisticClassifier {
	return &LogisticClassifier{
		Weights: make([]float64, 12),
		Bias:    0,
		LR:      0.01,
	}
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func (c *LogisticClassifier) predict(features []float64) float64 {
	z := c.Bias
	for i, w := range c.Weights {
		z += w * features[i]
	}
	return sigmoid(z)
}

func (c *LogisticClassifier) Predict(f SessionFeatures) int {
	prob := c.predict(f.ToSlice())
	if prob >= 0.5 {
		return 1
	}
	return 0
}

func (c *LogisticClassifier) PredictProb(f SessionFeatures) float64 {
	return c.predict(f.ToSlice())
}

func (c *LogisticClassifier) Train(samples []LabeledSample, epochs int) {
	for epoch := 0; epoch < epochs; epoch++ {
		for _, s := range samples {
			features := s.Features.ToSlice()
			label := 0.0
			if s.Label == LabelFingerprinting || s.Label == LabelExploit {
				label = 1.0
			}

			pred := c.predict(features)
			err := pred - label

			c.Bias -= c.LR * err
			for i := range c.Weights {
				c.Weights[i] -= c.LR * err * features[i]
			}
		}
	}
}
