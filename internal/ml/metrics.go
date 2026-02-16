package ml

import "fmt"

type ConfusionMatrix struct {
	Labels   []int
	Matrix   [][]int
	labelIdx map[int]int
}

func NewConfusionMatrix(labels []int) *ConfusionMatrix {
	n := len(labels)
	m := make([][]int, n)
	idx := map[int]int{}
	for i, l := range labels {
		m[i] = make([]int, n)
		idx[l] = i
	}
	return &ConfusionMatrix{Labels: labels, Matrix: m, labelIdx: idx}
}

func (cm *ConfusionMatrix) Add(actual, predicted int) {
	i := cm.labelIdx[actual]
	j := cm.labelIdx[predicted]
	cm.Matrix[i][j]++
}

func (cm *ConfusionMatrix) Print() {
	fmt.Printf("\n  Confusion Matrix:\n")
	fmt.Printf("  %20s", "Actual \\ Predicted")
	for _, l := range cm.Labels {
		fmt.Printf("  %-15s", LabelName(l))
	}
	fmt.Println()

	for i, actual := range cm.Labels {
		fmt.Printf("  %-20s", LabelName(actual))
		for _, count := range cm.Matrix[i] {
			fmt.Printf("  %-15d", count)
		}
		fmt.Println()
	}
	fmt.Println()
}

type ClassMetrics struct {
	Label     int
	Precision float64
	Recall    float64
	F1        float64
	Support   int
}

func ComputeMetrics(cm *ConfusionMatrix) []ClassMetrics {
	var metrics []ClassMetrics
	n := len(cm.Labels)

	for i, label := range cm.Labels {
		tp := float64(cm.Matrix[i][i])

		actualPos := 0.0
		for j := 0; j < n; j++ {
			actualPos += float64(cm.Matrix[i][j])
		}

		predPos := 0.0
		for j := 0; j < n; j++ {
			predPos += float64(cm.Matrix[j][i])
		}

		precision := 0.0
		if predPos > 0 {
			precision = tp / predPos
		}

		recall := 0.0
		if actualPos > 0 {
			recall = tp / actualPos
		}

		f1 := 0.0
		if precision+recall > 0 {
			f1 = 2 * precision * recall / (precision + recall)
		}

		metrics = append(metrics, ClassMetrics{
			Label:     label,
			Precision: precision,
			Recall:    recall,
			F1:        f1,
			Support:   int(actualPos),
		})
	}
	return metrics
}

func PrintMetrics(metrics []ClassMetrics) {
	fmt.Printf("  %-20s  %-10s  %-10s  %-10s  %-10s\n",
		"Class", "Precision", "Recall", "F1", "Support")
	fmt.Printf("  %s\n", "─────────────────────────────────────────────────────")

	var totalF1, totalPrec, totalRec float64
	for _, m := range metrics {
		fmt.Printf("  %-20s  %-10.3f  %-10.3f  %-10.3f  %-10d\n",
			LabelName(m.Label), m.Precision, m.Recall, m.F1, m.Support)
		totalF1 += m.F1
		totalPrec += m.Precision
		totalRec += m.Recall
	}

	n := float64(len(metrics))
	fmt.Printf("  %s\n", "─────────────────────────────────────────────────────")
	fmt.Printf("  %-20s  %-10.3f  %-10.3f  %-10.3f\n",
		"Macro Average",
		totalPrec/n,
		totalRec/n,
		totalF1/n,
	)
	fmt.Println()
}
