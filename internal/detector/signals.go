package detector

import (
	sshsession "GradGuard/internal/Session"
	"time"
)

type SignalType string
type Confidence string

const (
	SignalThreshold SignalType = "threshold_breach"
	SignalSequence  SignalType = "sequence_detection"
	SignalTiming    SignalType = "timing_analysis"

	ConfidenceWarning  Confidence = "warning"
	ConfidenceHigh     Confidence = "high"
	ConfidenceCritical Confidence = "critical"
)

type DetectionEvent struct {
	Timestamp      string     `json:"timestamp"`
	SessionID      string     `json:"session_id"`
	RemoteAddr     string     `json:"remote_addr"`
	Signal         SignalType `json:"signal"`
	Confidence     Confidence `json:"confidence"`
	Details        string     `json:"details"`
	CommandIndex   int        `json:"command_index"`
	TriggerCommand string     `json:"trigger_command"`
	ResponseTaken  string     `json:"response_taken"`
}

// ThresholdSignal fires when suspicion score crosses 50, 75, 100
type ThresholdSignal struct {
	firedAt50  bool
	firedAt75  bool
	firedAt100 bool
}

func (t *ThresholdSignal) Check(session *sshsession.SessionState, cmd string) *DetectionEvent {
	score := session.SuspicionScore

	if score >= 100 && !t.firedAt100 {
		t.firedAt100 = true
		return &DetectionEvent{
			Signal:         SignalThreshold,
			Confidence:     ConfidenceCritical,
			Details:        "suspicion score reached 100",
			TriggerCommand: cmd,
			CommandIndex:   session.CommandCount,
		}
	}
	if score >= 75 && !t.firedAt75 {
		t.firedAt75 = true
		return &DetectionEvent{
			Signal:         SignalThreshold,
			Confidence:     ConfidenceHigh,
			Details:        "suspicion score crossed 75",
			TriggerCommand: cmd,
			CommandIndex:   session.CommandCount,
		}
	}
	if score >= 50 && !t.firedAt50 {
		t.firedAt50 = true
		return &DetectionEvent{
			Signal:         SignalThreshold,
			Confidence:     ConfidenceWarning,
			Details:        "suspicion score crossed 50",
			TriggerCommand: cmd,
			CommandIndex:   session.CommandCount,
		}
	}
	return nil
}

// SequenceSignal fires when 3+ fingerprint commands appear in a row
type SequenceSignal struct {
	consecutiveFingerprints int
	fired                   bool
}

func (s *SequenceSignal) Check(session *sshsession.SessionState, cmd string, category string) *DetectionEvent {
	if category == "fingerprint" {
		s.consecutiveFingerprints++
	} else {
		s.consecutiveFingerprints = 0
	}

	if s.consecutiveFingerprints >= 3 && !s.fired {
		s.fired = true
		return &DetectionEvent{
			Signal:         SignalSequence,
			Confidence:     ConfidenceCritical,
			Details:        "3 or more fingerprint commands in sequence — likely automated scanner",
			TriggerCommand: cmd,
			CommandIndex:   session.CommandCount,
		}
	}
	return nil
}

// TimingSignal fires when median delay between last 5 commands is under 300ms
type TimingSignal struct {
	recentDelays []int64
	fired        bool
}

func (t *TimingSignal) Check(session *sshsession.SessionState, cmd string, delayMs int64) *DetectionEvent {
	// ignore system events and very first command
	if delayMs == 0 {
		return nil
	}

	t.recentDelays = append(t.recentDelays, delayMs)
	if len(t.recentDelays) > 5 {
		t.recentDelays = t.recentDelays[len(t.recentDelays)-5:]
	}

	// need at least 5 samples
	if len(t.recentDelays) < 5 {
		return nil
	}

	// reset if there's a long pause — human resumed typing
	for _, d := range t.recentDelays {
		if d > 5000 {
			t.recentDelays = nil
			return nil
		}
	}

	median := medianDelay(t.recentDelays)
	if median < 300 && !t.fired {
		t.fired = true
		return &DetectionEvent{
			Signal:         SignalTiming,
			Confidence:     ConfidenceHigh,
			Details:        "median command delay under 300ms — automated tool detected",
			TriggerCommand: cmd,
			CommandIndex:   session.CommandCount,
		}
	}
	return nil
}

func medianDelay(delays []int64) int64 {
	// simple median — copy and sort
	sorted := make([]int64, len(delays))
	copy(sorted, delays)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return sorted[len(sorted)/2]
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
