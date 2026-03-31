package Session

import "time"

type SessionState struct {
	ID              string
	RemoteAddr      string
	StartTime       time.Time
	LastCommandTime time.Time
	CommandCount    int
	SuspicionScore  int
	FlaggedCommands []string
	CategoryCounts  map[string]int
	UniqueCommands  map[string]bool
	LatencyDelay    time.Duration
	LastFeatures    []float64
}

func NewSession(id, remoteAddr string) *SessionState {
	return &SessionState{
		ID:         id,
		RemoteAddr: remoteAddr,
		StartTime:  time.Now(),
		CategoryCounts: map[string]int{
			"fingerprint": 0,
			"recon":       0,
			"exploit":     0,
			"unknown":     0,
		},
		UniqueCommands: make(map[string]bool),
	}
}

func (s *SessionState) UpdateStats(suspicion int, category string, cmd string) {
	s.CommandCount++
	s.UniqueCommands[cmd] = true

	s.SuspicionScore += suspicion
	if s.SuspicionScore > 100 {
		s.SuspicionScore = 100
	}
	if s.SuspicionScore < 0 {
		s.SuspicionScore = 0
	}

	s.CategoryCounts[category]++
	s.LastCommandTime = time.Now()
}
