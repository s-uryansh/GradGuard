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
	}
}
