package detector

import (
	sshsession "GradGuard/internal/Session"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var mu sync.Mutex

type Detector struct {
	session   *sshsession.SessionState
	container string
	threshold ThresholdSignal
	sequence  SequenceSignal
	timing    TimingSignal
}

func New(session *sshsession.SessionState) *Detector {
	return &Detector{
		session:   session,
		container: containerName(session.ID),
	}
}

func (d *Detector) Check(cmd string, category string, delayMs int64) []DetectionEvent {
	var events []DetectionEvent

	if e := d.threshold.Check(d.session, cmd); e != nil {
		e.ResponseTaken = Execute(d.container, e.Confidence)
		events = append(events, d.finalize(*e))
	}

	if e := d.sequence.Check(d.session, cmd, category); e != nil {
		e.ResponseTaken = Execute(d.container, ConfidenceCritical)
		events = append(events, d.finalize(*e))
	}

	if e := d.timing.Check(d.session, cmd, delayMs); e != nil {
		e.ResponseTaken = Execute(d.container, e.Confidence)
		events = append(events, d.finalize(*e))
	}

	for _, event := range events {
		writeDetection(d.session.ID, event)
	}

	return events
}

func (d *Detector) finalize(e DetectionEvent) DetectionEvent {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	e.SessionID = d.session.ID
	e.RemoteAddr = d.session.RemoteAddr
	return e
}

func writeDetection(sessionID string, event DetectionEvent) {
	mu.Lock()
	defer mu.Unlock()

	dir := "logs/detections"
	_ = os.MkdirAll(dir, 0755)

	path := filepath.Join(dir, sessionID+"-detections.json")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	json.NewEncoder(file).Encode(event)
}
