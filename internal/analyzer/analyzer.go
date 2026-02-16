package analyzer

import (
	Session "GradGuard/internal/Session"
)

const (
	VerdictClean                = "clean"
	VerdictSuspicious           = "suspicious"
	VerdictLikelyFingerprinting = "likely_fingerprinting"
	VerdictExploitAttempt       = "exploit_attempt"
)

func Analyze(session *Session.SessionState, cmd string) ClassificationResult {
	result := Classify(cmd)

	session.SuspicionScore += result.SuspicionWeight
	if session.SuspicionScore > 100 {
		session.SuspicionScore = 100
	}

	session.CategoryCounts[string(result.Category)]++

	if result.Category == CategoryFingerprint || result.Category == CategoryExploit {
		session.FlaggedCommands = append(session.FlaggedCommands, cmd)
	}

	return result
}

func Verdict(session *Session.SessionState) string {
	if session.CategoryCounts[string(CategoryExploit)] > 0 {
		return VerdictExploitAttempt
	}
	if session.SuspicionScore >= 70 {
		return VerdictLikelyFingerprinting
	}
	if session.SuspicionScore >= 30 {
		return VerdictSuspicious
	}
	return VerdictClean
}
