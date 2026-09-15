package backup

import "time"

// Status is a point-in-time snapshot of a Manager's backup history.
//
// It exists because the Manager already knows all of this and used to tell
// nobody: EventRecorder is fire-and-forget and the internal timestamps are
// unexported, so every consumer that reported backup health grew its own
// mutex-guarded copy of the same bookkeeping — and each one had to invent its
// own answer to "is a backup that last succeeded 70 hours ago healthy?".
//
// Poll it from a /healthz or /metrics handler. The answer to that question is
// still the consumer's to make, but the facts it needs are here:
//
//   - LastAttempt == LastSuccess means the most recent backup succeeded.
//   - LastAttempt after LastSuccess means backups are failing *now*, and the
//     gap between them is how long that has been true. This is why a failure
//     never moves LastSuccess.
//   - LastKey names the newest backup known to be good, so it can be found
//     without listing the bucket — which matters most while backups are
//     failing, exactly when LastKey is not the newest attempt.
//
// Read Configured and Scheduled before reading anything else. A Status whose
// timestamps are all zero says one of three quite different things, and only
// those two fields tell them apart: backups are not configured at all
// (Configured false — the NoopManager); they are configured but nothing
// schedules them (Scheduled false, Schedule "off" or Start never called, so
// only TriggerAsync and RunNow produce one); or the first scheduled backup has
// not come round yet.
type Status struct {
	// Configured reports whether backups can happen at all. False only for
	// the NoopManager, which is installed when no backup destination is
	// configured — the case where every other field being zero is expected
	// and permanent.
	Configured bool
	// Scheduled reports whether a goroutine is actually waiting to take the
	// next scheduled backup: Start has been called and Schedule is not "off".
	// A Manager that was constructed and never Started is not scheduled, and
	// says so rather than reporting a backup that is not coming.
	Scheduled bool
	// LastAttempt is when the most recent backup attempt finished, successful
	// or not. Zero if none has been made.
	LastAttempt time.Time
	// LastSuccess is when the most recent successful backup finished. Zero if
	// none has succeeded. A failed attempt does not move it.
	LastSuccess time.Time
	// LastKey is the object key of the most recent successful backup. It is
	// retained across later failures.
	LastKey string
	// LastError describes the most recent attempt if it failed, and is empty
	// if it succeeded — so a non-empty LastError means "failing right now".
	// It has been passed through RedactSecrets.
	LastError string
	// Successes and Failures count attempts since this Manager was created —
	// not since process start, which is a distinction for anything that
	// rebuilds its Manager on a config reload.
	Successes int
	Failures  int
	// NextRun is when the next scheduled backup is due, and is zero whenever
	// Scheduled is false. Triggered and on-demand backups are not scheduled
	// and do not affect it.
	NextRun time.Time
}

// Status returns a snapshot of what has happened to this Manager's backups.
// The returned value is a copy: it is safe to hold, and it will not change
// under a handler that is midway through rendering it.
func (m *Manager) Status() Status {
	// Computed outside the lock: it reads the clock, which is consumer code
	// and may call back in here.
	next := m.NextRun()

	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Configured = true
	s.Scheduled = m.started && m.cfg.Schedule != "off"
	if s.Scheduled {
		s.NextRun = next
	}
	return s
}

// finish records the outcome of a single backup attempt. Every path through
// run ends here, so the status, the event recorder and the log cannot disagree
// about what happened. errDetail is the redacted error description and is
// ignored when success is true.
func (m *Manager) finish(now time.Time, success bool, key, errDetail string) {
	m.mu.Lock()
	m.status.LastAttempt = now
	if success {
		m.status.LastSuccess = now
		m.status.LastKey = key
		m.status.LastError = ""
		m.status.Successes++
	} else {
		m.status.LastError = errDetail
		m.status.Failures++
	}
	m.mu.Unlock()

	if m.record == nil {
		return
	}
	// EventRecorder's long-standing contract: the key on success, a short
	// error description on failure. Called outside the lock — it is the
	// consumer's code and may do anything, including calling back into Status.
	detail := key
	if !success {
		detail = errDetail
	}
	m.record(success, detail)
}
