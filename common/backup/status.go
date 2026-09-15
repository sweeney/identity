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
type Status struct {
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
	// Successes and Failures count attempts since process start.
	Successes int
	Failures  int
	// NextRun is when the next scheduled backup is due, or zero when
	// Schedule is "off". Triggered and on-demand backups are not scheduled and
	// do not affect it.
	NextRun time.Time
}

// Status returns a snapshot of what has happened to this Manager's backups.
// The returned value is a copy: it is safe to hold, and it will not change
// under a handler that is midway through rendering it.
func (m *Manager) Status() Status {
	// Computed outside the lock: it reads the clock and the immutable config,
	// not the mutable status.
	next := m.NextRun()

	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.NextRun = next
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
