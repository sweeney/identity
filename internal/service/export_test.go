package service

import "time"

// SetClockForTest replaces the clock the refresh-reuse throttle reads.
func (s *AuthService) SetClockForTest(now func() time.Time) { s.now = now }
