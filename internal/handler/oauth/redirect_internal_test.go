package oauth

// redirect_internal_test.go exposes buildRedirect to the external test package,
// which is where the WP13 table test for it lives.

// BuildRedirectForTest is a test-only accessor for buildRedirect.
func BuildRedirectForTest(redirectURI, code, state string) string {
	return buildRedirect(redirectURI, code, state)
}
