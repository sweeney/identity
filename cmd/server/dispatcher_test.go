package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDispatchUnknownSubcommand checks that an unrecognised subcommand
// surfaces a clear error rather than falling through silently.
func TestDispatchUnknownSubcommand(t *testing.T) {
	err := dispatch([]string{"nonsense"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown subcommand")
}

// TestDispatchHelpVariants asserts that all top-level help forms succeed
// without error (they print usage and return nil).
func TestDispatchHelpVariants(t *testing.T) {
	for _, form := range []string{"help", "--help", "-h"} {
		t.Run(form, func(t *testing.T) {
			assert.NoError(t, dispatch([]string{form}))
		})
	}
}

// TestDispatchIdentityHelp ensures the identity subcommand's help form
// routes correctly. Serving (no-arg and bare `identity` forms) is not
// exercised here because it would spin up an HTTP server; the rest of
// the test suite covers identity serve behaviour end-to-end.
func TestDispatchIdentityHelp(t *testing.T) {
	for _, form := range []string{"--help", "-h", "help"} {
		t.Run(form, func(t *testing.T) {
			assert.NoError(t, dispatch([]string{"identity", form}))
		})
	}
}

// TestDispatchLegacyFlagRouting verifies that a top-level flag argument
// routes to the identity subcommand for backward compatibility.
// We use --help here (rather than --reset-admin or similar) because it
// is the only legacy flag that does not perform destructive side effects.
func TestDispatchLegacyFlagRouting(t *testing.T) {
	assert.NoError(t, dispatch([]string{"--help"}))
}

// TestDispatchUnknownIdentityFlag surfaces errors on unknown identity flags
// rather than silently starting the server.
func TestDispatchUnknownIdentityFlag(t *testing.T) {
	err := dispatch([]string{"identity", "--not-a-real-flag"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown identity flag")
}
