package ci_test

// workflow_test.go covers WP14 (#28): the CI workflow ran third-party code
// from mutable references with no permissions block.
//
// Every `uses:` named a mutable major tag, and two steps installed tooling from
// `@latest`. Whoever controls those references — or anyone who compromises
// them — chooses what executes in CI. The default GITHUB_TOKEN permissions then
// decide what that code can reach, and the workflow declared none, so it ran
// with whatever the repository default happens to be.

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const workflowPath = "../../.github/workflows/ci.yml"

func readWorkflow(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(workflowPath)
	require.NoError(t, err, "CI workflow must exist at %s", workflowPath)
	return string(b)
}

// pinnedUses matches `uses:` values pinned to a full 40-character commit SHA.
var pinnedUses = regexp.MustCompile(`^[\w.-]+/[\w.-]+(/[\w.-]+)*@[0-9a-f]{40}$`)

// A tag is a moving pointer; a commit SHA is not. Third-party actions must be
// pinned to the SHA so a retagged release cannot change what CI executes.
func TestWorkflow_ActionsPinnedToCommitSHA(t *testing.T) {
	for i, line := range strings.Split(readWorkflow(t), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- uses:") && !strings.HasPrefix(trimmed, "uses:") {
			continue
		}
		value := strings.TrimSpace(strings.SplitN(trimmed, "uses:", 2)[1])
		// Strip any trailing "# v5"-style version comment.
		if idx := strings.Index(value, "#"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}
		assert.Regexp(t, pinnedUses, value,
			"ci.yml:%d: action %q must be pinned to a 40-character commit SHA, not a mutable tag", i+1, value)
	}
}

// Installing tooling from @latest hands an unreviewed upstream release direct
// execution on every run. The Makefile runs the same spectral lint locally, so
// it is held to the same rule.
func TestWorkflow_NoMutableToolVersions(t *testing.T) {
	for _, path := range []string{workflowPath, "../../Makefile"} {
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		for i, line := range strings.Split(string(b), "\n") {
			assert.NotContains(t, line, "@latest",
				"%s:%d: pin this tool to an exact version rather than @latest", path, i+1)
		}
	}
}

// Without an explicit permissions block the workflow's GITHUB_TOKEN carries
// whatever the repository default grants, which may include write access.
func TestWorkflow_DeclaresPermissions(t *testing.T) {
	content := readWorkflow(t)
	require.True(t, strings.Contains(content, "\npermissions:"),
		"ci.yml must declare a top-level permissions block")

	// The declaration is only worth anything if it is restrictive.
	block := content[strings.Index(content, "\npermissions:"):]
	if end := strings.Index(block[1:], "\n\n"); end >= 0 {
		block = block[:end+1]
	}
	assert.Contains(t, block, "contents: read",
		"the top-level permissions block should grant read-only contents access")
	assert.NotContains(t, block, "write",
		"no job in this workflow needs write access")
}
