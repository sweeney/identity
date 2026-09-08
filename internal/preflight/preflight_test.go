package preflight_test

// preflight_test.go tests scripts/preflight-audience.sh end to end.
//
// Two bugs reached production use before these existed, both found by hand:
// a tab field separator that silently shifted every column left whenever a
// client had no audiences (tab is IFS whitespace, so bash collapsed runs of
// it), and an orphaned-client verdict that reported "LOSES ALL" for sessions
// carrying nothing to lose, inflating the impact count and firing the warning
// on a false alarm. Both are pinned below.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"
)

const (
	exitOK        = 0
	exitUsage     = 1
	exitEnv       = 2
	exitImpact    = 3
	future        = "2099-01-01T00:00:00.000Z"
	past          = "2020-01-01T00:00:00.000Z"
	scriptRelPath = "../../scripts/preflight-audience.sh"
)

// newDB builds a database with the real migrations applied and returns its path.
func newDB(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 CLI not installed; the script shells out to it")
	}
	path := filepath.Join(t.TempDir(), "preflight.db")
	database, err := db.Open(path)
	require.NoError(t, err)
	// Close before the script reads it: the connection is WAL-mode, and the
	// script opens the file read-only.
	require.NoError(t, database.Close())
	return path
}

// exec runs SQL against the test database.
func execSQL(t *testing.T, path, sql string) {
	t.Helper()
	cmd := exec.Command("sqlite3", path, sql)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "sqlite3 failed: %s", out)
}

// run executes the script and returns combined output and exit code.
func run(t *testing.T, path string, args ...string) (string, int) {
	t.Helper()
	script, err := filepath.Abs(scriptRelPath)
	require.NoError(t, err)
	cmd := exec.Command(script, args...)
	cmd.Env = append(os.Environ(), "DB_PATH="+path)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running script: %v", err)
	}
	return string(out), code
}

// --- seeding helpers -------------------------------------------------------

func addUser(t *testing.T, path, id, username, role string) {
	t.Helper()
	execSQL(t, path, `INSERT INTO users (id,username,display_name,password_hash,role,is_active,created_at,updated_at)
		VALUES ('`+id+`','`+username+`','`+username+`','x','`+role+`',1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');`)
}

func addClient(t *testing.T, path, id, audsJSON, secretHash string) {
	t.Helper()
	execSQL(t, path, `INSERT INTO oauth_clients (id,name,redirect_uris,grant_types,audiences,client_secret_hash,created_at,updated_at)
		VALUES ('`+id+`','`+id+`','[]','["authorization_code"]','`+audsJSON+`','`+secretHash+`','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');`)
}

func addToken(t *testing.T, path, id, userID, clientID, audsJSON, expires string, revoked int) {
	t.Helper()
	client := "NULL"
	if clientID != "" {
		client = "'" + clientID + "'"
	}
	execSQL(t, path, `INSERT INTO refresh_tokens (id,user_id,token_hash,family_id,device_hint,audiences,scope,client_id,issued_at,last_used_at,expires_at,is_revoked)
		VALUES ('`+id+`','`+userID+`','h`+id+`','f`+id+`','','`+audsJSON+`','',`+client+`,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z','`+expires+`',`+itoa(revoked)+`);`)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	return "1"
}

// --- environment and usage -------------------------------------------------

func TestExitCodes_Environment(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 CLI not installed")
	}
	dir := t.TempDir()

	t.Run("missing database is exit 2, and is not created", func(t *testing.T) {
		missing := filepath.Join(dir, "nope.db")
		out, code := run(t, missing)
		assert.Equal(t, exitEnv, code)
		assert.Contains(t, out, "no database at")
		_, err := os.Stat(missing)
		assert.True(t, os.IsNotExist(err),
			"a mistyped path must not leave an empty database behind — sqlite3 would happily create one")
	})

	t.Run("not a database is exit 2", func(t *testing.T) {
		junk := filepath.Join(dir, "junk.db")
		require.NoError(t, os.WriteFile(junk, []byte("definitely not sqlite"), 0o600))
		out, code := run(t, junk)
		assert.Equal(t, exitEnv, code)
		assert.Contains(t, out, "cannot read")
	})

	t.Run("wrong schema is exit 2", func(t *testing.T) {
		wrong := filepath.Join(dir, "wrong.db")
		execSQL(t, wrong, "CREATE TABLE unrelated (a);")
		out, code := run(t, wrong)
		assert.Equal(t, exitEnv, code)
		assert.Contains(t, out, "wrong database?")
	})
}

func TestExitCodes_Usage(t *testing.T) {
	path := newDB(t)

	t.Run("unknown argument is exit 1", func(t *testing.T) {
		out, code := run(t, path, "--wat")
		assert.Equal(t, exitUsage, code)
		assert.Contains(t, out, "unknown argument")
	})

	t.Run("--self without a value is exit 1", func(t *testing.T) {
		_, code := run(t, path, "--self")
		assert.Equal(t, exitUsage, code,
			"a flag that silently swallows the next flag would produce a wrong report, not an error")
	})

	t.Run("--help is exit 0", func(t *testing.T) {
		out, code := run(t, path, "--help")
		assert.Equal(t, exitOK, code)
		assert.Contains(t, out, "usage:")
	})
}

func TestCleanDatabase_IsSafeToDeploy(t *testing.T) {
	path := newDB(t)
	out, code := run(t, path, "--strict")
	assert.Equal(t, exitOK, code)
	assert.Contains(t, out, "No live session loses an audience")
	assert.Contains(t, out, "no live refresh tokens")
}

// --- audience impact -------------------------------------------------------

func TestAudienceImpact(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "u1", "alice", "user")
	addClient(t, path, "keeps", `["a","b"]`, "")
	addClient(t, path, "shrinks", `["a"]`, "")
	addClient(t, path, "namesnothing", `[]`, "")

	// Stored in the opposite order to the registration: equal sets must read as
	// unchanged, or every re-ordering looks like an impact.
	addToken(t, path, "t1", "u1", "keeps", `["b","a"]`, future, 0)
	addToken(t, path, "t2", "u1", "shrinks", `["a","b"]`, future, 0)
	addToken(t, path, "t3", "u1", "namesnothing", `["a"]`, future, 0)
	addToken(t, path, "t4", "u1", "", `[]`, future, 0)
	// Neither of these may appear anywhere in the report.
	addToken(t, path, "t5", "u1", "keeps", `["revoked-marker"]`, future, 1)
	addToken(t, path, "t6", "u1", "keeps", `["expired-marker"]`, past, 0)

	out, code := run(t, path)
	require.Equal(t, exitOK, code, out)

	assert.Contains(t, out, "keeps")
	assert.Regexp(t, `keeps\s+1\s+a,b\s+a,b\s+unchanged`, out,
		"equal sets stored in different order must normalise to unchanged")
	assert.Regexp(t, `shrinks\s+1\s+.*LOSES: b`, out)
	assert.Regexp(t, `namesnothing\s+1\s+.*LOSES: a`, out,
		"a client that now names nothing withdraws what its sessions carried")
	assert.Regexp(t, `<unbound>\s+1\s+.*unchanged`, out)

	assert.NotContains(t, out, "revoked-marker", "revoked tokens must be excluded")
	assert.NotContains(t, out, "expired-marker", "expired tokens must be excluded")

	_, code = run(t, path, "--strict")
	assert.Equal(t, exitImpact, code, "--strict must fail a deploy when sessions lose an audience")
}

// TestOrphanCarryingNothingIsNotAnImpact pins the false-alarm bug. A session
// whose client is gone but which carries no audiences loses nothing, and must
// not be counted or warned about.
func TestOrphanCarryingNothingIsNotAnImpact(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "u1", "alice", "user")
	addToken(t, path, "t1", "u1", "vanished", `[]`, future, 0)

	out, code := run(t, path, "--strict")
	assert.Equal(t, exitOK, code,
		"an orphan carrying nothing loses nothing and must not fail --strict")
	assert.Contains(t, out, "carried nothing")
	assert.NotContains(t, out, "LOSES ALL")
	assert.Contains(t, out, "groups whose client is unregistered: 0")
}

func TestOrphanCarryingSomethingIsAnImpact(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "u1", "alice", "user")
	addToken(t, path, "t1", "u1", "vanished", `["ghost"]`, future, 0)

	out, code := run(t, path, "--strict")
	assert.Equal(t, exitImpact, code)
	assert.Contains(t, out, "LOSES ALL")
	assert.Contains(t, out, "groups whose client is unregistered: 1")
}

// TestEmptyAudienceColumnDoesNotShiftColumns pins the tab-separator bug. A
// client with no audiences produced an empty field; with tab as IFS, bash
// collapsed it and every later column shifted left, so the report printed an
// internal classifier where the verdict belonged — while looking plausible.
func TestEmptyAudienceColumnDoesNotShiftColumns(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "u1", "alice", "user")
	addClient(t, path, "gainer", `["x","y"]`, "")
	addToken(t, path, "t1", "u1", "gainer", `[]`, future, 0)

	out, _ := run(t, path)
	assert.Regexp(t, `gainer\s+1\s+<none>\s+x,y\s+gains: x,y`, out,
		"an empty carried set must not shift the remaining columns")
	for _, internal := range []string{"bound", "unbound\t", "no-registration"} {
		assert.NotContains(t, out, "   "+internal,
			"internal classifier %q must never appear as a column value", internal)
	}
}

// --- #40: confidential clients --------------------------------------------

func TestConfidentialClientImpact(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "u1", "alice", "user")
	addClient(t, path, "public-app", `["a"]`, "")
	addClient(t, path, "conf-idle", `["a"]`, "$2a$10$hash")
	addClient(t, path, "conf-live", `["a"]`, "$2a$10$hash")
	addToken(t, path, "t1", "u1", "public-app", `["a"]`, future, 0)
	addToken(t, path, "t2", "u1", "conf-live", `["a"]`, future, 0)

	out, code := run(t, path, "--strict")
	require.Equal(t, exitOK, code, out)

	assert.Regexp(t, `public-app\s+public\s+1\s+none`, out)
	assert.Regexp(t, `conf-idle\s+confidential\s+0\s+none \(no live sessions\)`, out,
		"a confidential client with no sessions changes nothing")
	assert.Regexp(t, `conf-live\s+confidential\s+1\s+REFUSED`, out)
	assert.Contains(t, out, "1 live session(s) belong to confidential clients")
}

func TestNoConfidentialSessions_ReportsClean(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "u1", "alice", "user")
	addClient(t, path, "public-app", `["a"]`, "")
	addToken(t, path, "t1", "u1", "public-app", `["a"]`, future, 0)

	out, _ := run(t, path)
	assert.Contains(t, out, "No live session belongs to a confidential client")
}

// --- #37: management plane exclusivity ------------------------------------

func TestManagementPlaneImpact(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "admin1", "root", "admin")
	addUser(t, path, "user1", "alice", "user")

	addClient(t, path, "exclusive", `["id.swee.net"]`, "")
	addClient(t, path, "delegated", `["id.swee.net","statehouse"]`, "")

	addToken(t, path, "t1", "admin1", "exclusive", `["id.swee.net"]`, future, 0)
	addToken(t, path, "t2", "admin1", "delegated", `["id.swee.net","statehouse"]`, future, 0)
	addToken(t, path, "t3", "admin1", "", `[]`, future, 0)
	// A non-admin holding a delegated token cannot reach the management routes
	// at all, so it must not be reported as affected.
	addToken(t, path, "t4", "user1", "delegated", `["id.swee.net","statehouse"]`, future, 0)

	out, code := run(t, path, "--strict")
	require.Equal(t, exitImpact, code, out)

	assert.Regexp(t, `exclusive\s+root\s+1\s+id\.swee\.net\s+allowed`, out)
	assert.Regexp(t, `delegated\s+root\s+1\s+.*REFUSED — delegated to 'statehouse'`, out)
	assert.Regexp(t, `<unbound>\s+root\s+1\s+<none>\s+allowed`, out,
		"a direct-login token was never delegated and keeps management access")
	assert.Contains(t, out, "1 admin session(s) will be refused")
	assert.NotContains(t, out, "alice",
		"a non-admin cannot reach the management routes, so must not be listed")
}

func TestManagementPlane_NoAdminSessions(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "user1", "alice", "user")
	addClient(t, path, "delegated", `["id.swee.net","statehouse"]`, "")
	addToken(t, path, "t1", "user1", "delegated", `["id.swee.net","statehouse"]`, future, 0)

	out, code := run(t, path, "--strict")
	assert.Equal(t, exitOK, code)
	assert.Contains(t, out, "no live sessions belong to an admin account")
}

// TestSelfFlagIsHonoured checks the exclusivity comparison uses the configured
// name. Getting this wrong would report every admin session as refused, or none.
func TestSelfFlagIsHonoured(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "admin1", "root", "admin")
	addClient(t, path, "other", `["identity.example"]`, "")
	addToken(t, path, "t1", "admin1", "other", `["identity.example"]`, future, 0)

	out, code := run(t, path, "--strict", "--self", "identity.example")
	assert.Equal(t, exitOK, code, out)
	assert.Regexp(t, `other\s+root\s+1\s+identity\.example\s+allowed`, out)

	out, code = run(t, path, "--strict")
	assert.Equal(t, exitImpact, code,
		"under the default self name the same session is delegated elsewhere")
	assert.Contains(t, out, "REFUSED")
}

// TestHTTPSSpellingCountsAsSelf — both accepted spellings of this server name
// it, so a token carrying both is still exclusive.
func TestHTTPSSpellingCountsAsSelf(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "admin1", "root", "admin")
	addClient(t, path, "both", `["id.swee.net","https://id.swee.net"]`, "")
	addToken(t, path, "t1", "admin1", "both", `["id.swee.net"]`, future, 0)

	out, code := run(t, path, "--strict")
	assert.Equal(t, exitOK, code, out)
	assert.Contains(t, out, "allowed")
}

// --- the safety property --------------------------------------------------

// TestScriptNeverWritesToTheDatabase is the property the script's whole design
// rests on: it is pointed at a live production database, as root.
func TestScriptNeverWritesToTheDatabase(t *testing.T) {
	path := newDB(t)
	addUser(t, path, "admin1", "root", "admin")
	addClient(t, path, "c", `["a"]`, "$2a$10$hash")
	addToken(t, path, "t1", "admin1", "c", `["b"]`, future, 0)

	before, err := os.ReadFile(path)
	require.NoError(t, err)
	modBefore, err := os.Stat(path)
	require.NoError(t, err)

	_, _ = run(t, path, "--strict")
	time.Sleep(10 * time.Millisecond)

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	modAfter, err := os.Stat(path)
	require.NoError(t, err)

	assert.Equal(t, before, after, "the script must not modify the database byte-for-byte")
	assert.Equal(t, modBefore.ModTime(), modAfter.ModTime(), "not even the mtime")

	// And prove the refusal is SQLite's, not merely our intent.
	cmd := exec.Command("sqlite3", "file:"+path+"?mode=ro", "DELETE FROM refresh_tokens;")
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(string(out)), "readonly",
		"the read-only guarantee must come from SQLite, not from reviewing the SQL by eye")
}

// TestReadsALiveDatabase covers the path production actually uses.
//
// While the identity service is running the WAL's -shm file exists, so a
// read-only connection works directly. With the service stopped it does not,
// and SQLite refuses a read-only open outright — a WAL database needs to create
// -shm, which read-only cannot do. That surfaced as "locked, corrupt, or not a
// database", which is both alarming and wrong, so the script falls back to
// immutable mode and says so. Both branches are exercised: every other test
// here closes the database first, this one keeps it open.
func TestReadsALiveDatabase(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 CLI not installed")
	}
	path := filepath.Join(t.TempDir(), "live.db")
	database, err := db.Open(path)
	require.NoError(t, err)
	defer database.Close() //nolint:errcheck

	addUser(t, path, "admin1", "root", "admin")
	addClient(t, path, "c", `["id.swee.net"]`, "")
	addToken(t, path, "t1", "admin1", "c", `["id.swee.net"]`, future, 0)

	out, code := run(t, path, "--strict")
	require.Equal(t, exitOK, code, out)
	assert.NotContains(t, out, "immutable mode",
		"with a live writer the ordinary read-only path must be used")
	assert.Regexp(t, `c\s+root\s+1\s+id\.swee\.net\s+allowed`, out)
}

// TestQuiescentDatabaseIsAnnounced is the other side: the fallback must not be
// silent, because reading a database nobody is writing may mean the service is
// down — which the operator wants to know before trusting the numbers.
func TestQuiescentDatabaseIsAnnounced(t *testing.T) {
	path := newDB(t) // newDB closes the handle
	out, code := run(t, path)
	require.Equal(t, exitOK, code, out)
	assert.Contains(t, out, "no live writer detected",
		"falling back to immutable mode must be announced, not silent")
}
