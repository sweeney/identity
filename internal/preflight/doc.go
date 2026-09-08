// Package preflight exists to host tests for scripts/preflight-audience.sh.
//
// That script is an operational pre-deploy gate: it reports what a change to
// audience handling will do to live sessions, and --strict makes it fail a
// deploy. It has already gated two production deploys and found a real issue
// each time. Bugs in it are therefore not cosmetic — a false "safe to deploy"
// is worse than no tool at all, because it is trusted.
//
// The tests run the real script against a real database built by the real
// migrations, so they exercise the schema it actually reads rather than a
// fixture that can drift from it.
package preflight
