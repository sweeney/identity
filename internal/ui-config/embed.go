// Package uiconfig holds the embedded SPA bundle (HTML + JS + CSS) for the
// config service's admin UI. The SPA authenticates against identity via
// the OAuth Authorization Code + PKCE flow, stores tokens in localStorage,
// and calls the existing /api/v1/config/* endpoints with a Bearer header.
//
// See examples/spa-demo for the auth pattern this UI follows. There is no
// server-side session, no CSRF middleware, and no cookie crypto — the
// config service stays purely API-driven and serves these files
// statically.
package uiconfig

import (
	"embed"
	"strconv"
	"time"
)

//go:embed static
var StaticFS embed.FS

// AssetVersion is set at startup; append as ?v=… in templates so a fresh
// deploy invalidates browser caches.
var AssetVersion = strconv.FormatInt(time.Now().Unix(), 36)
