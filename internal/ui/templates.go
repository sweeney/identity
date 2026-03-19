package ui

import (
	"embed"
	"strconv"
	"time"
)

//go:embed templates/*.html
var TemplateFS embed.FS

//go:embed static/*
var StaticFS embed.FS

// AssetVersion is a cache-busting string set at startup. Append as ?v={{assetVer}}
// to static asset URLs in templates so deploys invalidate browser/CDN caches.
var AssetVersion = strconv.FormatInt(time.Now().Unix(), 36)
