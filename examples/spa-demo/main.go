// Minimal static file server for the SPA OAuth demo.
//
// Usage:
//
//	1. Register an OAuth client in the admin UI:
//	   - Client ID:     spa-demo
//	   - Name:          SPA Demo
//	   - Redirect URI:  http://localhost:9091/
//
//	2. Run this server:
//	   go run ./examples/spa-demo
//
//	3. Open http://localhost:9091 in your browser
package main

import (
	"log"
	"net/http"
)

func main() {
	dir := "examples/spa-demo"
	log.Printf("SPA demo serving %s on http://localhost:9091", dir)
	log.Printf("Register client_id=spa-demo with redirect_uri=http://localhost:9091/ in the admin UI first")
	log.Fatal(http.ListenAndServe(":9091", http.FileServer(http.Dir(dir))))
}
