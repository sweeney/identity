// Minimal static file server for the Passkey / WebAuthn demo.
//
// Usage:
//
//  1. Start the identity server in dev mode (passkeys auto-enable on localhost):
//     go run ./cmd/server
//
//  2. Create a user (via admin UI at http://localhost:8181/admin or API)
//
//  3. Run this demo:
//     go run ./examples/passkey-demo
//
//  4. Open http://localhost:9093 in your browser
package main

import (
	"log"
	"net/http"
)

func main() {
	dir := "examples/passkey-demo"
	log.Printf("Passkey demo serving %s on http://localhost:9093", dir)
	log.Printf("Make sure the identity server is running on http://localhost:8181")
	log.Fatal(http.ListenAndServe(":9093", http.FileServer(http.Dir(dir))))
}
