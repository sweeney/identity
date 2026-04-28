package httputil

import (
	"net/http"
	"testing"
)

func TestExtractClientIP_NoTrust(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "192.168.1.1:12345",
		Header:     http.Header{"Cf-Connecting-Ip": {"10.0.0.1"}},
	}
	got := ExtractClientIP(r, "")
	if got != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", got)
	}
}

func TestExtractClientIP_CloudflareTrust(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "192.168.1.1:12345",
		Header:     http.Header{"Cf-Connecting-Ip": {"10.0.0.1"}},
	}
	got := ExtractClientIP(r, "cloudflare")
	if got != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", got)
	}
}

func TestExtractClientIP_CloudflareTrust_NoHeader(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "192.168.1.1:12345",
		Header:     http.Header{},
	}
	got := ExtractClientIP(r, "cloudflare")
	if got != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", got)
	}
}

func TestCheckOrigin_SameOrigin(t *testing.T) {
	r := &http.Request{Host: "id.example.com", Header: http.Header{"Origin": {"https://id.example.com"}}}
	if !CheckOrigin(r) {
		t.Error("same origin should pass")
	}
}

func TestCheckOrigin_CrossOrigin(t *testing.T) {
	r := &http.Request{Host: "id.example.com", Header: http.Header{"Origin": {"https://evil.com"}}}
	if CheckOrigin(r) {
		t.Error("cross origin should fail")
	}
}

func TestCheckOrigin_NoOriginHeader(t *testing.T) {
	r := &http.Request{Host: "id.example.com", Header: http.Header{}}
	if !CheckOrigin(r) {
		t.Error("missing origin should pass (non-browser client)")
	}
}

func TestCheckOrigin_Localhost(t *testing.T) {
	r := &http.Request{Host: "localhost:8181", Header: http.Header{"Origin": {"http://localhost:8181"}}}
	if !CheckOrigin(r) {
		t.Error("localhost same-origin should pass")
	}
}

func TestCheckOrigin_LocalhostCrossPort(t *testing.T) {
	r := &http.Request{Host: "localhost:8181", Header: http.Header{"Origin": {"http://localhost:9093"}}}
	if CheckOrigin(r) {
		t.Error("localhost cross-port should fail")
	}
}

func TestExtractClientIP_RemoteAddrNoPort(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "192.168.1.1",
		Header:     http.Header{},
	}
	got := ExtractClientIP(r, "")
	if got != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", got)
	}
}
