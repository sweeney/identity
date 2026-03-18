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
