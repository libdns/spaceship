package libdnsspaceship

import (
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// The ACME DNS-01 solver (e.g. in Caddy/CertMagic) appends the challenge as a generic
// libdns.RR with a zero TTL. It must become a TXT item with a zone-relative name and a
// TTL the API accepts, not be dropped (which sent "items": null and failed with 422).
func TestFromLibdnsRR_GenericTXTFromACMESolver(t *testing.T) {
	provider := &Provider{}
	for _, zone := range []string{"example.com.", "example.com"} {
		rec := provider.fromLibdnsRR(libdns.RR{Type: "TXT", Name: "_acme-challenge", Data: "token-value"}, zone)
		if rec == nil {
			t.Fatalf("zone %q: generic TXT RR was dropped", zone)
		}
		if rec.Type != "TXT" || rec.Name != "_acme-challenge" || rec.Value != "token-value" {
			t.Fatalf("zone %q: unexpected conversion: %#v", zone, rec)
		}
		if rec.TTL != minTTL {
			t.Fatalf("zone %q: expected TTL %d for a zero TTL, got %d", zone, minTTL, rec.TTL)
		}
	}
}

func TestFromLibdnsRR_NamesRelativeToZone(t *testing.T) {
	provider := &Provider{}
	cases := map[string]string{
		"":                    "@",
		"@":                   "@",
		"www":                 "www",
		"www.example.com.":    "www",
		"a.b.example.com":     "a.b",
		"_acme-challenge.sub": "_acme-challenge.sub",
	}
	for in, want := range cases {
		rec := provider.fromLibdnsRR(libdns.TXT{Name: in, Text: "x", TTL: 300 * time.Second}, "example.com.")
		if rec == nil || rec.Name != want {
			t.Errorf("name %q: want %q, got %#v", in, want, rec)
		}
	}
}
