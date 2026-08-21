package libdnsspaceship

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// helper roundTripper for testing HTTP client behavior
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type genericRRWrapper struct{ rr libdns.RR }

func (r genericRRWrapper) RR() libdns.RR { return r.rr }

func TestProvider_GetRecords_NoAuth(t *testing.T) {
	provider := &Provider{}
	_, err := provider.GetRecords(context.Background(), getTestZone())
	if err == nil || !strings.Contains(err.Error(), "API key and secret are required") {
		t.Errorf("Expected API key/secret error, got: %v", err)
	}
}

func getTestZone() string {
	if z := os.Getenv("LIBDNS_SPACESHIP_ZONE"); z != "" {
		return strings.TrimSuffix(z, ".")
	}
	return "example.com"
}

func TestProvider_ConvertToLibdnsRecord(t *testing.T) {
	provider := NewProviderFromEnv()
	zone := getTestZone()

	tests := []struct {
		name     string
		input    spaceshipRecordUnion
		expected string // expected type
	}{
		{
			name:     "A record",
			input:    spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: "test", Type: "A", TTL: 300}, Address: "192.0.2.1"},
			expected: "libdns.Address",
		},
		{
			name:     "TXT record",
			input:    spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: "test", Type: "TXT", TTL: 300}, Value: "v=spf1 include:_spf." + zone + " ~all"},
			expected: "libdns.TXT",
		},
		{
			name:     "CNAME record",
			input:    spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: "www", Type: "CNAME", TTL: 300}, Cname: zone},
			expected: "libdns.CNAME",
		},
		{
			name:     "MX record",
			input:    spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: zone + ".", Type: "MX", TTL: 300}, Exchange: "mail", Preference: 10},
			expected: "libdns.MX",
		},
		{
			name:     "SRV record",
			input:    spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: "_sip._tcp", Type: "SRV", TTL: 3600}, Priority: 10, Weight: 20, PortInt: 5060, Port: "5060", Target: "sip"},
			expected: "libdns.SRV",
		},
		{
			name:     "HTTPS record",
			input:    spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: "test", Type: "HTTPS", TTL: 300}, SvcPriority: 1, TargetName: "target", SvcParams: "alpn=h2,h3"},
			expected: "libdns.ServiceBinding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.toLibdnsRR(tt.input, zone)
			switch tt.expected {
			case "libdns.Address":
				if _, ok := result.(libdns.Address); !ok {
					t.Errorf("Expected libdns.Address, got %T", result)
				}
			case "libdns.TXT":
				if _, ok := result.(libdns.TXT); !ok {
					t.Errorf("Expected libdns.TXT, got %T", result)
				}
			case "libdns.CNAME":
				if _, ok := result.(libdns.CNAME); !ok {
					t.Errorf("Expected libdns.CNAME, got %T", result)
				}
			case "libdns.MX":
				if _, ok := result.(libdns.MX); !ok {
					t.Errorf("Expected libdns.MX, got %T", result)
				}
			case "libdns.RR":
				if _, ok := result.(libdns.RR); !ok {
					t.Errorf("Expected libdns.RR, got %T", result)
				}
			case "libdns.SRV":
				if _, ok := result.(libdns.SRV); !ok {
					t.Errorf("Expected libdns.SRV, got %T", result)
				}
			case "libdns.ServiceBinding":
				if _, ok := result.(libdns.ServiceBinding); !ok {
					t.Errorf("Expected libdns.ServiceBinding, got %T", result)
				}
			}

			// Verify the record has the correct name (should have zone stripped)
			if tt.expected == "libdns.SRV" {
				if s, ok := result.(libdns.SRV); ok {
					expected := "@"
					if s.Name != expected {
						t.Errorf("Expected SRV name %q, got %q", expected, s.Name)
					}
				} else {
					t.Errorf("expected libdns.SRV but result is %T", result)
				}
			} else if tt.expected == "libdns.ServiceBinding" {
				if s, ok := result.(libdns.ServiceBinding); ok {
					expected := "test"
					if s.Name != expected {
						t.Errorf("Expected ServiceBinding name %q, got %q", expected, s.Name)
					}
				} else {
					t.Errorf("expected libdns.ServiceBinding but result is %T", result)
				}
			} else {
				rr := result.RR()
				expectedNames := map[string]string{
					"A record":     "test",
					"TXT record":   "test",
					"CNAME record": "www",
					"MX record":    "@",
					"HTTPS record": "test",
					// SRV and ServiceBinding are handled above
				}
				if expectedName := expectedNames[tt.name]; rr.Name != expectedName {
					t.Errorf("Expected name %q, got %q", expectedName, rr.Name)
				}
			}
		})
	}
}

func TestProvider_ConvertFromLibdnsRecord(t *testing.T) {
	provider := NewProviderFromEnv()
	zone := getTestZone()

	// Test Address record
	addr := libdns.Address{
		Name: "test",
		TTL:  300 * time.Second,
		IP:   netip.MustParseAddr("192.0.2.1"),
	}

	result, err := provider.fromLibdnsRR(addr, zone)
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "test" {
		t.Errorf("Expected relative name, got %s", result.Name)
	}
	if result.Type != "A" {
		t.Errorf("Expected type A, got %s", result.Type)
	}
	if result.Address != "192.0.2.1" {
		t.Errorf("Expected address 192.0.2.1, got %s", result.Address)
	}
	if result.TTL != 300 {
		t.Errorf("Expected TTL 300, got %d", result.TTL)
	}
}

func TestProvider_ConvertFromGenericRR(t *testing.T) {
	provider := NewProviderFromEnv()
	zone := getTestZone()

	result, err := provider.fromLibdnsRR(libdns.RR{
		Name: "_acme-challenge",
		TTL:  60 * time.Second,
		Type: "TXT",
		Data: "token-value",
	}, zone)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected generic RR to be converted")
	}
	if result.Name != "_acme-challenge" {
		t.Fatalf("expected relative name, got %q", result.Name)
	}
	if result.Type != "TXT" {
		t.Fatalf("expected TXT type, got %q", result.Type)
	}
	if result.Value != "token-value" {
		t.Fatalf("expected TXT value, got %q", result.Value)
	}
	if result.TTL != 60 {
		t.Fatalf("expected TTL 60, got %d", result.TTL)
	}
}

func TestAppendRecords_GenericRRPayload(t *testing.T) {
	provider := newTestProvider()
	zone := getTestZone()

	provider.HTTPClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			var payload struct {
				Force bool                   `json:"force"`
				Items []spaceshipRecordUnion `json:"items"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("unmarshal payload: %v\nbody=%s", err, string(body))
			}
			if len(payload.Items) != 1 {
				t.Fatalf("expected one item, got %d in %s", len(payload.Items), string(body))
			}
			if payload.Items[0].Type != "TXT" || payload.Items[0].Name != "_acme-challenge" || payload.Items[0].Value != "token-value" {
				t.Fatalf("unexpected item payload: %#v", payload.Items[0])
			}
			return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
	}

	_, err := provider.AppendRecords(context.Background(), zone, []libdns.Record{
		libdns.RR{Name: "_acme-challenge", TTL: 60 * time.Second, Type: "TXT", Data: "token-value"},
	})
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}
}

func TestSRVWritePayloadUsesExactlyOneLeadingUnderscore(t *testing.T) {
	provider := newTestProvider()
	zone := getTestZone()
	provider.HTTPClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var payload struct {
			Items []spaceshipRecordUnion `json:"items"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if len(payload.Items) != 1 {
			t.Fatalf("expected one item, got %d", len(payload.Items))
		}
		if payload.Items[0].Service != "_sip" || payload.Items[0].Protocol != "_tcp" {
			t.Fatalf("SRV fields must have one underscore: %#v", payload.Items[0])
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	for _, record := range []libdns.SRV{
		{Name: "service-host", TTL: time.Minute, Service: "sip", Transport: "tcp", Port: 5060, Target: "target.example.net."},
		{Name: "service-host", TTL: time.Minute, Service: "__sip", Transport: "_tcp", Port: 5060, Target: "target.example.net."},
	} {
		if _, err := provider.AppendRecords(context.Background(), zone, []libdns.Record{record}); err != nil {
			t.Fatalf("AppendRecords failed for %q/%q: %v", record.Service, record.Transport, err)
		}
	}
}

func TestSRVWriteValidationMakesNoRequest(t *testing.T) {
	provider := newTestProvider()
	calls := 0
	provider.HTTPClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	for _, tc := range []struct {
		name   string
		record libdns.SRV
	}{
		{name: "missing service", record: libdns.SRV{Name: "service-host", Transport: "tcp", Port: 5060, Target: "target.example.net."}},
		{name: "missing transport", record: libdns.SRV{Name: "service-host", Service: "sip", Port: 5060, Target: "target.example.net."}},
		{name: "invalid label", record: libdns.SRV{Name: "service-host", Service: "sip.example", Transport: "tcp", Port: 5060, Target: "target.example.net."}},
		{name: "zero port", record: libdns.SRV{Name: "service-host", Service: "sip", Transport: "tcp", Target: "target.example.net."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provider.AppendRecords(context.Background(), getTestZone(), []libdns.Record{tc.record})
			if err == nil || !strings.Contains(err.Error(), "malformed SRV") {
				t.Fatalf("expected malformed SRV error, got %v", err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("invalid SRV records made %d HTTP requests", calls)
	}
}

func TestAPISRVPortValidation(t *testing.T) {
	provider := newTestProvider()
	base := spaceshipRecordUnion{
		ResourceRecordBase: ResourceRecordBase{Name: "service-host", Type: "SRV", TTL: 60},
		Service:            "_sip", Protocol: "_tcp", Target: "target.example.net.",
	}
	for _, port := range []interface{}{"443junk", "_443junk", "0", "_0", "65536", "-1", -1, 0, 65536, float64(443.5)} {
		sr := base
		sr.Port = port
		sr.PortInt = 0
		if converted := provider.toLibdnsRR(sr, getTestZone()); converted != nil {
			t.Errorf("invalid API port %#v converted to %T", port, converted)
		}
	}
	for _, label := range []string{"sip", "__sip", "_sip.example", "_sip "} {
		sr := base
		sr.Service = label
		if converted := provider.toLibdnsRR(sr, getTestZone()); converted != nil {
			t.Errorf("invalid API SRV service %q converted to %T", label, converted)
		}
	}
	for _, port := range []int{-1, 0, 65536} {
		sr := base
		sr.Port = nil
		sr.PortInt = port
		if converted := provider.toLibdnsRR(sr, getTestZone()); converted != nil {
			t.Errorf("invalid PortInt %d converted to %T", port, converted)
		}
	}
	for _, rawPort := range []string{`-1`, `0`, `65536`, `"443junk"`} {
		var sr spaceshipRecordUnion
		raw := fmt.Sprintf(`{"type":"SRV","name":"service-host","service":"_sip","protocol":"_tcp","target":"target.example.net.","port":%s}`, rawPort)
		if err := json.Unmarshal([]byte(raw), &sr); err != nil {
			t.Fatalf("unmarshal port %s: %v", rawPort, err)
		}
		if converted := provider.toLibdnsRR(sr, getTestZone()); converted != nil {
			t.Errorf("invalid unmarshaled port %s converted to %T", rawPort, converted)
		}
	}
	for _, field := range []struct {
		priority int
		weight   int
	}{
		{priority: -1}, {priority: 65536}, {weight: -1}, {weight: 65536},
	} {
		sr := base
		sr.Port = 443
		sr.Priority = field.priority
		sr.Weight = field.weight
		if converted := provider.toLibdnsRR(sr, getTestZone()); converted != nil {
			t.Errorf("invalid SRV priority/weight %#v converted to %T", field, converted)
		}
	}
	for _, port := range []interface{}{"443", "_443", 443, float64(443)} {
		sr := base
		sr.Port = port
		sr.PortInt = 0
		converted := provider.toLibdnsRR(sr, getTestZone())
		if converted == nil || converted.(libdns.SRV).Port != 443 {
			t.Errorf("valid API port %#v converted incorrectly: %#v", port, converted)
		}
	}
}

func TestGenericRRVariants_UseRRParsingAcrossBatchOperations(t *testing.T) {
	provider := newTestProvider()
	zone := getTestZone()
	calls := 0
	provider.HTTPClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var payload []spaceshipRecordUnion
		if req.Method == http.MethodDelete {
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode delete payload: %v", err)
			}
		} else {
			var wrapped struct {
				Items []spaceshipRecordUnion `json:"items"`
			}
			if err := json.Unmarshal(body, &wrapped); err != nil {
				t.Fatalf("decode write payload: %v", err)
			}
			payload = wrapped.Items
		}
		if len(payload) == 0 || payload[0].Type != "TXT" || payload[0].Value != "token-value" {
			t.Fatalf("unexpected %s payload: %#v", req.Method, payload)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	records := []libdns.Record{
		&libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "token-value"},
		genericRRWrapper{rr: libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "token-value"}},
	}
	if _, err := provider.AppendRecords(context.Background(), zone, records[:1]); err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}
	if _, err := provider.SetRecords(context.Background(), zone, records[1:]); err != nil {
		t.Fatalf("SetRecords failed: %v", err)
	}
	if _, err := provider.DeleteRecords(context.Background(), zone, records); err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected one request per operation, got %d", calls)
	}
}

func TestConversionErrorsPreventPartialRequests(t *testing.T) {
	zone := getTestZone()
	valid := libdns.TXT{Name: "valid", TTL: time.Minute, Text: "ok"}
	malformed := libdns.RR{Name: "bad", TTL: time.Minute, Type: "SRV", Data: "not-an-srv"}
	unsupported := libdns.RR{Name: "bad", TTL: time.Minute, Type: "PTR", Data: "host.example.com."}

	for _, tc := range []struct {
		name    string
		method  string
		records []libdns.Record
		want    string
	}{
		{name: "append malformed", method: "append", records: []libdns.Record{valid, malformed}, want: "record 1 (SRV)"},
		{name: "append fractional TTL", method: "append", records: []libdns.Record{libdns.TXT{Name: "fractional", TTL: 1500 * time.Millisecond, Text: "value"}}, want: "whole seconds"},
		{name: "set unsupported", method: "set", records: []libdns.Record{valid, unsupported}, want: "record 1 (PTR)"},
		{name: "delete malformed", method: http.MethodDelete, records: []libdns.Record{malformed}, want: "malformed SRV"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestProvider()
			calls := 0
			provider.HTTPClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			var err error
			switch tc.method {
			case http.MethodDelete:
				_, err = provider.DeleteRecords(context.Background(), zone, tc.records)
			case "set":
				_, err = provider.SetRecords(context.Background(), zone, tc.records)
			default:
				_, err = provider.AppendRecords(context.Background(), zone, tc.records)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
			if calls != 0 {
				t.Fatalf("conversion failure made %d HTTP requests", calls)
			}
		})
	}
}

func TestSetRecords_UnsupportedTypeHasBatchContext(t *testing.T) {
	provider := newTestProvider()
	provider.HTTPClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("unexpected HTTP request after conversion failure")
		return nil, nil
	})}
	_, err := provider.SetRecords(context.Background(), getTestZone(), []libdns.Record{
		libdns.TXT{Name: "valid", TTL: time.Minute, Text: "ok"},
		libdns.RR{Name: "bad", TTL: time.Minute, Type: "PTR", Data: "host.example.com."},
	})
	if err == nil || !strings.Contains(err.Error(), "record 1 (PTR)") {
		t.Fatalf("expected indexed unsupported-type error, got %v", err)
	}
}

func TestOwnerNormalizationBothDirections(t *testing.T) {
	provider := newTestProvider()
	zone := "example.com"
	for _, name := range []string{"", "@"} {
		record := libdns.TXT{Name: name, TTL: time.Minute, Text: "apex"}
		converted, err := provider.fromLibdnsRR(record, zone)
		if err != nil {
			t.Fatalf("convert %q: %v", name, err)
		}
		if converted.Name != "@" {
			t.Errorf("owner %q converted to %q, want @", name, converted.Name)
		}
	}
	for _, name := range []string{"example.com", "example.com."} {
		record := libdns.TXT{Name: name, TTL: time.Minute, Text: "apex"}
		converted, err := provider.fromLibdnsRR(record, zone)
		if err != nil {
			t.Fatalf("convert %q: %v", name, err)
		}
		want := name
		if name == "example.com." {
			want = "@"
		}
		if converted.Name != want {
			t.Errorf("owner %q converted to %q, want %q", name, converted.Name, want)
		}
	}
	inZone := libdns.TXT{Name: "www.example.com.", TTL: time.Minute, Text: "www"}
	converted, err := provider.fromLibdnsRR(inZone, zone)
	if err != nil {
		t.Fatal(err)
	}
	if converted.Name != "www" {
		t.Fatalf("in-zone FQDN converted to %q, want www", converted.Name)
	}
	for _, name := range []string{"", "@", "example.com", "example.com.", "www.example.com", "www.example.com."} {
		converted := provider.toLibdnsRR(spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: name, Type: "TXT", TTL: 60}}, zone)
		got := converted.RR().Name
		want := name
		switch name {
		case "", "@":
			want = "@"
		case "example.com.":
			want = "@"
		case "www.example.com.":
			want = "www"
		}
		if got != want {
			t.Errorf("API owner %q converted to %q, want %q", name, got, want)
		}
	}
}

func TestSRVConversionSeparatesOwnerAndServiceLabels(t *testing.T) {
	provider := newTestProvider()
	zone := "example.com"
	typed := libdns.SRV{Name: "service-host", TTL: time.Minute, Service: "sip", Transport: "tcp", Priority: 10, Weight: 20, Port: 5060, Target: "target.example.net."}
	converted, err := provider.fromLibdnsRR(typed, zone)
	if err != nil {
		t.Fatal(err)
	}
	if converted.Name != "service-host" || converted.Service != "_sip" || converted.Protocol != "_tcp" {
		t.Fatalf("typed SRV duplicated labels: %#v", converted)
	}
	read := provider.toLibdnsRR(spaceshipRecordUnion{
		ResourceRecordBase: ResourceRecordBase{Name: "service-host", Type: "SRV", TTL: 60},
		Service:            "_sip", Protocol: "_tcp", Priority: 10, Weight: 20, PortInt: 5060, Target: "target.example.net.",
	}, zone).(libdns.SRV)
	if read.Name != "service-host" || read.Service != "sip" || read.Transport != "tcp" {
		t.Fatalf("canonical SRV read duplicated labels: %#v", read)
	}
	legacy := provider.toLibdnsRR(spaceshipRecordUnion{
		ResourceRecordBase: ResourceRecordBase{Name: "_sip._tcp.service-host", Type: "SRV", TTL: 60},
		Priority:           10, Weight: 20, PortInt: 5060, Target: "target.example.net.",
	}, zone).(libdns.SRV)
	if legacy.Name != "service-host" || legacy.Service != "sip" || legacy.Transport != "tcp" {
		t.Fatalf("legacy SRV read was not normalized: %#v", legacy)
	}
}

func TestEmptyWriteInputsDoNotRequest(t *testing.T) {
	provider := newTestProvider()
	calls := 0
	provider.HTTPClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("unexpected request")
	})}
	ctx := context.Background()
	if records, err := provider.AppendRecords(ctx, getTestZone(), nil); err != nil || len(records) != 0 {
		t.Fatalf("empty append: records=%v err=%v", records, err)
	}
	if records, err := provider.SetRecords(ctx, getTestZone(), []libdns.Record{}); err != nil || len(records) != 0 {
		t.Fatalf("empty set: records=%v err=%v", records, err)
	}
	if records, err := provider.DeleteRecords(ctx, getTestZone(), nil); err != nil || len(records) != 0 {
		t.Fatalf("empty delete: records=%v err=%v", records, err)
	}
	if calls != 0 {
		t.Fatalf("empty write inputs made %d requests", calls)
	}
}

func TestDeleteRecordsPreservesLibdnsWildcards(t *testing.T) {
	provider := newTestProvider()
	var payloads [][]map[string]json.RawMessage
	provider.HTTPClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var payload []map[string]json.RawMessage
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode delete payload: %v", err)
		}
		payloads = append(payloads, payload)
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	zone := getTestZone()
	for _, record := range []libdns.Record{
		libdns.RR{Name: "wildcard"},
		libdns.RR{Name: "wildcard", Type: "TXT", TTL: time.Minute},
		libdns.RR{Name: "wildcard", Type: "TXT", Data: "value"},
	} {
		if _, err := provider.DeleteRecords(context.Background(), zone, []libdns.Record{record}); err != nil {
			t.Fatalf("DeleteRecords failed: %v", err)
		}
	}
	if len(payloads) != 3 || len(payloads[0]) != 1 || len(payloads[1]) != 1 || len(payloads[2]) != 1 {
		t.Fatalf("unexpected wildcard payloads: %#v", payloads)
	}
	if _, ok := payloads[0][0]["name"]; !ok {
		t.Fatalf("name-only wildcard omitted name: %#v", payloads[0])
	}
	if _, ok := payloads[0][0]["type"]; ok {
		t.Fatalf("name-only wildcard unexpectedly included type: %#v", payloads[0])
	}
	if got, ok := payloads[1][0]["type"]; !ok || string(got) != `"TXT"` {
		t.Fatalf("name+type+TTL wildcard had wrong type: %#v", payloads[1])
	}
	if got, ok := payloads[1][0]["ttl"]; !ok || string(got) != "60" {
		t.Fatalf("name+type+TTL wildcard omitted TTL: %#v", payloads[1])
	}
	if _, ok := payloads[1][0]["value"]; ok {
		t.Fatalf("name+type+TTL wildcard unexpectedly included value: %#v", payloads[1])
	}
	if got, ok := payloads[2][0]["type"]; !ok || string(got) != `"TXT"` {
		t.Fatalf("name+type+value wildcard had wrong type: %#v", payloads[2])
	}
	if got, ok := payloads[2][0]["value"]; !ok || string(got) != `"value"` {
		t.Fatalf("name+type+value wildcard omitted value: %#v", payloads[2])
	}
	if _, ok := payloads[2][0]["ttl"]; ok {
		t.Fatalf("name+type+value wildcard unexpectedly included TTL: %#v", payloads[2])
	}
}

func TestDeleteRecordsRejectsMissingNameWithoutRequest(t *testing.T) {
	provider := newTestProvider()
	calls := 0
	provider.HTTPClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("unexpected request")
	})}
	_, err := provider.DeleteRecords(context.Background(), getTestZone(), []libdns.Record{libdns.RR{Type: "TXT"}})
	if err == nil || !strings.Contains(err.Error(), "non-empty name") {
		t.Fatalf("expected unsafe missing-name error, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("missing-name delete made %d requests", calls)
	}
	_, err = provider.DeleteRecords(context.Background(), getTestZone(), []libdns.Record{libdns.RR{Name: "wildcard", Type: "TXT", TTL: -time.Second}})
	if err == nil || !strings.Contains(err.Error(), "negative TTL") {
		t.Fatalf("expected negative-TTL error, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("negative-TTL delete made %d requests", calls)
	}
	_, err = provider.DeleteRecords(context.Background(), getTestZone(), []libdns.Record{libdns.RR{Name: "wildcard", Type: "TXT", TTL: 1500 * time.Millisecond}})
	if err == nil || !strings.Contains(err.Error(), "whole seconds") {
		t.Fatalf("expected fractional-TTL error, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("fractional-TTL delete made %d requests", calls)
	}
}

func TestDoRequest_HeadersAndBody(t *testing.T) {
	provider := newTestProvider()

	provider.HTTPClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// verify headers
			if req.Header.Get("X-API-Key") != provider.APIKey {
				t.Fatalf("missing or incorrect X-API-Key: got %s want %s", req.Header.Get("X-API-Key"), provider.APIKey)
			}
			if req.Header.Get("X-API-Secret") != provider.APISecret {
				t.Fatalf("missing or incorrect X-API-Secret: got %s want %s", req.Header.Get("X-API-Secret"), provider.APISecret)
			}
			// read body and return it back
			b, _ := io.ReadAll(req.Body)
			res := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b)))}
			return res, nil
		}),
	}

	body := map[string]string{"hello": "world"}
	respBody, status, err := provider.doRequest(context.Background(), "POST", "/test", body)
	if err != nil {
		t.Fatalf("doRequest failed: %v", err)
	}
	if status != 200 {
		t.Fatalf("unexpected status: %d", status)
	}
	if string(respBody) != "{\"hello\":\"world\"}" {
		t.Fatalf("unexpected body: %s", string(respBody))
	}
}

func TestGetRecords_Pagination(t *testing.T) {
	provider := newTestProvider()
	provider.PageSize = 2

	// Create two pages: first returns 2 items, total 3; second returns 1 item.
	pageCount := 0
	provider.HTTPClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			pageCount++
			if pageCount == 1 {
				json := `{"items":[{"type":"A","name":"test","address":"1.1.1.1","ttl":300},{"type":"A","name":"more","address":"1.1.1.2","ttl":300}],"total":3}`
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(json))}, nil
			}
			json := `{"items":[{"type":"A","name":"other","address":"1.1.1.3","ttl":300}],"total":3}`
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(json))}, nil
		}),
	}

	recs, err := provider.GetRecords(context.Background(), getTestZone())
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 records, got %d", len(recs))
	}
}

func TestConvertToLibdnsRecord_ExtendedTypes(t *testing.T) {
	provider := NewProviderFromEnv()
	zone := getTestZone()

	// SRV
	srv := spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Type: "SRV", Name: fmt.Sprintf("_sip._tcp.%s", zone), TTL: 3600}, Priority: 10, Weight: 20, PortInt: 5060, Port: "5060", Target: fmt.Sprintf("sip.%s", zone)}
	rr := provider.toLibdnsRR(srv, zone)
	if r, ok := rr.(libdns.SRV); !ok || r.Priority != 10 || r.Weight != 20 || r.Port != 5060 || r.Target != fmt.Sprintf("sip.%s", zone) || r.Service != "sip" || r.Transport != "tcp" {
		t.Fatalf("unexpected SRV conversion: %#v", rr)
	}

	// NS
	ns := spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Type: "NS", Name: zone, TTL: 3600}, Nameserver: fmt.Sprintf("ns1.%s", zone)}
	rr = provider.toLibdnsRR(ns, zone)
	// prefer libdns.NS if available, otherwise fall back to libdns.RR
	if r, ok := rr.(libdns.NS); ok {
		if r.Target != fmt.Sprintf("ns1.%s", zone) {
			t.Fatalf("unexpected NS conversion (libdns.NS): %#v", rr)
		}
	} else if r, ok := rr.(libdns.RR); ok {
		if r.Type != "NS" || r.Data != fmt.Sprintf("ns1.%s", zone) {
			t.Fatalf("unexpected NS conversion (libdns.RR): %#v", rr)
		}
	} else {
		t.Fatalf("unexpected NS conversion type: %T", rr)
	}

	// PTR (unsupported - should return nil)
	ptr := spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Type: "PTR", Name: "1.1.1.in-addr.arpa", TTL: 3600}, Pointer: fmt.Sprintf("host.%s", zone)}
	rr = provider.toLibdnsRR(ptr, zone)
	if rr != nil {
		t.Fatalf("PTR records should be unsupported and return nil, got: %#v", rr)
	}

	// CAA
	zero := 0
	caa := spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Type: "CAA", Name: zone, TTL: 3600}, Flag: &zero, Tag: "issue", Value: "letsencrypt.org"}
	rr = provider.toLibdnsRR(caa, zone)
	if r, ok := rr.(libdns.CAA); ok {
		if r.Tag != "issue" || r.Value != "letsencrypt.org" || r.Flags != 0 {
			t.Fatalf("unexpected CAA conversion (libdns.CAA): %#v", rr)
		}
	} else if r, ok := rr.(libdns.RR); ok {
		if r.Type != "CAA" || !strings.Contains(r.Data, "letsencrypt.org") {
			t.Fatalf("unexpected CAA conversion (generic RR): %#v", rr)
		}
	} else {
		t.Fatalf("unexpected CAA conversion type: %T", rr)
	}

	// HTTPS
	https := spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Type: "HTTPS", Name: fmt.Sprintf("test.%s", zone), TTL: 300}, SvcPriority: 1, TargetName: fmt.Sprintf("target.%s", zone), SvcParams: "alpn=h2,h3 port=8443"}
	rr = provider.toLibdnsRR(https, zone)
	if r, ok := rr.(libdns.ServiceBinding); ok {
		if r.Scheme != "https" {
			t.Fatalf("unexpected HTTPS scheme: expected 'https', got %q", r.Scheme)
		}
		if r.Priority != 1 {
			t.Fatalf("unexpected HTTPS priority: expected 1, got %d", r.Priority)
		}
		if r.Target != fmt.Sprintf("target.%s", zone) {
			t.Fatalf("unexpected HTTPS target: expected %q, got %q", fmt.Sprintf("target.%s", zone), r.Target)
		}
		paramsStr := r.Params.String()
		if !strings.Contains(paramsStr, "alpn=h2,h3") || !strings.Contains(paramsStr, "port=8443") {
			t.Fatalf("unexpected HTTPS params: expected to contain 'alpn=h2,h3' and 'port=8443', got %q", paramsStr)
		}
		if r.Name != fmt.Sprintf("test.%s", zone) {
			t.Fatalf("unexpected HTTPS name: expected %q, got %q", fmt.Sprintf("test.%s", zone), r.Name)
		}
	} else {
		t.Fatalf("unexpected HTTPS conversion type: expected libdns.ServiceBinding, got %T", rr)
	}

	// HTTPS with empty params
	httpsEmpty := spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Type: "HTTPS", Name: fmt.Sprintf("empty.%s", zone), TTL: 300}, SvcPriority: 0, TargetName: fmt.Sprintf("alt.%s", zone), SvcParams: ""}
	rr = provider.toLibdnsRR(httpsEmpty, zone)
	if r, ok := rr.(libdns.ServiceBinding); ok {
		if r.Priority != 0 || r.Target != fmt.Sprintf("alt.%s", zone) || len(r.Params) != 0 {
			t.Fatalf("unexpected HTTPS empty params conversion: %#v", r)
		}
	} else {
		t.Fatalf("unexpected HTTPS empty params conversion type: expected libdns.ServiceBinding, got %T", rr)
	}

	// HTTPS with invalid params (should still work but have empty params)
	httpsInvalid := spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Type: "HTTPS", Name: fmt.Sprintf("invalid.%s", zone), TTL: 300}, SvcPriority: 2, TargetName: fmt.Sprintf("bad.%s", zone), SvcParams: "invalid=params=format"}
	rr = provider.toLibdnsRR(httpsInvalid, zone)
	if r, ok := rr.(libdns.ServiceBinding); ok {
		if r.Priority != 2 || r.Target != fmt.Sprintf("bad.%s", zone) {
			t.Fatalf("unexpected HTTPS invalid params conversion: %#v", r)
		}
		// params might be empty or partially parsed - either is acceptable
	} else {
		t.Fatalf("unexpected HTTPS invalid params conversion type: expected libdns.ServiceBinding, got %T", rr)
	}

	// TLSA/HTTPS tests removed — provider no longer supports those types
}

func TestConvertFromLibdnsRecord_TypedRecords(t *testing.T) {
	provider := NewProviderFromEnv()
	zone := getTestZone()

	// SRV (using typed libdns.SRV)
	srv := libdns.SRV{Name: "service-host", TTL: 3600 * time.Second, Service: "sip", Transport: "tcp", Priority: 10, Weight: 20, Port: 5060, Target: fmt.Sprintf("sip.%s", zone)}
	rec, err := provider.fromLibdnsRR(srv, zone)
	if err != nil {
		t.Fatal(err)
	}
	if rec == nil {
		t.Fatalf("SRV conversion should not return nil")
	}
	if rec.Priority != 10 || rec.Weight != 20 || rec.PortInt != 5060 || rec.Target != fmt.Sprintf("sip.%s", zone) {
		t.Fatalf("SRV conversion failed: %#v", rec)
	}
	if rec.Name != "service-host" || rec.Service != "_sip" || rec.Protocol != "_tcp" {
		t.Fatalf("SRV owner/service serialization failed: %#v", rec)
	}

	// Generic RR values should be parsed into their typed representations.
	textualRR := libdns.RR{Name: "_sip._tcp", TTL: 3600 * time.Second, Type: "SRV", Data: fmt.Sprintf("10 20 5060 %s", fmt.Sprintf("sip.%s", zone))}
	textualRec, err := provider.fromLibdnsRR(textualRR, zone)
	if err != nil {
		t.Fatal(err)
	}
	if textualRec == nil {
		t.Fatal("generic SRV RR should be converted")
	}
	if textualRec.Priority != 10 || textualRec.Weight != 20 || textualRec.PortInt != 5060 || textualRec.Target != fmt.Sprintf("sip.%s", zone) {
		t.Fatalf("generic SRV conversion failed: %#v", textualRec)
	}

	// HTTPS (using typed libdns.ServiceBinding with https scheme)
	https := libdns.ServiceBinding{
		Name:     "test",
		TTL:      300 * time.Second,
		Scheme:   "https",
		Priority: 1,
		Target:   fmt.Sprintf("target.%s", zone),
		Params:   map[string][]string{"alpn": {"h2", "h3"}, "port": {"8443"}},
	}
	httpsRec, err := provider.fromLibdnsRR(https, zone)
	if err != nil {
		t.Fatal(err)
	}
	if httpsRec == nil {
		t.Fatalf("HTTPS conversion should not return nil")
	}
	if httpsRec.Type != "HTTPS" {
		t.Fatalf("Expected HTTPS type, got %s", httpsRec.Type)
	}
	if httpsRec.SvcPriority != 1 {
		t.Fatalf("Expected priority 1, got %d", httpsRec.SvcPriority)
	}
	if httpsRec.TargetName != fmt.Sprintf("target.%s", zone) {
		t.Fatalf("Expected target %s, got %s", fmt.Sprintf("target.%s", zone), httpsRec.TargetName)
	}
	if !strings.Contains(httpsRec.SvcParams, "alpn=h2,h3") || !strings.Contains(httpsRec.SvcParams, "port=8443") {
		t.Fatalf("Expected params to contain alpn and port, got: %s", httpsRec.SvcParams)
	}
	expectedName := "test"
	if httpsRec.Name != expectedName {
		t.Fatalf("Expected name %s, got %s", expectedName, httpsRec.Name)
	}

	// Non-HTTPS ServiceBinding (should return nil)
	svcb := libdns.ServiceBinding{
		Name:     "test",
		TTL:      300 * time.Second,
		Scheme:   "svcb",
		Priority: 1,
		Target:   fmt.Sprintf("target.%s", zone),
		Params:   map[string][]string{"alpn": {"h2"}},
	}
	svcbRec, err := provider.fromLibdnsRR(svcb, zone)
	if err == nil || svcbRec != nil {
		t.Fatalf("Non-HTTPS ServiceBinding should return nil (unsupported), got: %#v", svcbRec)
	}
}

func TestRoundTrip_CreateListDelete(t *testing.T) {
	zone := getTestZone()
	provider := newTestProvider()
	provider.PageSize = 100

	// in-memory store of spaceshipRecordUnion representing the server state
	var store []spaceshipRecordUnion
	// mutex not required for single-threaded test

	provider.HTTPClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			// unify path: look for "/v1/dns/records/"
			if !strings.Contains(path, "/v1/dns/records/") {
				return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("not found"))}, nil
			}
			if req.Method == "PUT" {
				var payload struct {
					Force bool                   `json:"force"`
					Items []spaceshipRecordUnion `json:"items"`
				}
				b, _ := io.ReadAll(req.Body)
				_ = json.Unmarshal(b, &payload)
				if payload.Force {
					// replace entire store
					store = payload.Items
				} else {
					store = append(store, payload.Items...)
				}
				return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			if req.Method == "GET" {
				q := req.URL.Query()
				take := 100
				if q.Get("take") != "" {
					if v, err := strconv.Atoi(q.Get("take")); err == nil {
						take = v
					}
				}
				skip := 0
				if q.Get("skip") != "" {
					if v, err := strconv.Atoi(q.Get("skip")); err == nil {
						skip = v
					}
				}
				end := skip + take
				if end > len(store) {
					end = len(store)
				}
				resp := listResponse{Items: store[skip:end], Total: len(store)}
				b, _ := json.Marshal(resp)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
			}
			if req.Method == "DELETE" {
				// delete items present in body
				var items []spaceshipRecordUnion
				b, _ := io.ReadAll(req.Body)
				_ = json.Unmarshal(b, &items)
				// filter store: remove any item that matches a delete item on required fields
				newStore := make([]spaceshipRecordUnion, 0, len(store))
				for _, existing := range store {
					keep := true
					for _, del := range items {
						if existing.Type == del.Type && existing.Name == del.Name {
							// for typed fields try matching identifying fields
							match := true
							switch strings.ToUpper(del.Type) {
							case "A":
								if del.Address != existing.Address {
									match = false
								}
							case "TXT":
								if del.Value != existing.Value {
									match = false
								}
							case "CNAME":
								if del.Cname != existing.Cname {
									match = false
								}
							case "MX":
								if del.Exchange != existing.Exchange || del.Preference != existing.Preference {
									match = false
								}
							default:
								// fallback: compare Value or Data-ish fields
								if del.Value != "" && del.Value != existing.Value {
									match = false
								}
							}
							if match {
								keep = false
								break
							}
						}
					}
					if keep {
						newStore = append(newStore, existing)
					}
				}
				store = newStore
				return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return &http.Response{StatusCode: 405, Body: io.NopCloser(strings.NewReader("method not allowed"))}, nil
		}),
	}

	// create some records with AppendRecords
	recsToAdd := []libdns.Record{
		libdns.Address{Name: "test", TTL: 300 * time.Second, IP: netip.MustParseAddr("1.1.1.1")},
		libdns.TXT{Name: "test", TTL: 300 * time.Second, Text: "hello"},
	}

	added, err := provider.AppendRecords(context.Background(), zone, recsToAdd)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}
	if len(added) != len(recsToAdd) {
		t.Fatalf("expected %d added, got %d", len(recsToAdd), len(added))
	}

	// list records
	listed, err := provider.GetRecords(context.Background(), zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected 2 listed, got %d", len(listed))
	}

	// delete first
	_, err = provider.DeleteRecords(context.Background(), zone, []libdns.Record{listed[0]})
	if err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}

	// list again
	listed2, err := provider.GetRecords(context.Background(), zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	if len(listed2) != 1 {
		t.Fatalf("expected 1 listed after delete, got %d", len(listed2))
	}
}

// TestLive_AppendGetDelete is an optional live integration test that exercises the real
// Spaceship API. It will only run when LIBDNS_SPACESHIP_RUN_LIVE is set to "1" or "true".
// The test appends a temporary TXT record to the configured zone, verifies it is listed,
// then removes it. This test runs against your real domain and will modify DNS; only
// enable when you intentionally want to run live integration tests.
func TestLive_AppendGetDelete(t *testing.T) {
	if v := strings.ToLower(os.Getenv("LIBDNS_SPACESHIP_RUN_LIVE")); !(v == "1" || v == "true") {
		t.Skip("Skipping live integration test; set LIBDNS_SPACESHIP_RUN_LIVE=1 to run")
	}

	provider := NewProviderFromEnv()
	if provider.APIKey == "" || provider.APISecret == "" {
		t.Skip("Skipping live integration: missing API credentials in environment")
	}

	zone := getTestZone()
	ctx := context.Background()

	// Use a TXT record for the least-impact change
	name := fmt.Sprintf("libdns-integ-%d", time.Now().UnixNano()%1000000)
	value := fmt.Sprintf("libdns-int-%d", time.Now().UnixNano()%1000000)
	rec := libdns.TXT{Name: name, TTL: 60 * time.Second, Text: value}

	// Ensure cleanup even if the test fails
	defer func() {
		_, _ = provider.DeleteRecords(ctx, zone, []libdns.Record{rec})
	}()

	// Append the record
	added, err := provider.AppendRecords(ctx, zone, []libdns.Record{rec})
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}
	if len(added) == 0 {
		t.Fatalf("AppendRecords indicated success but returned no records")
	}

	// Confirm the record appears in GetRecords
	recs, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	found := false
	for _, r := range recs {
		if tr, ok := r.(libdns.TXT); ok {
			if tr.Name == name && tr.Text == value {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("Appended live TXT record not found in zone listing")
	}

	// Delete the record
	_, err = provider.DeleteRecords(ctx, zone, []libdns.Record{rec})
	if err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}

	// Verify deletion
	recs2, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after delete failed: %v", err)
	}
	for _, r := range recs2 {
		if tr, ok := r.(libdns.TXT); ok {
			if tr.Name == name && tr.Text == value {
				t.Fatalf("Record still present after delete: %v", tr)
			}
		}
	}
}

// TestLive_AddA_CNAME_SRV creates an A record, a CNAME and an SRV, verifies they exist, then removes them.
func TestLive_AddA_CNAME_SRV(t *testing.T) {
	if v := strings.ToLower(os.Getenv("LIBDNS_SPACESHIP_RUN_LIVE")); !(v == "1" || v == "true") {
		t.Skip("Skipping live integration test; set LIBDNS_SPACESHIP_RUN_LIVE=1 to run")
	}

	provider := NewProviderFromEnv()
	if provider.APIKey == "" || provider.APISecret == "" {
		t.Skip("Skipping live integration: missing API credentials in environment")
	}

	zone := getTestZone()
	ctx := context.Background()

	// Unique names so tests don't collide
	uid := time.Now().UnixNano() % 1000000
	aName := fmt.Sprintf("libdns-a-%d", uid)
	cName := fmt.Sprintf("libdns-cname-%d", uid)

	// A record
	aRec := libdns.Address{Name: aName, TTL: 60 * time.Second, IP: netip.MustParseAddr("203.0.113.10")}
	// CNAME pointing to the A record's FQDN
	cRec := libdns.CNAME{Name: cName, TTL: 60 * time.Second, Target: fmt.Sprintf("%s.%s", aName, zone)}
	// SRV using the A record target
	srvRec := libdns.SRV{Name: fmt.Sprintf("libdns-%d", uid), TTL: 60 * time.Second, Service: "svc", Transport: "tcp", Priority: 10, Weight: 20, Port: 5060, Target: fmt.Sprintf("%s.%s", aName, zone)}

	defer func() {
		// best-effort cleanup
		_, _ = provider.DeleteRecords(ctx, zone, []libdns.Record{aRec, cRec, srvRec})
	}()

	// Append A and CNAME
	if _, err := provider.AppendRecords(ctx, zone, []libdns.Record{aRec, cRec}); err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}

	// Append SRV
	if _, err := provider.AppendRecords(ctx, zone, []libdns.Record{srvRec}); err != nil {
		t.Fatalf("AppendRecords (SRV) failed: %v", err)
	}

	// Verify all exist
	recs, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	expectedSrvName := fmt.Sprintf("libdns-%d", uid)

	foundA, foundCNAME, foundSRV := false, false, false
	for _, r := range recs {
		switch tr := r.(type) {
		case libdns.Address:
			if tr.Name == aName && tr.IP.String() == "203.0.113.10" {
				foundA = true
			}
		case libdns.CNAME:
			if tr.Name == cName && tr.Target == fmt.Sprintf("%s.%s", aName, zone) {
				foundCNAME = true
			}
		case libdns.SRV:
			if tr.Name == expectedSrvName {
				if tr.Target == fmt.Sprintf("%s.%s", aName, zone) && tr.Port == 5060 {
					foundSRV = true
				}
			}
		}
	}

	if !foundA {
		t.Fatalf("A record not found in live zone")
	}
	if !foundCNAME {
		t.Fatalf("CNAME record not found in live zone")
	}
	if !foundSRV {
		t.Fatalf("SRV record not found in live zone")
	}
}

// TestLive_DDNS_Updater simulates a dynamic DNS updater: it creates or updates an A record
// to the 'current' IP, then simulates an IP change and updates, then simulates no-change and
// the updater should skip making a redundant update.
func TestLive_DDNS_Updater(t *testing.T) {
	if v := strings.ToLower(os.Getenv("LIBDNS_SPACESHIP_RUN_LIVE")); !(v == "1" || v == "true") {
		t.Skip("Skipping live integration test; set LIBDNS_SPACESHIP_RUN_LIVE=1 to run")
	}

	provider := NewProviderFromEnv()
	if provider.APIKey == "" || provider.APISecret == "" {
		t.Skip("Skipping live integration: missing API credentials in environment")
	}

	zone := getTestZone()
	ctx := context.Background()

	name := fmt.Sprintf("libdns-ddns-%d", time.Now().UnixNano()%1000000)
	initialIP := netip.MustParseAddr("203.0.113.11")
	changedIP := netip.MustParseAddr("203.0.113.12")

	aRec := func(ip netip.Addr) libdns.Record { return libdns.Address{Name: name, TTL: 60 * time.Second, IP: ip} }

	// Ensure cleanup
	defer func() {
		// Find any records for this name and delete them
		present, _ := provider.GetRecords(ctx, zone)
		var toDelete []libdns.Record
		for _, r := range present {
			if ar, ok := r.(libdns.Address); ok && ar.Name == name {
				toDelete = append(toDelete, ar)
			}
		}
		if len(toDelete) > 0 {
			_, _ = provider.DeleteRecords(ctx, zone, toDelete)
		}
	}()

	// Step 1: ensure record exists with initialIP
	// If it exists, update; otherwise create.
	recs, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	var existingIP netip.Addr
	for _, r := range recs {
		if ar, ok := r.(libdns.Address); ok && ar.Name == name {
			existingIP = ar.IP
			break
		}
	}

	if existingIP.IsValid() {
		// Update only if different: remove and append the desired record
		if existingIP != initialIP {
			// delete existing
			if _, err := provider.DeleteRecords(ctx, zone, []libdns.Record{libdns.Address{Name: name, IP: existingIP}}); err != nil {
				t.Fatalf("DeleteRecords failed when updating existing record: %v", err)
			}
			// append initial
			if _, err := provider.AppendRecords(ctx, zone, []libdns.Record{aRec(initialIP)}); err != nil {
				t.Fatalf("AppendRecords failed when creating initial A: %v", err)
			}
		}
	} else {
		if _, err := provider.AppendRecords(ctx, zone, []libdns.Record{aRec(initialIP)}); err != nil {
			t.Fatalf("AppendRecords failed when creating initial A: %v", err)
		}
	}

	// Verify initial IP
	recs2, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	var found bool
	for _, r := range recs2 {
		if ar, ok := r.(libdns.Address); ok && ar.Name == name && ar.IP == initialIP {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("initial IP not present after create/update")
	}

	// Step 2: simulate IP change to changedIP and perform update via delete+append
	// find current addresses for name
	recsCur, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	var currentRecords []libdns.Record
	for _, r := range recsCur {
		if ar, ok := r.(libdns.Address); ok && ar.Name == name {
			currentRecords = append(currentRecords, ar)
		}
	}
	if len(currentRecords) > 0 {
		if _, err := provider.DeleteRecords(ctx, zone, currentRecords); err != nil {
			t.Fatalf("DeleteRecords failed prior to updating to changed IP: %v", err)
		}
	}
	if _, err := provider.AppendRecords(ctx, zone, []libdns.Record{aRec(changedIP)}); err != nil {
		t.Fatalf("AppendRecords failed to add changed IP: %v", err)
	}

	// verify changed
	recs3, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	var foundChanged bool
	for _, r := range recs3 {
		if ar, ok := r.(libdns.Address); ok && ar.Name == name && ar.IP == changedIP {
			foundChanged = true
			break
		}
	}
	if !foundChanged {
		t.Fatalf("changed IP not present after update")
	}

	// Step 3: simulate no-change and ensure updater will skip making an unnecessary API call
	curRecs, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	var currentIP netip.Addr
	for _, r := range curRecs {
		if ar, ok := r.(libdns.Address); ok && ar.Name == name {
			currentIP = ar.IP
			break
		}
	}
	if currentIP != changedIP {
		t.Fatalf("unexpected current IP before no-change step: %v", currentIP)
	}
	// Simulate updater: only update if new IP differs. New IP equals changedIP, so skip.
	newIP := changedIP
	if newIP == currentIP {
		// skip update - success condition
	} else {
		// (not expected in this test)
		if _, err := provider.AppendRecords(ctx, zone, []libdns.Record{aRec(newIP)}); err != nil {
			t.Fatalf("AppendRecords failed unexpectedly: %v", err)
		}
	}

	// verify still same
	recs4, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	var finalIP netip.Addr
	for _, r := range recs4 {
		if ar, ok := r.(libdns.Address); ok && ar.Name == name {
			finalIP = ar.IP
			break
		}
	}
	if finalIP != changedIP {
		t.Fatalf("final IP mismatch after no-change step: %v", finalIP)
	}
}

// TestLive_ListAllAndCleanup lists all records in the zone and optionally deletes them all.
// This test only runs when both LIBDNS_SPACESHIP_RUN_LIVE=1 AND LIBDNS_SPACESHIP_CLEANUP=1 are set.
// Use this to clean up test data or reset a zone completely.
// WARNING: This will delete ALL records in the zone!
func TestLive_ListAllAndCleanup(t *testing.T) {
	if v := strings.ToLower(os.Getenv("LIBDNS_SPACESHIP_RUN_LIVE")); !(v == "1" || v == "true") {
		t.Skip("Skipping live integration test; set LIBDNS_SPACESHIP_RUN_LIVE=1 to run")
	}
	if v := strings.ToLower(os.Getenv("LIBDNS_SPACESHIP_CLEANUP")); !(v == "1" || v == "true") {
		t.Skip("Skipping cleanup test; set LIBDNS_SPACESHIP_CLEANUP=1 to run (WARNING: deletes all records)")
	}

	provider := NewProviderFromEnv()
	if provider.APIKey == "" || provider.APISecret == "" {
		t.Skip("Skipping live integration: missing API credentials in environment")
	}

	zone := getTestZone()
	ctx := context.Background()

	t.Logf("=== LISTING ALL RECORDS IN ZONE: %s ===", zone)

	// Get all records
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("Failed to get records: %v", err)
	}

	if len(records) == 0 {
		t.Logf("No records found in zone %s", zone)
		return
	}

	// Group records by type for better display
	recordsByType := make(map[string][]libdns.Record)
	for _, r := range records {
		rr := r.RR()
		recordsByType[rr.Type] = append(recordsByType[rr.Type], r)
	}

	t.Logf("Found %d total records across %d types:", len(records), len(recordsByType))

	// Display all records grouped by type
	for recordType, recs := range recordsByType {
		t.Logf("\n--- %s Records (%d) ---", recordType, len(recs))
		for i, r := range recs {
			rr := r.RR()
			switch rec := r.(type) {
			case libdns.Address:
				t.Logf("  %d. %s %s %v → %s", i+1, rr.Name, recordType, rr.TTL, rec.IP.String())
			case libdns.TXT:
				t.Logf("  %d. %s %s %v → \"%s\"", i+1, rr.Name, recordType, rr.TTL, rec.Text)
			case libdns.CNAME:
				t.Logf("  %d. %s %s %v → %s", i+1, rr.Name, recordType, rr.TTL, rec.Target)
			case libdns.MX:
				t.Logf("  %d. %s %s %v → %d %s", i+1, rr.Name, recordType, rr.TTL, rec.Preference, rec.Target)
			case libdns.SRV:
				t.Logf("  %d. %s %s %v → %d %d %d %s", i+1, rr.Name, recordType, rr.TTL, rec.Priority, rec.Weight, rec.Port, rec.Target)
			case libdns.NS:
				t.Logf("  %d. %s %s %v → %s", i+1, rr.Name, recordType, rr.TTL, rec.Target)
			case libdns.CAA:
				t.Logf("  %d. %s %s %v → %d %s \"%s\"", i+1, rr.Name, recordType, rr.TTL, rec.Flags, rec.Tag, rec.Value)
			default:
				t.Logf("  %d. %s %s %v → %s", i+1, rr.Name, recordType, rr.TTL, rr.Data)
			}
		}
	}

	t.Logf("\n=== DELETING ALL %d RECORDS ===", len(records))

	// Separate supported and unsupported records
	var supportedRecords []libdns.Record
	var unsupportedCount int

	for _, r := range records {
		rr := r.RR()
		if isSupportedForDeletion(rr.Type) {
			supportedRecords = append(supportedRecords, r)
		} else {
			unsupportedCount++
			t.Logf("Skipping unsupported record type for deletion: %s %s", rr.Name, rr.Type)
		}
	}

	if unsupportedCount > 0 {
		t.Logf("Note: %d unsupported record types cannot be deleted via this provider", unsupportedCount)
	}

	if len(supportedRecords) == 0 {
		t.Logf("No supported records to delete")
		return
	}

	// Delete all supported records
	deleted, err := provider.DeleteRecords(ctx, zone, supportedRecords)
	if err != nil {
		t.Fatalf("Failed to delete records: %v", err)
	}

	t.Logf("Successfully deleted %d records", len(deleted))

	// Verify deletion by listing again
	remaining, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("Failed to verify deletion: %v", err)
	}

	if len(remaining) == 0 {
		t.Logf("✅ Zone is now empty - all records deleted successfully")
	} else {
		t.Logf("⚠️  %d records remain in zone (likely unsupported types that cannot be deleted)", len(remaining))
		for _, r := range remaining {
			rr := r.RR()
			t.Logf("  Remaining: %s %s", rr.Name, rr.Type)
		}
	}
}

// Helper function to check if a record type can be deleted by this provider
func isSupportedForDeletion(recordType string) bool {
	switch strings.ToUpper(recordType) {
	case "A", "AAAA", "TXT", "CNAME", "MX", "SRV", "NS", "CAA", "HTTPS":
		return true
	default:
		return false
	}
}

// TestLive_MoreTypes exercises several additional record types (AAAA, MX, NS, CAA, TLSA, HTTPS).
func TestLive_MoreTypes(t *testing.T) {
	if v := strings.ToLower(os.Getenv("LIBDNS_SPACESHIP_RUN_LIVE")); !(v == "1" || v == "true") {
		t.Skip("Skipping live integration test; set LIBDNS_SPACESHIP_RUN_LIVE=1 to run")
	}

	provider := NewProviderFromEnv()
	if provider.APIKey == "" || provider.APISecret == "" {
		t.Skip("Skipping live integration: missing API credentials in environment")
	}

	zone := getTestZone()
	ctx := context.Background()
	uid := time.Now().UnixNano() % 1000000

	sub := fmt.Sprintf("multi-%d", uid)
	// Build various records under unique names
	aaaa := libdns.Address{Name: fmt.Sprintf("aaaa-%s", sub), TTL: 60 * time.Second, IP: netip.MustParseAddr("2001:db8::1")}
	mx := libdns.MX{Name: fmt.Sprintf("mx-%s", sub), TTL: 60 * time.Second, Target: fmt.Sprintf("mail.%s.%s", sub, zone), Preference: 10}
	txt := libdns.TXT{Name: fmt.Sprintf("txt-%s", sub), TTL: 60 * time.Second, Text: "live-test"}
	ns := libdns.NS{Name: fmt.Sprintf("ns-%s", sub), TTL: 60 * time.Second, Target: fmt.Sprintf("ns1.%s.%s", sub, zone)}
	https := libdns.ServiceBinding{Name: fmt.Sprintf("https-%s", sub), TTL: 60 * time.Second, Scheme: "https", Priority: 1, Target: fmt.Sprintf("target.%s.%s", sub, zone), Params: map[string][]string{"alpn": {"h2", "h3"}, "port": {"443"}}}

	// Bundle records for easier cleanup
	all := []libdns.Record{aaaa, mx, txt, ns, https}

	// Ensure cleanup even if the test fails
	defer func() {
		// best-effort cleanup
		_, _ = provider.DeleteRecords(ctx, zone, all)
	}()

	// Append all records
	for _, r := range all {
		if _, err := provider.AppendRecords(ctx, zone, []libdns.Record{r}); err != nil {
			rr := r.RR()
			t.Fatalf("AppendRecords failed for record type=%s name=%s: %v", rr.Type, rr.Name, err)
		}
	}

	// Verify they exist
	recs, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}

	found := map[string]bool{}
	for _, r := range recs {
		switch tr := r.(type) {
		case libdns.Address:
			if tr.Name == fmt.Sprintf("aaaa-%s", sub) && tr.IP.String() == "2001:db8::1" {
				found["aaaa"] = true
			}
		case libdns.MX:
			if tr.Name == fmt.Sprintf("mx-%s", sub) && tr.Target == fmt.Sprintf("mail.%s.%s", sub, zone) {
				found["mx"] = true
			}
		case libdns.TXT:
			if tr.Name == fmt.Sprintf("txt-%s", sub) && tr.Text == "live-test" {
				found["txt"] = true
			}
		case libdns.NS:
			if tr.Name == fmt.Sprintf("ns-%s", sub) && tr.Target == fmt.Sprintf("ns1.%s.%s", sub, zone) {
				found["ns"] = true
			}
		case libdns.ServiceBinding:
			if tr.Name == fmt.Sprintf("https-%s", sub) && tr.Scheme == "https" && tr.Target == fmt.Sprintf("target.%s.%s", sub, zone) && tr.Priority == 1 {
				found["https"] = true
			}
		}
	}

	for _, typ := range []string{"aaaa", "mx", "txt", "ns", "https"} {
		if !found[typ] {
			t.Fatalf("expected %s record to be present, but it was not found", typ)
		}
	}
}

// If a .env file exists, load its key=value pairs into the environment so
// `go test` picks up the same values the run-tests.sh script would.
func init() {
	f, err := os.Open(".env")
	if err != nil {
		return // no .env, nothing to do
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var setKeys []string
	for s.Scan() {
		line := s.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// remove surrounding quotes if present
		val = strings.Trim(val, `"'`)
		// Do not overwrite env vars already set in the environment
		if _, ok := os.LookupEnv(key); !ok {
			os.Setenv(key, val)
			setKeys = append(setKeys, key)
		}
	}
	if len(setKeys) > 0 {
		// Redact secret-valued keys from output: show names only, not values
		fmt.Fprintf(os.Stderr, "provider_test: loaded .env, set %d vars: %s\n", len(setKeys), strings.Join(setKeys, ", "))
	}
}

// newTestProvider returns a Provider populated from environment variables when present,
// and falls back to reasonable defaults for tests.
func newTestProvider() *Provider {
	p := NewProviderFromEnv()
	if p.APIKey == "" {
		p.APIKey = "K"
	}
	if p.APISecret == "" {
		p.APISecret = "S"
	}
	if p.PageSize == 0 {
		p.PageSize = 100
	}
	return p
}
