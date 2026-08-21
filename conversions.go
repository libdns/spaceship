package libdnsspaceship

import (
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// toLibdnsRR converts a Spaceship record into a libdns record. Unsupported API
// record types are intentionally ignored by callers (the provider only
// exposes the record types it supports).
func (p *Provider) toLibdnsRR(sr spaceshipRecordUnion, zone string) libdns.Record {
	zone = normalizeZone(zone)
	name := apiRelativeName(sr.Name, zone)
	ttl := time.Duration(sr.TTL) * time.Second

	switch strings.ToUpper(sr.Type) {
	case "A", "AAAA":
		if sr.Address != "" {
			if ip, err := netip.ParseAddr(sr.Address); err == nil {
				return libdns.Address{Name: name, TTL: ttl, IP: ip, ProviderData: sr}
			}
		}
	case "TXT":
		return libdns.TXT{Name: name, TTL: ttl, Text: sr.Value, ProviderData: sr}
	case "CNAME":
		return libdns.CNAME{Name: name, TTL: ttl, Target: sr.Cname, ProviderData: sr}
	case "MX":
		return libdns.MX{Name: name, TTL: ttl, Target: sr.Exchange, Preference: uint16(sr.Preference), ProviderData: sr}
	case "SRV":
		// Spaceship normally returns the owner in Name and the service and
		// protocol in separate fields. Older responses encoded the first two
		// labels in Name, so retain a compatibility fallback for those.
		service, serviceOK := spaceshipSRVReadLabel(sr.Service)
		transport, transportOK := spaceshipSRVReadLabel(sr.Protocol)
		if !serviceOK || !transportOK {
			return nil
		}
		if service == "" || transport == "" {
			fallbackService, fallbackTransport, fallbackName, ok := splitSRVOwner(sr.Name)
			if ok {
				if service == "" {
					service = fallbackService
				}
				if transport == "" {
					transport = fallbackTransport
				}
				if sr.Service == "" && sr.Protocol == "" {
					name = apiRelativeName(fallbackName, zone)
				}
			}
		}
		if service == "" || transport == "" {
			return nil
		}
		if sr.Priority < 0 || sr.Priority > 65535 || sr.Weight < 0 || sr.Weight > 65535 {
			return nil
		}
		// If an API response redundantly includes both the labels and the
		// fields, strip the labels so libdns.SRV does not duplicate them when
		// it is serialized again.
		name = stripSRVLabels(name, service, transport)
		port, ok := apiSRVPort(sr)
		if !ok {
			return nil
		}
		return libdns.SRV{
			Name: name, TTL: ttl, Service: service, Transport: transport,
			Priority: uint16(sr.Priority), Weight: uint16(sr.Weight),
			Port: uint16(port), Target: sr.Target, ProviderData: sr,
		}
	case "NS":
		return libdns.NS{Name: name, TTL: ttl, Target: sr.Nameserver, ProviderData: sr}
	case "CAA":
		flag := 0
		if sr.Flag != nil {
			flag = *sr.Flag
		}
		var flags uint8
		switch {
		case flag < 0:
			flags = 0
		case flag > 255:
			flags = 255
		default:
			flags = uint8(flag)
		}
		return libdns.CAA{Name: name, TTL: ttl, Flags: flags, Tag: sr.Tag, Value: sr.Value, ProviderData: sr}
	case "HTTPS":
		var params libdns.SvcParams
		if sr.SvcParams != "" {
			if parsed, err := libdns.ParseSvcParams(sr.SvcParams); err == nil {
				params = parsed
			}
		}
		target := sr.SvcTarget
		if target == "" {
			target = sr.TargetName
		}
		return libdns.ServiceBinding{
			Name: name, TTL: ttl, Scheme: "https", Priority: uint16(sr.SvcPriority),
			Target: target, Params: params, ProviderData: sr,
		}
	}
	return nil
}

// fromLibdnsRR converts a libdns record into a Spaceship record and reports
// malformed or unsupported input to its caller.
func (p *Provider) fromLibdnsRR(lr libdns.Record, zone string) (*spaceshipRecordUnion, error) {
	if isNilRecord(lr) {
		return nil, fmt.Errorf("record is nil")
	}

	rr := lr.RR()
	rr.Type = strings.ToUpper(strings.TrimSpace(rr.Type))
	if rr.Type == "SRV" {
		if err := validateSRVWireName(rr.Name); err != nil {
			return nil, fmt.Errorf("malformed SRV record: %w", err)
		}
	}
	parsed, err := rr.Parse()
	if err != nil {
		return nil, fmt.Errorf("malformed %s record: %w", rr.Type, err)
	}
	if _, unsupported := parsed.(libdns.RR); unsupported {
		return nil, fmt.Errorf("unsupported record type %q", rr.Type)
	}

	owner := recordOwner(parsed, rr)
	name, err := relativeOwnerName(owner, zone)
	if err != nil {
		return nil, fmt.Errorf("invalid owner name %q: %w", owner, err)
	}
	ttl, err := ttlSeconds(rr.TTL)
	if err != nil {
		return nil, fmt.Errorf("malformed %s record: %w", rr.Type, err)
	}
	rec := spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{
		Name: name, Type: rr.Type, TTL: ttl,
	}}

	switch record := parsed.(type) {
	case libdns.Address:
		rec.Address = record.IP.String()
	case libdns.TXT:
		rec.Value = record.Text
	case libdns.CNAME:
		rec.Cname = record.Target
	case libdns.MX:
		rec.Exchange = record.Target
		rec.Preference = int(record.Preference)
	case libdns.SRV:
		// libdns.SRV.Name is only the owner. Service and Transport are
		// separate fields and must not be included in the API owner again.
		var err error
		rec.Service, err = spaceshipSRVLabel(record.Service)
		if err != nil {
			return nil, fmt.Errorf("malformed SRV record: %w", err)
		}
		rec.Protocol, err = spaceshipSRVLabel(record.Transport)
		if err != nil {
			return nil, fmt.Errorf("malformed SRV record: %w", err)
		}
		rec.Priority = int(record.Priority)
		rec.Weight = int(record.Weight)
		rec.Target = record.Target
		rec.PortInt = int(record.Port)
		if rec.PortInt == 0 {
			return nil, fmt.Errorf("malformed SRV record: port must be between 1 and 65535")
		}
		rec.Port = rec.PortInt
	case libdns.NS:
		rec.Nameserver = record.Target
	case libdns.CAA:
		flags := int(record.Flags)
		rec.Flag = &flags
		rec.Tag = record.Tag
		rec.Value = record.Value
	case libdns.ServiceBinding:
		if !strings.EqualFold(record.Scheme, "https") {
			return nil, fmt.Errorf("unsupported ServiceBinding scheme %q", record.Scheme)
		}
		rec.Type = "HTTPS"
		rec.SvcPriority = int(record.Priority)
		rec.TargetName = record.Target
		rec.SvcParams = record.Params.String()
	default:
		// RR.Parse currently returns only the supported libdns record types,
		// but keep this guard to prevent future types from being sent by
		// accident if libdns grows its parser.
		return nil, fmt.Errorf("unsupported record type %q", rr.Type)
	}
	return &rec, nil
}

func normalizeZone(zone string) string {
	return strings.TrimSuffix(strings.TrimSpace(zone), ".")
}

func apiRelativeName(name, zone string) string {
	explicitFQDN := strings.HasSuffix(name, ".")
	nameWithoutDot := strings.TrimSuffix(name, ".")
	zone = normalizeZone(zone)
	if nameWithoutDot == "" || nameWithoutDot == "@" {
		return "@"
	}
	if explicitFQDN && zone != "" {
		if strings.EqualFold(nameWithoutDot, zone) {
			return "@"
		}
		suffix := "." + zone
		if len(nameWithoutDot) > len(suffix) && strings.EqualFold(nameWithoutDot[len(nameWithoutDot)-len(suffix):], suffix) {
			return nameWithoutDot[:len(nameWithoutDot)-len(suffix)]
		}
		return nameWithoutDot
	}
	// Spaceship documents API names as relative. In particular, a no-dot
	// multi-label value such as "foo.example.com" is a relative owner and
	// must not be mistaken for an FQDN.
	return nameWithoutDot
}

func relativeOwnerName(name, zone string) (string, error) {
	if name == "" || name == "@" {
		return "@", nil
	}
	if !strings.HasSuffix(name, ".") {
		// libdns permits multi-label relative owners without a final dot.
		return name, nil
	}
	zone = normalizeZone(zone)
	withoutDot := strings.TrimSuffix(name, ".")
	if zone != "" {
		if strings.EqualFold(withoutDot, zone) {
			return "@", nil
		}
		suffix := "." + zone
		if len(withoutDot) > len(suffix) && strings.EqualFold(withoutDot[len(withoutDot)-len(suffix):], suffix) {
			relative := withoutDot[:len(withoutDot)-len(suffix)]
			if relative == "" {
				return "@", nil
			}
			return relative, nil
		}
	}
	// A trailing dot explicitly marks an FQDN. If it was not in this zone,
	// reject it rather than accidentally sending an out-of-zone FQDN as a
	// relative Spaceship owner.
	if strings.HasSuffix(name, ".") {
		return "", fmt.Errorf("fully-qualified name is outside zone %q", zone)
	}
	return "", fmt.Errorf("owner must be relative")
}

func recordOwner(record libdns.Record, rr libdns.RR) string {
	switch record := record.(type) {
	case libdns.Address:
		return record.Name
	case libdns.TXT:
		return record.Name
	case libdns.CNAME:
		return record.Name
	case libdns.MX:
		return record.Name
	case libdns.SRV:
		return record.Name
	case libdns.NS:
		return record.Name
	case libdns.CAA:
		return record.Name
	case libdns.ServiceBinding:
		return record.Name
	default:
		return rr.Name
	}
}

func isNilRecord(record libdns.Record) bool {
	if record == nil {
		return true
	}
	value := reflect.ValueOf(record)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func normalizeSRVLabel(label string) string {
	return strings.TrimLeft(strings.TrimSpace(label), "_")
}

func spaceshipSRVReadLabel(label string) (string, bool) {
	if label == "" {
		return "", true
	}
	if !strings.HasPrefix(label, "_") || strings.HasPrefix(label, "__") {
		return "", false
	}
	label = strings.TrimPrefix(label, "_")
	if _, err := spaceshipSRVLabel(label); err != nil {
		return "", false
	}
	return label, true
}

func spaceshipSRVLabel(label string) (string, error) {
	label = strings.TrimLeft(label, "_")
	if label == "" {
		return "", fmt.Errorf("service and transport are required")
	}
	for _, char := range label {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-') {
			return "", fmt.Errorf("invalid service or transport label %q", label)
		}
	}
	return "_" + label, nil
}

func validateSRVWireName(name string) error {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) < 2 || !strings.HasPrefix(labels[0], "_") || !strings.HasPrefix(labels[1], "_") {
		return fmt.Errorf("service and transport labels are required")
	}
	if _, err := spaceshipSRVLabel(labels[0]); err != nil {
		return err
	}
	if _, err := spaceshipSRVLabel(labels[1]); err != nil {
		return err
	}
	return nil
}

func splitSRVOwner(name string) (service, transport, owner string, ok bool) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) < 2 || !strings.HasPrefix(labels[0], "_") || !strings.HasPrefix(labels[1], "_") {
		return "", "", name, false
	}
	service, serviceOK := spaceshipSRVReadLabel(labels[0])
	transport, transportOK := spaceshipSRVReadLabel(labels[1])
	if !serviceOK || !transportOK {
		return "", "", name, false
	}
	owner = strings.Join(labels[2:], ".")
	if owner == "" {
		owner = "@"
	}
	return service, transport, owner, true
}

func stripSRVLabels(name, service, transport string) string {
	if service == "" || transport == "" {
		return name
	}
	prefix := "_" + service + "." + "_" + transport
	if strings.EqualFold(name, prefix) {
		return "@"
	}
	if len(name) > len(prefix) && strings.EqualFold(name[:len(prefix)], prefix) && name[len(prefix)] == '.' {
		owner := strings.TrimPrefix(name[len(prefix):], ".")
		if owner == "" {
			return "@"
		}
		return owner
	}
	return name
}

func parsePort(port string) (int, error) {
	if strings.HasPrefix(port, "_") {
		port = strings.TrimPrefix(port, "_")
	}
	if port == "" {
		return 0, fmt.Errorf("empty port")
	}
	for _, char := range port {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("invalid port %q", port)
		}
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		if err == nil {
			err = fmt.Errorf("port out of range")
		}
		return 0, err
	}
	return value, nil
}

func ttlSeconds(ttl time.Duration) (int, error) {
	if ttl < 0 {
		return 0, fmt.Errorf("negative TTL")
	}
	if ttl%time.Second != 0 {
		return 0, fmt.Errorf("TTL must be whole seconds")
	}
	return int(ttl / time.Second), nil
}

func apiSRVPort(sr spaceshipRecordUnion) (int, bool) {
	if sr.Port != nil {
		switch port := sr.Port.(type) {
		case string:
			value, err := parsePort(port)
			return value, err == nil
		case float64:
			if port >= 1 && port <= 65535 && port == float64(int(port)) {
				return int(port), true
			}
			return 0, false
		case int:
			if port >= 1 && port <= 65535 {
				return port, true
			}
			return 0, false
		default:
			return 0, false
		}
	}
	if sr.PortInt >= 1 && sr.PortInt <= 65535 {
		return sr.PortInt, true
	}
	return 0, false
}

func (p *Provider) fromLibdnsDeleteRR(lr libdns.Record, zone string) (*spaceshipRecordUnion, error) {
	if isNilRecord(lr) {
		return nil, fmt.Errorf("record is nil")
	}
	rr := lr.RR()
	if rr.Name == "" {
		return nil, fmt.Errorf("invalid owner name: delete requires a non-empty name")
	}
	name, err := relativeOwnerName(rr.Name, zone)
	if err != nil {
		return nil, fmt.Errorf("invalid owner name %q: %w", rr.Name, err)
	}
	ttl, err := ttlSeconds(rr.TTL)
	if err != nil {
		return nil, fmt.Errorf("malformed delete record: %w", err)
	}
	typeName := strings.ToUpper(strings.TrimSpace(rr.Type))
	if typeName == "" {
		if rr.Data != "" {
			return nil, fmt.Errorf("malformed delete record: value requires a record type")
		}
		return &spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: name, TTL: ttl}}, nil
	}
	if !isSupportedRecordType(typeName) {
		return nil, fmt.Errorf("unsupported record type %q", typeName)
	}
	// An empty RDATA is libdns's wildcard marker. Preserve only the name and
	// type so omitempty fields remain absent from the DELETE JSON payload.
	if rr.Data == "" {
		return &spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: name, Type: typeName, TTL: ttl}}, nil
	}
	converted, err := p.fromLibdnsRR(lr, zone)
	if err != nil {
		return nil, err
	}
	return converted, nil
}

func isSupportedRecordType(recordType string) bool {
	switch recordType {
	case "A", "AAAA", "TXT", "CNAME", "MX", "SRV", "NS", "CAA", "HTTPS":
		return true
	default:
		return false
	}
}
