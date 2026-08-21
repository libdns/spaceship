Spaceship for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/github.com/empressmarissa/libdns_spaceship.svg)](https://pkg.go.dev/github.com/empressmarissa/libdns_spaceship)

This maintained fork implements the [libdns interfaces](https://github.com/libdns/libdns) for Spaceship, allowing you to manage DNS records. It addresses the upstream project's conversion and ownership-name gaps so Spaceship, libdns, and CertMagic can be used together.

The module path is `github.com/empressmarissa/libdns_spaceship`.

## Configuration

To use this provider, you need a Spaceship API key and secret. Configure the provider as follows:

```go
provider := &libdnsspaceship.Provider{
    APIKey:    "your-spaceship-api-key",
    APISecret: "your-spaceship-api-secret",
}
```

Optionally, you can customize the API base URL (defaults to `https://spaceship.dev/api`):

```go
provider := &libdnsspaceship.Provider{
    APIKey:    "your-spaceship-api-key",
    APISecret: "your-spaceship-api-secret",
    BaseURL:   "https://custom-api.spaceship.com",
}
```

### Environment Variables

Alternatively, you can use environment variables or the `NewProviderFromEnv()` constructor to configure the provider:

```go
provider := libdnsspaceship.NewProviderFromEnv()
```

The following environment variables are supported:

| Environment Variable | Description | Required | Default |
|---------------------|-------------|----------|---------|
| `LIBDNS_SPACESHIP_APIKEY` | Your Spaceship API key | Yes | - |
| `LIBDNS_SPACESHIP_APISECRET` | Your Spaceship API secret | Yes | - |
| `LIBDNS_SPACESHIP_BASEURL` | Custom API base URL | No | `https://spaceship.dev/api` |
| `LIBDNS_SPACESHIP_PAGESIZE` | Page size for GetRecords pagination | No | 100 |
| `LIBDNS_SPACESHIP_TIMEOUT` | HTTP client timeout in seconds | No | 30 |

### Example .env file

```bash
LIBDNS_SPACESHIP_APIKEY=your_api_key_here
LIBDNS_SPACESHIP_APISECRET=your_api_secret_here
LIBDNS_SPACESHIP_BASEURL=https://spaceship.dev/api
LIBDNS_SPACESHIP_PAGESIZE=100
LIBDNS_SPACESHIP_TIMEOUT=30
```

## Usage

```go
package main

import (
    "context"
    "net/netip"
    "time"
    
    libdnsspaceship "github.com/empressmarissa/libdns_spaceship"
    "github.com/libdns/libdns"
)

func main() {
    provider := &libdnsspaceship.Provider{
        APIKey:    "your-spaceship-api-key",
        APISecret: "your-spaceship-api-secret",
    }
    
    zone := "example.com."
    
    // Get all records
    records, err := provider.GetRecords(context.TODO(), zone)
    if err != nil {
        panic(err)
    }
    
    // Add a new A record
    newRecords := []libdns.Record{
        libdns.Address{
            Name: "test",
            TTL:  300 * time.Second,
            IP:   netip.MustParseAddr("192.0.2.1"),
        },
    }
    
    createdRecords, err := provider.AppendRecords(context.TODO(), zone, newRecords)
    if err != nil {
        panic(err)
    }
}
```

### Using the maintained fork with Caddy

A maintained Caddy adapter should import this module directly:
`github.com/empressmarissa/libdns_spaceship`. This keeps the final Caddy build
free of module replacement directives.

### Local development

The repository has no required external services for unit checks. With Docker
installed, run `make docker-check` (Go 1.27) or `make docker-check-min` (Go
1.18). Native `make check` runs the same formatting, vet, and unit-test checks
when Go is installed locally. Live Spaceship tests are opt-in and are never
run by these checks or by CI.

## Supported Record Types

This provider supports the following DNS record types:
- A and AAAA records (`libdns.Address`)
- TXT records (`libdns.TXT`)
- CNAME records (`libdns.CNAME`)  
- MX records (`libdns.MX`)
- SRV records (`libdns.SRV`)
- NS records (`libdns.NS`)
- CAA records (`libdns.CAA`)
- HTTPS records (`libdns.ServiceBinding` with scheme "https")

Unsupported record types (such as PTR, TLSA, etc.) are filtered out and not returned by `GetRecords`.

## API Documentation

For more information about the Spaceship API, see the [official documentation](https://docs.spaceship.dev/).

## License

MIT License (See [LICENSE](./LICENSE) file)
