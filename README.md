# pulumi-cloudflare-free-edge-protection

[![Develop](https://github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/actions/workflows/develop.yaml/badge.svg)](https://github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/actions/workflows/develop.yaml) [![Go Coverage](https://raw.githubusercontent.com/wiki/davidmontoyago/pulumi-cloudflare-free-edge-protection/coverage.svg)](https://raw.githack.com/wiki/davidmontoyago/pulumi-cloudflare-free-edge-protection/coverage.html) [![Go Reference](https://pkg.go.dev/badge/github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection.svg)](https://pkg.go.dev/github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection)

Pulumi component to setup internet-grade protection under the Cloudlflare free tier. Secure public endpoints in any cloud with Cloudflare's edge infrastructure.

## Features
- Traffic proxying through Cloudfare
- L4 and L7 DDoS protection
- Rate limits
- WAF rules to block common attack patterns
- TLS enforcement
- Browser integrity checks
- Cache web assets
- [Challenge requests](https://developers.cloudflare.com/cloudflare-challenges/) based on threat score
- Request header transforms to pass real client IP, geolocation, TLS, and transport headers to upstream

### Pre-requisites
- A cloudflare free tier account
- A domain registered with cloudflare
- Pulumi & Go

## Getting Started
```
go get github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection
```
#### GCP integration

Secure a couple Cloud Run instances running in GCP:

```go
cloudflareEdgeProxy, err := cloudflare.NewEdgeProtection(ctx, "my-endpoint-edge-waf", &cloudflare.EdgeProtectionArgs{
  Upstreams: []cloudflare.Upstream{
    // DNS entries of the Domain Mapping config for each Cloud Run instance
    {
      DomainURL:         "myfrontend.mydomain.dev",
      CanonicalNameURL:  "ghs.googlehosted.com",
    },
    {
      DomainURL:         "mybackend.mydomain.dev",
      CanonicalNameURL:  "ghs.googlehosted.com",
    },
  },
  CloudflareZone: cloudflare.Zone{
    CloudflareAccountID: os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
    Protected:           true,
  },
  // Required for GCP Cloud Run instances with Domain Mapping
  AlwaysUseHTTPS:    pulumi.Bool(false),
  TLSEncryptionMode: pulumi.String("full"),
})
if err != nil {
  return fmt.Errorf("failed to setup cloudflare protection: %w", err)
}
```

## Architecture

```
            Internet
                │
                ▼
    CNAME record proxied through
      Cloudflare Global Network
      (Anycast Edge Servers)
                │
                ▼
          Upstream Cloud
(e.g. for GCP, ghs.googlehosted.com)
                │
                ▼
  Internal Cloud DNS Resolution
                │
                ▼
      App Server Container
    (e.g. Cloud Run instance)
```

### Cloudflare free tier

- Unmetered application layer DDoS protection
- IP-based rate limiting
- Protect against high severity and widespread vulnerabilities with WAF
- Detect and challenge common bots only
- Universal SSL certificate
- Fast, easy-to-use DNS
- Global CDN

#### Free Managed Ruleset (default)

This component does not manage the Free Managed Ruleset. Cloudflare automatically deploys the Free Managed Ruleset on free zones (including zones provisioned via API/IaC) hence not managed by this component. This ruleset provides baseline managed WAF protection against high-impact, widely exploited vulnerabilities (for example, major RCE and injection exploit patterns).

See: https://developers.cloudflare.com/waf/managed-rules/

Rules
- 70 Cloudflare Rules
- 5 WAF Rules
- 10 Transform Rules

### Upstream security

Make sure the upstream services allow-list Cloudflare IPs to only allow traffic from the edge proxies.

### Client IP, geolocation, TLS, and transport forwarding

To make origin-side client context handling explicit, this component creates a request header transform rule that sets:

- `X-Real-Client-IP: <client-ip>`
- `X-Real-Client-Country: <ISO 3166-1 Alpha-2 country code>`
- `X-Real-Client-Continent: <continent code>`
- `X-Real-Client-City: <city>`
- `X-Real-Client-Region: <region/state>`
- `X-Real-Client-Region-Code: <region code>`
- `X-Real-Client-Postal-Code: <postal code>`
- `X-Real-Client-Metro-Code: <metro code>`
- `X-Real-Client-Lat: <latitude>`
- `X-Real-Client-Lon: <longitude>`
- `X-Real-Client-Timezone: <IANA timezone>`
- `X-Real-Client-TLS-Version: <TLS version>`
- `X-Real-Client-TLS-Cipher: <TLS cipher suite>`
- `X-Real-Client-TLS-Client-Hello-Length: <client hello length>`
- `X-Real-Client-TLS-Client-Random: <base64 client random>`
- `X-Real-Client-TLS-Client-Extensions-SHA1: <sha1 fingerprint>`
- `X-Real-Client-TLS-Client-Extensions-SHA1-LE: <sha1 fingerprint little-endian>`
- `X-Real-Client-TLS-Client-Ciphers-SHA1: <sha1 fingerprint>`
- `X-Real-Client-RTT: <tcp rtt in ms>`
- `X-Real-Client-QUIC-RTT: <quic rtt in ms for HTTP/3>`
- `X-Real-Client-TCP: <true if TCP, false if QUIC>`
- `X-Real-Client-Delivery-Rate: <estimated bytes/sec>`

Values are derived from Cloudflare trusted `ip.src.*` request fields (with `ip.src` equivalent to `CF-Connecting-IP` for proxied traffic), instead of parsing `X-Forwarded-For`.

TLS header values are derived from Cloudflare `cf.tls_*` request fields available for request header transform expressions.
Transport and RTT headers are derived from Cloudflare `cf.timings.*` and `cf.edge.*` request fields available for request header transform expressions.

This approach avoids trusting intermediary-provided `X-Forwarded-For` chains while keeping the configuration compatible with the Cloudflare free tier.

See:
- https://developers.cloudflare.com/dns/proxy-status
