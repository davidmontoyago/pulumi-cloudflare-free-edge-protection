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

Rules
- 70 Cloudflare Rules
- 5 WAF Rules

### Upstream security

Make sure the upstream services allow-list Cloudflare IPs to only allow traffic from the edge proxies.

See:
- https://developers.cloudflare.com/dns/proxy-status
