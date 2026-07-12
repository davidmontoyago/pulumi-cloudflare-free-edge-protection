// Package cloudflare provides Cloudflare edge protection infrastructure components.
package cloudflare

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Upstream is a service that will be proxied through Cloudflare.
type Upstream struct {
	// Domain URL of the upstream service (e.g., "mybackend.path2prod.dev")
	// Traffic bound to this URL will be proxied through Cloudflare to the CanonicalNameURL.
	DomainURL string
	// Canonical name URL of the upstream service (e.g., "backend-service-abc123-uc.a.run.app")
	// Set to another cloud's DNS endpooint for cross-cloud domain integration.
	// E.g.: In GCP, using Cloud Run's domain mapping this should be set to "ghs.googlehosted.com"
	// to have GCP DNS servers resolve to an internal A record pointing to a cloud run instance.
	// See: https://cloud.google.com/run/docs/mapping-custom-domains
	CanonicalNameURL string
	// DisableProtection is whether to disable Cloudflare proxy for CDN + DDoS protection.
	// Defaults to false.
	// For first time setup, set to true until the cross-cloud DNS is resolved
	// (E.g. In GCP Doman Mapping shows success).
	// See:
	// - https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/#proxied-cname-records
	// - https://developers.cloudflare.com/dns/proxy-status/
	DisableProtection bool
}

// Zone contains configuration for the zone to deploy the edge protection stack to.
type Zone struct {
	// Cloudflare Account ID. Required.
	CloudflareAccountID string
	// Whether to protect the zone from deletion.
	// Set this to true if the zone was created via other Cloudflare means (e.g. via domain transfer).
	// E.g. import the zone into state:
	// > pulumi import "cloudflare:index/zone:Zone" "my-zone-dns" "<zone-id>"
	// See: https://www.pulumi.com/docs/reference/pkg/cloudflare/zone/import/
	Protected bool
}

// EdgeProtectionArgs contains configuration arguments for creating an EdgeProtection instance.
type EdgeProtectionArgs struct {
	// Upstreams to be protected by Cloudflare edge protection.
	// A DNS record will be created for each upstream in the Cloudflare zone.
	Upstreams []Upstream
	// Configuration for the Cloudflare zone to deploy the edge protection stack to.
	CloudflareZone Zone
	// TODO link to docs
	// Security level for Cloudflare protection (optional, defaults to "medium")
	// Valid values: "off", "essentially_off", "low", "medium", "high", "under_attack"
	SecurityLevel pulumi.StringInput
	// Browser cache TTL in seconds (optional, defaults to 14400 = 4 hours)
	BrowserCacheTTL pulumi.IntInput
	// Edge cache TTL in seconds for static assets (optional, defaults to 2419200 = 28 days)
	EdgeCacheTTLSeconds pulumi.IntInput
	// Rate limit threshold - number of requests per 10s periods (optional, defaults to 60)
	RateLimitThreshold pulumi.IntInput
	// Rate limit action mode (optional, defaults to "block")
	// Valid values: "managed_challenge", "block", "challenge", "js_challenge"
	RateLimitMode pulumi.StringInput
	// TLS Encryption Mode for the zone (optional, defaults to "strict")
	// Valid values: "off", "flexible", "full", "strict"
	TLSEncryptionMode pulumi.StringInput
	// Minimum TLS version (optional, defaults to "1.2")
	// Valid values: "1.0", "1.1", "1.2", "1.3"
	MinTLSVersion pulumi.StringInput
	// Whether to always use HTTPS (optional, defaults to true)
	// This must be disabled for GCP Cloud Run instances
	// See: https://cloud.google.com/run/docs/mapping-custom-domains#dns_update
	AlwaysUseHTTPS pulumi.BoolInput
	// Whether to enable TLS 1.3 (optional, defaults to true)
	TLS13Enabled pulumi.BoolInput
	// Whether to enable browser check for bot protection (optional, defaults to true)
	BrowserCheckEnabled pulumi.BoolInput
	// Whether to enable HSTS via Cloudflare security_header setting (optional, defaults to true).
	// When enabled, this component sets strict transport security with:
	// - max-age: 31536000 (1 year)
	// - includeSubDomains: true
	// - nosniff: true
	// - preload: false
	HSTSEnabled pulumi.BoolInput
	// Whether to enable Automatic HTTPS Rewrites (optional, defaults to true).
	// This rewrites mixed-content HTTP asset URLs in HTML to HTTPS when supported.
	// This is independent from AlwaysUseHTTPS redirects.
	AutomaticHTTPSRewritesEnabled pulumi.BoolInput
	// Whether to enable Hotlink Protection (optional, defaults to false).
	// Hotlink Protection blocks external sites from embedding your images based on Referer.
	// Enable only when this behavior matches your content-sharing requirements.
	HotlinkProtectionEnabled pulumi.BoolInput
	// Whether to enable DNSSEC zone signing (optional, defaults to false).
	// For domains registered outside Cloudflare Registrar, the generated DS record must be
	// copied to the registrar to complete the chain of trust.
	DNSSECEnabled pulumi.BoolInput
	// URL normalization type (optional, defaults to "cloudflare").
	// Valid values: "cloudflare", "rfc3986".
	// Cloudflare's own zone default is "rfc3986". The "cloudflare" type additionally collapses
	// repeated slashes and converts backslashes to forward slashes before the RFC 3986 pass,
	// closing more WAF-bypass encoding tricks.
	URLNormalizationType pulumi.StringInput
	// URL normalization scope (optional, defaults to "both").
	// Valid values: "incoming", "both", "none".
	// Cloudflare's own zone default is "incoming" (normalizes the URL seen by WAF/Rules/Workers,
	// but forwards the original, un-normalized URL to the origin). "both" additionally normalizes
	// the URL sent to the origin, so the origin sees the same URL the WAF evaluated.
	URLNormalizationScope pulumi.StringInput
	// Additional labels to apply to resources
	Labels map[string]string
	// Where to send DDoS attack notifications. Disabled if unset.
	DDoSAttackNotificationsEmail string
	// Whether to enable Cloudflare Bot Fight Mode. Defaults to false.
	// Bot Fight Mode runs outside the Ruleset Engine and cannot be skipped with custom rules.
	// Bot Fight Mode also enables JavaScript Detections, so strict CSP policies may require
	// updates to allow Cloudflare challenge scripts.
	BotFightModeEnabled bool
}
