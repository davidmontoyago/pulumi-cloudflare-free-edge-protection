// Package cloudflare provides Cloudflare edge protection infrastructure components.
package cloudflare

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// EdgeProtectionArgs contains configuration arguments for creating an EdgeProtection instance.
type EdgeProtectionArgs struct {
	// Domain for which edge protection will be configured (e.g., "myapp.path2prod.dev")
	Domain string
	// Backend URL of the Cloud Run service or other backend (e.g., "backend-service-abc123-uc.a.run.app")
	BackendURL pulumi.StringInput
	// Frontend URL of the Cloud Run service or other frontend (e.g., "frontend-service-def456-uc.a.run.app")
	FrontendURL pulumi.StringInput
	// Cloudflare Account ID. Required.
	CloudflareAccountID string
	// TODO link to docs
	// Security level for Cloudflare protection (optional, defaults to "medium")
	// Valid values: "off", "essentially_off", "low", "medium", "high", "under_attack"
	SecurityLevel pulumi.StringInput
	// Cache level for CDN optimization (optional, defaults to "aggressive")
	// Valid values: "aggressive", "basic", "simplified"
	CacheLevel pulumi.StringInput
	// Browser cache TTL in seconds (optional, defaults to 14400 = 4 hours)
	BrowserCacheTTL pulumi.IntInput
	// Edge cache TTL in seconds for static assets (optional, defaults to 2419200 = 28 days)
	EdgeCacheTTLSeconds pulumi.IntInput
	// Rate limit threshold - number of requests (optional, defaults to 60)
	RateLimitThreshold pulumi.IntInput
	// Rate limit period in seconds (optional, defaults to 60)
	RateLimitPeriod pulumi.IntInput
	// Rate limit timeout in seconds when threshold is exceeded (optional, defaults to 600 = 10 minutes)
	RateLimitTimeout pulumi.IntInput
	// Rate limit action mode (optional, defaults to "simulate")
	// Valid values: "simulate", "ban", "challenge", "js_challenge"
	RateLimitMode pulumi.StringInput
	// SSL mode for the zone (optional, defaults to "full")
	// Valid values: "off", "flexible", "full", "strict"
	SSLMode pulumi.StringInput
	// Minimum TLS version (optional, defaults to "1.2")
	// Valid values: "1.0", "1.1", "1.2", "1.3"
	MinTLSVersion pulumi.StringInput
	// Whether to always use HTTPS (optional, defaults to true)
	AlwaysUseHTTPS pulumi.BoolInput
	// Whether to enable TLS 1.3 (optional, defaults to true)
	TLS13Enabled pulumi.BoolInput
	// Whether to enable browser check for bot protection (optional, defaults to true)
	BrowserCheckEnabled pulumi.BoolInput
	// Whether to enable automatic HTTPS rewrites (optional, defaults to true)
	AutoHTTPSRewrites pulumi.BoolInput
	// Additional labels to apply to resources
	Labels map[string]string
}
