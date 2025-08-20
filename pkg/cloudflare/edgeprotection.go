// Package cloudflare provides Cloudflare edge protection infrastructure components.
package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// EdgeProtection represents a Cloudflare edge protection stack for internet applications.
type EdgeProtection struct {
	pulumi.ResourceState

	Domain              string
	BackendURL          pulumi.StringOutput
	FrontendURL         pulumi.StringOutput
	CloudflareAccountID string
	SecurityLevel       pulumi.StringOutput
	CacheLevel          pulumi.StringOutput
	BrowserCacheTTL     pulumi.IntOutput
	EdgeCacheTTLSeconds pulumi.IntOutput
	RateLimitThreshold  pulumi.IntOutput
	RateLimitPeriod     pulumi.IntOutput
	RateLimitTimeout    pulumi.IntOutput
	RateLimitMode       pulumi.StringOutput
	SSLMode             pulumi.StringOutput
	MinTLSVersion       pulumi.StringOutput
	AlwaysUseHTTPS      pulumi.BoolOutput
	TLS13Enabled        pulumi.BoolOutput
	BrowserCheckEnabled pulumi.BoolOutput
	AutoHTTPSRewrites   pulumi.BoolOutput
	Labels              map[string]string

	name string

	// Core resources
	zone                 *cloudflare.Zone
	backendDNSRecord     *cloudflare.DnsRecord
	frontendDNSRecord    *cloudflare.DnsRecord
	rootDNSRecord        *cloudflare.DnsRecord
	zoneSettings         *cloudflare.ZoneSetting
	securityFilter       *cloudflare.Filter
	securityFirewallRule *cloudflare.FirewallRule
	rateLimitRule        *cloudflare.RateLimit
	cachePageRule        *cloudflare.PageRule
	httpsPageRule        *cloudflare.PageRule
	securityPageRule     *cloudflare.PageRule
}

// NewEdgeProtection creates a new EdgeProtection instance with the provided configuration.
func NewEdgeProtection(ctx *pulumi.Context, name string, args *EdgeProtectionArgs, opts ...pulumi.ResourceOption) (*EdgeProtection, error) {
	if args.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if args.BackendURL == nil {
		return nil, fmt.Errorf("backend URL is required")
	}
	if args.FrontendURL == nil {
		return nil, fmt.Errorf("frontend URL is required")
	}
	if args.CloudflareAccountID == "" {
		return nil, fmt.Errorf("cloudflare account ID is required")
	}

	edgeProtection := &EdgeProtection{
		Domain:              args.Domain,
		BackendURL:          args.BackendURL.ToStringOutput(),
		FrontendURL:         args.FrontendURL.ToStringOutput(),
		CloudflareAccountID: args.CloudflareAccountID,
		SecurityLevel:       setDefaultString(args.SecurityLevel, "medium"),
		CacheLevel:          setDefaultString(args.CacheLevel, "aggressive"),
		BrowserCacheTTL:     setDefaultInt(args.BrowserCacheTTL, 14400),       // 4 hours
		EdgeCacheTTLSeconds: setDefaultInt(args.EdgeCacheTTLSeconds, 2419200), // 28 days
		RateLimitThreshold:  setDefaultInt(args.RateLimitThreshold, 60),       // 60 requests
		RateLimitPeriod:     setDefaultInt(args.RateLimitPeriod, 60),          // 60 seconds
		RateLimitTimeout:    setDefaultInt(args.RateLimitTimeout, 600),        // 10 minutes
		RateLimitMode:       setDefaultString(args.RateLimitMode, "simulate"),
		SSLMode:             setDefaultString(args.SSLMode, "full"),
		MinTLSVersion:       setDefaultString(args.MinTLSVersion, "1.2"),
		AlwaysUseHTTPS:      setDefaultBool(args.AlwaysUseHTTPS, true),
		TLS13Enabled:        setDefaultBool(args.TLS13Enabled, true),
		BrowserCheckEnabled: setDefaultBool(args.BrowserCheckEnabled, true),
		AutoHTTPSRewrites:   setDefaultBool(args.AutoHTTPSRewrites, true),
		Labels:              args.Labels,

		name: name,
	}

	err := ctx.RegisterComponentResource("pulumi-cloudflare-free-waf:cloudflare:EdgeProtection", name, edgeProtection, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to register component resource: %w", err)
	}

	// Deploy the infrastructure
	err = edgeProtection.deploy(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy edge protection: %w", err)
	}

	err = ctx.RegisterResourceOutputs(edgeProtection, pulumi.Map{
		"cloudflare_zone_id":                edgeProtection.zone.ID(),
		"cloudflare_zone_name":              edgeProtection.zone.Name,
		"cloudflare_zone_status":            edgeProtection.zone.Status,
		"cloudflare_zone_name_servers":      edgeProtection.zone.NameServers,
		"cloudflare_backend_dns_record_id":  edgeProtection.backendDNSRecord.ID(),
		"cloudflare_frontend_dns_record_id": edgeProtection.frontendDNSRecord.ID(),
		// "cloudflare_root_dns_record_id":    edgeProtection.rootDNSRecord.ID(),
		"cloudflare_security_filter_id":    edgeProtection.securityFilter.ID(),
		"cloudflare_firewall_rule_id":      edgeProtection.securityFirewallRule.ID(),
		"cloudflare_rate_limit_rule_id":    edgeProtection.rateLimitRule.ID(),
		"cloudflare_cache_page_rule_id":    edgeProtection.cachePageRule.ID(),
		"cloudflare_https_page_rule_id":    edgeProtection.httpsPageRule.ID(),
		"cloudflare_security_page_rule_id": edgeProtection.securityPageRule.ID(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register resource outputs: %w", err)
	}

	return edgeProtection, nil
}

// deploy provisions all the resources for the Cloudflare edge protection.
func (e *EdgeProtection) deploy(ctx *pulumi.Context) error {
	// 1. Create DNS Zone
	zone, err := e.createZone(ctx)
	if err != nil {
		return fmt.Errorf("failed to create zone: %w", err)
	}
	e.zone = zone

	// 2. Create DNS records
	err = e.createDNSRecords(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create DNS records: %w", err)
	}

	// 3. Configure SSL/TLS settings
	zoneSettings, err := e.configureSSLSettings(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to configure SSL settings: %w", err)
	}
	e.zoneSettings = zoneSettings

	// 4. Create security filters and firewall rules
	err = e.createSecurityRules(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create security rules: %w", err)
	}

	// 5. Create rate limiting rules
	rateLimitRule, err := e.createRateLimitRule(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create rate limit rule: %w", err)
	}
	e.rateLimitRule = rateLimitRule

	// 6. Create page rules
	err = e.createPageRules(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create page rules: %w", err)
	}

	return nil
}

// Getter methods for accessing internal resources

// GetZone returns the Cloudflare Zone resource.
func (e *EdgeProtection) GetZone() *cloudflare.Zone {
	return e.zone
}

// GetBackendDNSRecord returns the backend DNS record resource.
func (e *EdgeProtection) GetBackendDNSRecord() *cloudflare.DnsRecord {
	return e.backendDNSRecord
}

// GetFrontendDNSRecord returns the frontend DNS record resource.
func (e *EdgeProtection) GetFrontendDNSRecord() *cloudflare.DnsRecord {
	return e.frontendDNSRecord
}

// GetRootDNSRecord returns the root DNS record resource.
func (e *EdgeProtection) GetRootDNSRecord() *cloudflare.DnsRecord {
	return e.rootDNSRecord
}

// GetZoneSettings returns the zone settings override resource.
func (e *EdgeProtection) GetZoneSettings() *cloudflare.ZoneSetting {
	return e.zoneSettings
}

// GetSecurityFilter returns the security filter resource.
func (e *EdgeProtection) GetSecurityFilter() *cloudflare.Filter {
	return e.securityFilter
}

// GetSecurityFirewallRule returns the security firewall rule resource.
func (e *EdgeProtection) GetSecurityFirewallRule() *cloudflare.FirewallRule {
	return e.securityFirewallRule
}

// GetRateLimitRule returns the rate limit rule resource.
func (e *EdgeProtection) GetRateLimitRule() *cloudflare.RateLimit {
	return e.rateLimitRule
}

// GetCachePageRule returns the cache page rule resource.
func (e *EdgeProtection) GetCachePageRule() *cloudflare.PageRule {
	return e.cachePageRule
}

// GetHTTPSPageRule returns the HTTPS page rule resource.
func (e *EdgeProtection) GetHTTPSPageRule() *cloudflare.PageRule {
	return e.httpsPageRule
}

// GetSecurityPageRule returns the security page rule resource.
func (e *EdgeProtection) GetSecurityPageRule() *cloudflare.PageRule {
	return e.securityPageRule
}
