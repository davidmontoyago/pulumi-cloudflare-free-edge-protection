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
	zone              *cloudflare.Zone
	backendDNSRecord  *cloudflare.DnsRecord
	frontendDNSRecord *cloudflare.DnsRecord
	rootDNSRecord     *cloudflare.DnsRecord
	zoneSettings      *cloudflare.ZoneSetting
	rateLimitRuleset  *cloudflare.Ruleset
	ddosL4Ruleset     *cloudflare.Ruleset
	ddosL7Ruleset     *cloudflare.Ruleset
	wafManagedRuleset *cloudflare.Ruleset
	wafCustomRuleset  *cloudflare.Ruleset
	cacheRuleset      *cloudflare.Ruleset
	redirectRuleset   *cloudflare.Ruleset
	configRuleset     *cloudflare.Ruleset
	rulesCount        pulumi.IntOutput
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
		"cloudflare_rate_limit_ruleset_id":  edgeProtection.rateLimitRuleset.ID(),
		"cloudflare_ddos_l4_ruleset_id":     edgeProtection.ddosL4Ruleset.ID(),
		"cloudflare_ddos_l7_ruleset_id":     edgeProtection.ddosL7Ruleset.ID(),
		"cloudflare_waf_managed_ruleset_id": edgeProtection.wafManagedRuleset.ID(),
		"cloudflare_waf_custom_ruleset_id":  edgeProtection.wafCustomRuleset.ID(),
		"cloudflare_cache_ruleset_id":       edgeProtection.cacheRuleset.ID(),
		"cloudflare_redirect_ruleset_id":    edgeProtection.redirectRuleset.ID(),
		"cloudflare_config_ruleset_id":      edgeProtection.configRuleset.ID(),
		"cloudflare_ruleset_rules_count":    edgeProtection.rulesCount,
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

	// 4. Create rate limiting rules
	rateLimitRuleset, err := e.createRateLimitRuleset(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create rate limit rule: %w", err)
	}
	e.rateLimitRuleset = rateLimitRuleset

	// 5. Create DDoS protection rules
	ddosL4Ruleset, ddosL7Ruleset, err := e.createDDoSProtectionRules(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create DDoS protection rules: %w", err)
	}
	e.ddosL4Ruleset = ddosL4Ruleset
	e.ddosL7Ruleset = ddosL7Ruleset

	// 6. Create WAF managed rules
	wafManagedRuleset, err := e.createWAFManagedRules(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create WAF managed rules: %w", err)
	}
	e.wafManagedRuleset = wafManagedRuleset

	// 7. Create custom WAF rules
	wafCustomRuleset, err := e.createWAFCustomRules(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create WAF custom rules: %w", err)
	}
	e.wafCustomRuleset = wafCustomRuleset

	// 8. Create traffic optimization rules
	cacheRuleset, redirectRuleset, configRuleset, err := e.createOptimizationRules(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create optimization rules: %w", err)
	}
	e.cacheRuleset = cacheRuleset
	e.redirectRuleset = redirectRuleset
	e.configRuleset = configRuleset

	// Count total number of rules
	pulumi.All(
		cacheRuleset.Rules,
		redirectRuleset.Rules,
		configRuleset.Rules,
		wafManagedRuleset.Rules,
		wafCustomRuleset.Rules,
		ddosL4Ruleset.Rules,
		ddosL7Ruleset.Rules,
		rateLimitRuleset.Rules,
	).ApplyT(func(rules []interface{}) error {
		allRules := flattenRulesetRules(rules)
		e.rulesCount = pulumi.Int(len(allRules)).ToIntOutput()
		return nil
	})

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

// GetRateLimitRuleset returns the rate limit ruleset resource.
func (e *EdgeProtection) GetRateLimitRuleset() *cloudflare.Ruleset {
	return e.rateLimitRuleset
}

// GetDDoSL4Ruleset returns the DDoS L4 protection ruleset resource.
func (e *EdgeProtection) GetDDoSL4Ruleset() *cloudflare.Ruleset {
	return e.ddosL4Ruleset
}

// GetDDoSL7Ruleset returns the DDoS L7 protection ruleset resource.
func (e *EdgeProtection) GetDDoSL7Ruleset() *cloudflare.Ruleset {
	return e.ddosL7Ruleset
}

// GetWAFManagedRuleset returns the WAF managed ruleset resource.
func (e *EdgeProtection) GetWAFManagedRuleset() *cloudflare.Ruleset {
	return e.wafManagedRuleset
}

// GetWAFCustomRuleset returns the WAF custom ruleset resource.
func (e *EdgeProtection) GetWAFCustomRuleset() *cloudflare.Ruleset {
	return e.wafCustomRuleset
}

// GetCacheRuleset returns the cache optimization ruleset resource.
func (e *EdgeProtection) GetCacheRuleset() *cloudflare.Ruleset {
	return e.cacheRuleset
}

// GetRedirectRuleset returns the redirect ruleset resource.
func (e *EdgeProtection) GetRedirectRuleset() *cloudflare.Ruleset {
	return e.redirectRuleset
}

// GetConfigurationRuleset returns the configuration ruleset resource.
func (e *EdgeProtection) GetConfigurationRuleset() *cloudflare.Ruleset {
	return e.configRuleset
}
