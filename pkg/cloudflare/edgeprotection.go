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

	Upstreams                    []Upstream
	CloudflareZone               Zone
	SecurityLevel                pulumi.StringOutput
	BrowserCacheTTL              pulumi.IntOutput
	EdgeCacheTTLSeconds          pulumi.IntOutput
	RateLimitThreshold           pulumi.IntOutput
	RateLimitPeriodSeconds       pulumi.IntOutput
	MitigationTimeoutSeconds     pulumi.IntOutput
	RateLimitMode                pulumi.StringOutput
	TLSEncryptionMode            pulumi.StringOutput
	MinTLSVersion                pulumi.StringOutput
	AlwaysUseHTTPS               pulumi.BoolOutput
	TLS13Enabled                 pulumi.BoolOutput
	BrowserCheckEnabled          pulumi.BoolOutput
	DDoSAttackNotificationsEmail string
	Labels                       map[string]string

	name string

	// Core resources
	zone               *cloudflare.Zone
	upstreamDNSRecords []*cloudflare.DnsRecord
	zoneSettings       []*cloudflare.ZoneSetting
	rateLimitRuleset   *cloudflare.Ruleset
	ddosL7Ruleset      *cloudflare.Ruleset
	wafCustomRuleset   *cloudflare.Ruleset
	cacheRuleset       *cloudflare.Ruleset
	redirectRuleset    *cloudflare.Ruleset
	configRuleset      *cloudflare.Ruleset
	freeTierRulesCount pulumi.IntOutput

	ddosAttackNotifications *cloudflare.NotificationPolicy
}

// NewEdgeProtection creates a new EdgeProtection instance with the provided configuration.
func NewEdgeProtection(ctx *pulumi.Context, name string, args *EdgeProtectionArgs, opts ...pulumi.ResourceOption) (*EdgeProtection, error) {
	if len(args.Upstreams) == 0 {
		return nil, fmt.Errorf("upstreams are required")
	}
	if args.CloudflareZone.CloudflareAccountID == "" {
		return nil, fmt.Errorf("cloudflare account ID is required")
	}

	edgeProtection := &EdgeProtection{
		Upstreams:                    args.Upstreams,
		CloudflareZone:               args.CloudflareZone,
		SecurityLevel:                setDefaultString(args.SecurityLevel, "medium"),
		BrowserCacheTTL:              setDefaultInt(args.BrowserCacheTTL, 14400),       // 4 hours
		EdgeCacheTTLSeconds:          setDefaultInt(args.EdgeCacheTTLSeconds, 2419200), // 28 days
		RateLimitPeriodSeconds:       setDefaultInt(nil, 10),                           // Free tier requires 10 seconds
		MitigationTimeoutSeconds:     setDefaultInt(nil, 10),                           // Free tier requires 10 seconds
		RateLimitThreshold:           setDefaultInt(args.RateLimitThreshold, 60),       // 60 requests per 10s period
		RateLimitMode:                setDefaultString(args.RateLimitMode, "block"),
		TLSEncryptionMode:            setDefaultString(args.TLSEncryptionMode, "strict"),
		MinTLSVersion:                setDefaultString(args.MinTLSVersion, "1.2"),
		AlwaysUseHTTPS:               setDefaultBool(args.AlwaysUseHTTPS, true),
		TLS13Enabled:                 setDefaultBool(args.TLS13Enabled, true),
		BrowserCheckEnabled:          setDefaultBool(args.BrowserCheckEnabled, true),
		DDoSAttackNotificationsEmail: args.DDoSAttackNotificationsEmail,
		Labels:                       args.Labels,

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
		"cloudflare_zone_id":                   edgeProtection.zone.ID(),
		"cloudflare_zone_name":                 edgeProtection.zone.Name,
		"cloudflare_zone_status":               edgeProtection.zone.Status,
		"cloudflare_zone_name_servers":         edgeProtection.zone.NameServers,
		"cloudflare_upstream_dns_record_count": pulumi.Int(len(edgeProtection.upstreamDNSRecords)),
		"cloudflare_rate_limit_ruleset_id":     edgeProtection.rateLimitRuleset.ID(),
		"cloudflare_ddos_l7_ruleset_id":        edgeProtection.ddosL7Ruleset.ID(),
		"cloudflare_waf_custom_ruleset_id":     edgeProtection.wafCustomRuleset.ID(),
		"cloudflare_cache_ruleset_id":          edgeProtection.cacheRuleset.ID(),
		"cloudflare_redirect_ruleset_id":       edgeProtection.redirectRuleset.ID(),
		"cloudflare_config_ruleset_id":         edgeProtection.configRuleset.ID(),
		"cloudflare_ruleset_rules_count":       edgeProtection.freeTierRulesCount,
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

	// 2. Create DNS records for each upstream
	upstreamDNSRecords, err := e.createDNSRecords(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create upstream DNS records: %w", err)
	}
	e.upstreamDNSRecords = upstreamDNSRecords

	// 3. Configure SSL/TLS settings
	zoneSettings, err := e.configureTLSSettings(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to configure TLS settings: %w", err)
	}
	e.zoneSettings = zoneSettings

	// 4. Create rate limiting rules
	rateLimitRuleset, err := e.createRateLimitRuleset(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create rate limit rule: %w", err)
	}
	e.rateLimitRuleset = rateLimitRuleset

	// 5. Create DDoS protection rules
	ddosL7Ruleset, err := e.createDDoSProtectionRules(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create DDoS protection rules: %w", err)
	}
	e.ddosL7Ruleset = ddosL7Ruleset

	// 6. Create custom WAF rules.
	// Predefined best-practice managed rulesets are provided by default.
	// See: https://developers.cloudflare.com/waf/managed-rules/
	wafCustomRuleset, err := e.createWAFCustomRules(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create WAF custom rules: %w", err)
	}
	e.wafCustomRuleset = wafCustomRuleset

	// 7. Create traffic optimization rules
	cacheRuleset, redirectRuleset, configRuleset, err := e.createOptimizationRules(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create optimization rules: %w", err)
	}
	e.cacheRuleset = cacheRuleset
	e.redirectRuleset = redirectRuleset
	e.configRuleset = configRuleset

	// Count total number of free-tier rules
	pulumi.All(
		cacheRuleset.Rules,
		redirectRuleset.Rules,
		configRuleset.Rules,
		wafCustomRuleset.Rules,
		ddosL7Ruleset.Rules,
		rateLimitRuleset.Rules,
	).ApplyT(func(rules []interface{}) error {
		freeRules := flattenRulesetRules(rules)
		e.freeTierRulesCount = pulumi.Int(len(freeRules)).ToIntOutput()

		return nil
	})

	// 8. Create DDoS attack notifications
	if e.DDoSAttackNotificationsEmail != "" {
		ddosAttackNotifications, err := e.setupDDoSAttackNotifications(ctx, e.DDoSAttackNotificationsEmail)
		if err != nil {
			return fmt.Errorf("failed to create DDoS attack notifications: %w", err)
		}
		e.ddosAttackNotifications = ddosAttackNotifications
	}

	return nil
}

// Getter methods for accessing internal resources

// GetZone returns the Cloudflare Zone resource.
func (e *EdgeProtection) GetZone() *cloudflare.Zone {
	return e.zone
}

// GetUpstreamDNSRecords returns the upstream DNS records resource.
func (e *EdgeProtection) GetUpstreamDNSRecords() []*cloudflare.DnsRecord {
	return e.upstreamDNSRecords
}

// GetZoneSettings returns the zone settings override resource.
func (e *EdgeProtection) GetZoneSettings() []*cloudflare.ZoneSetting {
	return e.zoneSettings
}

// GetRateLimitRuleset returns the rate limit ruleset resource.
func (e *EdgeProtection) GetRateLimitRuleset() *cloudflare.Ruleset {
	return e.rateLimitRuleset
}

// GetDDoSL7Ruleset returns the DDoS L7 protection ruleset resource.
func (e *EdgeProtection) GetDDoSL7Ruleset() *cloudflare.Ruleset {
	return e.ddosL7Ruleset
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

// GetDDoSAttackNotifications returns the DDoS attack notification policy resource.
func (e *EdgeProtection) GetDDoSAttackNotifications() *cloudflare.NotificationPolicy {
	return e.ddosAttackNotifications
}
