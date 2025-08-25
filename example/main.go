package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/pkg/cloudflare"
	"github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/pkg/cloudflare/config"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Load configuration from environment variables
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		// Convert config to EdgeProtectionArgs
		args := cfg.ToEdgeProtectionArgs()

		// Create the edge protection component
		edgeProtection, err := cloudflare.NewEdgeProtection(ctx, "cloudflare-edge-protection", args)
		if err != nil {
			return err
		}

		// Export key outputs
		ctx.Export("cloudflare_zone_id", edgeProtection.GetZone().ID())
		ctx.Export("cloudflare_zone_name", edgeProtection.GetZone().Name)
		ctx.Export("cloudflare_zone_status", edgeProtection.GetZone().Status)
		ctx.Export("cloudflare_zone_name_servers", edgeProtection.GetZone().NameServers)

		// Export DNS records info
		upstreamRecords := edgeProtection.GetUpstreamDNSRecords()
		if len(upstreamRecords) > 0 {
			ctx.Export("cloudflare_upstream_dns_record_id", upstreamRecords[0].ID())
		}

		// Export ruleset IDs
		ctx.Export("cloudflare_rate_limit_ruleset_id", edgeProtection.GetRateLimitRuleset().ID())
		ctx.Export("cloudflare_ddos_l7_ruleset_id", edgeProtection.GetDDoSL7Ruleset().ID())
		ctx.Export("cloudflare_waf_custom_ruleset_id", edgeProtection.GetWAFCustomRuleset().ID())
		ctx.Export("cloudflare_cache_ruleset_id", edgeProtection.GetCacheRuleset().ID())
		ctx.Export("cloudflare_redirect_ruleset_id", edgeProtection.GetRedirectRuleset().ID())
		ctx.Export("cloudflare_config_ruleset_id", edgeProtection.GetConfigurationRuleset().ID())

		return nil
	})
}
