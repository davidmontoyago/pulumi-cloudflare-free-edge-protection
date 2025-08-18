package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createPageRules creates page rules for additional optimization.
func (e *EdgeProtection) createPageRules(ctx *pulumi.Context, zone *cloudflare.Zone) error {
	// Page Rules for additional optimization (Free tier allows 3 rules)

	// 1. Cache everything on static assets
	cachePageRule, err := cloudflare.NewPageRule(ctx, e.newResourceName("cache", "static-assets", 64), &cloudflare.PageRuleArgs{
		ZoneId:   zone.ID(),
		Target:   pulumi.Sprintf("*%s/*", e.Domain),
		Priority: pulumi.Int(1),
		Status:   pulumi.String("active"),
		Actions: &cloudflare.PageRuleActionsArgs{
			CacheLevel:      pulumi.String("cache_everything"),
			EdgeCacheTtl:    e.EdgeCacheTTL,
			BrowserCacheTtl: e.BrowserCacheTTL,
		},
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create cache page rule: %w", err)
	}
	e.cachePageRule = cachePageRule

	// 2. Always use HTTPS
	httpsPageRule, err := cloudflare.NewPageRule(ctx, e.newResourceName("force", "https", 64), &cloudflare.PageRuleArgs{
		ZoneId:   zone.ID(),
		Target:   pulumi.Sprintf("http://%s/*", e.Domain),
		Priority: pulumi.Int(2),
		Status:   pulumi.String("active"),
		Actions: &cloudflare.PageRuleActionsArgs{
			AlwaysUseHttps: pulumi.Bool(true),
		},
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create HTTPS page rule: %w", err)
	}
	e.httpsPageRule = httpsPageRule

	// 3. Security headers
	securityPageRule, err := cloudflare.NewPageRule(ctx, e.newResourceName("security", "headers", 64), &cloudflare.PageRuleArgs{
		ZoneId:   zone.ID(),
		Target:   pulumi.Sprintf("%s/*", e.Domain),
		Priority: pulumi.Int(3),
		Status:   pulumi.String("active"),
		Actions: &cloudflare.PageRuleActionsArgs{
			SecurityLevel: e.SecurityLevel,
			BrowserCheck: e.BrowserCheckEnabled.ApplyT(func(enabled bool) string {
				if enabled {
					return "on"
				}
				return "off"
			}).(pulumi.StringOutput),
		},
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create security page rule: %w", err)
	}
	e.securityPageRule = securityPageRule

	return nil
}
