package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createCacheRules creates modern Ruleset for cached content (replaces legacy cache page rule).
//
// Uses 3 rules of the 70 under the free tier.
func (e *EdgeProtection) createCacheRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {

	cacheRuleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("cache-ruleset", "optimization", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("Cache Optimization Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_request_cache_settings"),
		Description: pulumi.String("Cache rules for static assets and performance optimization"),
		Rules: cloudflare.RulesetRuleArray{
			// Cache everything for static assets (more specific than legacy page rule)
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("set_cache_settings"),
				// TODO make me configurable
				Expression: pulumi.String(`
									(http.request.uri.path matches ".*\\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip|mp4|mp3)$") or
									(http.request.uri.path matches "^/static/.*") or
									(http.request.uri.path matches "^/assets/.*") or
									(http.request.uri.path matches "^/public/.*")
							`),
				Description: pulumi.String("Cache static assets aggressively"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Cache: pulumi.Bool(true),
					BrowserTtl: &cloudflare.RulesetRuleActionParametersBrowserTtlArgs{
						Mode:    pulumi.String("override*origin"),
						Default: e.BrowserCacheTTL,
					},
					EdgeTtl: &cloudflare.RulesetRuleActionParametersEdgeTtlArgs{
						Mode:    pulumi.String("override*origin"),
						Default: e.EdgeCacheTTLSeconds,
					},
					CacheKey: &cloudflare.RulesetRuleActionParametersCacheKeyArgs{
						CacheByDeviceType: pulumi.Bool(false),
					},
					ServeStale: &cloudflare.RulesetRuleActionParametersServeStaleArgs{
						DisableStaleWhileUpdating: pulumi.Bool(false),
					},
				},
				Enabled: pulumi.Bool(true),
			},

			// Different cache settings for HTML pages
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("set_cache_settings"),
				// TODO make me configurable
				Expression: pulumi.String(`
									(http.request.uri.path matches ".*\\.(html|htm)$") or
									(http.request.uri.path eq "/") or
									(not http.request.uri.path contains ".")
							`),
				Description: pulumi.String("Cache HTML pages with shorter TTL"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Cache: pulumi.Bool(true),
					// TODO make me configurable
					BrowserTtl: &cloudflare.RulesetRuleActionParametersBrowserTtlArgs{
						Mode:    pulumi.String("override*origin"),
						Default: pulumi.Int(1800), // 30 minutes for browser
					},
					EdgeTtl: &cloudflare.RulesetRuleActionParametersEdgeTtlArgs{
						Mode:    pulumi.String("override*origin"),
						Default: pulumi.Int(7200), // 2 hours for HTML
					},
					CacheKey: &cloudflare.RulesetRuleActionParametersCacheKeyArgs{
						CacheByDeviceType: pulumi.Bool(false),
					},
				},
				Enabled: pulumi.Bool(true),
			},

			// Bypass cache for dynamic content
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("set_cache_settings"),
				// TODO make me configurable
				Expression: pulumi.String(`
									(http.request.uri.path matches "^/api/.*") or
									(http.request.uri.path matches "^/admin/.*") or
									(http.request.uri.path contains "/login") or
									(http.request.uri.path contains "/checkout") or
									(http.request.uri.path contains "/cart") or
									(http.request.method ne "GET")
							`),
				Description: pulumi.String("Bypass cache for dynamic and sensitive content"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Cache: pulumi.Bool(true),
					BrowserTtl: &cloudflare.RulesetRuleActionParametersBrowserTtlArgs{
						Mode: pulumi.String("bypass"),
					},
					EdgeTtl: &cloudflare.RulesetRuleActionParametersEdgeTtlArgs{
						Mode: pulumi.String("bypass"),
					},
				},
				Enabled: pulumi.Bool(true),
			},
		},
	}, pulumi.Parent(e))

	if err != nil {
		return nil, fmt.Errorf("failed to create cache ruleset: %w", err)
	}

	return cacheRuleset, nil
}
