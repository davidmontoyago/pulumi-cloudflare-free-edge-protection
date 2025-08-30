package cloudflare

import (
	"fmt"
	"strings"

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
				Expression: pulumi.Sprintf("(%s)", strings.Join([]string{
					`(http.request.uri.path contains ".css")`,
					`(http.request.uri.path contains ".js")`,
					`(http.request.uri.path contains ".jpg")`,
					`(http.request.uri.path contains ".jpeg")`,
					`(http.request.uri.path contains ".png")`,
					`(http.request.uri.path contains ".gif")`,
					`(http.request.uri.path contains ".ico")`,
					`(http.request.uri.path contains ".svg")`,
					`(http.request.uri.path contains ".woff")`,
					`(http.request.uri.path contains ".woff2")`,
					`(http.request.uri.path contains ".ttf")`,
					`(http.request.uri.path contains ".eot")`,
					`(http.request.uri.path contains ".pdf")`,
					`(http.request.uri.path contains ".zip")`,
					`(http.request.uri.path contains ".mp4")`,
					`(http.request.uri.path contains ".mp3")`,
					`(http.request.uri.path contains "/static/")`,
					`(http.request.uri.path contains "/assets/")`,
					`(http.request.uri.path contains "/public/")`,
					`(http.request.uri.path contains "/fonts/")`,
					`(http.request.headers["content-type"][0] eq "image/jpeg")`,
					`(http.request.headers["content-type"][0] eq "image/png")`,
					`(http.request.headers["content-type"][0] eq "image/gif")`,
					`(http.request.headers["content-type"][0] eq "image/svg+xml")`,
				}, " or ")),
				Description: pulumi.String("Cache static assets aggressively"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Cache: pulumi.Bool(true),
					BrowserTtl: &cloudflare.RulesetRuleActionParametersBrowserTtlArgs{
						Mode:    pulumi.String("override_origin"),
						Default: e.BrowserCacheTTL,
					},
					EdgeTtl: &cloudflare.RulesetRuleActionParametersEdgeTtlArgs{
						Mode:    pulumi.String("override_origin"),
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
				Expression: pulumi.Sprintf("(%s)", strings.Join([]string{
					`(http.request.uri.path contains ".html")`,
					`(http.request.uri.path contains ".htm")`,
					`(http.request.uri.path eq "/")`,
					`(not http.request.uri.path contains ".")`,
				}, " or ")),
				Description: pulumi.String("Cache HTML pages with shorter TTL"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Cache: pulumi.Bool(true),
					// TODO make me configurable
					BrowserTtl: &cloudflare.RulesetRuleActionParametersBrowserTtlArgs{
						Mode:    pulumi.String("override_origin"),
						Default: pulumi.Int(1800), // 30 minutes for browser
					},
					EdgeTtl: &cloudflare.RulesetRuleActionParametersEdgeTtlArgs{
						Mode:    pulumi.String("override_origin"),
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
				Expression: pulumi.Sprintf("(%s)", strings.Join([]string{
					`(http.request.uri.path contains "/api/")`,
					`(http.request.uri.path contains "/admin/")`,
					`(http.request.uri.path contains "/login")`,
					`(http.request.uri.path contains "/checkout")`,
					`(http.request.uri.path contains "/cart")`,
					`(http.request.method ne "GET")`,
				}, " or ")),
				Description: pulumi.String("Bypass cache for dynamic and sensitive content"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Cache: pulumi.Bool(true),
					// TODO make me configurable
					BrowserTtl: &cloudflare.RulesetRuleActionParametersBrowserTtlArgs{
						Mode: pulumi.String("bypass"),
					},
					EdgeTtl: &cloudflare.RulesetRuleActionParametersEdgeTtlArgs{
						Mode: pulumi.String("bypass_by_default"),
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
