package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createRateLimitRules creates modern rate limiting rules (replaces legacy RateLimit).
// Only 1 rule in the phase http_ratelimit can be used under the free tier.
// See:
// https://developers.cloudflare.com/waf/rate-limiting-rules/#availability
func (e *EdgeProtection) createRateLimitRuleset(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {
	rules := cloudflare.RulesetRuleArray{
		// General rate limiting rule
		&cloudflare.RulesetRuleArgs{
			Action:      e.RateLimitMode,
			Expression:  pulumi.String("true"), // Apply to all requests
			Description: pulumi.String("General rate limiting for DDoS protection"),
			Ratelimit: &cloudflare.RulesetRuleRatelimitArgs{
				Characteristics: pulumi.StringArray{
					// Rate limit by source IP
					pulumi.String("ip.src"),
					// Mandatory characteristic for all rate limiting rules to
					// ensure counters are not shared across data centers
					pulumi.String("cf.colo.id"),
				},
				Period: e.RateLimitPeriodSeconds.ApplyT(func(rateLimitPeriod int) int {
					return rateLimitPeriod
				}).(pulumi.IntOutput),
				RequestsPerPeriod: e.RateLimitThreshold.ApplyT(func(rateLimitThreshold int) int {
					return rateLimitThreshold
				}).(pulumi.IntOutput),
				MitigationTimeout: e.MitigationTimeoutSeconds.ApplyT(func(rateLimitTimeout int) int {
					return rateLimitTimeout
				}).(pulumi.IntOutput),
			},
			Enabled: pulumi.Bool(true),
		},
	}

	// ---- maximum number of rules in the phase http_ratelimit is 1 ----
	if !e.EnableFreeTier {

		rules = append(rules, &cloudflare.RulesetRuleArgs{
			Action: e.RateLimitMode,
			// Stricter rate limiting for API endpoints
			Expression:  pulumi.String(`http.request.uri.path matches "^/api/.*"`),
			Description: pulumi.String("Stricter rate limiting for API endpoints"),
			Ratelimit: &cloudflare.RulesetRuleRatelimitArgs{
				Characteristics: pulumi.StringArray{
					pulumi.String("ip.src"),
					// Mandatory characteristic for all rate limiting rules to
					// ensure counters are not shared across data centers
					pulumi.String("cf.colo.id"),
				},
				Period:            pulumi.Int(60),  // 1 minute
				RequestsPerPeriod: pulumi.Int(30),  // 30 requests per minute for APIs
				MitigationTimeout: pulumi.Int(300), // 5 minute timeout
			},
			Enabled: pulumi.Bool(true),
		}, &cloudflare.RulesetRuleArgs{
			Action: pulumi.String("managed_challenge"),
			// Challenge-based rate limiting for login endpoints
			Expression:  pulumi.String(`(http.request.uri.path matches "\/[login|signin|auth]+$")`),
			Description: pulumi.String("Challenge-based protection for authentication endpoints"),
			Ratelimit: &cloudflare.RulesetRuleRatelimitArgs{
				Characteristics: pulumi.StringArray{
					pulumi.String("ip.src"),
					// Mandatory characteristic for all rate limiting rules to
					// ensure counters are not shared across data centers
					pulumi.String("cf.colo.id"),
				},
				Period:            pulumi.Int(300), // 5 minutes
				RequestsPerPeriod: pulumi.Int(5),   // 5 login attempts per 5 minutes
				MitigationTimeout: pulumi.Int(900), // 15 minute timeout
			},
			Enabled: pulumi.Bool(true),
		})

	}

	rateLimitRuleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("rate-limit-ruleset", "ddos-custom", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("Rate Limiting Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_ratelimit"),
		Description: pulumi.String("Rate limiting for DDoS protection and abuse prevention"),
		Rules:       rules,
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limit ruleset: %w", err)
	}

	return rateLimitRuleset, nil
}
