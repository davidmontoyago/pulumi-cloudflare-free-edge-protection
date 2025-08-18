package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createRateLimitRule creates rate limiting rules for DDoS protection.
func (e *EdgeProtection) createRateLimitRule(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.RateLimit, error) {
	// Rate limiting for DDoS protection (Free tier allows 1 rule)
	rateLimit, err := cloudflare.NewRateLimit(ctx, e.newResourceName("ddos", "protection", 64), &cloudflare.RateLimitArgs{
		ZoneId: zone.ID(),
		Threshold: e.RateLimitThreshold.ApplyT(func(v int) float64 {
			return float64(v)
		}).(pulumi.Float64Output),
		Period: e.RateLimitPeriod.ApplyT(func(v int) float64 {
			return float64(v)
		}).(pulumi.Float64Output),
		Match: &cloudflare.RateLimitMatchArgs{
			Request: &cloudflare.RateLimitMatchRequestArgs{
				Url: pulumi.String("*"), // Apply to all URLs
				Schemes: pulumi.StringArray{
					pulumi.String("HTTP"),
					pulumi.String("HTTPS"),
				},
				Methods: pulumi.StringArray{
					pulumi.String("GET"),
					pulumi.String("POST"),
					pulumi.String("PUT"),
					pulumi.String("DELETE"),
				},
			},
		},
		Action: &cloudflare.RateLimitActionArgs{
			Mode: e.RateLimitMode,
			Timeout: e.RateLimitTimeout.ApplyT(func(v int) float64 {
				return float64(v)
			}).(pulumi.Float64Output),
		},
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limit rule for DDoS protection: %w", err)
	}
	return rateLimit, nil
}
