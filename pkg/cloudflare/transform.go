package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createXRealClientIPHeaderTransformRules creates the request header transformation rule
// that sets X-Real-Client-IP from Cloudflare's trusted client IP field.
//
// Uses 1 rule of the 10 Transform Rules available under free tier.
// See: https://developers.cloudflare.com/rules/transform/
func (e *EdgeProtection) createXRealClientIPHeaderTransformRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {
	transformRuleset, err := cloudflare.NewRuleset(ctx, e.NewResourceName("request-header-transform-ruleset", "optimization", 63), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("Request Header Transform Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_request_late_transform"),
		Description: pulumi.String("Set trusted client IP header for origin services"),
		Rules: cloudflare.RulesetRuleArray{
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("rewrite"),
				Expression:  pulumi.String("true"),
				Description: pulumi.String("Set X-Real-Client-IP to Cloudflare trusted client IP"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Headers: cloudflare.RulesetRuleActionParametersHeadersMap{
						"x-real-client-ip": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							// Prefer Cloudflare's trusted ip.src over parsing X-Forwarded-For,
							// which can include intermediary/provided values and is easier to spoof.
							Expression: pulumi.String("to_string(ip.src)"),
						},
					},
				},
				Enabled: pulumi.Bool(true),
			},
		},
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create request header transform ruleset: %w", err)
	}

	return transformRuleset, nil
}
