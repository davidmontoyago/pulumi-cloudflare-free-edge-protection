package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	// Cloudflare L7 DDoS Attack Protection Ruleset ID
	// See: https://developers.cloudflare.com/terraform/additional-configurations/ddos-managed-rulesets/
	ddosL7RulesetID = "4d21379b4f9f4bb088e0729962c8b3cf"
)

// createDDoSProtectionRules deploys DDoS managed protection for L7. L4 is provided by default.
//
// Uses 1 rules of the 70 under the free tier.
func (e *EdgeProtection) createDDoSProtectionRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {

	// DDoS L7 Protection
	ddosL7Ruleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("l7-ruleset", "ddos-managed", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("DDoS L7 Protection"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("ddos_l7"),
		Description: pulumi.String("Layer 7 DDoS protection"),
		Rules: cloudflare.RulesetRuleArray{
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("execute"),
				Expression:  pulumi.String("true"),
				Description: pulumi.String("Execute DDoS L7 Managed Ruleset"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Id: pulumi.String(ddosL7RulesetID),
				},
				Enabled: pulumi.Bool(true),
			},
		},
	}, pulumi.Parent(e))

	if err != nil {
		return nil, fmt.Errorf("failed to create DDoS L7 ruleset: %w", err)
	}

	return ddosL7Ruleset, nil
}
