package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	// Cloudflare L4 and L7 DDoS Attack Protection Rulesets IDs
	// See: https://developers.cloudflare.com/terraform/additional-configurations/ddos-managed-rulesets/
	ddosL4RulesetID = "3b64149bfa6e4220bbbc2bd6db589552"
	ddosL7RulesetID = "4d21379b4f9f4bb088e0729962c8b3cf"
)

// createDDoSProtectionRules deploys DDoS managed protection for L4 and L7.
//
// Uses 2 rules of the 70 under the free tier.
func (e *EdgeProtection) createDDoSProtectionRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, *cloudflare.Ruleset, error) {
	// DDoS L4 Protection
	ddosL4Ruleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("l4-ruleset", "ddos-managed", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("DDoS L4 Protection"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("ddos_l4"),
		Description: pulumi.String("Layer 4 DDoS protection"),
		Rules: cloudflare.RulesetRuleArray{
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("execute"),
				Expression:  pulumi.String("true"),
				Description: pulumi.String("Execute DDoS L4 Managed Ruleset"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Id: pulumi.String(ddosL4RulesetID),
				},
				Enabled: pulumi.Bool(true),
			},
		},
	}, pulumi.Parent(e))

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create DDoS L4 ruleset: %w", err)
	}

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
		return nil, nil, fmt.Errorf("failed to create DDoS L7 ruleset: %w", err)
	}

	return ddosL4Ruleset, ddosL7Ruleset, nil
}
