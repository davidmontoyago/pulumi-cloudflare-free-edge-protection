package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createOptimizationRules applies all the traffic optimization rules.
func (e *EdgeProtection) createOptimizationRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, *cloudflare.Ruleset, *cloudflare.Ruleset, error) {

	// 1. Create cache ruleset
	cacheRuleset, err := e.createCacheRules(ctx, zone)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create cache ruleset: %w", err)
	}

	// 2. Create redirect ruleset
	redirectRuleset, err := e.createRedirectRules(ctx, zone)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create redirect ruleset: %w", err)
	}

	// 3. Create configuration ruleset
	configRuleset, err := e.createConfigurationRules(ctx, zone)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create configuration ruleset: %w", err)
	}

	return cacheRuleset, redirectRuleset, configRuleset, nil
}

// createConfigurationRules creates configuration rules (replaces security settings page rule) to:
// - set security level
// - enable browser integrity check
//
// See: https://developers.cloudflare.com/rules/configuration-rules/
func (e *EdgeProtection) createConfigurationRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {

	// See: https://developers.cloudflare.com/rules/configuration-rules/create-api/#basic-rule-settings
	configRuleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("config-ruleset", "optimization", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("Configuration Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_config_settings"),
		Description: pulumi.String("Zone configuration overrides for security and optimization"),
		Rules: cloudflare.RulesetRuleArray{
			// Security level configuration (replaces SecurityLevel page rule setting)
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("set_config"),
				Expression:  pulumi.String("true"), // Apply to all requests
				Description: pulumi.String("Set security level and browser checks"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					// Security level equivalent
					SecurityLevel: e.SecurityLevel,
					// Browser integrity check
					Bic: e.BrowserCheckEnabled,
				},
				Enabled: pulumi.Bool(true),
			},
		},
	}, pulumi.Parent(e))

	if err != nil {
		return nil, fmt.Errorf("failed to create configuration ruleset: %w", err)
	}

	return configRuleset, nil
}
