package cloudflare

import (
	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Helper functions for setting defaults
func setDefaultString(input pulumi.StringInput, defaultValue string) pulumi.StringOutput {
	if input == nil {
		return pulumi.String(defaultValue).ToStringOutput()
	}

	return input.ToStringOutput()
}

func setDefaultInt(input pulumi.IntInput, defaultValue int) pulumi.IntOutput {
	if input == nil {
		return pulumi.Int(defaultValue).ToIntOutput()
	}

	return input.ToIntOutput()
}

func setDefaultBool(input pulumi.BoolInput, defaultValue bool) pulumi.BoolOutput {
	if input == nil {
		return pulumi.Bool(defaultValue).ToBoolOutput()
	}

	return input.ToBoolOutput()
}

func flattenRulesetRules(rules []interface{}) []cloudflare.RulesetRule {
	var allRules []cloudflare.RulesetRule
	for _, item := range rules {
		rules := item.([]cloudflare.RulesetRule)
		allRules = append(allRules, rules...)
	}

	return allRules
}
