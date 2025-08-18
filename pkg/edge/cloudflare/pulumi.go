package cloudflare

import "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

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

// toPulumiStringMap converts a map[string]string to pulumi.StringMap
func toPulumiStringMap(labels map[string]string) pulumi.StringMap {
	pulumiLabels := pulumi.StringMap{}
	for key, value := range labels {
		pulumiLabels[key] = pulumi.String(value)
	}
	return pulumiLabels
}
