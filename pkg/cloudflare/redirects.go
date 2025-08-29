package cloudflare

import (
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createRedirectRules creates modern redirect rules (replaces legacy HTTPS page rule)
func (e *EdgeProtection) createRedirectRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {
	rules := cloudflare.RulesetRuleArray{}
	for _, upstream := range e.Upstreams {
		rules = append(rules,
			&cloudflare.RulesetRuleArgs{
				// Redirect www to root
				// See: https://developers.cloudflare.com/rules/url-forwarding/examples/redirect-www-to-root/
				Action:      pulumi.String("redirect"),
				Expression:  pulumi.Sprintf(`http.host eq "www.%s"`, upstream.DomainURL),
				Description: pulumi.Sprintf("Redirect www.%s to %s domain", upstream.DomainURL, upstream.DomainURL),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					FromValue: &cloudflare.RulesetRuleActionParametersFromValueArgs{
						PreserveQueryString: pulumi.Bool(true),
						StatusCode:          pulumi.Float64(301),
						TargetUrl: &cloudflare.RulesetRuleActionParametersFromValueTargetUrlArgs{
							Value: pulumi.Sprintf(`https://%s${request.uri}`, upstream.DomainURL),
						},
					},
				},
				Enabled: pulumi.Bool(true),
			},
			&cloudflare.RulesetRuleArgs{
				// Redirect trailing slashes for SEO
				Action: pulumi.String("redirect"),
				Expression: pulumi.Sprintf("(%s)", strings.Join([]string{
					`ends_with(http.request.uri.path, "/")`,             // Ends with /
					`(http.request.uri.path ne "/")`,                    // Not root path
					`(not starts_with(http.request.uri.path, "/api/"))`, // Doesn't start
				}, " and ")),
				Description: pulumi.String("Remove trailing slashes for SEO"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					FromValue: &cloudflare.RulesetRuleActionParametersFromValueArgs{
						PreserveQueryString: pulumi.Bool(true),
						StatusCode:          pulumi.Float64(301),
						TargetUrl: &cloudflare.RulesetRuleActionParametersFromValueTargetUrlArgs{
							Expression: pulumi.String(`substring(http.request.uri.path,0,-1)`),
						},
					},
				},
				Enabled: pulumi.Bool(true),
			},
			// TODO add configurable geo location rules
			// See: https://developers.cloudflare.com/rules/url-forwarding/examples/redirect-all-country/
		)
	}

	// See: https://developers.cloudflare.com/rules/url-forwarding/
	redirectRuleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("redirect-ruleset", "optimization", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("HTTPS Redirect Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_request_dynamic_redirect"),
		Description: pulumi.String("Force HTTPS and handle redirects"),
		Rules:       rules,
	}, pulumi.Parent(e))

	if err != nil {
		return nil, fmt.Errorf("failed to create redirect ruleset: %w", err)
	}

	return redirectRuleset, nil
}
