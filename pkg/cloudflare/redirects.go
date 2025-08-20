package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createRedirectRules creates modern redirect rules (replaces legacy HTTPS page rule)
//
// Uses 3 rules of the 70 under the free tier.
func (e *EdgeProtection) createRedirectRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {

	// See: https://developers.cloudflare.com/rules/url-forwarding/
	redirectRuleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("redirect-ruleset", "optimization", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("HTTPS Redirect Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_request_dynamic_redirect"),
		Description: pulumi.String("Force HTTPS and handle redirects"),
		Rules: cloudflare.RulesetRuleArray{
			// Force HTTPS for all HTTP traffic (replaces AlwaysUseHttps page rule)
			// See: https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("redirect"),
				Expression:  pulumi.String("not ssl"),
				Description: pulumi.String("Force HTTPS for all HTTP requests"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					AutomaticHttpsRewrites: pulumi.Bool(true),
				},
				Enabled: pulumi.Bool(true),
			},

			// Redirect www to root
			// See: https://developers.cloudflare.com/rules/url-forwarding/examples/redirect-www-to-root/
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("redirect"),
				Expression:  pulumi.Sprintf(`http.host eq "www.%s"`, e.Domain),
				Description: pulumi.String("Redirect www to root domain"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					FromValue: &cloudflare.RulesetRuleActionParametersFromValueArgs{
						PreserveQueryString: pulumi.Bool(true),
						StatusCode:          pulumi.Float64(301),
						TargetUrl: &cloudflare.RulesetRuleActionParametersFromValueTargetUrlArgs{
							Expression: pulumi.Sprintf(`https://%s${request.uri}`, e.Domain),
						},
					},
				},
				Enabled: pulumi.Bool(true),
			},

			// Redirect trailing slashes for SEO
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("redirect"),
				Expression: pulumi.String(`
									http.request.uri.path matches "^.+/$" and
									http.request.uri.path ne "/" and
									not http.request.uri.path matches "^/api/"
							`),
				Description: pulumi.String("Remove trailing slashes for SEO"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					FromValue: &cloudflare.RulesetRuleActionParametersFromValueArgs{
						PreserveQueryString: pulumi.Bool(true),
						StatusCode:          pulumi.Float64(301),
						TargetUrl: &cloudflare.RulesetRuleActionParametersFromValueTargetUrlArgs{
							Expression: pulumi.Sprintf(`https://%s${substring(request.uri,0,-1)}`, e.Domain),
						},
					},
				},
				Enabled: pulumi.Bool(true),
			},

			// TODO add configurable geo location rules
			// See: https://developers.cloudflare.com/rules/url-forwarding/examples/redirect-all-country/
		},
	}, pulumi.Parent(e))

	if err != nil {
		return nil, fmt.Errorf("failed to create redirect ruleset: %w", err)
	}

	return redirectRuleset, nil
}
