package cloudflare

import (
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createWAFCustomRules creates custom WAF rules for apps to customize to their needs.
//
// Max 5 WAF rules allowed under free tier.
//
// Operator "matches" for expressions is reserved for Business plan and WAF Advanced plan.
func (e *EdgeProtection) createWAFCustomRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {
	wafCustomRuleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("waf-custom-ruleset", "security", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("WAF Custom Security Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_request_firewall_custom"),
		Description: pulumi.String("Custom WAF rules for blocking common attacks and malicious traffic"),
		Rules: cloudflare.RulesetRuleArray{
			// Rule 1: Block CMS and WordPress specific paths
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("block"),
				Expression:  pulumi.String(generateCMSPathBlockingExpression()),
				Description: pulumi.String("Block CMS, WordPress, and application-specific attack vectors"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 2: Block system, configuration, version control paths and malicious user agents
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("block"),
				Expression: pulumi.Sprintf("(%s) or (%s)",
					generateSystemConfigPathBlockingExpression(),
					generateUserAgentBlockingExpression()),
				Description: pulumi.String("Block system files, configuration, version control access, and malicious user agents"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 3: Block admin panels, backup files, and sensitive areas
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("block"),
				Expression:  pulumi.String(generateAdminBackupPathBlockingExpression()),
				Description: pulumi.String("Block admin panels, backup files, and sensitive directories"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 4: Block development, API, and server information paths
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("block"),
				Expression:  pulumi.String(generateDevAPIPathBlockingExpression()),
				Description: pulumi.String("Block development tools, API endpoints, and server information"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 5: Block dangerous HTTP methods and challenge suspicious behavior
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("managed_challenge"),
				Expression: pulumi.Sprintf("(%s)", strings.Join([]string{
					`(http.request.method eq "TRACE")`,
					`(http.request.method eq "TRACK")`,
					`(http.request.method eq "DEBUG")`,
					`(http.request.method eq "CONNECT")`,
					`(http.request.uri.query contains "union select")`,
					`(http.request.uri.query contains "drop table")`,
					`(http.request.uri.query contains "insert into")`,
					`(http.request.uri.query contains "<script")`,
					`(http.request.uri.query contains "javascript:")`,
				}, " or ")),
				Description: pulumi.String("Challenge dangerous HTTP methods and requests with SQL injection or XSS patterns"),
				Enabled:     pulumi.Bool(true),
			},
		},
	}, pulumi.Parent(e))

	if err != nil {
		return nil, fmt.Errorf("failed to create WAF custom ruleset: %w", err)
	}

	return wafCustomRuleset, nil
}
