package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Cloudflare Managed Ruleset IDs
// See: https://developers.cloudflare.com/waf/managed-rules/
const (
	cloudflareManagedRulesetID            = "efb7b8c949ac4650a09736fc376e9aee"
	cloudflareOWASPManagedRulesetID       = "4814384a9e5d4991b9815dcfc25d2f1f"
	cloudflareExposedCredentialsRulesetID = "c2e184081120413c86c3ab7e14069605"
)

// createWAFManagedRules deploys Cloudflare's managed security rulesets
// for firewall, best-practice OWASP core, and exposed credentials protection.
//
// Uses 3 rules of the 70 under the free tier.
func (e *EdgeProtection) createWAFManagedRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {
	wafManagedRuleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("managed-ruleset", "waf", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("WAF Managed Security Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_request_firewall_managed"),
		Description: pulumi.String("Deploy Cloudflare managed security rulesets"),
		Rules: cloudflare.RulesetRuleArray{
			// Cloudflare Managed Ruleset - Core WAF protection
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("execute"),
				Expression:  pulumi.String("true"),
				Description: pulumi.String("Execute Cloudflare Managed Ruleset"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Id: pulumi.String(cloudflareManagedRulesetID),
					// Override specific rules if needed
					Overrides: &cloudflare.RulesetRuleActionParametersOverridesArgs{
						Action: pulumi.String("managed_challenge"), // Less aggressive than block
					},
				},
				Enabled: pulumi.Bool(true),
			},

			// Cloudflare OWASP Core Ruleset
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("execute"),
				Expression:  pulumi.String("true"),
				Description: pulumi.String("Execute OWASP Core Ruleset for common web attacks"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Id: pulumi.String(cloudflareOWASPManagedRulesetID),
				},
				Enabled: pulumi.Bool(true),
			},

			// Exposed Credentials Check
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("execute"),
				Expression:  pulumi.String("true"),
				Description: pulumi.String("Check for exposed credentials in requests"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Id: pulumi.String(cloudflareExposedCredentialsRulesetID),
				},
				Enabled: pulumi.Bool(true),
			},
		},
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF managed ruleset: %w", err)
	}

	return wafManagedRuleset, nil
}

// createWAFCustomRules creates custom WAF rules for apps to customize to their needs.
//
// Uses 5 free WAF rules.
func (e *EdgeProtection) createWAFCustomRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {
	wafCustomRuleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("waf-custom-ruleset", "security", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("WAF Custom Security Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_request_firewall_custom"),
		Description: pulumi.String("Custom WAF rules for blocking common attacks and malicious traffic"),
		Rules: cloudflare.RulesetRuleArray{
			// Rule 1: Block common CMS attack patterns (WordPress, etc.)
			// TODO add more paths and extensions
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("block"),
				Expression: pulumi.String(`
									(http.request.uri.path contains "/wp-admin") or
									(http.request.uri.path contains "/wp-login.php") or
									(http.request.uri.path contains "/xmlrpc.php") or
									(http.request.uri.path contains "/.env") or
									(http.request.uri.path contains "/phpmyadmin") or
									(http.request.uri.path contains "/config.php") or
									(http.request.uri.path contains "/wp-config.php")
							`),
				Description: pulumi.String("Block common CMS and config file access attempts"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 2: Block malicious user agents and tools
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("block"),
				Expression: pulumi.String(`
									(http.user_agent contains "sqlmap") or
									(http.user_agent contains "nmap") or
									(http.user_agent contains "nikto") or
									(http.user_agent contains "masscan") or
									(http.user_agent contains "dirbuster") or
									(http.user_agent eq "") or
									(len(http.user_agent) < 10)
							`),
				Description: pulumi.String("Block malicious scanners and empty user agents"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 3: Block dangerous HTTP methods and protocols
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("block"),
				Expression: pulumi.String(`
									(http.request.method eq "TRACE") or
									(http.request.method eq "TRACK") or
									(http.request.method eq "DEBUG") or
									(http.request.method eq "CONNECT")
							`),
				Description: pulumi.String("Block dangerous HTTP methods"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 4: Challenge suspicious bot behavior
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("managed_challenge"),
				Expression: pulumi.String(`
									(http.request.uri.query contains "union select") or
									(http.request.uri.query contains "drop table") or
									(http.request.uri.query contains "insert into") or
									(http.request.uri.query contains "<script") or
									(http.request.uri.query contains "javascript:") or
									(http.request.uri.path contains "..") or
									(http.request.uri.path contains "%2e%2e")
							`),
				Description: pulumi.String("Challenge requests with SQL injection or XSS patterns"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 5: Block requests to sensitive file types and admin paths
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("block"),
				Expression: pulumi.String(`
									(http.request.uri.path matches ".*\\.(bak|backup|old|orig|tmp|temp|log)$") or
									(http.request.uri.path contains "/admin") or
									(http.request.uri.path contains "/administrator") or
									(http.request.uri.path contains "/.git") or
									(http.request.uri.path contains "/.svn") or
									(http.request.uri.path contains "/server-status") or
									(http.request.uri.path contains "/server-info")
							`),
				Description: pulumi.String("Block access to sensitive files and admin paths"),
				Enabled:     pulumi.Bool(true),
			},
		},
	}, pulumi.Parent(e))

	if err != nil {
		return nil, fmt.Errorf("failed to create WAF custom ruleset: %w", err)
	}

	return wafCustomRuleset, nil
}
