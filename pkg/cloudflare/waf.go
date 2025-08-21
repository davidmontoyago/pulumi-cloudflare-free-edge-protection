package cloudflare

import (
	"fmt"
	"strings"

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
	rules := cloudflare.RulesetRuleArray{
		&cloudflare.RulesetRuleArgs{
			Action:      pulumi.String("execute"),
			Expression:  pulumi.String("true"),
			Description: pulumi.String("Execute Cloudflare Managed Ruleset"),
			ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
				Id: pulumi.String(cloudflareManagedRulesetID),

				Overrides: &cloudflare.RulesetRuleActionParametersOverridesArgs{
					Action: pulumi.String("managed_challenge"),
				},
			},
			Enabled: pulumi.Bool(true),
		},
		&cloudflare.RulesetRuleArgs{
			Action:      pulumi.String("execute"),
			Expression:  pulumi.String("true"),
			Description: pulumi.String("Check for exposed credentials in requests"),
			ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
				Id: pulumi.String(cloudflareExposedCredentialsRulesetID),
			},
			Enabled: pulumi.Bool(true),
		},
	}

	if !e.EnableFreeTier {
		rules = append(rules, &cloudflare.RulesetRuleArgs{
			Action:      pulumi.String("execute"),
			Expression:  pulumi.String("true"),
			Description: pulumi.String("Execute OWASP Core Ruleset for common web attacks"),
			ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
				Id: pulumi.String(cloudflareOWASPManagedRulesetID),
			},
			Enabled: pulumi.Bool(true),
		})
	}

	wafManagedRuleset, err := cloudflare.NewRuleset(ctx, e.newResourceName("managed-ruleset", "waf", 64), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("WAF Managed Security Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_request_firewall_managed"),
		Description: pulumi.String("Deploy Cloudflare managed security rulesets"),
		Rules:       rules,
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF managed ruleset: %w", err)
	}

	return wafManagedRuleset, nil
}

// createWAFCustomRules creates custom WAF rules for apps to customize to their needs.
//
// Uses 5 free WAF rules.
// Operator "matches" for expressions is reserved for Business plan and WAF Advanced plan.
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
				Expression: pulumi.Sprintf("(%s)", strings.Join([]string{
					`(http.request.uri.path contains "/wp-admin")`,
					`(http.request.uri.path contains "/wp-login.php")`,
					`(http.request.uri.path contains "/xmlrpc.php")`,
					`(http.request.uri.path contains "/.env")`,
					`(http.request.uri.path contains "/phpmyadmin")`,
					`(http.request.uri.path contains "/config.php")`,
					`(http.request.uri.path contains "/wp-config.php")`,
				}, " or ")),
				Description: pulumi.String("Block common CMS and config file access attempts"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 2: Block malicious user agents and tools
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("block"),
				Expression: pulumi.Sprintf("(%s)", strings.Join([]string{
					`(http.user_agent contains "sqlmap")`,
					`(http.user_agent contains "nmap")`,
					`(http.user_agent contains "nikto")`,
					`(http.user_agent contains "masscan")`,
					`(http.user_agent contains "dirbuster")`,
					`(http.user_agent eq "")`,
					`(len(http.user_agent) < 10)`,
				}, " or ")),
				Description: pulumi.String("Block malicious scanners and empty user agents"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 3: Block dangerous HTTP methods and protocols
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("block"),
				Expression:  pulumi.String(`(http.request.method eq "TRACE") or (http.request.method eq "TRACK") or (http.request.method eq "DEBUG") or (http.request.method eq "CONNECT")`),
				Description: pulumi.String("Block dangerous HTTP methods"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 4: Challenge suspicious bot behavior
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("managed_challenge"),
				Expression: pulumi.Sprintf("(%s)", strings.Join([]string{
					`(http.request.uri.query contains "union select")`,
					`(http.request.uri.query contains "drop table")`,
					`(http.request.uri.query contains "insert into")`,
					`(http.request.uri.query contains "<script")`,
					`(http.request.uri.query contains "javascript:")`,
					`(http.request.uri.path contains "..")`,
					`(http.request.uri.path contains "%2e%2e")`,
				}, " or ")),
				Description: pulumi.String("Challenge requests with SQL injection or XSS patterns"),
				Enabled:     pulumi.Bool(true),
			},

			// Rule 5: Block requests to sensitive file types and admin paths
			&cloudflare.RulesetRuleArgs{
				Action: pulumi.String("block"),
				Expression: pulumi.Sprintf("(%s)", strings.Join([]string{
					`(http.request.uri.path contains ".bak")`,
					`(http.request.uri.path contains ".backup")`,
					`(http.request.uri.path contains ".old")`,
					`(http.request.uri.path contains ".orig")`,
					`(http.request.uri.path contains ".tmp")`,
					`(http.request.uri.path contains ".temp")`,
					`(http.request.uri.path contains ".log")`,
					`(http.request.uri.path contains "/admin")`,
					`(http.request.uri.path contains "/administrator")`,
					`(http.request.uri.path contains "/.git")`,
					`(http.request.uri.path contains "/.svn")`,
					`(http.request.uri.path contains "/server-status")`,
					`(http.request.uri.path contains "/server-info")`,
				}, " or ")),
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
