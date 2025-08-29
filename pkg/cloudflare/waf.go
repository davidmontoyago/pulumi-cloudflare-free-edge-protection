package cloudflare

import (
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

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
			// Rule 1: Block common attack patterns and malicious paths
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("block"),
				Expression:  pulumi.String(generatePathBlockingExpression()),
				Description: pulumi.String("Block common attack vectors and malicious path access attempts"),
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

// generatePathBlockingExpression concatenates all malicious path lists and generates
// a single WAF expression to block requests containing any of these paths
func generatePathBlockingExpression() string {
	// Concatenate all path slices from wafpaths.go
	allPaths := make([]string, 0)
	allPaths = append(allPaths, WordPressPaths...)
	allPaths = append(allPaths, DatabaseManagementPaths...)
	allPaths = append(allPaths, ConfigurationFilePaths...)
	allPaths = append(allPaths, VersionControlPaths...)
	allPaths = append(allPaths, AdminPanelPaths...)
	allPaths = append(allPaths, BackupFilePaths...)
	allPaths = append(allPaths, DevelopmentTestingPaths...)
	allPaths = append(allPaths, SystemInformationPaths...)
	allPaths = append(allPaths, APIEndpointPaths...)
	allPaths = append(allPaths, ApplicationSpecificPaths...)
	allPaths = append(allPaths, ServerFilePaths...)
	allPaths = append(allPaths, CMSSpecificPaths...)
	allPaths = append(allPaths, PathTraversalPatterns...)

	// Generate expressions for each path
	expressions := make([]string, len(allPaths))
	for i, path := range allPaths {
		expressions[i] = fmt.Sprintf(`(http.request.uri.path contains "%s")`, path)
	}

	// Join all expressions with "or" and wrap in parentheses
	return fmt.Sprintf("(%s)", strings.Join(expressions, " or "))
}
