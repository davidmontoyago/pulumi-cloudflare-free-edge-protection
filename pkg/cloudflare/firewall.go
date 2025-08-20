package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createFirewallRules creates security filters and firewall rules for protection.
func (e *EdgeProtection) createFirewallRules(ctx *pulumi.Context, zone *cloudflare.Zone) error {
	// Create security filter to block common attack patterns
	securityFilter, err := cloudflare.NewFilter(ctx, e.newResourceName("filter", "firewall", 64), &cloudflare.FilterArgs{
		ZoneId: zone.ID(),
		// TODO add more filters for JS/CSS/HTML/etc.
		Expression: pulumi.String(`
			(http.request.uri.path contains "/wp-admin") or
			(http.request.uri.path contains "/wp-login.php") or
			(http.request.uri.path contains "/xmlrpc.php") or
			(http.request.uri.path contains "/.env") or
			(http.request.uri.path contains "/phpmyadmin") or
			(http.user_agent contains "sqlmap") or
			(http.user_agent contains "nmap") or
			(http.user_agent eq "") or
			(http.request.method eq "TRACE")
		`),
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create security filter: %w", err)
	}
	e.securityFilter = securityFilter

	// Apply the security filter as a firewall rule, aka WAF Custom Rules, aka WAF Rules.
	//
	// We get 5 of these under the free tier.
	//
	// See:
	// https://developers.cloudflare.com/waf/custom-rules/
	securityFirewallRule, err := cloudflare.NewFirewallRule(ctx, e.newResourceName("rule", "firewall", 64), &cloudflare.FirewallRuleArgs{
		ZoneId: zone.ID(),
		Filter: &cloudflare.FirewallRuleFilterArgs{
			Description: pulumi.String("Block common attacks and malicious bots"),
			Ref: securityFilter.ID().ApplyT(func(id pulumi.ID) string {
				return string(id)
			}).(pulumi.StringOutput),
		},
		Action: &cloudflare.FirewallRuleActionArgs{
			// One of "simulate" "ban" "challenge" "js_challenge" "managed_challenge"
			// Choosing "ban" to return a 403 page
			Mode: pulumi.String("ban"),
			// Configure Response for a custom error page
		},
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create security firewall rule: %w", err)
	}
	e.securityFirewallRule = securityFirewallRule

	return nil
}
