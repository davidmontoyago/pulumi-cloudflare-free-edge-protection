package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createSecurityRules creates security filters and firewall rules for protection.
func (e *EdgeProtection) createSecurityRules(ctx *pulumi.Context, zone *cloudflare.Zone) error {
	// Create security filter to block common attack patterns
	securityFilter, err := cloudflare.NewFilter(ctx, e.newResourceName("security", "filter", 64), &cloudflare.FilterArgs{
		ZoneId: zone.ID(),
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

	// Apply the security filter as a firewall rule
	securityFirewallRule, err := cloudflare.NewFirewallRule(ctx, e.newResourceName("security", "rule", 64), &cloudflare.FirewallRuleArgs{
		ZoneId: zone.ID(),
		Filter: &cloudflare.FirewallRuleFilterArgs{
			Description: pulumi.String("Block common attacks and malicious bots"),
			Id: securityFilter.ID().ApplyT(func(id pulumi.ID) string {
				return string(id)
			}).(pulumi.StringOutput),
		},
		Action: &cloudflare.FirewallRuleActionArgs{
			Mode: pulumi.String("block"),
			// Configure Response for a custom error page
		},
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create security firewall rule: %w", err)
	}
	e.securityFirewallRule = securityFirewallRule

	return nil
}
