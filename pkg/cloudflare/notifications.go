package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// setupDDoSAttackNotifications sets up email notifications for DDoS attacks
//
// Free plan only supports email notifications.
//
// See: https://developers.cloudflare.com/notifications/
func (e *EdgeProtection) setupDDoSAttackNotifications(ctx *pulumi.Context, email string) (*cloudflare.NotificationPolicy, error) {
	policyName := e.newResourceName("ddos-attack", "notification-policy", 64)
	ddosNotificationPolicy, err := cloudflare.NewNotificationPolicy(ctx, policyName, &cloudflare.NotificationPolicyArgs{
		AccountId: pulumi.String(e.CloudflareZone.CloudflareAccountID),
		AlertType: pulumi.String("dos_attack_l7"), // dos*attack*l7 ???
		Mechanisms: &cloudflare.NotificationPolicyMechanismsArgs{
			Emails: cloudflare.NotificationPolicyMechanismsEmailArray{
				&cloudflare.NotificationPolicyMechanismsEmailArgs{
					Id: pulumi.String(email),
				},
			},
		},
		Name:        pulumi.String(policyName),
		Description: pulumi.String("DDoS attack notifications."),
		Filters:     &cloudflare.NotificationPolicyFiltersArgs{},

		Enabled: pulumi.Bool(true),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create DDoS attack notification policy: %w", err)
	}

	return ddosNotificationPolicy, nil
}
