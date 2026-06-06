package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// enableBotFightMode enables Cloudflare Bot Fight Mode for the zone.
// Bot Fight Mode is available on the free plan and runs outside the Ruleset Engine.
func (e *EdgeProtection) enableBotFightMode(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.BotManagement, error) {
	botManagement, err := cloudflare.NewBotManagement(ctx, e.NewResourceName("bot-management", "security", 63), &cloudflare.BotManagementArgs{
		ZoneId:    zone.ID(),
		FightMode: pulumi.Bool(true),
		// Cloudflare requires JavaScript Detections when Bot Fight Mode is enabled.
		EnableJs: pulumi.Bool(true),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create bot management resource: %w", err)
	}

	return botManagement, nil
}
