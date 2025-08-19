package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// configureSSLSettings configures SSL/TLS settings for the zone.
func (e *EdgeProtection) configureSSLSettings(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.ZoneSetting, error) {
	// Configure zone wide TLS settings
	zoneSetting, err := cloudflare.NewZoneSetting(ctx, e.newResourceName("ssl", "settings", 64), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("ssl"),
		Value: pulumi.Map{
			"ssl":             e.SSLMode,
			"min_tls_version": e.MinTLSVersion,
			"tls_13": e.TLS13Enabled.ApplyT(func(enabled bool) string {
				if enabled {
					return "on"
				}
				return "off"
			}).(pulumi.StringOutput),
			// TODO verify
			"universal_ssl": pulumi.String("on"),
			//See: https://www.reddit.com/r/googlecloud/comments/kvj2ss/comment/gy7k2my/
			"always_use_https": e.AlwaysUseHTTPS.ApplyT(func(enabled bool) string {
				return "off"
			}).(pulumi.StringOutput),
			"automatic_https_rewrites": e.AutoHTTPSRewrites.ApplyT(func(enabled bool) string {
				return "off"
			}).(pulumi.StringOutput),
		},
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure SSL/TLS zone settings: %w", err)
	}
	return zoneSetting, nil
}
