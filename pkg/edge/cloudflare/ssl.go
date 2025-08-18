package cloudflare

import (
	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// configureSSLSettings configures SSL/TLS settings for the zone.
func (e *EdgeProtection) configureSSLSettings(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.ZoneSetting, error) {
	// Configure zone wide TLS settings
	return cloudflare.NewZoneSetting(ctx, e.newResourceName("ssl", "settings", 64), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("ssl"),
		Value: pulumi.Map{
			"ssl": e.SSLMode,
			"always_use_https": e.AlwaysUseHTTPS.ApplyT(func(enabled bool) string {
				if enabled {
					return "on"
				}
				return "off"
			}).(pulumi.StringOutput),
			"min_tls_version": e.MinTLSVersion,
			"tls_13": e.TLS13Enabled.ApplyT(func(enabled bool) string {
				if enabled {
					return "on"
				}
				return "off"
			}).(pulumi.StringOutput),
			"automatic_https_rewrites": e.AutoHTTPSRewrites.ApplyT(func(enabled bool) string {
				if enabled {
					return "on"
				}
				return "off"
			}).(pulumi.StringOutput),
			"universal_ssl": pulumi.String("on"),
		},
	}, pulumi.Parent(e))
}
