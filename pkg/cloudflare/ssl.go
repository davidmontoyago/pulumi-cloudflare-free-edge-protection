package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// configureSSLSettings configures SSL/TLS settings for the zone.
func (e *EdgeProtection) configureSSLSettings(ctx *pulumi.Context, zone *cloudflare.Zone) ([]*cloudflare.ZoneSetting, error) {
	// 1. SSL/TLS Encryption Mode
	sslModeSetting, err := cloudflare.NewZoneSetting(ctx, e.newResourceName("ssl-mode", "tls", 64), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("ssl"), // Setting name for encryption mode
		Value:     e.SSLMode,            // "off", "flexible", "full", "strict"
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure SSL mode: %w", err)
	}

	// 2. Minimum TLS Version
	minTLSSetting, err := cloudflare.NewZoneSetting(ctx, e.newResourceName("min-tls", "tls", 64), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("min_tls_version"), // Individual setting
		Value:     e.MinTLSVersion,                  // "1.0", "1.1", "1.2", "1.3"
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure minimum TLS version: %w", err)
	}

	// 3. TLS 1.3 Support
	tls13Setting, err := cloudflare.NewZoneSetting(ctx, e.newResourceName("tls13", "tls", 64), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("tls_1_3"), // Note: tls_1_3, not tls_13
		Value: e.TLS13Enabled.ApplyT(func(enabled bool) string {
			if enabled {
				return "on"
			}
			return "off"
		}).(pulumi.StringOutput),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS 1.3: %w", err)
	}

	// 4. Always Use HTTPS
	alwaysHTTPSSetting, err := cloudflare.NewZoneSetting(ctx, e.newResourceName("always-https", "tls", 64), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("always_use_https"),
		Value: e.AlwaysUseHTTPS.ApplyT(func(enabled bool) string {
			if enabled {
				return "on"
			}
			return "off"
		}).(pulumi.StringOutput),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Always Use HTTPS: %w", err)
	}

	// 5. Automatic HTTPS Rewrites
	httpsRewritesSetting, err := cloudflare.NewZoneSetting(ctx, e.newResourceName("https-rewrites", "tls", 64), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("automatic_https_rewrites"),
		Value: e.AutoHTTPSRewrites.ApplyT(func(enabled bool) string {
			if enabled {
				return "on"
			}
			return "off"
		}).(pulumi.StringOutput),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Automatic HTTPS Rewrites: %w", err)
	}

	// 6. Universal SSL (if you need to manage it explicitly)
	universalSSLSetting, err := cloudflare.NewZoneSetting(ctx, e.newResourceName("universal-ssl", "tls", 64), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("universal_ssl"),
		Value:     pulumi.String("on"), // Usually always "on"
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Universal SSL: %w", err)
	}

	return []*cloudflare.ZoneSetting{
		sslModeSetting,
		minTLSSetting,
		tls13Setting,
		alwaysHTTPSSetting,
		httpsRewritesSetting,
		universalSSLSetting,
	}, nil
}
