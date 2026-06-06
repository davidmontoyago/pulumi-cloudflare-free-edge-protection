package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	// hstsMaxAgeSeconds configures HSTS for one year.
	hstsMaxAgeSeconds = 31536000
	settingOn         = "on"
	settingOff        = "off"
)

// configureTLSSettings configures SSL/TLS settings for the zone.
func (e *EdgeProtection) configureTLSSettings(ctx *pulumi.Context, zone *cloudflare.Zone) ([]*cloudflare.ZoneSetting, error) {
	// 1. SSL/TLS Encryption Mode
	// There are edge certificates and origin certificates.
	// Edge certs are between the browser and Cloudflare proxies. These are automatically provisioned.
	// Origin certs are between Cloudflare and the app.
	// See:
	// - https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/
	// - https://developers.cloudflare.com/ssl/concepts/#ssltls-certificate
	sslModeSetting, err := cloudflare.NewZoneSetting(ctx, e.NewResourceName("ssl-mode", "tls", 63), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("ssl"), // Setting name for encryption mode
		Value:     e.TLSEncryptionMode,  // "off", "flexible", "full", "strict"
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure SSL mode: %w", err)
	}

	// 2. Minimum TLS Version
	minTLSSetting, err := cloudflare.NewZoneSetting(ctx, e.NewResourceName("min-tls", "tls", 63), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("min_tls_version"), // Individual setting
		Value:     e.MinTLSVersion,                  // "1.0", "1.1", "1.2", "1.3"
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure minimum TLS version: %w", err)
	}

	// 3. TLS 1.3 Support
	tls13Setting, err := cloudflare.NewZoneSetting(ctx, e.NewResourceName("tls13", "tls", 63), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("tls_1_3"), // Note: tls_1_3, not tls_13
		Value: e.TLS13Enabled.ApplyT(func(enabled bool) string {
			if enabled {
				return settingOn
			}

			return settingOff
		}).(pulumi.StringOutput),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS 1.3: %w", err)
	}

	// 4. Always Use HTTPS
	// Redirects HTTP requests to HTTPS.
	// Note: this is different from automatic_https_rewrites, which rewrites mixed-content
	// asset URLs in page HTML from http:// to https:// when supported.
	// See:
	// - https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/
	// - https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/
	alwaysHTTPSSetting, err := cloudflare.NewZoneSetting(ctx, e.NewResourceName("always-https", "tls", 63), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("always_use_https"),
		Value: e.AlwaysUseHTTPS.ApplyT(func(enabled bool) string {
			if enabled {
				return settingOn
			}

			return settingOff
		}).(pulumi.StringOutput),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Always Use HTTPS: %w", err)
	}

	// 5. Automatic HTTPS Rewrites
	autoHTTPSRewritesSetting, err := cloudflare.NewZoneSetting(ctx, e.NewResourceName("auto-https-rewrites", "tls", 63), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("automatic_https_rewrites"),
		Value: e.AutomaticHTTPSRewritesEnabled.ApplyT(func(enabled bool) string {
			if enabled {
				return settingOn
			}

			return settingOff
		}).(pulumi.StringOutput),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Automatic HTTPS Rewrites: %w", err)
	}

	// 6. Hotlink Protection (off by default)
	hotlinkProtectionSetting, err := cloudflare.NewZoneSetting(ctx, e.NewResourceName("hotlink-protection", "tls", 63), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("hotlink_protection"),
		Value: e.HotlinkProtectionEnabled.ApplyT(func(enabled bool) string {
			if enabled {
				return settingOn
			}

			return settingOff
		}).(pulumi.StringOutput),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Hotlink Protection: %w", err)
	}

	// 7. Strict Transport Security (HSTS)
	// Cloudflare API "security_header" requires nested strict transport security fields.
	// See:
	// - https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/edit/
	// - https://www.pulumi.com/registry/packages/cloudflare/api-docs/zonesetting/
	hstsSetting, err := cloudflare.NewZoneSetting(ctx, e.NewResourceName("hsts", "tls", 63), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("security_header"),
		Value: e.HSTSEnabled.ApplyT(func(enabled bool) interface{} {
			return map[string]interface{}{
				"strictTransportSecurity": map[string]interface{}{
					"enabled":           enabled,
					"includeSubdomains": true,
					"maxAge":            hstsMaxAgeSeconds,
					"nosniff":           true,
					"preload":           false,
				},
			}
		}).(pulumi.AnyOutput),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure HSTS security header: %w", err)
	}

	// 8. Automatic universal certificates for all domains.
	// Automatic, no configuration needed. Ensure domain is added to Cloudflare
	// and it will automatically get Universal certs.
	//
	// Automatically provisioned certs covers:
	// - Zone apex (e.g., example.com)
	// - All first-level subdomains (e.g., subdomain.example.com)
	//
	// Cloudflare chooses the certificate authority (CA) and it can change anytime.
	// See:
	// - https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/enable-universal-ssl/

	return []*cloudflare.ZoneSetting{
		sslModeSetting,
		minTLSSetting,
		tls13Setting,
		alwaysHTTPSSetting,
		autoHTTPSRewritesSetting,
		hotlinkProtectionSetting,
		hstsSetting,
	}, nil
}
