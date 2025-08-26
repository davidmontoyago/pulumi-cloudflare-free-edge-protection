package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
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
	sslModeSetting, err := cloudflare.NewZoneSetting(ctx, e.newResourceName("ssl-mode", "tls", 64), &cloudflare.ZoneSettingArgs{
		ZoneId:    zone.ID(),
		SettingId: pulumi.String("ssl"), // Setting name for encryption mode
		Value:     e.TLSEncryptionMode,  // "off", "flexible", "full", "strict"
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
	// An alterative approach is to use a Ruleset on the phase "http_request_dynamic_redirect"
	// to use the Automatic Https Rewrites feature.
	// See: https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/
	// Favoring always_use_https zone setting to handle redirect before rules are evaluated.
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

	// 6. Automatic universal certificates for all domains.
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
	}, nil
}
