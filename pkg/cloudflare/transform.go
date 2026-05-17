package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createXRealClientIPHeaderTransformRules creates the request header transformation rule
// that sets X-Real-Client-IP and geolocation headers from Cloudflare trusted fields.
//
// Uses 1 rule of the 10 Transform Rules available under free tier.
// See: https://developers.cloudflare.com/rules/transform/
func (e *EdgeProtection) createXRealClientIPHeaderTransformRules(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.Ruleset, error) {
	transformRuleset, err := cloudflare.NewRuleset(ctx, e.NewResourceName("request-header-transform-ruleset", "optimization", 63), &cloudflare.RulesetArgs{
		ZoneId:      zone.ID(),
		Name:        pulumi.String("Request Header Transform Rules"),
		Kind:        pulumi.String("zone"),
		Phase:       pulumi.String("http_request_late_transform"),
		Description: pulumi.String("Set trusted client IP header for origin services"),
		Rules: cloudflare.RulesetRuleArray{
			&cloudflare.RulesetRuleArgs{
				Action:      pulumi.String("rewrite"),
				Expression:  pulumi.String("true"),
				Description: pulumi.String("Set trusted client IP and geolocation headers for origin services"),
				ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
					Headers: cloudflare.RulesetRuleActionParametersHeadersMap{
						// ===== Client IP and geolocation headers =====

						// Single client IP address (IPv4 or IPv6), sourced from Cloudflare trusted ip.src.
						"x-real-client-ip": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation: pulumi.String("set"),
							// Prefer Cloudflare's trusted ip.src over parsing X-Forwarded-For,
							// which can include intermediary/provided values and is easier to spoof.
							Expression: pulumi.String("to_string(ip.src)"),
						},
						// ISO 3166-1 Alpha-2 country code (for example, "US").
						"x-real-client-country": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.country"),
						},
						// Two-letter continent code (for example, "NA", "EU").
						"x-real-client-continent": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.continent"),
						},
						// City name derived from Cloudflare geolocation (for example, "Chicago").
						"x-real-client-city": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.city"),
						},
						// Region or state name (for example, "Illinois").
						"x-real-client-region": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.region"),
						},
						// Region code (for example, "IL").
						"x-real-client-region-code": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.region_code"),
						},
						// Postal or ZIP code (for example, "60601").
						"x-real-client-postal-code": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.postal_code"),
						},
						// DMA/metro code for US markets (for example, "602").
						"x-real-client-metro-code": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.metro_code"),
						},
						// Latitude as a decimal string (for example, "37.78044").
						"x-real-client-lat": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.lat"),
						},
						// Longitude as a decimal string (for example, "-122.42413").
						"x-real-client-lon": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.lon"),
						},
						// IANA timezone name (for example, "America/Chicago").
						"x-real-client-timezone": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("ip.src.timezone.name"),
						},

						// ===== TLS and connection headers =====

						// TLS protocol version used by the client (for example, "TLSv1.3").
						"x-real-client-tls-version": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("cf.tls_version"),
						},
						// TLS cipher suite selected for the client connection.
						"x-real-client-tls-cipher": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("cf.tls_cipher"),
						},
						// TLS ClientHello message length as a decimal string.
						"x-real-client-tls-client-hello-length": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("to_string(cf.tls_client_hello_length)"),
						},
						// Base64-encoded 32-byte random value from the TLS handshake.
						"x-real-client-tls-client-random": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("cf.tls_client_random"),
						},
						// SHA-1 fingerprint of TLS client extensions (big-endian).
						"x-real-client-tls-client-extensions-sha1": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("cf.tls_client_extensions_sha1"),
						},
						// SHA-1 fingerprint of TLS client extensions (little-endian).
						"x-real-client-tls-client-extensions-sha1-le": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("cf.tls_client_extensions_sha1_le"),
						},
						// SHA-1 fingerprint of client cipher list in received order.
						"x-real-client-tls-client-ciphers-sha1": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("cf.tls_client_ciphers_sha1"),
						},

						// ===== QUIC/TCP protocol and RTT headers =====

						// TCP round-trip time in milliseconds as a decimal string.
						"x-real-client-rtt": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("to_string(cf.timings.client_tcp_rtt_msec)"),
						},
						// QUIC round-trip time in milliseconds as a decimal string (HTTP/3 only).
						"x-real-client-quic-rtt": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("to_string(cf.timings.client_quic_rtt_msec)"),
						},
						// Client transport protocol where true indicates TCP and false indicates QUIC.
						"x-real-client-tcp": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("to_string(cf.edge.client_tcp)"),
						},
						// Estimated layer-4 delivery rate in bytes per second as a decimal string.
						"x-real-client-delivery-rate": &cloudflare.RulesetRuleActionParametersHeadersArgs{
							Operation:  pulumi.String("set"),
							Expression: pulumi.String("to_string(cf.edge.l4.delivery_rate)"),
						},
					},
				},
				Enabled: pulumi.Bool(true),
			},
		},
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create request header transform ruleset: %w", err)
	}

	return transformRuleset, nil
}
