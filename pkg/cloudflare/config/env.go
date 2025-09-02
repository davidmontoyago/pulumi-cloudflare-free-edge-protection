// Package config provides an environment config helper
package config

import (
	"fmt"
	"log"

	"github.com/kelseyhightower/envconfig"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/pkg/cloudflare"
)

// Config is a helper for loading and launching via environment variables
// Defaults to a single backend for the upstream.
type Config struct {
	CloudflareAPIToken           string `envconfig:"CLOUDFLARE_API_TOKEN" required:"true"`
	CloudflareAccountID          string `envconfig:"CLOUDFLARE_ACCOUNT_ID" required:"true"`
	BackendURL                   string `envconfig:"BACKEND_URL" required:"true"`
	BackendUpstreamURL           string `envconfig:"BACKEND_UPSTREAM_URL" required:"true"`
	SecurityLevel                string `envconfig:"SECURITY_LEVEL" default:"medium"`
	BrowserCacheTTL              int    `envconfig:"BROWSER_CACHE_TTL" default:"14400"`
	EdgeCacheTTLSeconds          int    `envconfig:"EDGE_CACHE_TTL_SECONDS" default:"2419200"`
	RateLimitThreshold           int    `envconfig:"RATE_LIMIT_THRESHOLD" default:"60"`
	RateLimitMode                string `envconfig:"RATE_LIMIT_MODE" default:"block"`
	TLSEncryptionMode            string `envconfig:"TLS_ENCRYPTION_MODE" default:"strict"`
	MinTLSVersion                string `envconfig:"MIN_TLS_VERSION" default:"1.2"`
	AlwaysUseHTTPS               bool   `envconfig:"ALWAYS_USE_HTTPS" default:"true"`
	TLS13Enabled                 bool   `envconfig:"TLS_13_ENABLED" default:"true"`
	BrowserCheckEnabled          bool   `envconfig:"BROWSER_CHECK_ENABLED" default:"true"`
	DDoSAttackNotificationsEmail string `envconfig:"DDOS_ATTACK_NOTIFICATIONS_EMAIL" default:""`
}

// LoadConfig loads configuration from environment variables
// All required environment variables must be set or will cause an error
func LoadConfig() (*Config, error) {
	var config Config

	err := envconfig.Process("", &config)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration from environment variables: %w", err)
	}

	log.Printf("Configuration loaded successfully:")
	log.Printf("  Backend URL: %s", config.BackendURL)
	log.Printf("  Backend Upstream URL: %s", config.BackendUpstreamURL)
	log.Printf("  Security Level: %s", config.SecurityLevel)
	log.Printf("  Rate Limit Mode: %s", config.RateLimitMode)
	log.Printf("  Browser Cache TTL: %d seconds", config.BrowserCacheTTL)
	log.Printf("  Edge Cache TTL: %d seconds", config.EdgeCacheTTLSeconds)
	log.Printf("  Rate Limit Threshold: %d requests", config.RateLimitThreshold)
	log.Printf("  TLS Encryption Mode: %s", config.TLSEncryptionMode)
	log.Printf("  Min TLS Version: %s", config.MinTLSVersion)
	log.Printf("  Always Use HTTPS: %t", config.AlwaysUseHTTPS)
	log.Printf("  TLS 1.3 Enabled: %t", config.TLS13Enabled)
	log.Printf("  Browser Check Enabled: %t", config.BrowserCheckEnabled)

	return &config, nil
}

// ToEdgeProtectionArgs converts the config to EdgeProtectionArgs for use with the Pulumi component
func (c *Config) ToEdgeProtectionArgs() *cloudflare.EdgeProtectionArgs {
	args := &cloudflare.EdgeProtectionArgs{
		Upstreams: []cloudflare.Upstream{
			{
				DomainURL:        c.BackendURL,
				CanonicalNameURL: c.BackendUpstreamURL,
			},
		},
		CloudflareZone: cloudflare.Zone{
			CloudflareAccountID: c.CloudflareAccountID,
			Protected:           true,
		},
		SecurityLevel:                pulumi.String(c.SecurityLevel),
		BrowserCacheTTL:              pulumi.Int(c.BrowserCacheTTL),
		EdgeCacheTTLSeconds:          pulumi.Int(c.EdgeCacheTTLSeconds),
		RateLimitThreshold:           pulumi.Int(c.RateLimitThreshold),
		RateLimitMode:                pulumi.String(c.RateLimitMode),
		TLSEncryptionMode:            pulumi.String(c.TLSEncryptionMode),
		MinTLSVersion:                pulumi.String(c.MinTLSVersion),
		AlwaysUseHTTPS:               pulumi.Bool(c.AlwaysUseHTTPS),
		TLS13Enabled:                 pulumi.Bool(c.TLS13Enabled),
		BrowserCheckEnabled:          pulumi.Bool(c.BrowserCheckEnabled),
		DDoSAttackNotificationsEmail: c.DDoSAttackNotificationsEmail,
	}

	return args
}
