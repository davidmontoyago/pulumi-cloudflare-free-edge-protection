// Package config provides an environment config helper
package config

import (
	"fmt"
	"log"

	"github.com/kelseyhightower/envconfig"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/pkg/cloudflare"
)

// Config allows setting the cloudflare edge protection configuration via environment variables
type Config struct {
	CloudflareAPIToken  string `envconfig:"CLOUDFLARE_API_TOKEN" required:"true"`
	CloudflareAccountID string `envconfig:"CLOUDFLARE_ACCOUNT_ID" required:"true"`
	Domain              string `envconfig:"DOMAIN" required:"true"`
	BackendURL          string `envconfig:"BACKEND_URL" required:"true"`
	FrontendURL         string `envconfig:"FRONTEND_URL" required:"true"`
	SecurityLevel       string `envconfig:"SECURITY_LEVEL" default:"medium"`
	CacheLevel          string `envconfig:"CACHE_LEVEL" default:"aggressive"`
	BrowserCacheTTL     int    `envconfig:"BROWSER_CACHE_TTL" default:"14400"`
	EdgeCacheTTLSeconds int    `envconfig:"EDGE_CACHE_TTL_SECONDS" default:"2419200"`
	RateLimitThreshold  int    `envconfig:"RATE_LIMIT_THRESHOLD" default:"60"`
	RateLimitPeriod     int    `envconfig:"RATE_LIMIT_PERIOD" default:"60"`
	RateLimitTimeout    int    `envconfig:"RATE_LIMIT_TIMEOUT" default:"600"`
	RateLimitMode       string `envconfig:"RATE_LIMIT_MODE" default:"simulate"`
	SSLMode             string `envconfig:"SSL_MODE" default:"full"`
	MinTLSVersion       string `envconfig:"MIN_TLS_VERSION" default:"1.2"`
	AlwaysUseHTTPS      bool   `envconfig:"ALWAYS_USE_HTTPS" default:"true"`
	TLS13Enabled        bool   `envconfig:"TLS_13_ENABLED" default:"true"`
	BrowserCheckEnabled bool   `envconfig:"BROWSER_CHECK_ENABLED" default:"true"`
	AutoHTTPSRewrites   bool   `envconfig:"AUTO_HTTPS_REWRITES" default:"true"`
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
	log.Printf("  Domain: %s", config.Domain)
	log.Printf("  Backend URL: %s", config.BackendURL)
	log.Printf("  Frontend URL: %s", config.FrontendURL)
	log.Printf("  Security Level: %s", config.SecurityLevel)
	log.Printf("  Cache Level: %s", config.CacheLevel)
	log.Printf("  Browser Cache TTL: %d seconds", config.BrowserCacheTTL)
	log.Printf("  Edge Cache TTL: %d seconds", config.EdgeCacheTTLSeconds)
	log.Printf("  Rate Limit Threshold: %d requests", config.RateLimitThreshold)
	log.Printf("  Rate Limit Period: %d seconds", config.RateLimitPeriod)
	log.Printf("  Rate Limit Timeout: %d seconds", config.RateLimitTimeout)
	log.Printf("  Rate Limit Mode: %s", config.RateLimitMode)
	log.Printf("  SSL Mode: %s", config.SSLMode)
	log.Printf("  Min TLS Version: %s", config.MinTLSVersion)
	log.Printf("  Always Use HTTPS: %t", config.AlwaysUseHTTPS)
	log.Printf("  TLS 1.3 Enabled: %t", config.TLS13Enabled)
	log.Printf("  Browser Check Enabled: %t", config.BrowserCheckEnabled)
	log.Printf("  Auto HTTPS Rewrites: %t", config.AutoHTTPSRewrites)

	return &config, nil
}

// ToEdgeProtectionArgs converts the config to EdgeProtectionArgs for use with the Pulumi component
func (c *Config) ToEdgeProtectionArgs() *cloudflare.EdgeProtectionArgs {
	args := &cloudflare.EdgeProtectionArgs{
		Domain:              c.Domain,
		BackendURL:          pulumi.String(c.BackendURL),
		FrontendURL:         pulumi.String(c.FrontendURL),
		CloudflareAccountID: c.CloudflareAccountID,
		SecurityLevel:       pulumi.String(c.SecurityLevel),
		CacheLevel:          pulumi.String(c.CacheLevel),
		BrowserCacheTTL:     pulumi.Int(c.BrowserCacheTTL),
		EdgeCacheTTLSeconds: pulumi.Int(c.EdgeCacheTTLSeconds),
		RateLimitThreshold:  pulumi.Int(c.RateLimitThreshold),
		RateLimitPeriod:     pulumi.Int(c.RateLimitPeriod),
		RateLimitTimeout:    pulumi.Int(c.RateLimitTimeout),
		RateLimitMode:       pulumi.String(c.RateLimitMode),
		SSLMode:             pulumi.String(c.SSLMode),
		MinTLSVersion:       pulumi.String(c.MinTLSVersion),
		AlwaysUseHTTPS:      pulumi.Bool(c.AlwaysUseHTTPS),
		TLS13Enabled:        pulumi.Bool(c.TLS13Enabled),
		BrowserCheckEnabled: pulumi.Bool(c.BrowserCheckEnabled),
		AutoHTTPSRewrites:   pulumi.Bool(c.AutoHTTPSRewrites),
	}

	return args
}
