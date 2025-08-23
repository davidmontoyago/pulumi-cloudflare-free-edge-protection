package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/pkg/cloudflare/config"
)

const (
	testCloudflareAPIToken  = "test-cloudflare-api-token-123"
	testDomain              = "myapp.path2prod.dev"
	testBackendURL          = "backend-service-abc123-uc.a.run.app"
	testBackendUpstreamURL  = "ghs.googlehosted.com"
	testCloudflareAccountID = "test-cloudflare-account-id-123"
)

func TestLoadConfig_HappyPath(t *testing.T) {
	// Set required environment variables
	envVars := map[string]string{
		"CLOUDFLARE_API_TOKEN":  testCloudflareAPIToken,
		"CLOUDFLARE_ACCOUNT_ID": testCloudflareAccountID,
		"BACKEND_URL":           testDomain,
		"BACKEND_UPSTREAM_URL":  testBackendUpstreamURL,
		"SECURITY_LEVEL":        "high",
		"CACHE_LEVEL":           "basic",
		"BROWSER_CACHE_TTL":     "7200",
		"EDGE_CACHE_TTL_SECONDS": "1296000",
		"RATE_LIMIT_THRESHOLD":  "100",
		"RATE_LIMIT_PERIOD":     "120",
		"RATE_LIMIT_TIMEOUT":    "300",
		"RATE_LIMIT_MODE":       "ban",
		"SSL_MODE":              "strict",
		"MIN_TLS_VERSION":       "1.3",
		"ALWAYS_USE_HTTPS":      "false",
		"TLS_13_ENABLED":        "false",
		"BROWSER_CHECK_ENABLED": "false",
		"AUTO_HTTPS_REWRITES":   "false",
	}

	// Set environment variables
	for key, value := range envVars {
		err := os.Setenv(key, value)
		require.NoError(t, err)
	}

	// Cleanup environment variables after test
	t.Cleanup(func() {
		for key := range envVars {
			_ = os.Unsetenv(key)
		}
	})

	config, err := config.LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify all configuration values
	assert.Equal(t, testCloudflareAPIToken, config.CloudflareAPIToken)
	assert.Equal(t, testDomain, config.BackendURL)
	assert.Equal(t, testBackendUpstreamURL, config.BackendUpstreamURL)
	assert.Equal(t, "high", config.SecurityLevel)
	assert.Equal(t, 7200, config.BrowserCacheTTL)
	assert.Equal(t, 1296000, config.EdgeCacheTTLSeconds)
	assert.Equal(t, 100, config.RateLimitThreshold)
	assert.Equal(t, "ban", config.RateLimitMode)
	assert.Equal(t, "strict", config.TLSEncryptionMode)
	assert.Equal(t, "1.3", config.MinTLSVersion)
	assert.False(t, config.AlwaysUseHTTPS)
	assert.False(t, config.TLS13Enabled)
	assert.False(t, config.BrowserCheckEnabled)
	assert.False(t, config.AutoHTTPSRewrites)
}

func TestLoadConfig_WithDefaults(t *testing.T) {
	// Set only required environment variables
	envVars := map[string]string{
		"CLOUDFLARE_API_TOKEN":  testCloudflareAPIToken,
		"CLOUDFLARE_ACCOUNT_ID": testCloudflareAccountID,
		"BACKEND_URL":           testDomain,
		"BACKEND_UPSTREAM_URL":  testBackendUpstreamURL,
	}

	// Set environment variables
	for key, value := range envVars {
		err := os.Setenv(key, value)
		require.NoError(t, err)
	}

	// Cleanup environment variables after test
	t.Cleanup(func() {
		for key := range envVars {
			_ = os.Unsetenv(key)
		}
	})

	config, err := config.LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify required values
	assert.Equal(t, testCloudflareAPIToken, config.CloudflareAPIToken)
	assert.Equal(t, testDomain, config.BackendURL)
	assert.Equal(t, testBackendUpstreamURL, config.BackendUpstreamURL)

	// Verify default values
	assert.Equal(t, "medium", config.SecurityLevel)
	assert.Equal(t, 14400, config.BrowserCacheTTL)
	assert.Equal(t, 2419200, config.EdgeCacheTTLSeconds)
	assert.Equal(t, 60, config.RateLimitThreshold)
	assert.Equal(t, "strict", config.TLSEncryptionMode)
	assert.Equal(t, "1.2", config.MinTLSVersion)
	assert.True(t, config.AlwaysUseHTTPS)
	assert.True(t, config.TLS13Enabled)
	assert.True(t, config.BrowserCheckEnabled)
	assert.True(t, config.AutoHTTPSRewrites)
}

func TestLoadConfig_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		expectedErr string
	}{
		{
			name: "missing cloudflare api token",
			envVars: map[string]string{
				"CLOUDFLARE_ACCOUNT_ID": testCloudflareAccountID,
				"BACKEND_URL":           testDomain,
				"BACKEND_UPSTREAM_URL":  testBackendUpstreamURL,
			},
			expectedErr: "CLOUDFLARE_API_TOKEN",
		},
		{
			name: "missing backend url",
			envVars: map[string]string{
				"CLOUDFLARE_API_TOKEN":  testCloudflareAPIToken,
				"CLOUDFLARE_ACCOUNT_ID": testCloudflareAccountID,
				"BACKEND_UPSTREAM_URL":  testBackendUpstreamURL,
			},
			expectedErr: "BACKEND_URL",
		},
		{
			name: "missing backend upstream url",
			envVars: map[string]string{
				"CLOUDFLARE_API_TOKEN":  testCloudflareAPIToken,
				"CLOUDFLARE_ACCOUNT_ID": testCloudflareAccountID,
				"BACKEND_URL":           testDomain,
			},
			expectedErr: "BACKEND_UPSTREAM_URL",
		},
		{
			name: "missing cloudflare account id",
			envVars: map[string]string{
				"CLOUDFLARE_API_TOKEN": testCloudflareAPIToken,
				"BACKEND_URL":          testDomain,
				"BACKEND_UPSTREAM_URL": testBackendUpstreamURL,
			},
			expectedErr: "CLOUDFLARE_ACCOUNT_ID",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range testCase.envVars {
				err := os.Setenv(key, value)
				require.NoError(t, err)
			}

			// Cleanup environment variables after test
			t.Cleanup(func() {
				for key := range testCase.envVars {
					_ = os.Unsetenv(key)
				}
			})

			config, err := config.LoadConfig()
			assert.Error(t, err)
			assert.Nil(t, config)
			assert.Contains(t, err.Error(), testCase.expectedErr)
		})
	}
}

func TestToEdgeProtectionArgs(t *testing.T) {
	// Set required environment variables
	envVars := map[string]string{
		"CLOUDFLARE_API_TOKEN":  testCloudflareAPIToken,
		"CLOUDFLARE_ACCOUNT_ID": testCloudflareAccountID,
		"BACKEND_URL":           testDomain,
		"BACKEND_UPSTREAM_URL":  testBackendUpstreamURL,
	}

	// Set environment variables
	for key, value := range envVars {
		err := os.Setenv(key, value)
		require.NoError(t, err)
	}

	// Cleanup environment variables after test
	t.Cleanup(func() {
		for key := range envVars {
			_ = os.Unsetenv(key)
		}
	})

	config, err := config.LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, config)

	args := config.ToEdgeProtectionArgs()
	require.NotNil(t, args)

	// Verify that all args are set correctly
	assert.Equal(t, testDomain, args.Upstreams[0].DomainURL)
	assert.Equal(t, testBackendUpstreamURL, args.Upstreams[0].CanonicalNameURL)
	assert.False(t, args.Upstreams[0].DisableProtection) // Should default to false
	assert.Equal(t, testCloudflareAccountID, args.CloudflareZone.CloudflareAccountID)
	assert.True(t, args.CloudflareZone.Protected) // Should default to true
	assert.NotNil(t, args.SecurityLevel)
	assert.NotNil(t, args.BrowserCacheTTL)
	assert.NotNil(t, args.EdgeCacheTTLSeconds)
	assert.NotNil(t, args.RateLimitThreshold)
	assert.NotNil(t, args.RateLimitMode)
	assert.NotNil(t, args.TLSEncryptionMode)
	assert.NotNil(t, args.MinTLSVersion)
	assert.NotNil(t, args.AlwaysUseHTTPS)
	assert.NotNil(t, args.TLS13Enabled)
	assert.NotNil(t, args.BrowserCheckEnabled)
	assert.NotNil(t, args.AutoHTTPSRewrites)
}
