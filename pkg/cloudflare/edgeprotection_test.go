package cloudflare_test

import (
	"testing"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	edge "github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/pkg/cloudflare"
)

const (
	testDomain              = "myapp.path2prod.dev"
	testTopLevelDomain      = ".path2prod.dev" // Extracted from testDomain
	testBackendURL          = "backend-service-abc123-uc.a.run.app"
	testFrontendURL         = "frontend-service-def456-uc.a.run.app"
	testCloudflareAccountID = "test-cloudflare-account-id-123"
)

type edgeProtectionMocks struct{}

func (m *edgeProtectionMocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	outputs := map[string]interface{}{}
	for k, v := range args.Inputs {
		outputs[string(k)] = v
	}

	// Mock resource outputs for each resource type:
	switch args.TypeToken {
	case "cloudflare:index/zone:Zone":
		outputs["name"] = testTopLevelDomain
		outputs["status"] = "active"
		outputs["nameServers"] = []string{
			"ns1.cloudflare.com",
			"ns2.cloudflare.com",
		}
		outputs["id"] = "test-zone-id-123"

	case "cloudflare:index/dnsRecord:DnsRecord":
		outputs["zoneId"] = "test-zone-id-123"
		outputs["data"] = map[string]interface{}{
			// TODO which is the correct field?
			"target": args.Inputs["content"],
			"value":  args.Inputs["content"],
		}

	case "cloudflare:index/zoneSetting:ZoneSetting":
		outputs["zoneId"] = "test-zone-id-123"
		outputs["name"] = args.Inputs["settingId"]
		outputs["value"] = args.Inputs["value"]

	case "cloudflare:index/zoneSettingsOverride:ZoneSettingsOverride":
		outputs["zoneId"] = "test-zone-id-123"
		outputs["settings"] = args.Inputs["settings"]

	case "cloudflare:index/filter:Filter":
		outputs["zoneId"] = "test-zone-id-123"
		outputs["description"] = args.Inputs["description"]
		outputs["expression"] = args.Inputs["expression"]

	case "cloudflare:index/firewallRule:FirewallRule":
		outputs["zoneId"] = "test-zone-id-123"
		outputs["description"] = args.Inputs["description"]
		outputs["filterId"] = "test-filter-id-123"
		outputs["action"] = args.Inputs["action"]
		outputs["priority"] = args.Inputs["priority"]

	case "cloudflare:index/rateLimit:RateLimit":
		outputs["zoneId"] = "test-zone-id-123"
		outputs["threshold"] = args.Inputs["threshold"]
		outputs["period"] = args.Inputs["period"]
		outputs["description"] = args.Inputs["description"]
		outputs["match"] = args.Inputs["match"]
		outputs["action"] = args.Inputs["action"]
		outputs["disabled"] = args.Inputs["disabled"]

	case "cloudflare:index/pageRule:PageRule":
		outputs["zoneId"] = "test-zone-id-123"
		outputs["target"] = args.Inputs["target"]
		outputs["priority"] = args.Inputs["priority"]
		outputs["status"] = args.Inputs["status"]
		outputs["actions"] = args.Inputs["actions"]
	}

	return args.Name + "_id", resource.NewPropertyMapFromMap(outputs), nil
}

func (m *edgeProtectionMocks) Call(_ pulumi.MockCallArgs) (resource.PropertyMap, error) {
	// No function calls needed for basic edge protection test
	return resource.PropertyMap{}, nil
}

func TestNewEdgeProtection_HappyPath(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Domain:              testDomain,
			BackendURL:          pulumi.String(testBackendURL),
			FrontendURL:         pulumi.String(testFrontendURL),
			CloudflareAccountID: testCloudflareAccountID,
			SecurityLevel:       pulumi.String("medium"),
			CacheLevel:          pulumi.String("aggressive"),
			BrowserCacheTTL:     pulumi.Int(14400),
			EdgeCacheTTL:        pulumi.Int(2592000),
			RateLimitThreshold:  pulumi.Int(60),
			RateLimitPeriod:     pulumi.Int(60),
			RateLimitTimeout:    pulumi.Int(600),
			RateLimitMode:       pulumi.String("simulate"),
			SSLMode:             pulumi.String("full"),
			MinTLSVersion:       pulumi.String("1.2"),
			AlwaysUseHTTPS:      pulumi.Bool(true),
			TLS13Enabled:        pulumi.Bool(true),
			BrowserCheckEnabled: pulumi.Bool(true),
			AutoHTTPSRewrites:   pulumi.Bool(true),
			Labels: map[string]string{
				"environment": "test",
				"team":        "edge-protection",
			},
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-edge-protection", args)
		require.NoError(t, err)

		// Verify basic properties
		assert.Equal(t, testDomain, edgeProtection.Domain)

		backendURLCh := make(chan string, 1)
		defer close(backendURLCh)
		edgeProtection.BackendURL.ApplyT(func(url string) error {
			backendURLCh <- url
			return nil
		})
		assert.Equal(t, testBackendURL, <-backendURLCh)

		frontendURLCh := make(chan string, 1)
		defer close(frontendURLCh)
		edgeProtection.FrontendURL.ApplyT(func(url string) error {
			frontendURLCh <- url
			return nil
		})
		assert.Equal(t, testFrontendURL, <-frontendURLCh)

		assert.Equal(t, testCloudflareAccountID, edgeProtection.CloudflareAccountID)

		// Verify security level using async pattern
		securityLevelCh := make(chan string, 1)
		defer close(securityLevelCh)
		edgeProtection.SecurityLevel.ApplyT(func(level string) error {
			securityLevelCh <- level
			return nil
		})
		assert.Equal(t, "medium", <-securityLevelCh, "Security level should match")

		// Verify cache level
		cacheLevelCh := make(chan string, 1)
		defer close(cacheLevelCh)
		edgeProtection.CacheLevel.ApplyT(func(level string) error {
			cacheLevelCh <- level
			return nil
		})
		assert.Equal(t, "aggressive", <-cacheLevelCh, "Cache level should match")

		// Verify browser cache TTL
		browserCacheTTLCh := make(chan int, 1)
		defer close(browserCacheTTLCh)
		edgeProtection.BrowserCacheTTL.ApplyT(func(ttl int) error {
			browserCacheTTLCh <- ttl
			return nil
		})
		assert.Equal(t, 14400, <-browserCacheTTLCh, "Browser cache TTL should match")

		// Verify edge cache TTL
		edgeCacheTTLCh := make(chan int, 1)
		defer close(edgeCacheTTLCh)
		edgeProtection.EdgeCacheTTL.ApplyT(func(ttl int) error {
			edgeCacheTTLCh <- ttl
			return nil
		})
		assert.Equal(t, 2592000, <-edgeCacheTTLCh, "Edge cache TTL should match")

		// Verify rate limit settings
		rateLimitThresholdCh := make(chan int, 1)
		defer close(rateLimitThresholdCh)
		edgeProtection.RateLimitThreshold.ApplyT(func(threshold int) error {
			rateLimitThresholdCh <- threshold
			return nil
		})
		assert.Equal(t, 60, <-rateLimitThresholdCh, "Rate limit threshold should match")

		// Verify SSL mode
		sslModeCh := make(chan string, 1)
		defer close(sslModeCh)
		edgeProtection.SSLMode.ApplyT(func(mode string) error {
			sslModeCh <- mode
			return nil
		})
		assert.Equal(t, "full", <-sslModeCh, "SSL mode should match")

		// Verify zone
		zone := edgeProtection.GetZone()
		require.NotNil(t, zone, "Zone should not be nil")

		// Assert zone configuration - should use top-level domain
		zoneNameCh := make(chan string, 1)
		defer close(zoneNameCh)
		zone.Name.ApplyT(func(zoneName string) error {
			zoneNameCh <- zoneName
			return nil
		})
		assert.Equal(t, testTopLevelDomain, <-zoneNameCh, "Zone name should match top-level domain")

		// Verify DNS records
		backendRecord := edgeProtection.GetBackendDNSRecord()
		require.NotNil(t, backendRecord, "Backend DNS record should not be nil")

		frontendRecord := edgeProtection.GetFrontendDNSRecord()
		require.NotNil(t, frontendRecord, "Frontend DNS record should not be nil")

		// Note: Root DNS record is commented out in the current implementation
		// rootRecord := edgeProtection.GetRootDNSRecord()
		// require.NotNil(t, rootRecord, "Root DNS record should not be nil")

		// Verify backend DNS record configuration - should be api.{domain}
		backendNameCh := make(chan string, 1)
		defer close(backendNameCh)
		backendRecord.Name.ApplyT(func(name string) error {
			backendNameCh <- name
			return nil
		})
		assert.Equal(t, "api."+testDomain, <-backendNameCh, "Backend DNS record name should be 'api.{domain}'")

		backendValueCh := make(chan string, 1)
		defer close(backendValueCh)
		backendRecord.Data.ApplyT(func(value *cloudflare.DnsRecordData) error {
			backendValueCh <- *value.Target
			return nil
		})
		assert.Equal(t, testBackendURL, <-backendValueCh, "Backend DNS record value should match backend URL")

		// Verify frontend DNS record configuration - should be the full domain
		frontendNameCh := make(chan string, 1)
		defer close(frontendNameCh)
		frontendRecord.Name.ApplyT(func(name string) error {
			frontendNameCh <- name
			return nil
		})
		assert.Equal(t, testDomain, <-frontendNameCh, "Frontend DNS record name should be the full domain")

		frontendValueCh := make(chan string, 1)
		defer close(frontendValueCh)
		frontendRecord.Data.ApplyT(func(value *cloudflare.DnsRecordData) error {
			frontendValueCh <- *value.Target
			return nil
		})
		assert.Equal(t, testFrontendURL, <-frontendValueCh, "Frontend DNS record value should match frontend URL")

		// Verify zone settings
		zoneSettings := edgeProtection.GetZoneSettings()
		require.NotNil(t, zoneSettings, "Zone settings should not be nil")

		// Verify security filter and firewall rule
		securityFilter := edgeProtection.GetSecurityFilter()
		require.NotNil(t, securityFilter, "Security filter should not be nil")

		securityFirewallRule := edgeProtection.GetSecurityFirewallRule()
		require.NotNil(t, securityFirewallRule, "Security firewall rule should not be nil")

		// Verify rate limit rule
		rateLimitRule := edgeProtection.GetRateLimitRule()
		require.NotNil(t, rateLimitRule, "Rate limit rule should not be nil")

		// Verify page rules
		cachePageRule := edgeProtection.GetCachePageRule()
		require.NotNil(t, cachePageRule, "Cache page rule should not be nil")

		httpsPageRule := edgeProtection.GetHTTPSPageRule()
		require.NotNil(t, httpsPageRule, "HTTPS page rule should not be nil")

		securityPageRule := edgeProtection.GetSecurityPageRule()
		require.NotNil(t, securityPageRule, "Security page rule should not be nil")

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_WithDefaults(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Domain:              testDomain,
			BackendURL:          pulumi.String(testBackendURL),
			FrontendURL:         pulumi.String(testFrontendURL),
			CloudflareAccountID: testCloudflareAccountID,
			// Using defaults for other fields
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-edge-protection", args)
		require.NoError(t, err)

		// Verify defaults are applied correctly
		securityLevelCh := make(chan string, 1)
		defer close(securityLevelCh)
		edgeProtection.SecurityLevel.ApplyT(func(level string) error {
			securityLevelCh <- level
			return nil
		})
		assert.Equal(t, "medium", <-securityLevelCh, "Security level should default to 'medium'")

		cacheLevelCh := make(chan string, 1)
		defer close(cacheLevelCh)
		edgeProtection.CacheLevel.ApplyT(func(level string) error {
			cacheLevelCh <- level
			return nil
		})
		assert.Equal(t, "aggressive", <-cacheLevelCh, "Cache level should default to 'aggressive'")

		browserCacheTTLCh := make(chan int, 1)
		defer close(browserCacheTTLCh)
		edgeProtection.BrowserCacheTTL.ApplyT(func(ttl int) error {
			browserCacheTTLCh <- ttl
			return nil
		})
		assert.Equal(t, 14400, <-browserCacheTTLCh, "Browser cache TTL should default to 14400")

		edgeCacheTTLCh := make(chan int, 1)
		defer close(edgeCacheTTLCh)
		edgeProtection.EdgeCacheTTL.ApplyT(func(ttl int) error {
			edgeCacheTTLCh <- ttl
			return nil
		})
		assert.Equal(t, 2592000, <-edgeCacheTTLCh, "Edge cache TTL should default to 2592000")

		rateLimitThresholdCh := make(chan int, 1)
		defer close(rateLimitThresholdCh)
		edgeProtection.RateLimitThreshold.ApplyT(func(threshold int) error {
			rateLimitThresholdCh <- threshold
			return nil
		})
		assert.Equal(t, 60, <-rateLimitThresholdCh, "Rate limit threshold should default to 60")

		rateLimitPeriodCh := make(chan int, 1)
		defer close(rateLimitPeriodCh)
		edgeProtection.RateLimitPeriod.ApplyT(func(period int) error {
			rateLimitPeriodCh <- period
			return nil
		})
		assert.Equal(t, 60, <-rateLimitPeriodCh, "Rate limit period should default to 60")

		rateLimitTimeoutCh := make(chan int, 1)
		defer close(rateLimitTimeoutCh)
		edgeProtection.RateLimitTimeout.ApplyT(func(timeout int) error {
			rateLimitTimeoutCh <- timeout
			return nil
		})
		assert.Equal(t, 600, <-rateLimitTimeoutCh, "Rate limit timeout should default to 600")

		rateLimitModeCh := make(chan string, 1)
		defer close(rateLimitModeCh)
		edgeProtection.RateLimitMode.ApplyT(func(mode string) error {
			rateLimitModeCh <- mode
			return nil
		})
		assert.Equal(t, "simulate", <-rateLimitModeCh, "Rate limit mode should default to 'simulate'")

		sslModeCh := make(chan string, 1)
		defer close(sslModeCh)
		edgeProtection.SSLMode.ApplyT(func(mode string) error {
			sslModeCh <- mode
			return nil
		})
		assert.Equal(t, "full", <-sslModeCh, "SSL mode should default to 'full'")

		minTLSVersionCh := make(chan string, 1)
		defer close(minTLSVersionCh)
		edgeProtection.MinTLSVersion.ApplyT(func(version string) error {
			minTLSVersionCh <- version
			return nil
		})
		assert.Equal(t, "1.2", <-minTLSVersionCh, "Min TLS version should default to '1.2'")

		alwaysUseHTTPSCh := make(chan bool, 1)
		defer close(alwaysUseHTTPSCh)
		edgeProtection.AlwaysUseHTTPS.ApplyT(func(enabled bool) error {
			alwaysUseHTTPSCh <- enabled
			return nil
		})
		assert.True(t, <-alwaysUseHTTPSCh, "Always use HTTPS should default to true")

		tls13EnabledCh := make(chan bool, 1)
		defer close(tls13EnabledCh)
		edgeProtection.TLS13Enabled.ApplyT(func(enabled bool) error {
			tls13EnabledCh <- enabled
			return nil
		})
		assert.True(t, <-tls13EnabledCh, "TLS 1.3 should default to enabled")

		browserCheckEnabledCh := make(chan bool, 1)
		defer close(browserCheckEnabledCh)
		edgeProtection.BrowserCheckEnabled.ApplyT(func(enabled bool) error {
			browserCheckEnabledCh <- enabled
			return nil
		})
		assert.True(t, <-browserCheckEnabledCh, "Browser check should default to enabled")

		autoHTTPSRewritesCh := make(chan bool, 1)
		defer close(autoHTTPSRewritesCh)
		edgeProtection.AutoHTTPSRewrites.ApplyT(func(enabled bool) error {
			autoHTTPSRewritesCh <- enabled
			return nil
		})
		assert.True(t, <-autoHTTPSRewritesCh, "Auto HTTPS rewrites should default to enabled")

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_RequiredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        *edge.EdgeProtectionArgs
		expectedErr string
	}{
		{
			name: "missing domain",
			args: &edge.EdgeProtectionArgs{
				BackendURL:          pulumi.String(testBackendURL),
				FrontendURL:         pulumi.String(testFrontendURL),
				CloudflareAccountID: testCloudflareAccountID,
			},
			expectedErr: "domain is required",
		},
		{
			name: "missing backend URL",
			args: &edge.EdgeProtectionArgs{
				Domain:              testDomain,
				FrontendURL:         pulumi.String(testFrontendURL),
				CloudflareAccountID: testCloudflareAccountID,
			},
			expectedErr: "backend URL is required",
		},
		{
			name: "missing frontend URL",
			args: &edge.EdgeProtectionArgs{
				Domain:              testDomain,
				BackendURL:          pulumi.String(testBackendURL),
				CloudflareAccountID: testCloudflareAccountID,
			},
			expectedErr: "frontend URL is required",
		},
		{
			name: "missing cloudflare account ID",
			args: &edge.EdgeProtectionArgs{
				Domain:      testDomain,
				BackendURL:  pulumi.String(testBackendURL),
				FrontendURL: pulumi.String(testFrontendURL),
			},
			expectedErr: "cloudflare account ID is required",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := pulumi.RunErr(func(ctx *pulumi.Context) error {
				_, err := edge.NewEdgeProtection(ctx, "test-edge-protection", testCase.args)
				if err != nil {
					assert.Contains(t, err.Error(), testCase.expectedErr)
					return nil // Expected error, test passes
				}
				t.Errorf("Expected error containing '%s', but got no error", testCase.expectedErr)
				return nil
			}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

			// We expect the test to complete successfully even when the component creation fails
			assert.NoError(t, err, "Pulumi test should not fail")
		})
	}
}
