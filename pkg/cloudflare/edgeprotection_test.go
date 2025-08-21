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

	case "cloudflare:index/zoneSettingsOverride:ZoneSettingsOverride":
		outputs["zoneId"] = "test-zone-id-123"

	case "cloudflare:index/filter:Filter":
		outputs["zoneId"] = "test-zone-id-123"

	case "cloudflare:index/firewallRule:FirewallRule":
		outputs["zoneId"] = "test-zone-id-123"
		outputs["filterId"] = "test-filter-id-123"

	case "cloudflare:index/rateLimit:RateLimit":
		outputs["zoneId"] = "test-zone-id-123"

	case "cloudflare:index/pageRule:PageRule":
		outputs["zoneId"] = "test-zone-id-123"

	case "cloudflare:index/ruleset:Ruleset":
		outputs["zoneId"] = "test-zone-id-123"
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
			BrowserCacheTTL:     pulumi.Int(14400),
			EdgeCacheTTLSeconds: pulumi.Int(2419200),
			RateLimitThreshold:  pulumi.Int(60),
			RateLimitPeriod:     pulumi.Int(60),
			RateLimitTimeout:    pulumi.Int(600),
			RateLimitMode:       pulumi.String("managed_challenge"),
			TLSEncryptionMode:   pulumi.String("full"),
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
		edgeProtection.EdgeCacheTTLSeconds.ApplyT(func(ttl int) error {
			edgeCacheTTLCh <- ttl
			return nil
		})
		assert.Equal(t, 2419200, <-edgeCacheTTLCh, "Edge cache TTL should match")

		// Verify rate limit settings
		rateLimitThresholdCh := make(chan int, 1)
		defer close(rateLimitThresholdCh)
		edgeProtection.RateLimitThreshold.ApplyT(func(threshold int) error {
			rateLimitThresholdCh <- threshold
			return nil
		})
		assert.Equal(t, 60, <-rateLimitThresholdCh, "Rate limit threshold should match")

		// Verify SSL mode
		tlsModeCh := make(chan string, 1)
		defer close(tlsModeCh)
		edgeProtection.TLSEncryptionMode.ApplyT(func(mode string) error {
			tlsModeCh <- mode
			return nil
		})
		assert.Equal(t, "full", <-tlsModeCh, "SSL mode should match")

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
		assert.Greater(t, len(zoneSettings), 0, "Zone settings should have at least 1 setting")

		// Verify rate limit rule
		rateLimitRuleset := edgeProtection.GetRateLimitRuleset()
		require.NotNil(t, rateLimitRuleset, "Rate limit ruleset should not be nil")

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

		browserCacheTTLCh := make(chan int, 1)
		defer close(browserCacheTTLCh)
		edgeProtection.BrowserCacheTTL.ApplyT(func(ttl int) error {
			browserCacheTTLCh <- ttl
			return nil
		})
		assert.Equal(t, 14400, <-browserCacheTTLCh, "Browser cache TTL should default to 14400")

		edgeCacheTTLCh := make(chan int, 1)
		defer close(edgeCacheTTLCh)
		edgeProtection.EdgeCacheTTLSeconds.ApplyT(func(ttl int) error {
			edgeCacheTTLCh <- ttl
			return nil
		})
		assert.Equal(t, 2419200, <-edgeCacheTTLCh, "Edge cache TTL should default to 2419200")

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
		assert.Equal(t, "block", <-rateLimitModeCh, "Rate limit mode should default to 'block'")

		tlsModeCh := make(chan string, 1)
		defer close(tlsModeCh)
		edgeProtection.TLSEncryptionMode.ApplyT(func(mode string) error {
			tlsModeCh <- mode
			return nil
		})
		assert.Equal(t, "strict", <-tlsModeCh, "SSL mode should default to 'strict'")

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

func TestNewEdgeProtection_RateLimitRuleset(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Domain:              testDomain,
			BackendURL:          pulumi.String(testBackendURL),
			FrontendURL:         pulumi.String(testFrontendURL),
			CloudflareAccountID: testCloudflareAccountID,
			RateLimitThreshold:  pulumi.Int(100),
			RateLimitPeriod:     pulumi.Int(120),
			RateLimitTimeout:    pulumi.Int(900),
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-rate-limit", args)
		require.NoError(t, err)

		// Verify rate limit ruleset is created
		rateLimitRuleset := edgeProtection.GetRateLimitRuleset()
		require.NotNil(t, rateLimitRuleset, "Rate limit ruleset should not be nil")

		// Verify basic properties
		nameCh := make(chan string, 1)
		defer close(nameCh)
		rateLimitRuleset.Name.ApplyT(func(name string) error {
			nameCh <- name
			return nil
		})
		assert.Equal(t, "Rate Limiting Rules", <-nameCh)

		kindCh := make(chan string, 1)
		defer close(kindCh)
		rateLimitRuleset.Kind.ApplyT(func(kind string) error {
			kindCh <- kind
			return nil
		})
		assert.Equal(t, "zone", <-kindCh)

		phaseCh := make(chan string, 1)
		defer close(phaseCh)
		rateLimitRuleset.Phase.ApplyT(func(phase string) error {
			phaseCh <- phase
			return nil
		})
		assert.Equal(t, "http_ratelimit", <-phaseCh)

		rateLimitRuleset.Rules.ApplyT(func(rules []cloudflare.RulesetRule) error {
			assert.Len(t, rules, 3, "Rate limit ruleset should have 3 rules")
			return nil
		})

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_DDoSProtectionRulesets(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Domain:              testDomain,
			BackendURL:          pulumi.String(testBackendURL),
			FrontendURL:         pulumi.String(testFrontendURL),
			CloudflareAccountID: testCloudflareAccountID,
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-ddos-protection", args)
		require.NoError(t, err)

		// Verify DDoS L4 ruleset is created
		ddosL4Ruleset := edgeProtection.GetDDoSL4Ruleset()
		require.NotNil(t, ddosL4Ruleset, "DDoS L4 ruleset should not be nil")

		// Verify DDoS L4 properties
		phaseCh := make(chan string, 1)
		defer close(phaseCh)
		ddosL4Ruleset.Phase.ApplyT(func(phase string) error {
			phaseCh <- phase
			return nil
		})
		assert.Equal(t, "ddos_l4", <-phaseCh)

		nameCh := make(chan string, 1)
		defer close(nameCh)
		ddosL4Ruleset.Name.ApplyT(func(name string) error {
			nameCh <- name
			return nil
		})
		assert.Equal(t, "DDoS L4 Protection", <-nameCh)

		// Verify DDoS L7 ruleset is created
		ddosL7Ruleset := edgeProtection.GetDDoSL7Ruleset()
		require.NotNil(t, ddosL7Ruleset, "DDoS L7 ruleset should not be nil")

		// Verify DDoS L7 properties
		phaseCh2 := make(chan string, 1)
		defer close(phaseCh2)
		ddosL7Ruleset.Phase.ApplyT(func(phase string) error {
			phaseCh2 <- phase
			return nil
		})
		assert.Equal(t, "ddos_l7", <-phaseCh2)

		nameCh2 := make(chan string, 1)
		defer close(nameCh2)
		ddosL7Ruleset.Name.ApplyT(func(name string) error {
			nameCh2 <- name
			return nil
		})
		assert.Equal(t, "DDoS L7 Protection", <-nameCh2)

		ddosL4Ruleset.Rules.ApplyT(func(rules []cloudflare.RulesetRule) error {
			assert.Len(t, rules, 1, "DDoS L4 ruleset should have 1 rule")
			return nil
		})

		ddosL7Ruleset.Rules.ApplyT(func(rules []cloudflare.RulesetRule) error {
			assert.Len(t, rules, 1, "DDoS L7 ruleset should have 1 rule")
			return nil
		})

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_WAFManagedRuleset(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Domain:              testDomain,
			BackendURL:          pulumi.String(testBackendURL),
			FrontendURL:         pulumi.String(testFrontendURL),
			CloudflareAccountID: testCloudflareAccountID,
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-waf-managed", args)
		require.NoError(t, err)

		// Verify WAF managed ruleset is created
		wafManagedRuleset := edgeProtection.GetWAFManagedRuleset()
		require.NotNil(t, wafManagedRuleset, "WAF managed ruleset should not be nil")

		// Verify basic properties
		phaseCh := make(chan string, 1)
		defer close(phaseCh)
		wafManagedRuleset.Phase.ApplyT(func(phase string) error {
			phaseCh <- phase
			return nil
		})
		assert.Equal(t, "http_request_firewall_managed", <-phaseCh)

		nameCh := make(chan string, 1)
		defer close(nameCh)
		wafManagedRuleset.Name.ApplyT(func(name string) error {
			nameCh <- name
			return nil
		})
		assert.Equal(t, "WAF Managed Security Rules", <-nameCh)

		wafManagedRuleset.Rules.ApplyT(func(rules []cloudflare.RulesetRule) error {
			assert.Len(t, rules, 3, "WAF managed ruleset should have 3 rules")
			return nil
		})

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_WAFCustomRuleset(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Domain:              testDomain,
			BackendURL:          pulumi.String(testBackendURL),
			FrontendURL:         pulumi.String(testFrontendURL),
			CloudflareAccountID: testCloudflareAccountID,
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-waf-custom", args)
		require.NoError(t, err)

		// Verify WAF custom ruleset is created
		wafCustomRuleset := edgeProtection.GetWAFCustomRuleset()
		require.NotNil(t, wafCustomRuleset, "WAF custom ruleset should not be nil")

		// Verify basic properties
		phaseCh := make(chan string, 1)
		defer close(phaseCh)
		wafCustomRuleset.Phase.ApplyT(func(phase string) error {
			phaseCh <- phase
			return nil
		})
		assert.Equal(t, "http_request_firewall_custom", <-phaseCh)

		nameCh := make(chan string, 1)
		defer close(nameCh)
		wafCustomRuleset.Name.ApplyT(func(name string) error {
			nameCh <- name
			return nil
		})
		assert.Equal(t, "WAF Custom Security Rules", <-nameCh)

		wafCustomRuleset.Rules.ApplyT(func(rules []cloudflare.RulesetRule) error {
			assert.Len(t, rules, 5, "WAF custom ruleset should have 5 rules")
			return nil
		})

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_CacheRuleset(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Domain:              testDomain,
			BackendURL:          pulumi.String(testBackendURL),
			FrontendURL:         pulumi.String(testFrontendURL),
			CloudflareAccountID: testCloudflareAccountID,
			BrowserCacheTTL:     pulumi.Int(7200),
			EdgeCacheTTLSeconds: pulumi.Int(86400),
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-cache", args)
		require.NoError(t, err)

		// Verify cache ruleset is created
		cacheRuleset := edgeProtection.GetCacheRuleset()
		require.NotNil(t, cacheRuleset, "Cache ruleset should not be nil")

		// Verify basic properties
		phaseCh := make(chan string, 1)
		defer close(phaseCh)
		cacheRuleset.Phase.ApplyT(func(phase string) error {
			phaseCh <- phase
			return nil
		})
		assert.Equal(t, "http_request_cache_settings", <-phaseCh)

		nameCh := make(chan string, 1)
		defer close(nameCh)
		cacheRuleset.Name.ApplyT(func(name string) error {
			nameCh <- name
			return nil
		})
		assert.Equal(t, "Cache Optimization Rules", <-nameCh)

		cacheRuleset.Rules.ApplyT(func(rules []cloudflare.RulesetRule) error {
			assert.Len(t, rules, 3, "Cache ruleset should have 2 rules")
			return nil
		})

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_RedirectRuleset(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Domain:              testDomain,
			BackendURL:          pulumi.String(testBackendURL),
			FrontendURL:         pulumi.String(testFrontendURL),
			CloudflareAccountID: testCloudflareAccountID,
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-redirect", args)
		require.NoError(t, err)

		// Verify redirect ruleset is created
		redirectRuleset := edgeProtection.GetRedirectRuleset()
		require.NotNil(t, redirectRuleset, "Redirect ruleset should not be nil")

		// Verify basic properties
		phaseCh := make(chan string, 1)
		defer close(phaseCh)
		redirectRuleset.Phase.ApplyT(func(phase string) error {
			phaseCh <- phase
			return nil
		})
		assert.Equal(t, "http_request_dynamic_redirect", <-phaseCh)

		nameCh := make(chan string, 1)
		defer close(nameCh)
		redirectRuleset.Name.ApplyT(func(name string) error {
			nameCh <- name
			return nil
		})
		assert.Equal(t, "HTTPS Redirect Rules", <-nameCh)

		redirectRuleset.Rules.ApplyT(func(rules []cloudflare.RulesetRule) error {
			assert.Len(t, rules, 3, "Redirect ruleset should have 3 rules")
			return nil
		})

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_ConfigurationRuleset(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Domain:              testDomain,
			BackendURL:          pulumi.String(testBackendURL),
			FrontendURL:         pulumi.String(testFrontendURL),
			CloudflareAccountID: testCloudflareAccountID,
			SecurityLevel:       pulumi.String("high"),
			BrowserCheckEnabled: pulumi.Bool(true),
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-config", args)
		require.NoError(t, err)

		// Verify configuration ruleset is created
		configRuleset := edgeProtection.GetConfigurationRuleset()
		require.NotNil(t, configRuleset, "Configuration ruleset should not be nil")

		// Verify basic properties
		phaseCh := make(chan string, 1)
		defer close(phaseCh)
		configRuleset.Phase.ApplyT(func(phase string) error {
			phaseCh <- phase
			return nil
		})
		assert.Equal(t, "http_config_settings", <-phaseCh)

		nameCh := make(chan string, 1)
		defer close(nameCh)
		configRuleset.Name.ApplyT(func(name string) error {
			nameCh <- name
			return nil
		})
		assert.Equal(t, "Configuration Rules", <-nameCh)

		configRuleset.Rules.ApplyT(func(rules []cloudflare.RulesetRule) error {
			assert.Len(t, rules, 1, "Configuration ruleset should have 1 rule")
			return nil
		})

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}
