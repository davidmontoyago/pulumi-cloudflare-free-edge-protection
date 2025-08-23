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
	testTopLevelDomain      = "path2prod.dev" // Extracted from testDomain
	testBackendUpstreamURL  = "ghs.googlehosted.com"
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
			Upstreams: []edge.Upstream{
				{
					DomainURL:         testDomain,
					CanonicalNameURL:  testBackendUpstreamURL,
					DisableProtection: false,
				},
			},
			CloudflareZone: edge.CloudflareZone{
				CloudflareAccountID: testCloudflareAccountID,
				Protected:           false,
			},
			SecurityLevel:       pulumi.String("medium"),
			BrowserCacheTTL:     pulumi.Int(14400),
			EdgeCacheTTLSeconds: pulumi.Int(2419200),
			RateLimitThreshold:  pulumi.Int(60),
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
		assert.Equal(t, testDomain, edgeProtection.Upstreams[0].DomainURL)
		assert.Equal(t, testBackendUpstreamURL, edgeProtection.Upstreams[0].CanonicalNameURL)
		assert.False(t, edgeProtection.Upstreams[0].DisableProtection)
		assert.Equal(t, testCloudflareAccountID, edgeProtection.CloudflareZone.CloudflareAccountID)
		assert.False(t, edgeProtection.CloudflareZone.Protected)

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
		upstreamRecords := edgeProtection.GetUpstreamDNSRecords()
		require.NotNil(t, upstreamRecords, "Upstream DNS records should not be nil")
		assert.Len(t, upstreamRecords, 1, "Should have 1 upstream DNS record")

		// Verify upstream DNS record configuration
		recordNameCh := make(chan string, 1)
		defer close(recordNameCh)
		upstreamRecords[0].Name.ApplyT(func(name string) error {
			recordNameCh <- name
			return nil
		})
		assert.Equal(t, testDomain, <-recordNameCh, "Upstream DNS record name should match domain")

		recordValueCh := make(chan string, 1)
		defer close(recordValueCh)
		upstreamRecords[0].Data.ApplyT(func(value *cloudflare.DnsRecordData) error {
			recordValueCh <- *value.Target
			return nil
		})
		assert.Equal(t, testBackendUpstreamURL, <-recordValueCh, "Upstream DNS record target should match upstream URL")

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
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
				},
			},
			CloudflareZone: edge.CloudflareZone{
				CloudflareAccountID: testCloudflareAccountID,
			},
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
		edgeProtection.RateLimitPeriodSeconds.ApplyT(func(period int) error {
			rateLimitPeriodCh <- period
			return nil
		})
		assert.Equal(t, 10, <-rateLimitPeriodCh, "Rate limit period should default to 10")

		rateLimitTimeoutCh := make(chan int, 1)
		defer close(rateLimitTimeoutCh)
		edgeProtection.MitigationTimeoutSeconds.ApplyT(func(timeout int) error {
			rateLimitTimeoutCh <- timeout
			return nil
		})
		assert.Equal(t, 10, <-rateLimitTimeoutCh, "Rate limit timeout should default to 10")

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
			name: "missing upstreams",
			args: &edge.EdgeProtectionArgs{
				CloudflareZone: edge.CloudflareZone{
					CloudflareAccountID: testCloudflareAccountID,
				},
			},
			expectedErr: "upstreams are required",
		},
		{
			name: "missing cloudflare account id",
			args: &edge.EdgeProtectionArgs{
				Upstreams: []edge.Upstream{
					{
						DomainURL:        testDomain,
						CanonicalNameURL: testBackendUpstreamURL,
					},
				},
				CloudflareZone: edge.CloudflareZone{
					CloudflareAccountID: "",
				},
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
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
				},
			},
			CloudflareZone: edge.CloudflareZone{
				CloudflareAccountID: testCloudflareAccountID,
			},
			RateLimitThreshold: pulumi.Int(100),
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
			assert.Len(t, rules, 1, "Rate limit ruleset should have 1 rule under the free tier")
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
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
				},
			},
			CloudflareZone: edge.CloudflareZone{
				CloudflareAccountID: testCloudflareAccountID,
			},
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-ddos-protection", args)
		require.NoError(t, err)

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
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
				},
			},
			CloudflareZone: edge.CloudflareZone{
				CloudflareAccountID: testCloudflareAccountID,
			},
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
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
				},
			},
			CloudflareZone: edge.CloudflareZone{
				CloudflareAccountID: testCloudflareAccountID,
			},
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
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
				},
			},
			CloudflareZone: edge.CloudflareZone{
				CloudflareAccountID: testCloudflareAccountID,
			},
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
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
				},
			},
			CloudflareZone: edge.CloudflareZone{
				CloudflareAccountID: testCloudflareAccountID,
			},
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
			assert.Len(t, rules, 2, "Redirect ruleset should have 2 rules per upstream")
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
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
				},
			},
			CloudflareZone: edge.CloudflareZone{
				CloudflareAccountID: testCloudflareAccountID,
			},
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
