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
	testZoneID              = "test-zone-id-123"
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
		outputs["id"] = testZoneID

	case "cloudflare:index/dnsRecord:DnsRecord":
		outputs["zoneId"] = testZoneID
		outputs["data"] = map[string]interface{}{
			// TODO which is the correct field?
			"target": args.Inputs["content"],
			"value":  args.Inputs["content"],
		}

	case "cloudflare:index/zoneSetting:ZoneSetting":
		outputs["zoneId"] = testZoneID
		outputs["name"] = args.Inputs["settingId"]

	case "cloudflare:index/zoneSettingsOverride:ZoneSettingsOverride":
		outputs["zoneId"] = testZoneID

	case "cloudflare:index/filter:Filter":
		outputs["zoneId"] = testZoneID

	case "cloudflare:index/firewallRule:FirewallRule":
		outputs["zoneId"] = testZoneID
		outputs["filterId"] = "test-filter-id-123"

	case "cloudflare:index/rateLimit:RateLimit":
		outputs["zoneId"] = testZoneID

	case "cloudflare:index/pageRule:PageRule":
		outputs["zoneId"] = testZoneID

	case "cloudflare:index/ruleset:Ruleset":
		outputs["zoneId"] = testZoneID

	case "cloudflare:index/notificationPolicy:NotificationPolicy":
		outputs["accountId"] = testCloudflareAccountID
		// Copy the mechanisms structure
		if mechanisms, ok := args.Inputs["mechanisms"]; ok {
			outputs["mechanisms"] = mechanisms
		}
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
			CloudflareZone: edge.Zone{
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
			CloudflareZone: edge.Zone{
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
				CloudflareZone: edge.Zone{
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
				CloudflareZone: edge.Zone{
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
			CloudflareZone: edge.Zone{
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
			CloudflareZone: edge.Zone{
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
			CloudflareZone: edge.Zone{
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

			// Verify Rule 1: CMS and WordPress specific paths
			rule1 := rules[0]
			assert.Equal(t, "block", *rule1.Action, "Rule 1 should be a block action")

			rule1Expression := *rule1.Expression
			assert.Contains(t, rule1Expression, `(http.request.uri.path contains "/wp-admin/")`, "Rule 1 should contain WordPress paths")
			assert.Contains(t, rule1Expression, `(http.request.uri.path contains "/administrator/")`, "Rule 1 should contain CMS specific paths")
			assert.Contains(t, rule1Expression, `(http.request.uri.path contains "/app/")`, "Rule 1 should contain application specific paths")

			// Verify Rule 2: System, configuration, version control paths AND malicious user agents
			rule2 := rules[1]
			assert.Equal(t, "block", *rule2.Action, "Rule 2 should be a block action")

			rule2Expression := *rule2.Expression
			// Test path blocking expressions
			assert.Contains(t, rule2Expression, `(http.request.uri.path contains "/.env")`, "Rule 2 should contain configuration file paths")
			assert.Contains(t, rule2Expression, `(http.request.uri.path contains "/.git/")`, "Rule 2 should contain version control paths")
			assert.Contains(t, rule2Expression, `(http.request.uri.path contains "/proc/")`, "Rule 2 should contain system information paths")
			assert.Contains(t, rule2Expression, `(http.request.uri.path contains "../")`, "Rule 2 should contain path traversal patterns")
			// Test user agent expressions
			assert.Contains(t, rule2Expression, `(http.user_agent contains "sqlmap")`, "Rule 2 should contain malicious user agent sqlmap")
			assert.Contains(t, rule2Expression, `(http.user_agent contains "nmap")`, "Rule 2 should contain malicious user agent nmap")
			assert.Contains(t, rule2Expression, `(http.user_agent eq "")`, "Rule 2 should contain empty user agent check")
			assert.Contains(t, rule2Expression, `(len(http.user_agent) < 10)`, "Rule 2 should contain short user agent check")

			// Verify Rule 3: Admin panels, backup files, and sensitive areas
			rule3 := rules[2]
			assert.Equal(t, "block", *rule3.Action, "Rule 3 should be a block action")
			assert.Contains(t, *rule3.Description, "admin panels, backup files, and sensitive", "Rule 3 should be for admin/backup paths")

			rule3Expression := *rule3.Expression
			assert.Contains(t, rule3Expression, `(http.request.uri.path contains "/admin/")`, "Rule 3 should contain admin panel paths")
			assert.Contains(t, rule3Expression, `(http.request.uri.path contains "/backup/")`, "Rule 3 should contain backup file paths")
			assert.Contains(t, rule3Expression, `(http.request.uri.path contains "/phpmyadmin/")`, "Rule 3 should contain database management paths")

			// Verify Rule 4: Development, API, and server information paths
			rule4 := rules[3]
			assert.Equal(t, "block", *rule4.Action, "Rule 4 should be a block action")
			assert.Contains(t, *rule4.Description, "development tools, API endpoints, and server", "Rule 4 should be for dev/API paths")

			rule4Expression := *rule4.Expression
			assert.Contains(t, rule4Expression, `(http.request.uri.path contains "/test/")`, "Rule 4 should contain development testing paths")
			assert.Contains(t, rule4Expression, `(http.request.uri.path contains "/api/v1/admin")`, "Rule 4 should contain API endpoint paths")
			assert.Contains(t, rule4Expression, `(http.request.uri.path contains "/server-status")`, "Rule 4 should contain server file paths")

			// Verify Rule 5: Challenge dangerous HTTP methods and suspicious behavior
			rule5 := rules[4]
			assert.Equal(t, "managed_challenge", *rule5.Action, "Rule 5 should be a managed_challenge action")

			rule5Expression := *rule5.Expression
			assert.Contains(t, rule5Expression, `(http.request.method eq "TRACE")`, "Rule 5 should contain dangerous TRACE method")
			assert.Contains(t, rule5Expression, `(http.request.method eq "DEBUG")`, "Rule 5 should contain dangerous DEBUG method")
			assert.Contains(t, rule5Expression, `(http.request.uri.query contains "union select")`, "Rule 5 should contain SQL injection patterns")
			assert.Contains(t, rule5Expression, `(http.request.uri.query contains "<script")`, "Rule 5 should contain XSS patterns")

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
			CloudflareZone: edge.Zone{
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
			assert.Len(t, rules, 3, "Cache ruleset should have 3 rules")

			// Verify Rule 1: Static assets cache rule with Content-Type headers
			rule1 := rules[0]
			assert.Equal(t, "set_cache_settings", *rule1.Action, "Rule 1 should be a set_cache_settings action")

			rule1Expression := *rule1.Expression
			// Verify file extension checks
			assert.Contains(t, rule1Expression, `(http.request.uri.path contains ".css")`, "Rule 1 should contain CSS file extension")
			assert.Contains(t, rule1Expression, `(http.request.uri.path contains ".js")`, "Rule 1 should contain JS file extension")
			assert.Contains(t, rule1Expression, `(http.request.uri.path contains ".jpg")`, "Rule 1 should contain JPG file extension")
			assert.Contains(t, rule1Expression, `(http.request.uri.path contains ".jpeg")`, "Rule 1 should contain JPEG file extension")
			assert.Contains(t, rule1Expression, `(http.request.uri.path contains ".png")`, "Rule 1 should contain PNG file extension")

			// Verify Content-Type header checks for images without extensions
			assert.Contains(t, rule1Expression, `(http.request.headers["content-type"][0] eq "image/jpeg")`, "Rule 1 should contain Content-Type check for image/jpeg")
			assert.Contains(t, rule1Expression, `(http.request.headers["content-type"][0] eq "image/png")`, "Rule 1 should contain Content-Type check for image/png")
			assert.Contains(t, rule1Expression, `(http.request.headers["content-type"][0] eq "image/gif")`, "Rule 1 should contain Content-Type check for image/gif")
			assert.Contains(t, rule1Expression, `(http.request.headers["content-type"][0] eq "image/svg+xml")`, "Rule 1 should contain Content-Type check for image/svg+xml")

			// Verify Rule 2: HTML pages cache rule
			rule2 := rules[1]
			assert.Equal(t, "set_cache_settings", *rule2.Action, "Rule 2 should be a set_cache_settings action")

			// Verify Rule 3: Dynamic content bypass rule
			rule3 := rules[2]
			assert.Equal(t, "set_cache_settings", *rule3.Action, "Rule 3 should be a set_cache_settings action")

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
			CloudflareZone: edge.Zone{
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

			// Verify Rule 1: www to root redirect
			rule1 := rules[0]
			assert.Equal(t, "redirect", *rule1.Action, "Rule 1 should be a redirect action")
			assert.Contains(t, *rule1.Expression, "http.host eq", "Rule 1 should check host")

			// Verify Rule 2: Trailing slash redirect
			rule2 := rules[1]
			assert.Equal(t, "redirect", *rule2.Action, "Rule 2 should be a redirect action")
			assert.Contains(t, *rule2.Expression, `ends_with(http.request.uri.path, "/")`, "Rule 2 should check for trailing slash")

			// Verify that the trailing slash redirect has the correct Expression field in target URL
			assert.NotNil(t, rule2.ActionParameters, "Rule 2 should have action parameters")
			assert.NotNil(t, rule2.ActionParameters.FromValue, "Rule 2 should have from_value parameters")
			assert.NotNil(t, rule2.ActionParameters.FromValue.TargetUrl, "Rule 2 should have target_url")
			assert.NotNil(t, rule2.ActionParameters.FromValue.TargetUrl.Expression, "Rule 2 should have Expression field set")
			assert.Contains(t, *rule2.ActionParameters.FromValue.TargetUrl.Expression, "http.request.uri.path", "Rule 2 Expression should contain http.request.uri.path")

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
			CloudflareZone: edge.Zone{
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

func TestNewEdgeProtection_DDoSAttackNotifications(t *testing.T) {
	t.Parallel()

	testEmail := "admin@example.com"

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
				},
			},
			CloudflareZone: edge.Zone{
				CloudflareAccountID: testCloudflareAccountID,
			},
			DDoSAttackNotificationsEmail: testEmail,
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-ddos-notifications", args)
		require.NoError(t, err)

		// Verify DDoS attack notification policy is created
		ddosNotificationPolicy := edgeProtection.GetDDoSAttackNotifications()
		require.NotNil(t, ddosNotificationPolicy, "DDoS attack notification policy should not be nil")

		// Verify alert type
		alertTypeCh := make(chan string, 1)
		defer close(alertTypeCh)
		ddosNotificationPolicy.AlertType.ApplyT(func(alertType string) error {
			alertTypeCh <- alertType

			return nil
		})
		assert.Equal(t, "dos_attack_l7", <-alertTypeCh, "Alert type should be dos_attack_l7")

		// Verify enabled
		enabledCh := make(chan bool, 1)
		defer close(enabledCh)
		ddosNotificationPolicy.Enabled.ApplyT(func(enabled bool) error {
			enabledCh <- enabled

			return nil
		})
		assert.True(t, <-enabledCh, "Notification policy should be enabled")

		// Verify email mechanism
		ddosNotificationPolicy.Mechanisms.ApplyT(func(mechanisms cloudflare.NotificationPolicyMechanisms) error {
			require.NotNil(t, mechanisms, "Mechanisms should not be nil")
			require.NotNil(t, mechanisms.Emails, "Email mechanisms should not be nil")
			assert.Len(t, mechanisms.Emails, 1, "Should have 1 email mechanism")

			if len(mechanisms.Emails) > 0 {
				assert.Equal(t, testEmail, *mechanisms.Emails[0].Id, "Email should match the configured email")
			}

			return nil
		})

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}
