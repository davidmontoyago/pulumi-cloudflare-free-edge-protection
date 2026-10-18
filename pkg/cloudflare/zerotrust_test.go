package cloudflare_test

import (
	"testing"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/internals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	edge "github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/pkg/cloudflare"
)

const (
	testAPIDomain         = "api-myapp.path2prod.dev"
	testFrontendOriginURL = "https://frontend-abc-uc.a.run.app"
	testBackendOriginURL  = "https://backend-abc-uc.a.run.app"
	testBackendOriginHost = "backend-abc-uc.a.run.app"
	testTeamName          = "myteam"
	testAdminEmail        = "admin@path2prod.dev"
)

// awaitOutput resolves a Pulumi output inside a mocked program.
func awaitOutput(t *testing.T, ctx *pulumi.Context, output pulumi.Output) internals.UnsafeAwaitOutputResult {
	t.Helper()

	result, err := internals.UnsafeAwaitOutput(ctx.Context(), output)
	require.NoError(t, err)

	return result
}

func tunnelUpstreamsArgs() *edge.EdgeProtectionArgs {
	return &edge.EdgeProtectionArgs{
		Upstreams: []edge.Upstream{
			{
				DomainURL: testDomain,
				Connector: edge.ConnectorTunnel,
				OriginURL: pulumi.String(testFrontendOriginURL),
			},
			{
				DomainURL: testAPIDomain,
				Connector: edge.ConnectorTunnel,
				OriginURL: pulumi.String(testBackendOriginURL),
				Access: &edge.AccessConfig{
					AllowedEmails: []string{testAdminEmail},
					ServiceTokens: []string{"ci"},
					Paths:         []string{"/admin"},
				},
			},
		},
		CloudflareZone: edge.Zone{
			CloudflareAccountID: testCloudflareAccountID,
		},
		ZeroTrust: &edge.ZeroTrust{
			TeamName: testTeamName,
		},
	}
}

func TestNewEdgeProtection_ZeroTrustTunnel(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-zt-tunnel", tunnelUpstreamsArgs())
		require.NoError(t, err)

		tunnel := edgeProtection.GetTunnel()
		require.NotNil(t, tunnel, "Tunnel should be created for tunnel upstreams")
		assert.Equal(t, "cloudflare", awaitOutput(t, ctx, tunnel.ConfigSrc).Value)
		tunnelCNAME := string(awaitOutput(t, ctx, tunnel.ID()).Value.(pulumi.ID)) + ".cfargotunnel.com"

		// DNS records point to the tunnel and are always proxied
		records := edgeProtection.GetUpstreamDNSRecords()
		require.Len(t, records, 2)
		for _, record := range records {
			assert.Equal(t, tunnelCNAME, awaitOutput(t, ctx, record.Content).Value)
			assert.Equal(t, true, awaitOutput(t, ctx, record.Proxied).Value)
		}

		// Ingress rules: frontend, api /admin (Access), api, catch-all
		tunnelConfig := edgeProtection.GetTunnelConfig()
		require.NotNil(t, tunnelConfig)
		config := awaitOutput(t, ctx, tunnelConfig.Config).Value.(cloudflare.ZeroTrustTunnelCloudflaredConfigConfig)
		require.Len(t, config.Ingresses, 4)

		frontend := config.Ingresses[0]
		assert.Equal(t, testDomain, *frontend.Hostname)
		assert.Equal(t, testFrontendOriginURL, frontend.Service)
		assert.Nil(t, frontend.Path)
		assert.Nil(t, frontend.OriginRequest.Access, "Frontend should not require Access")

		admin := config.Ingresses[1]
		assert.Equal(t, testAPIDomain, *admin.Hostname)
		assert.Equal(t, `^/admin(/.*)?$`, *admin.Path)
		assert.Equal(t, testBackendOriginURL, admin.Service)
		assert.Equal(t, testBackendOriginHost, *admin.OriginRequest.HttpHostHeader)
		assert.Equal(t, testBackendOriginHost, *admin.OriginRequest.OriginServerName)
		require.NotNil(t, admin.OriginRequest.Access)
		assert.True(t, *admin.OriginRequest.Access.Required)
		assert.Equal(t, testTeamName, admin.OriginRequest.Access.TeamName)
		require.Len(t, admin.OriginRequest.Access.AudTags, 1)
		assert.Contains(t, admin.OriginRequest.Access.AudTags[0], "test-aud-")

		api := config.Ingresses[2]
		assert.Equal(t, testAPIDomain, *api.Hostname)
		assert.Nil(t, api.Path)
		assert.Nil(t, api.OriginRequest.Access, "Non-admin API paths should not require Access")

		catchAll := config.Ingresses[3]
		assert.Nil(t, catchAll.Hostname)
		assert.Equal(t, "http_status:404", catchAll.Service)

		// Token is secret
		token := awaitOutput(t, ctx, edgeProtection.GetTunnelToken())
		assert.Equal(t, testTunnelAuth, token.Value)
		assert.True(t, token.Secret, "Tunnel token should be marked as secret")

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_ZeroTrustAccessApplication(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-zt-access", tunnelUpstreamsArgs())
		require.NoError(t, err)

		apps := edgeProtection.GetAccessApplications()
		require.Len(t, apps, 1, "Only the API upstream has Access")
		app := apps[testAPIDomain]
		require.NotNil(t, app)

		assert.Equal(t, "self_hosted", awaitOutput(t, ctx, app.Type).Value)
		assert.Equal(t, testAPIDomain+"/admin", awaitOutput(t, ctx, app.Domain).Value)
		assert.Equal(t, "24h", awaitOutput(t, ctx, app.SessionDuration).Value)

		destinations := awaitOutput(t, ctx, app.Destinations).Value.([]cloudflare.ZeroTrustAccessApplicationDestination)
		require.Len(t, destinations, 1)
		assert.Equal(t, "public", *destinations[0].Type)
		assert.Equal(t, testAPIDomain+"/admin", *destinations[0].Uri)

		policies := edgeProtection.GetAccessPolicies()[testAPIDomain]
		require.Len(t, policies, 2)
		assert.Equal(t, "allow", awaitOutput(t, ctx, policies[0].Decision).Value)
		assert.Equal(t, "non_identity", awaitOutput(t, ctx, policies[1].Decision).Value)

		userIncludes := awaitOutput(t, ctx, policies[0].Includes).Value.([]cloudflare.ZeroTrustAccessPolicyInclude)
		require.Len(t, userIncludes, 1)
		assert.Equal(t, testAdminEmail, userIncludes[0].Email.Email)

		serviceTokens := edgeProtection.GetAccessServiceTokens()[testAPIDomain]
		require.Len(t, serviceTokens, 1)
		tokenID := awaitOutput(t, ctx, serviceTokens[0].ID()).Value
		serviceIncludes := awaitOutput(t, ctx, policies[1].Includes).Value.([]cloudflare.ZeroTrustAccessPolicyInclude)
		require.Len(t, serviceIncludes, 1)
		assert.Equal(t, string(tokenID.(pulumi.ID)), serviceIncludes[0].ServiceToken.TokenId)

		appPolicies := awaitOutput(t, ctx, app.Policies).Value.([]cloudflare.ZeroTrustAccessApplicationPolicy)
		require.Len(t, appPolicies, 2)
		assert.Equal(t, 1, *appPolicies[0].Precedence)
		assert.Equal(t, 2, *appPolicies[1].Precedence)

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_ZeroTrustAccessWithDNSConnector(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Upstreams: []edge.Upstream{
				{
					DomainURL:        testDomain,
					CanonicalNameURL: testBackendUpstreamURL,
					Access: &edge.AccessConfig{
						AllowedEmailDomains: []string{testTopLevelDomain},
						SessionDuration:     "8h",
						BypassCORSPreflight: true,
					},
				},
			},
			CloudflareZone: edge.Zone{
				CloudflareAccountID: testCloudflareAccountID,
			},
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-zt-access-dns", args)
		require.NoError(t, err)

		assert.Nil(t, edgeProtection.GetTunnel(), "Access alone should not create a tunnel")
		assert.Nil(t, edgeProtection.GetTunnelConfig())

		records := edgeProtection.GetUpstreamDNSRecords()
		require.Len(t, records, 1)
		assert.Equal(t, testBackendUpstreamURL, awaitOutput(t, ctx, records[0].Content).Value)

		app := edgeProtection.GetAccessApplications()[testDomain]
		require.NotNil(t, app)
		assert.Equal(t, testDomain, awaitOutput(t, ctx, app.Domain).Value)
		assert.Equal(t, "8h", awaitOutput(t, ctx, app.SessionDuration).Value)
		assert.True(t, *awaitOutput(t, ctx, app.OptionsPreflightBypass).Value.(*bool))

		policies := edgeProtection.GetAccessPolicies()[testDomain]
		require.Len(t, policies, 1)
		includes := awaitOutput(t, ctx, policies[0].Includes).Value.([]cloudflare.ZeroTrustAccessPolicyInclude)
		require.Len(t, includes, 1)
		assert.Equal(t, testTopLevelDomain, includes[0].EmailDomain.Domain)
		assert.Empty(t, edgeProtection.GetAccessServiceTokens()[testDomain])

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_ZeroTrustTunnelAccessWholeHost(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := &edge.EdgeProtectionArgs{
			Upstreams: []edge.Upstream{
				{
					DomainURL: testAPIDomain,
					Connector: edge.ConnectorTunnel,
					OriginURL: pulumi.String(testBackendOriginURL),
					Access:    &edge.AccessConfig{AllowedEmails: []string{testAdminEmail}},
				},
			},
			CloudflareZone: edge.Zone{CloudflareAccountID: testCloudflareAccountID},
			ZeroTrust:      &edge.ZeroTrust{TeamName: testTeamName},
		}

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-zt-access-host", args)
		require.NoError(t, err)

		// Without paths, the whole hostname requires Access: one rule plus the catch-all
		config := awaitOutput(t, ctx, edgeProtection.GetTunnelConfig().Config).Value.(cloudflare.ZeroTrustTunnelCloudflaredConfigConfig)
		require.Len(t, config.Ingresses, 2)
		api := config.Ingresses[0]
		assert.Equal(t, testAPIDomain, *api.Hostname)
		assert.Nil(t, api.Path)
		require.NotNil(t, api.OriginRequest.Access)
		assert.True(t, *api.OriginRequest.Access.Required)
		assert.Equal(t, "http_status:404", config.Ingresses[1].Service)

		app := edgeProtection.GetAccessApplications()[testAPIDomain]
		require.NotNil(t, app)
		assert.Equal(t, testAPIDomain, awaitOutput(t, ctx, app.Domain).Value)

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))
	require.NoError(t, err)
}

func TestNewEdgeProtection_ZeroTrustInvalidOriginURL(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := edge.NewEdgeProtection(ctx, "test-zt-invalid-origin", &edge.EdgeProtectionArgs{
			Upstreams: []edge.Upstream{
				{
					DomainURL: testDomain,
					Connector: edge.ConnectorTunnel,
					OriginURL: pulumi.String("backend-without-scheme"),
				},
			},
			CloudflareZone: edge.Zone{CloudflareAccountID: testCloudflareAccountID},
		})

		return err
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	// The origin host is resolved from an output, so the error surfaces when the program runs
	require.Error(t, err)
	assert.Contains(t, err.Error(), `origin URL "backend-without-scheme" has no host`)
}

func TestNewEdgeProtection_ZeroTrustTunnelSecret(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		args := tunnelUpstreamsArgs()
		args.ZeroTrust.TunnelSecret = pulumi.String("dGVzdC10dW5uZWwtc2VjcmV0LWF0LWxlYXN0LTMyLWJ5dGVz")

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-zt-tunnel-secret", args)
		require.NoError(t, err)

		secret := awaitOutput(t, ctx, edgeProtection.GetTunnel().TunnelSecret)
		assert.Equal(t, "dGVzdC10dW5uZWwtc2VjcmV0LWF0LWxlYXN0LTMyLWJ5dGVz", *secret.Value.(*string))
		assert.True(t, secret.Secret, "Tunnel secret should be marked as secret")

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_ZeroTrustDisabledByDefault(t *testing.T) {
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

		edgeProtection, err := edge.NewEdgeProtection(ctx, "test-zt-disabled", args)
		require.NoError(t, err)

		assert.Nil(t, edgeProtection.GetTunnel())
		assert.Nil(t, edgeProtection.GetTunnelConfig())
		assert.Empty(t, edgeProtection.GetAccessApplications())

		records := edgeProtection.GetUpstreamDNSRecords()
		require.Len(t, records, 1)
		assert.Equal(t, testBackendUpstreamURL, awaitOutput(t, ctx, records[0].Content).Value)
		assert.Equal(t, true, awaitOutput(t, ctx, records[0].Proxied).Value)

		return nil
	}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewEdgeProtection_ZeroTrustValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		upstream    edge.Upstream
		zeroTrust   *edge.ZeroTrust
		expectedErr string
	}{
		{
			name: "invalid connector",
			upstream: edge.Upstream{
				DomainURL: testDomain,
				Connector: "worker",
			},
			expectedErr: `invalid connector "worker"`,
		},
		{
			name: "tunnel without origin URL",
			upstream: edge.Upstream{
				DomainURL: testDomain,
				Connector: edge.ConnectorTunnel,
			},
			expectedErr: "origin URL is required",
		},
		{
			name: "access without rules",
			upstream: edge.Upstream{
				DomainURL:        testDomain,
				CanonicalNameURL: testBackendUpstreamURL,
				Access:           &edge.AccessConfig{Paths: []string{"/admin"}},
			},
			expectedErr: "requires allowed emails, email domains or service tokens",
		},
		{
			name: "tunnel with access without team name",
			upstream: edge.Upstream{
				DomainURL: testDomain,
				Connector: edge.ConnectorTunnel,
				OriginURL: pulumi.String(testBackendOriginURL),
				Access:    &edge.AccessConfig{AllowedEmails: []string{testAdminEmail}},
			},
			zeroTrust:   &edge.ZeroTrust{},
			expectedErr: "zero trust team name is required",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := pulumi.RunErr(func(ctx *pulumi.Context) error {
				_, err := edge.NewEdgeProtection(ctx, "test-zt-validation", &edge.EdgeProtectionArgs{
					Upstreams: []edge.Upstream{testCase.upstream},
					CloudflareZone: edge.Zone{
						CloudflareAccountID: testCloudflareAccountID,
					},
					ZeroTrust: testCase.zeroTrust,
				})
				if err != nil {
					assert.Contains(t, err.Error(), testCase.expectedErr)

					return nil // Expected error, test passes
				}
				t.Errorf("Expected error containing '%s', but got no error", testCase.expectedErr)

				return nil
			}, pulumi.WithMocks("project", "stack", &edgeProtectionMocks{}))

			assert.NoError(t, err, "Pulumi test should not fail")
		})
	}
}
