package cloudflare

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	// Remotely-managed tunnel: ingress rules live in Cloudflare, not in a local config file.
	tunnelConfigSource = "cloudflare"
	// Tunnel CNAME target domain. See: https://developers.cloudflare.com/tunnel/routing/
	tunnelCNAMEDomain = "cfargotunnel.com"
	// Required last ingress rule for requests matching no hostname.
	tunnelCatchAllService = "http_status:404"
)

// createTunnel creates a remotely-managed Cloudflare Tunnel shared by all tunnel upstreams.
// See: https://www.pulumi.com/registry/packages/cloudflare/api-docs/zerotrusttunnelcloudflared/
func (e *EdgeProtection) createTunnel(ctx *pulumi.Context) (*cloudflare.ZeroTrustTunnelCloudflared, error) {
	var tunnelSecret pulumi.StringPtrInput
	if e.ZeroTrust != nil && e.ZeroTrust.TunnelSecret != nil {
		tunnelSecret = e.ZeroTrust.TunnelSecret.ToStringOutput().ToStringPtrOutput()
	}

	tunnelName := e.NewResourceName("tunnel", "zt", 63)
	tunnel, err := cloudflare.NewZeroTrustTunnelCloudflared(ctx, tunnelName, &cloudflare.ZeroTrustTunnelCloudflaredArgs{
		AccountId:    pulumi.String(e.CloudflareZone.CloudflareAccountID),
		Name:         pulumi.String(tunnelName),
		ConfigSrc:    pulumi.String(tunnelConfigSource),
		TunnelSecret: tunnelSecret,
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	return tunnel, nil
}

// createTunnelConfig routes each tunnel upstream hostname to its origin.
// Upstreams with Access get cloudflared-side validation of the Access JWT.
// See: https://www.pulumi.com/registry/packages/cloudflare/api-docs/zerotrusttunnelcloudflaredconfig/
func (e *EdgeProtection) createTunnelConfig(ctx *pulumi.Context, tunnel *cloudflare.ZeroTrustTunnelCloudflared) (*cloudflare.ZeroTrustTunnelCloudflaredConfig, error) {
	ingresses := cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArray{}
	for _, upstream := range e.Upstreams {
		if !isTunnelUpstream(upstream) {
			continue
		}
		ingresses = append(ingresses, e.newTunnelIngresses(upstream)...)
	}
	ingresses = append(ingresses, cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArgs{
		Service: pulumi.String(tunnelCatchAllService),
	})

	config, err := cloudflare.NewZeroTrustTunnelCloudflaredConfig(ctx, e.NewResourceName("tunnel", "zt-config", 63), &cloudflare.ZeroTrustTunnelCloudflaredConfigArgs{
		AccountId: pulumi.String(e.CloudflareZone.CloudflareAccountID),
		TunnelId:  tunnel.ID(),
		Source:    pulumi.String(tunnelConfigSource),
		Config: &cloudflare.ZeroTrustTunnelCloudflaredConfigConfigArgs{
			Ingresses: ingresses,
		},
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel config: %w", err)
	}

	return config, nil
}

// newTunnelIngresses returns the ingress rules for an upstream.
// Access-protected paths get their own rule (evaluated first) requiring a valid Access JWT.
func (e *EdgeProtection) newTunnelIngresses(upstream Upstream) cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArray {
	originHost := upstream.OriginURL.ToStringOutput().ApplyT(originHostname).(pulumi.StringOutput)

	newIngress := func(path pulumi.StringPtrInput, access cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressOriginRequestAccessPtrInput) cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArgs {
		return cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArgs{
			Hostname: pulumi.String(upstream.DomainURL),
			Path:     path,
			Service:  upstream.OriginURL,
			OriginRequest: &cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressOriginRequestArgs{
				// Cross-cloud origins (e.g. Cloud Run) route by Host and SNI.
				HttpHostHeader:   originHost,
				OriginServerName: originHost,
				Access:           access,
			},
		}
	}

	app, protected := e.accessApplications[upstream.DomainURL]
	if !protected || app == nil {
		return cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArray{newIngress(nil, nil)}
	}

	access := &cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressOriginRequestAccessArgs{
		AudTags:  pulumi.StringArray{app.Aud},
		Required: pulumi.Bool(true),
		TeamName: pulumi.String(e.ZeroTrust.TeamName),
	}

	// Whole hostname protected
	if len(upstream.Access.Paths) == 0 {
		return cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArray{newIngress(nil, access)}
	}

	ingresses := make(cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArray, 0, len(upstream.Access.Paths)+1)
	for _, path := range upstream.Access.Paths {
		ingresses = append(ingresses, newIngress(pulumi.String(tunnelPathRegex(path)), access))
	}

	return append(ingresses, newIngress(nil, nil))
}

// newTunnelToken returns the token cloudflared needs to run the tunnel, marked as secret.
// See: https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/
func (e *EdgeProtection) newTunnelToken(ctx *pulumi.Context, tunnel *cloudflare.ZeroTrustTunnelCloudflared) pulumi.StringOutput {
	token := cloudflare.GetZeroTrustTunnelCloudflaredTokenOutput(ctx, cloudflare.GetZeroTrustTunnelCloudflaredTokenOutputArgs{
		AccountId: pulumi.String(e.CloudflareZone.CloudflareAccountID),
		TunnelId:  tunnel.ID(),
	}, pulumi.Parent(e)).Token()

	// The invoke result is not secret-marked by the SDK.
	return pulumi.ToSecret(token).(pulumi.StringOutput)
}

// tunnelCNAMETarget returns the DNS target for hostnames routed through the tunnel.
func tunnelCNAMETarget(tunnel *cloudflare.ZeroTrustTunnelCloudflared) pulumi.StringOutput {
	return pulumi.Sprintf("%s.%s", tunnel.ID(), tunnelCNAMEDomain)
}

// tunnelPathRegex converts an Access path (e.g. "/admin") to a tunnel ingress path regex
// matching the path and its subpaths.
func tunnelPathRegex(path string) string {
	return fmt.Sprintf("^%s(/.*)?$", regexp.QuoteMeta(path))
}

// originHostname extracts the host of an origin URL (e.g. "backend-abc-uc.a.run.app").
func originHostname(originURL string) (string, error) {
	parsed, err := url.Parse(originURL)
	if err != nil {
		return "", fmt.Errorf("invalid origin URL %q: %w", originURL, err)
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("origin URL %q has no host", originURL)
	}

	return parsed.Hostname(), nil
}

func isTunnelUpstream(upstream Upstream) bool {
	return upstream.Connector == ConnectorTunnel
}
