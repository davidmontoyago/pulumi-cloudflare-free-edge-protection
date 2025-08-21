package cloudflare

import (
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createZone creates a Cloudflare DNS Zone with free tier plan.
func (e *EdgeProtection) createZone(ctx *pulumi.Context) (*cloudflare.Zone, error) {
	// Extract mydomain.com from my-app.mydomain.com
	zoneDomainURL := e.Domain[strings.Index(e.Domain, ".")+1:]

	zone, err := cloudflare.NewZone(ctx, e.newResourceName("zone", "dns", 64), &cloudflare.ZoneArgs{
		Account: cloudflare.ZoneAccountArgs{
			Id: pulumi.String(e.CloudflareAccountID),
		},
		Name: pulumi.String(zoneDomainURL),
		// Full zone management. A partial setup with CNAMEs wouldn't be enough.
		Type: pulumi.String("full"),
	},
		// TODO make configurable
		pulumi.Protect(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloudflare DNS zone: %w", err)
	}

	return zone, nil
}

// createDNSRecords creates DNS records pointing to backend and frontend services.
func (e *EdgeProtection) createDNSRecords(ctx *pulumi.Context, zone *cloudflare.Zone) error {
	// Backend DNS record (api.domain.com)
	backendRecord, err := cloudflare.NewDnsRecord(ctx, e.newResourceName("backend", "dns", 64), &cloudflare.DnsRecordArgs{
		ZoneId:  zone.ID(),
		Name:    pulumi.Sprintf("api.%s", e.Domain),
		Content: e.BackendURL,
		Type:    pulumi.String("CNAME"),
		Ttl:     pulumi.Float64(1), // Automatic TTL when proxied
		Proxied: pulumi.Bool(true), // Enable Cloudflare proxy for CDN + DDoS protection. A partial setup with CNAMEs wouldn't be enough.
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create backend DNS record: %w", err)
	}
	e.backendDNSRecord = backendRecord

	// Frontend DNS record (domain.com)
	frontendRecord, err := cloudflare.NewDnsRecord(ctx, e.newResourceName("frontend", "dns", 64), &cloudflare.DnsRecordArgs{
		ZoneId:  zone.ID(),
		Name:    pulumi.String(e.Domain),
		Content: e.FrontendURL,
		Type:    pulumi.String("CNAME"),
		Ttl:     pulumi.Float64(1), // Automatic TTL when proxied
		Proxied: pulumi.Bool(true), // Enables CDN and DDoS protection
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create frontend DNS record: %w", err)
	}
	e.frontendDNSRecord = frontendRecord

	// Root domain redirect to www
	// rootRecord, err := cloudflare.NewRecord(ctx, e.newResourceName("root", "dns", 64), &cloudflare.RecordArgs{
	// 	ZoneId:  zone.ID(),
	// 	Name:    pulumi.String("@"), // Root domain
	// 	Value:   pulumi.String(e.FrontendURL),
	// 	Type:    pulumi.String("CNAME"),
	// 	Ttl:     pulumi.Int(1),
	// 	Proxied: pulumi.Bool(true),
	// }, pulumi.Parent(e))
	// if err != nil {
	// 	return fmt.Errorf("failed to create root DNS record: %w", err)
	// }
	// e.rootDNSRecord = rootRecord

	return nil
}
