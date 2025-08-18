package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createZone creates a Cloudflare DNS Zone with free tier plan.
func (e *EdgeProtection) createZone(ctx *pulumi.Context) (*cloudflare.Zone, error) {
	zone, err := cloudflare.NewZone(ctx, e.newResourceName("zone", "dns", 64), &cloudflare.ZoneArgs{
		Account: cloudflare.ZoneAccountArgs{
			Id: pulumi.String(e.CloudflareAccountID),
		},
		// TODO extract yourdomain.com from domain URL
		Name: pulumi.String(e.Domain),
		Type: pulumi.String("full"), // Full zone management. A partial setup with CNAMEs wouldn't be enough.
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloudflare DNS zone: %w", err)
	}
	return zone, nil
}

// createDNSRecords creates all DNS records forzoneSettings the edge protection.
func (e *EdgeProtection) createDNSRecords(ctx *pulumi.Context, zone *cloudflare.Zone) error {
	// Backend DNS record (api.domain.com)
	backendRecord, err := cloudflare.NewDnsRecord(ctx, e.newResourceName("backend", "dns", 64), &cloudflare.DnsRecordArgs{
		ZoneId:  zone.ID(),
		Name:    pulumi.String(e.Domain), // api.yourdomain.com
		Content: pulumi.String(e.BackendURL),
		Type:    pulumi.String("CNAME"),
		Ttl:     pulumi.Float64(1), // Automatic TTL when proxied
		Proxied: pulumi.Bool(true), // Enable Cloudflare proxy for CDN + DDoS protection. A partial setup with CNAMEs wouldn't be enough.
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create backend DNS record: %w", err)
	}
	e.backendDNSRecord = backendRecord

	// Frontend DNS record (www.domain.com)
	_, err = cloudflare.NewRecord(ctx, e.newResourceName("frontend", "dns", 64), &cloudflare.RecordArgs{
		ZoneId:  zone.ID(),
		Name:    pulumi.String(e.Domain), // www.yourdomain.com
		Content: pulumi.String(e.FrontendURL),
		Type:    pulumi.String("CNAME"),
		Ttl:     pulumi.Float64(1),
		Proxied: pulumi.Bool(true), // Enables CDN and DDoS protection
	}, pulumi.Parent(e))
	if err != nil {
		return fmt.Errorf("failed to create frontend DNS record: %w", err)
	}
	// e.frontendDNSRecord = frontendRecord

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
