package cloudflare

import (
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// createZone manages a Cloudflare DNS Zone with free tier plan.
func (e *EdgeProtection) createZone(ctx *pulumi.Context) (*cloudflare.Zone, error) {
	// Extract mydomain.com from my-app.mydomain.com
	firstUpstream := e.Upstreams[0]
	zoneDomainURL := firstUpstream.DomainURL[strings.Index(firstUpstream.DomainURL, ".")+1:]

	zone, err := cloudflare.NewZone(ctx, e.newResourceName("zone", "dns", 64), &cloudflare.ZoneArgs{
		Account: cloudflare.ZoneAccountArgs{
			Id: pulumi.String(e.CloudflareZone.CloudflareAccountID),
		},
		Name: pulumi.String(zoneDomainURL),
		// Full zone management. A partial setup with CNAMEs wouldn't be enough.
		Type: pulumi.String("full"),
	}, pulumi.Protect(e.CloudflareZone.Protected))
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloudflare DNS zone: %w", err)
	}

	return zone, nil
}

// createDNSRecords creates DNS records pointing to backend and frontend services.
func (e *EdgeProtection) createDNSRecords(ctx *pulumi.Context, zone *cloudflare.Zone) ([]*cloudflare.DnsRecord, error) {
	var upstreamRecords []*cloudflare.DnsRecord
	for _, upstream := range e.Upstreams {
		recordName := strings.Split(upstream.DomainURL, ".")[0]
		recordResourceName := e.newResourceName(fmt.Sprintf("upstream-%s", recordName), "dns", 64)
		record, err := cloudflare.NewDnsRecord(ctx, recordResourceName, &cloudflare.DnsRecordArgs{
			ZoneId:  zone.ID(),
			Name:    pulumi.String(upstream.DomainURL),
			Content: pulumi.String(upstream.CanonicalNameURL),
			Type:    pulumi.String("CNAME"),
			// Enable Cloudflare proxy for CDN + DDoS protection
			// For first time setup, set to false until the
			// cross-cloud DNS is resolved (E.g. In GCP Doman Mapping shows success).
			Proxied: pulumi.Bool(!upstream.DisableProtection),
			Ttl:     pulumi.Float64(1), // Automatic TTL when proxied
		}, pulumi.Parent(e), pulumi.Protect(e.CloudflareZone.Protected))
		if err != nil {
			return nil, fmt.Errorf("failed to create upstream DNS record %s: %w", upstream.DomainURL, err)
		}
		upstreamRecords = append(upstreamRecords, record)
	}

	return upstreamRecords, nil
}
