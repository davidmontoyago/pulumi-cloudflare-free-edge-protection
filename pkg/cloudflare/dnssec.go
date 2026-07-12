package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	dnssecStatusActive   = "active"
	dnssecStatusDisabled = "disabled"
)

// enableDNSSEC enables DNSSEC zone signing and returns DS record details that can
// be exported for manual registrar updates when needed.
func (e *EdgeProtection) enableDNSSEC(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.ZoneDnssec, error) {
	dnssec, err := cloudflare.NewZoneDnssec(ctx, e.NewResourceName("dnssec", "dns", 63), &cloudflare.ZoneDnssecArgs{
		ZoneId: zone.ID(),
		Status: e.DNSSECEnabled.ApplyT(func(enabled bool) string {
			if enabled {
				return dnssecStatusActive
			}

			return dnssecStatusDisabled
		}).(pulumi.StringOutput),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to enable DNSSEC: %w", err)
	}

	return dnssec, nil
}
