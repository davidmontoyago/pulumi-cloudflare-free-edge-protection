package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// configureURLNormalization normalizes incoming request URLs (and, depending on scope, the
// URL forwarded to the origin) so that WAF/Rules evaluation and the origin see a consistent,
// decoded URL. This closes common WAF-bypass techniques that rely on percent-encoding,
// repeated slashes, or backslash path separators.
// See: https://developers.cloudflare.com/rules/normalization/
func (e *EdgeProtection) configureURLNormalization(ctx *pulumi.Context, zone *cloudflare.Zone) (*cloudflare.UrlNormalizationSettings, error) {
	urlNormalization, err := cloudflare.NewUrlNormalizationSettings(ctx, e.NewResourceName("url-normalization", "security", 63), &cloudflare.UrlNormalizationSettingsArgs{
		ZoneId: zone.ID(),
		Type:   e.URLNormalizationType,
		Scope:  e.URLNormalizationScope,
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to configure URL normalization: %w", err)
	}

	return urlNormalization, nil
}
