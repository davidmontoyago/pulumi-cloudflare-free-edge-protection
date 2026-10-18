package cloudflare

// import (
// 	"fmt"

// 	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )

// setupContinousScriptMonitoring enables client side script monitoring included under the free tier.
// See: https://developers.cloudflare.com/page-shield/detection/monitor-connections-scripts/
// func (e *EdgeProtection) enableContinuousScriptMonitoring(ctx *pulumi.Context) (*cloudflare.PageShieldPolicy, error) {

// 	// cloudflare.NewWebAnalyticsRule()
// 	// cloudflare.NewWebAnalyticsSite()

// 	scriptMonitoringPolicy, err := cloudflare.NewPageShieldPolicy(ctx,
// 		e.NewResourceName("script-monitoring", "page-shield", 63), &cloudflare.PageShieldPolicyArgs{
// 			Action:      pulumi.String("allow"),
// 			Description: pulumi.String("Automatically detects and monitors changes to JavaScript files on your website."),
// 			Expression:  pulumi.String("true"),
// 			Value:       pulumi.String("true"),
// 			ZoneId:      pulumi.String(e.CloudflareZone.CloudflareAccountID),
// 			Enabled:     pulumi.Bool(true),
// 		})

// 	if err != nil {
// 		return nil, fmt.Errorf("failed to enable continuous script monitoring: %w", err)
// 	}

// 	return scriptMonitoringPolicy, nil
// }
