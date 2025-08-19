package main

import (
	"log"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/pkg/cloudflare"
	"github.com/davidmontoyago/pulumi-cloudflare-free-edge-protection/pkg/cloudflare/config"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Load configuration from environment variables
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		// Convert config to EdgeProtectionArgs
		args := cfg.ToEdgeProtectionArgs()

		// Create the edge protection component
		edgeProtection, err := cloudflare.NewEdgeProtection(ctx, "cloudflare-edge-protection", args)
		if err != nil {
			return err
		}

		// Export key outputs
		ctx.Export("cloudflare_zone_id", edgeProtection.GetZone().ID())
		ctx.Export("cloudflare_zone_name", edgeProtection.GetZone().Name)
		ctx.Export("cloudflare_zone_status", edgeProtection.GetZone().Status)
		ctx.Export("cloudflare_zone_name_servers", edgeProtection.GetZone().NameServers)
		ctx.Export("cloudflare_backend_dns_record_id", edgeProtection.GetBackendDNSRecord().ID())
		ctx.Export("cloudflare_frontend_dns_record_id", edgeProtection.GetFrontendDNSRecord().ID())
		ctx.Export("cloudflare_root_dns_record_id", edgeProtection.GetRootDNSRecord().ID())

		log.Printf("Edge protection deployed successfully for domain: %s", cfg.Domain)
		log.Printf("Backend URL: %s -> api.%s", cfg.BackendURL, cfg.Domain)
		log.Printf("Frontend URL: %s -> www.%s", cfg.FrontendURL, cfg.Domain)
		log.Printf("Root domain: %s -> www.%s", cfg.Domain, cfg.Domain)

		return nil
	})
}
