package cloudflare

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	accessApplicationType   = "self_hosted"
	accessDestinationPublic = "public"
	accessDecisionAllow     = "allow"
	// "Service Auth" action: authenticates service tokens without an IdP login.
	// See: https://developers.cloudflare.com/cloudflare-one/access-controls/policies/
	accessDecisionServiceAuth    = "non_identity"
	defaultAccessSessionDuration = "24h"
)

// accessResources groups the Access resources created for an upstream.
type accessResources struct {
	application   *cloudflare.ZeroTrustAccessApplication
	policies      []*cloudflare.ZeroTrustAccessPolicy
	serviceTokens []*cloudflare.ZeroTrustAccessServiceToken
}

// createAccessApplication puts a Cloudflare Access self-hosted application in front of an upstream.
// See: https://www.pulumi.com/registry/packages/cloudflare/api-docs/zerotrustaccessapplication/
func (e *EdgeProtection) createAccessApplication(ctx *pulumi.Context, upstream Upstream) (*accessResources, error) {
	name := upstreamRecordName(upstream)
	accountID := pulumi.String(e.CloudflareZone.CloudflareAccountID)
	resources := &accessResources{}

	// Identity policy: allowed emails and email domains
	userIncludes := make(cloudflare.ZeroTrustAccessPolicyIncludeArray, 0, len(upstream.Access.AllowedEmails)+len(upstream.Access.AllowedEmailDomains))
	for _, email := range upstream.Access.AllowedEmails {
		userIncludes = append(userIncludes, cloudflare.ZeroTrustAccessPolicyIncludeArgs{
			Email: &cloudflare.ZeroTrustAccessPolicyIncludeEmailArgs{Email: pulumi.String(email)},
		})
	}
	for _, domain := range upstream.Access.AllowedEmailDomains {
		userIncludes = append(userIncludes, cloudflare.ZeroTrustAccessPolicyIncludeArgs{
			EmailDomain: &cloudflare.ZeroTrustAccessPolicyIncludeEmailDomainArgs{Domain: pulumi.String(domain)},
		})
	}
	if len(userIncludes) > 0 {
		policyName := e.NewResourceName(fmt.Sprintf("access-%s-users", name), "zt", 63)
		policy, err := cloudflare.NewZeroTrustAccessPolicy(ctx, policyName, &cloudflare.ZeroTrustAccessPolicyArgs{
			AccountId: accountID,
			Name:      pulumi.String(policyName),
			Decision:  pulumi.String(accessDecisionAllow),
			Includes:  userIncludes,
		}, pulumi.Parent(e))
		if err != nil {
			return nil, fmt.Errorf("failed to create access users policy for %s: %w", upstream.DomainURL, err)
		}
		resources.policies = append(resources.policies, policy)
	}

	// Service Auth policy: machine-to-machine service tokens
	if len(upstream.Access.ServiceTokens) > 0 {
		tokenIncludes := make(cloudflare.ZeroTrustAccessPolicyIncludeArray, 0, len(upstream.Access.ServiceTokens))
		for _, tokenName := range upstream.Access.ServiceTokens {
			resourceName := e.NewResourceName(fmt.Sprintf("access-%s-%s", name, tokenName), "zt-token", 63)
			serviceToken, err := cloudflare.NewZeroTrustAccessServiceToken(ctx, resourceName, &cloudflare.ZeroTrustAccessServiceTokenArgs{
				AccountId: accountID,
				Name:      pulumi.String(resourceName),
			}, pulumi.Parent(e))
			if err != nil {
				return nil, fmt.Errorf("failed to create access service token %s for %s: %w", tokenName, upstream.DomainURL, err)
			}
			resources.serviceTokens = append(resources.serviceTokens, serviceToken)

			tokenIncludes = append(tokenIncludes, cloudflare.ZeroTrustAccessPolicyIncludeArgs{
				ServiceToken: &cloudflare.ZeroTrustAccessPolicyIncludeServiceTokenArgs{TokenId: serviceToken.ID()},
			})
		}

		policyName := e.NewResourceName(fmt.Sprintf("access-%s-services", name), "zt", 63)
		policy, err := cloudflare.NewZeroTrustAccessPolicy(ctx, policyName, &cloudflare.ZeroTrustAccessPolicyArgs{
			AccountId: accountID,
			Name:      pulumi.String(policyName),
			Decision:  pulumi.String(accessDecisionServiceAuth),
			Includes:  tokenIncludes,
		}, pulumi.Parent(e))
		if err != nil {
			return nil, fmt.Errorf("failed to create access service auth policy for %s: %w", upstream.DomainURL, err)
		}
		resources.policies = append(resources.policies, policy)
	}

	appPolicies := make(cloudflare.ZeroTrustAccessApplicationPolicyArray, 0, len(resources.policies))
	for i, policy := range resources.policies {
		appPolicies = append(appPolicies, cloudflare.ZeroTrustAccessApplicationPolicyArgs{
			Id:         policy.ID(),
			Precedence: pulumi.Int(i + 1),
		})
	}

	sessionDuration := upstream.Access.SessionDuration
	if sessionDuration == "" {
		sessionDuration = defaultAccessSessionDuration
	}

	appName := e.NewResourceName(fmt.Sprintf("access-%s", name), "zt-app", 63)
	application, err := cloudflare.NewZeroTrustAccessApplication(ctx, appName, &cloudflare.ZeroTrustAccessApplicationArgs{
		AccountId:              accountID,
		Name:                   pulumi.String(appName),
		Type:                   pulumi.String(accessApplicationType),
		Domain:                 pulumi.String(accessDomain(upstream)),
		Destinations:           accessDestinations(upstream),
		Policies:               appPolicies,
		SessionDuration:        pulumi.String(sessionDuration),
		OptionsPreflightBypass: pulumi.Bool(upstream.Access.BypassCORSPreflight),
		AppLauncherVisible:     pulumi.Bool(false),
	}, pulumi.Parent(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create access application for %s: %w", upstream.DomainURL, err)
	}
	resources.application = application

	return resources, nil
}

// accessDomain returns the application's primary domain: the hostname plus the first path, if any.
func accessDomain(upstream Upstream) string {
	if len(upstream.Access.Paths) == 0 {
		return upstream.DomainURL
	}

	return upstream.DomainURL + upstream.Access.Paths[0]
}

// accessDestinations returns the public hostname (and optional paths) protected by Access.
func accessDestinations(upstream Upstream) cloudflare.ZeroTrustAccessApplicationDestinationArray {
	if len(upstream.Access.Paths) == 0 {
		return cloudflare.ZeroTrustAccessApplicationDestinationArray{
			cloudflare.ZeroTrustAccessApplicationDestinationArgs{
				Type: pulumi.String(accessDestinationPublic),
				Uri:  pulumi.String(upstream.DomainURL),
			},
		}
	}

	destinations := make(cloudflare.ZeroTrustAccessApplicationDestinationArray, 0, len(upstream.Access.Paths))
	for _, path := range upstream.Access.Paths {
		destinations = append(destinations, cloudflare.ZeroTrustAccessApplicationDestinationArgs{
			Type: pulumi.String(accessDestinationPublic),
			Uri:  pulumi.String(upstream.DomainURL + path),
		})
	}

	return destinations
}
