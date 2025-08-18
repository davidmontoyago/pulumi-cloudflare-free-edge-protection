package cloudflare

import (
	"fmt"
	"math"
)

// newResourceName generates a consistent resource name with length limits.
func (e *EdgeProtection) newResourceName(serviceName, resourceType string, maxLength int) string {
	var resourceName string
	if resourceType == "" {
		resourceName = fmt.Sprintf("%s-%s", e.name, serviceName)
	} else {
		resourceName = fmt.Sprintf("%s-%s-%s", e.name, serviceName, resourceType)
	}

	if len(resourceName) <= maxLength {
		return resourceName
	}

	surplus := len(resourceName) - maxLength
	resourceName = e.truncateResourceName(serviceName, resourceType, surplus, maxLength)

	return resourceName
}

// truncateResourceName handles the complex logic for truncating resource names.
func (e *EdgeProtection) truncateResourceName(serviceName, resourceType string, surplus, maxLength int) string {
	mainComponentLength := len(e.name)
	if mainComponentLength > surplus {
		return e.truncateMainComponent(serviceName, resourceType, surplus)
	}

	return e.proportionalTruncate(serviceName, resourceType, maxLength)
}

// truncateMainComponent truncates the main component name when it's long enough.
func (e *EdgeProtection) truncateMainComponent(serviceName, resourceType string, surplus int) string {
	truncatedMainComponent := e.name[:len(e.name)-surplus]
	if resourceType == "" {
		return fmt.Sprintf("%s-%s", truncatedMainComponent, serviceName)
	}

	return fmt.Sprintf("%s-%s-%s", truncatedMainComponent, serviceName, resourceType)
}

// proportionalTruncate applies proportional truncation when main component is too short.
func (e *EdgeProtection) proportionalTruncate(serviceName, resourceType string, maxLength int) string {
	originalLength := len(fmt.Sprintf("%s-%s-%s", e.name, serviceName, resourceType))
	if resourceType == "" {
		originalLength = len(fmt.Sprintf("%s-%s", e.name, serviceName))
	}

	truncateFactorFloat := float64(maxLength) / float64(originalLength)
	truncateFactor := math.Floor(truncateFactorFloat*100) / 100

	mainComponentLength := int(math.Floor(float64(len(e.name)) * truncateFactor))
	serviceNameLength := int(math.Floor(float64(len(serviceName)) * truncateFactor))
	resourceTypeLength := int(math.Floor(float64(len(resourceType)) * truncateFactor))

	if resourceType == "" {
		return fmt.Sprintf("%s-%s", e.name[:mainComponentLength], serviceName[:serviceNameLength])
	}

	return fmt.Sprintf("%s-%s-%s", e.name[:mainComponentLength], serviceName[:serviceNameLength], resourceType[:resourceTypeLength])
}
