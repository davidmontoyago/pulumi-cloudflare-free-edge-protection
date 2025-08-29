package cloudflare

import (
	"fmt"
	"strings"
)

// WAF Path Blocking Configuration
// Generated slices for comprehensive web application firewall protection

// WordPressPaths - Paths commonly targeted by attackers in this category
var WordPressPaths = []string{
	"/wp-admin/",
	"/wp-login.php",
	"/wp-config.php",
	"/xmlrpc.php",
	"/wp-includes/",
	"/wp-content/debug.log",
	"/wp-json/wp/v2/users",
	"/wp-cron.php",
	"/wp-config-sample.php",
	"/wp-load.php",
	"/wp-settings.php",
	"/wp-blog-header.php",
	"/wp-links-opml.php",
	"/wp-trackback.php",
	"/wp-comments-post.php",
	"/readme.html",
	"/license.txt",
}

// DatabaseManagementPaths - Paths commonly targeted by attackers in this category
var DatabaseManagementPaths = []string{
	"/phpmyadmin/",
	"/pma/",
	"/phpMyAdmin/",
	"/mysql/",
	"/myadmin/",
	"/db/",
	"/dbadmin/",
	"/database/",
	"/adminer.php",
	"/adminer/",
	"/sql/",
	"/mysql-admin/",
	"/phpMiniAdmin.php",
	"/mydb/",
}

// ConfigurationFilePaths - Paths commonly targeted by attackers in this category
var ConfigurationFilePaths = []string{
	"/.env",
	"/.env.local",
	"/.env.production",
	"/.env.development",
	"/.env.staging",
	"/config.php",
	"/configuration.php",
	"/config/",
	"/settings.php",
	"/app.config",
	"/web.config",
	"/application.properties",
	"/.htaccess",
	"/.htpasswd",
	"/httpd.conf",
	"/nginx.conf",
	"/apache.conf",
}

// VersionControlPaths - Paths commonly targeted by attackers in this category
var VersionControlPaths = []string{
	"/.git/",
	"/.git/HEAD",
	"/.git/config",
	"/.git/index",
	"/.git/objects/",
	"/.git/refs/",
	"/.git/logs/",
	"/.svn/",
	"/.hg/",
	"/.bzr/",
	"/CVS/",
	"/.gitignore",
	"/.gitconfig",
	"/git/",
	"/.git-credentials",
}

// AdminPanelPaths - Paths commonly targeted by attackers in this category
var AdminPanelPaths = []string{
	"/admin/",
	"/administrator/",
	"/admin.php",
	"/admin.html",
	"/adminpanel/",
	"/control/",
	"/controlpanel/",
	"/cpanel/",
	"/dashboard/",
	"/manage/",
	"/manager/",
	"/panel/",
	"/webadmin/",
	"/sysadmin/",
	"/root/",
	"/superuser/",
}

// BackupFilePaths - Paths commonly targeted by attackers in this category
var BackupFilePaths = []string{
	"/backup/",
	"/backups/",
	"/bak/",
	"/backup.sql",
	"/backup.zip",
	"/backup.tar.gz",
	"/db_backup/",
	"/site_backup/",
	"/*.bak",
	"/*.backup",
	"/*.old",
	"/*.orig",
	"/*.tmp",
	"/dump/",
	"/dumps/",
	"/.backup/",
}

// DevelopmentTestingPaths - Paths commonly targeted by attackers in this category
var DevelopmentTestingPaths = []string{
	"/test/",
	"/tests/",
	"/testing/",
	"/dev/",
	"/development/",
	"/debug/",
	"/tmp/",
	"/temp/",
	"/cache/",
	"/log/",
	"/logs/",
	"/error_log",
	"/access_log",
	"/phpinfo.php",
	"/info.php",
	"/test.php",
	"/debug.php",
}

// SystemInformationPaths - Paths commonly targeted by attackers in this category
var SystemInformationPaths = []string{
	"/proc/",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/hosts",
	"/var/log/",
	"/usr/",
	"/bin/",
	"/boot/",
	"/dev/",
	"/home/",
	"/lib/",
	"/media/",
	"/mnt/",
	"/opt/",
	"/root/",
	"/sbin/",
	"/srv/",
	"/sys/",
	"/var/",
}

// APIEndpointPaths - Paths commonly targeted by attackers in this category
var APIEndpointPaths = []string{
	"/api/v1/admin",
	"/api/admin",
	"/api/config",
	"/api/users",
	"/api/user/",
	"/api/internal/",
	"/api/private/",
	"/api/debug/",
	"/api/test/",
	"/graphql",
	"/swagger/",
	"/swagger-ui/",
	"/api-docs/",
	"/openapi.json",
	"/api/health",
}

// ApplicationSpecificPaths - Paths commonly targeted by attackers in this category
var ApplicationSpecificPaths = []string{
	"/app/",
	"/application/",
	"/includes/",
	"/inc/",
	"/lib/",
	"/libraries/",
	"/vendor/",
	"/composer.json",
	"/composer.lock",
	"/package.json",
	"/package-lock.json",
	"/node_modules/",
	"/.dockerignore",
	"/Dockerfile",
	"/docker-compose.yml",
	"/Makefile",
}

// ServerFilePaths - Paths commonly targeted by attackers in this category
var ServerFilePaths = []string{
	"/server-status",
	"/server-info",
	"/status",
	"/stats/",
	"/statistics/",
	"/metrics/",
	"/health/",
	"/ping",
	"/version",
	"/info",
	"/.well-known/",
	"/crossdomain.xml",
	"/clientaccesspolicy.xml",
	"/robots.txt",
	"/sitemap.xml",
}

// CMSSpecificPaths - Paths commonly targeted by attackers in this category
var CMSSpecificPaths = []string{
	"/administrator/",
	"/components/",
	"/modules/",
	"/templates/",
	"/plugins/",
	"/libraries/",
	"/configuration.php",
	"/sites/default/settings.php",
	"/sites/default/files/",
	"/user/",
	"/admin/config/",
	"/app/etc/local.xml",
	"/admin/",
	"/downloader/",
	"/concrete/",
	"/system/",
	"/fuel/",
	"/craft/",
	"/ghost/",
	"/typo3/",
}

// PathTraversalPatterns - Paths commonly targeted by attackers in this category
var PathTraversalPatterns = []string{
	"../",
	"%2e%2e",
	"%2e%2e%2f",
	"%2e%2e%5c",
	"....//",
	"%252e%252e%252f",
	"%c0%ae%c0%ae%c0%af",
	"%c1%1c%c1%1c%c1%1c",
	"..%2f",
	"..%5c",
	"..%252f",
	"..%255c",
}

// MaliciousUserAgents - User agents commonly used by attackers and bots
var MaliciousUserAgents = []string{
	"sqlmap",
	"nmap",
	"nikto",
	"masscan",
	"dirbuster",
}

// generateCMSPathBlockingExpression creates WAF expression for CMS and WordPress specific paths
func generateCMSPathBlockingExpression() string {
	// Group 1: CMS-related paths (WordPress, CMS-specific, Application-specific)
	group1Paths := make([]string, 0)
	group1Paths = append(group1Paths, WordPressPaths...)
	group1Paths = append(group1Paths, CMSSpecificPaths...)
	group1Paths = append(group1Paths, ApplicationSpecificPaths...)

	return generatePathExpression(group1Paths)
}

// generateSystemConfigPathBlockingExpression creates WAF expression for system and configuration paths
func generateSystemConfigPathBlockingExpression() string {
	// Group 2: System, configuration, and version control paths
	group2Paths := make([]string, 0)
	group2Paths = append(group2Paths, ConfigurationFilePaths...)
	group2Paths = append(group2Paths, VersionControlPaths...)
	group2Paths = append(group2Paths, SystemInformationPaths...)
	group2Paths = append(group2Paths, PathTraversalPatterns...)

	return generatePathExpression(group2Paths)
}

// generateAdminBackupPathBlockingExpression creates WAF expression for admin and backup paths
func generateAdminBackupPathBlockingExpression() string {
	// Group 3: Admin panels, backup files, and database management
	group3Paths := make([]string, 0)
	group3Paths = append(group3Paths, AdminPanelPaths...)
	group3Paths = append(group3Paths, BackupFilePaths...)
	group3Paths = append(group3Paths, DatabaseManagementPaths...)

	return generatePathExpression(group3Paths)
}

// generateDevAPIPathBlockingExpression creates WAF expression for development and API paths
func generateDevAPIPathBlockingExpression() string {
	// Group 4: Development, testing, API endpoints, and server info
	group4Paths := make([]string, 0)
	group4Paths = append(group4Paths, DevelopmentTestingPaths...)
	group4Paths = append(group4Paths, APIEndpointPaths...)
	group4Paths = append(group4Paths, ServerFilePaths...)

	return generatePathExpression(group4Paths)
}

// generatePathExpression helper function to create WAF expressions from path slices
func generatePathExpression(paths []string) string {
	expressions := make([]string, len(paths))
	for i, path := range paths {
		expressions[i] = fmt.Sprintf(`(http.request.uri.path contains "%s")`, path)
	}

	// Join all expressions with "or" and wrap in parentheses
	return fmt.Sprintf("(%s)", strings.Join(expressions, " or "))
}

// generateUserAgentBlockingExpression creates WAF expression for blocking malicious user agents
func generateUserAgentBlockingExpression() string {
	// Create user agent expressions
	userAgentExpressions := make([]string, len(MaliciousUserAgents))
	for i, agent := range MaliciousUserAgents {
		userAgentExpressions[i] = fmt.Sprintf(`(http.user_agent contains "%s")`, agent)
	}

	// Add additional user agent checks
	additionalChecks := []string{
		`(http.user_agent eq "")`,
		`(len(http.user_agent) < 10)`,
	}

	// Combine all expressions
	allExpressions := append(userAgentExpressions, additionalChecks...)

	// Join all expressions with "or" and wrap in parentheses
	return fmt.Sprintf("(%s)", strings.Join(allExpressions, " or "))
}
