package cloudflare

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
	"..\\",
	"%2e%2e%2f",
	"%2e%2e%5c",
	"....//",
	"....\\",
	"%252e%252e%252f",
	"%c0%ae%c0%ae%c0%af",
	"%c1%1c%c1%1c%c1%1c",
	"..%2f",
	"..%5c",
	"..%252f",
	"..%255c",
}
