"""
Directory and Common Path Enumeration Module — Enhanced.

Multi-stage discovery pipeline:
  1. Multi-probe Wildcard Detection: 3 random paths + body-hash comparison for reliable
     false-positive filtering (replaces single-probe approach).
  2. Static Wordlist (600+ paths): APIs, admin panels, configs, secrets, frameworks,
     cloud infra, CMS platforms, build files, and more.
  3. robots.txt Parsing: Extracts Disallow/Allow entries declared by the server itself.
  4. Sitemap Crawling: Follows sitemap_index.xml chains (up to 6 sitemaps),
     extracts all <loc> paths as enumeration candidates.
  5. Homepage HTML Crawling: Mines <a href>, <form action>, <script src> from the landing page.
  6. JS Endpoint Mining: Downloads linked JavaScript files and regex-extracts embedded API routes.
  7. Backup Extension Probing: Tests .bak, .old, .orig, .copy, ~, .tmp, .swp variants.
  8. Recursive Directory Scanning: Probes 1 level inside each found open directory.
  9. Snippet Grabbing: Downloads first 200 chars of critical sensitive files when open.
"""

import asyncio
import hashlib
import re
import uuid
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

import aiohttp

from utils.safety import TIMEOUTS, ScanError, error_response
from utils.concurrency import run_bounded

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
    "/sitemap1.xml", "/sitemap2.xml", "/sitemap3.xml", "/sitemap-news.xml",
    "/sitemap-posts.xml", "/sitemap-pages.xml", "/humans.txt", "/ads.txt",
    "/.well-known/security.txt", "/.well-known/change-password",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    "/.well-known/host-meta", "/.well-known/webfinger", "/.well-known/traffic-advice",
    "/favicon.ico", "/manifest.json", "/browserconfig.xml", "/security.txt",
    "/CHANGELOG.md", "/CHANGES.txt", "/README.md", "/readme.txt",
    "/version.txt", "/version.json", "/build.txt", "/INSTALL", "/LICENSE",
    "/.env", "/.env.local", "/.env.production", "/.env.staging", "/.env.backup",
    "/.env.example", "/.env.sample", "/.env.test", "/.env.dev", "/.env.ci",
    "/config.json", "/config.yml", "/config.yaml", "/config.php", "/config.ini",
    "/config.xml", "/config.toml", "/configuration.json",
    "/settings.json", "/settings.py", "/settings.php", "/app.config",
    "/web.config", "/appsettings.json", "/appsettings.Development.json",
    "/database.yml", "/database.json", "/secrets.json", "/secrets.yml",
    "/credentials.json", "/key.json", "/keys.json", "/service-account.json",
    "/private.pem", "/private.key", "/server.key", "/ssl.key", "/tls.key",
    "/.npmrc", "/.babelrc", "/.eslintrc.json",
    "/tsconfig.json", "/jsconfig.json", "/jest.config.js",
    "/app.yaml", "/app.json", "/Procfile", "/nginx.conf", "/httpd.conf",
    "/.travis.yml", "/.circleci/config.yml", "/.github/workflows/deploy.yml",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG", "/.git/index",
    "/.git/FETCH_HEAD", "/.git/packed-refs", "/.git/refs/heads/master",
    "/.git/refs/heads/main", "/.git/logs/HEAD",
    "/.gitignore", "/.gitmodules", "/.gitattributes",
    "/.svn/entries", "/.svn/wc.db", "/.hg/hgrc", "/.bzr/branch-format",
    "/.htaccess", "/.htpasswd", "/.DS_Store", "/Thumbs.db",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/.user.ini", "/php.ini",
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/index.php",
    "/admin/login.php", "/admin/config", "/admin/users", "/admin/settings",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-cron.php", "/wp-config.php",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/",
    "/adminer", "/adminer.php", "/dbadmin",
    "/cpanel", "/whm", "/plesk", "/directadmin",
    "/panel", "/panel/", "/controlpanel", "/control-panel",
    "/manage", "/manager", "/management",
    "/backend", "/backoffice", "/superuser", "/superadmin",
    "/admin1", "/admin2", "/admin_area", "/siteadmin", "/webadmin",
    "/adminpanel", "/admin-panel", "/cms-admin",
    "/login", "/signin", "/signup", "/register", "/logout", "/logoff",
    "/auth", "/auth/login", "/auth/register", "/auth/logout",
    "/auth/callback", "/auth/refresh", "/auth/verify",
    "/oauth/authorize", "/oauth/token", "/oauth/callback",
    "/oauth2/authorize", "/oauth2/token", "/oauth2/callback",
    "/saml/login", "/saml/metadata", "/saml/acs", "/saml/slo",
    "/sso", "/sso/login", "/sso/callback",
    "/forgot-password", "/reset-password", "/change-password", "/set-password",
    "/2fa", "/mfa", "/totp", "/otp", "/verify", "/confirm",
    "/account/login", "/account/register", "/account/forgot-password",
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/",
    "/api/v3", "/api/v3/", "/api/v4", "/api/v5",
    "/api/latest", "/api/beta", "/api/alpha",
    "/api/internal", "/api/private", "/api/public", "/api/external",
    "/api/health", "/api/status", "/api/ping", "/api/info", "/api/version",
    "/api/users", "/api/user", "/api/me", "/api/profile", "/api/account",
    "/api/admin", "/api/auth", "/api/login", "/api/token", "/api/refresh",
    "/api/search", "/api/data", "/api/config", "/api/settings", "/api/keys",
    "/api/files", "/api/upload", "/api/download", "/api/export", "/api/import",
    "/api/reports", "/api/analytics", "/api/dashboard", "/api/metrics", "/api/stats",
    "/api/products", "/api/orders", "/api/customers", "/api/payments",
    "/api/notifications", "/api/messages", "/api/webhooks", "/api/events",
    "/api/v1/users", "/api/v1/me", "/api/v1/auth", "/api/v1/login",
    "/api/v1/admin", "/api/v1/health", "/api/v1/status", "/api/v1/config",
    "/api/v1/token", "/api/v1/register", "/api/v1/profile", "/api/v1/products",
    "/api/v2/users", "/api/v2/me", "/api/v2/auth", "/api/v2/token",
    "/api/v3/users", "/api/v3/me",
    "/graphql", "/graphql/", "/graphiql", "/graphql/playground",
    "/graphql/explorer", "/graphql/subscriptions", "/api/graphql",
    "/v1/graphql", "/v2/graphql", "/gql",
    "/rest", "/rest/", "/rest/api", "/rest/v1", "/rest/v2", "/rest/v3",
    "/rpc", "/rpc/", "/jsonrpc", "/xmlrpc.php",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json", "/openapi.json", "/openapi.yaml",
    "/redoc", "/docs", "/documentation", "/scalar", "/rapidoc",
    "/v1", "/v2", "/v3",
    "/debug", "/debug/", "/phpinfo.php", "/info.php", "/test.php", "/test.html",
    "/_debug_toolbar", "/debugbar", "/telescope", "/horizon", "/pulse",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/metrics", "/actuator/mappings", "/actuator/beans",
    "/actuator/configprops", "/actuator/loggers", "/actuator/threaddump",
    "/actuator/heapdump", "/actuator/conditions", "/actuator/sessions",
    "/actuator/scheduledtasks", "/actuator/auditevents",
    "/__debug__", "/django-admin", "/django-admin/", "/django-admin/login/",
    "/api-auth/login/", "/api-auth/logout/",
    "/rails/info", "/rails/info/properties", "/rails/mailers",
    "/_ignition/health-check", "/_ignition/execute-solution",
    "/server-status", "/server-info", "/nginx_status", "/basic_status",
    "/status", "/health", "/health/", "/healthz", "/readyz", "/livez",
    "/ping", "/metrics", "/stats", "/__health", "/__status",
    "/management/health", "/management/info", "/management/metrics",
    "/test", "/tests", "/dev", "/staging",
    "/grafana", "/kibana", "/jaeger", "/zipkin", "/prometheus",
    "/metrics/json", "/_cat/indices", "/_cluster/health",
    "/solr", "/solr/admin", "/consul", "/v1/agent/self",
    "/backup", "/backups", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/backup.json", "/db_backup.sql", "/dump.sql",
    "/dump", "/dumps", "/db.sql", "/database.sql", "/mysql.sql",
    "/data", "/data/", "/export", "/exports", "/import",
    "/logs", "/log", "/error.log", "/access.log", "/debug.log",
    "/app.log", "/application.log", "/server.log", "/error_log",
    "/tmp", "/temp", "/cache", "/swap",
    "/wp-content", "/wp-includes", "/wp-json", "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
    "/wp-trackback.php", "/wp-comments-post.php",
    "/joomla", "/components/", "/modules/", "/plugins/", "/templates/",
    "/sites/default/files", "/sites/default/settings.php",
    "/core/misc/drupal.js", "/misc/drupal.js",
    "/typo3", "/typo3conf", "/typo3temp",
    "/magento", "/skin/frontend",
    "/_next/static", "/_next/data", "/_next/image",
    "/_nuxt", "/_nuxt/builds",
    "/.aws/credentials", "/.aws/config",
    "/docker-compose.yml", "/docker-compose.yaml", "/Dockerfile", "/.dockerenv",
    "/kubernetes.yml", "/k8s.yml", "/.kube/config",
    "/terraform.tfstate", "/terraform.tfvars", "/terraform.tf",
    "/ansible.cfg", "/inventory", "/hosts", "/playbook.yml",
    "/.ssh/id_rsa", "/.ssh/id_rsa.pub", "/.ssh/authorized_keys", "/.ssh/known_hosts",
    "/Jenkinsfile",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/composer.json", "/composer.lock",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock", "/pyproject.toml",
    "/Gemfile", "/Gemfile.lock", "/Rakefile",
    "/pom.xml", "/build.gradle", "/build.gradle.kts", "/settings.gradle",
    "/Makefile", "/Gruntfile.js", "/gulpfile.js", "/webpack.config.js",
    "/vite.config.js", "/rollup.config.js", "/babel.config.js",
    "/uploads", "/upload", "/files", "/downloads", "/download",
    "/images", "/img", "/assets", "/static", "/media",
    "/public", "/private", "/protected",
    "/user", "/users", "/account", "/accounts", "/profile", "/profiles",
    "/storage", "/content", "/resources",
    "/cgi-bin", "/cgi-bin/admin", "/cgi-bin/login", "/cgi-bin/test.cgi",
    "/shell.php", "/cmd.php", "/exec.php",
    "/trace.axd", "/elmah.axd",
    "/pgadmin", "/pgadmin4", "/redis-commander", "/mongo-express",
    "/myadmin", "/mysqlmanager",

    "/about", "/about-us", "/about_us", "/aboutus",
    "/contact", "/contact-us", "/contact_us", "/contactus",
    "/help", "/support", "/faq", "/faqs", "/knowledgebase",
    "/home", "/news", "/blog", "/blogs", "/feed", "/feeds", "/rss",
    "/shop", "/store", "/market", "/marketplace",
    "/search", "/results", "/find", "/query",
    "/portal", "/welcome", "/start",
    "/old", "/new", "/archive", "/archives", "/deprecated", "/legacy",
    "/apps", "/application", "/applications",
    "/web", "/www",
    "/lib", "/libs", "/library", "/libraries", "/include", "/includes",
    "/js", "/css", "/fonts", "/font", "/icons", "/icon", "/svg",
    "/src", "/source", "/dist", "/release", "/releases",
    "/service", "/services",
    "/jobs", "/careers", "/pricing", "/plans", "/features", "/enterprise",
    "/console", "/cp", "/webmaster", "/webpanel",
    "/member", "/members", "/employee", "/employees", "/staff", "/team",
    "/billing", "/invoice", "/invoices", "/payment", "/checkout", "/cart",
    "/basket", "/wishlist", "/order", "/orders",
    "/ticket", "/tickets", "/helpdesk", "/desk", "/issue", "/issues",
    "/chat", "/inbox", "/notification",
    "/activate", "/activation", "/verification", "/unsubscribe", "/subscribe",
    "/newsletter", "/campaign", "/campaigns",
    "/gallery", "/photos", "/photo", "/video", "/videos", "/audio",
    "/wiki", "/guide", "/guides", "/manual", "/manuals", "/howto", "/tutorial", "/tutorials",
    "/forum", "/forums", "/board", "/boards", "/community",
    "/post", "/posts", "/article", "/articles",
    "/comment", "/comments", "/review", "/reviews", "/feedback", "/rating", "/ratings",
    "/tag", "/tags", "/category", "/categories", "/topic", "/topics",
    "/product", "/products", "/catalog", "/catalogue", "/item", "/items",
    "/shipping", "/delivery", "/track", "/tracking",
    "/customer", "/customers", "/vendor", "/vendors", "/partner", "/partners",
    "/project", "/projects", "/task", "/tasks", "/workflow", "/workflows",
    "/event", "/events", "/calendar", "/schedule", "/meeting", "/meetings",
    "/statistics", "/reporting",
    "/audit", "/audits", "/activity", "/activities",
    "/notice", "/notices", "/announcement", "/announcements",
    "/policy", "/policies", "/terms", "/privacy", "/legal", "/agreement", "/tos", "/gdpr",
    "/ajax", "/async", "/xhr",
    "/proxy", "/tunnel", "/relay",
    "/mobile", "/native", "/ios", "/android",
    "/overview", "/summary", "/main",
    "/lock", "/locked", "/ban", "/banned", "/block", "/blocked",
    "/echo", "/heartbeat",
    "/token", "/tokens", "/session", "/sessions",
    "/permission", "/permissions", "/role", "/roles", "/scope", "/scopes",
    "/group", "/groups", "/org", "/organization", "/organizations",
    "/department", "/departments",
    "/webhook", "/webhooks", "/callback", "/callbacks",
    "/queue", "/queues", "/worker", "/workers", "/cron",
    "/flush", "/clear", "/purge",
    "/migrate", "/migration", "/migrations", "/seed", "/seeds",
    "/alive", "/ready", "/startup", "/probe",

    "/index.php", "/home.php", "/main.php", "/default.php", "/welcome.php",
    "/login.php", "/logout.php", "/register.php", "/signup.php",
    "/admin.php", "/dashboard.php", "/panel.php", "/control.php",
    "/profile.php", "/account.php", "/user.php", "/users.php",
    "/settings.php", "/config.php", "/configuration.php",
    "/contact.php", "/about.php", "/help.php", "/support.php",
    "/upload.php", "/download.php", "/file.php", "/files.php",
    "/search.php", "/news.php", "/blog.php", "/gallery.php",
    "/error.php", "/404.php", "/500.php", "/maintenance.php",
    "/ajax.php", "/api.php", "/db.php", "/database.php",
    "/functions.php", "/function.php", "/common.php", "/global.php",
    "/lib.php", "/library.php", "/include.php", "/includes.php",
    "/footer.php", "/header.php", "/sidebar.php",
    "/install.php", "/setup.php", "/wizard.php", "/install/index.php",
    "/update.php", "/upgrade.php",
    "/cron.php", "/scheduler.php", "/queue.php",
    "/sitemap.php", "/feed.php", "/rss.php",
    "/edit.php", "/delete.php", "/create.php", "/add.php", "/new.php",
    "/view.php", "/show.php", "/detail.php", "/details.php",
    "/list.php", "/mail.php", "/send.php", "/email.php",
    "/check.php", "/verify.php", "/validate.php", "/token.php",
    "/payment.php", "/billing.php", "/checkout.php", "/cart.php",
    "/order.php", "/orders.php", "/invoice.php",
    "/export.php", "/import.php", "/report.php", "/reports.php",
    "/chat.php", "/message.php", "/messages.php",
    "/redirect.php", "/forward.php", "/goto.php",
    "/test.php", "/debug.php", "/log.php", "/trace.php",
    "/backup.php", "/restore.php", "/dump.php",
    "/clear.php", "/flush.php", "/cache.php", "/purge.php",
    "/auth.php", "/oauth.php", "/sso.php",

    "/default.asp", "/index.asp", "/home.asp", "/login.asp",
    "/admin.asp", "/register.asp", "/contact.asp", "/about.asp",
    "/default.aspx", "/index.aspx", "/home.aspx", "/login.aspx",
    "/admin.aspx", "/register.aspx", "/contact.aspx", "/about.aspx",
    "/dashboard.aspx", "/profile.aspx", "/account.aspx", "/settings.aspx",
    "/upload.aspx", "/download.aspx", "/search.aspx", "/error.aspx",
    "/global.asax", "/App_Config", "/App_Data", "/App_Code",
    "/WebResource.axd", "/ScriptResource.axd",

    "/index.jsp", "/login.jsp", "/admin.jsp", "/dashboard.jsp",
    "/register.jsp", "/profile.jsp", "/home.jsp", "/main.jsp",
    "/WEB-INF/web.xml", "/WEB-INF/classes/", "/WEB-INF/lib/",
    "/META-INF/MANIFEST.MF",
    "/manager/html", "/host-manager/html",
    "/manager/text", "/manager/status",
    "/j_spring_security_check", "/j_security_check",
    "/h2-console", "/h2",
    "/jolokia", "/jolokia/list",

    "/index.html", "/index.htm", "/home.html", "/default.html",
    "/login.html", "/register.html", "/signup.html",
    "/admin.html", "/dashboard.html", "/panel.html",
    "/about.html", "/contact.html", "/help.html", "/faq.html",
    "/404.html", "/500.html", "/error.html", "/403.html",
    "/maintenance.html", "/offline.html",
    "/terms.html", "/privacy.html", "/license.html",

    "/config/database.yml", "/config/secrets.yml", "/config/master.key",
    "/config/credentials.yml.enc", "/config/application.yml",
    "/config/application.properties", "/config/application.json",
    "/config/log4j.properties", "/config/log4j2.xml",
    "/local.xml", "/local.config", "/local.properties",
    "/wp-config.php.bak", "/wp-config.php.save",
    "/wp-config.php.orig", "/wp-config.bak",
    "/web.config.bak", "/web.config.orig",
    "/.htpasswd.bak", "/.htaccess.bak",

    "/.bash_history", "/.bash_profile", "/.bashrc", "/.profile",
    "/.zsh_history", "/.zshrc", "/.zprofile",
    "/.mysql_history", "/.psql_history", "/.python_history",
    "/.netrc", "/.ftpconfig", "/.curlrc",
    "/.git-credentials", "/.gitconfig",
    "/.pip/pip.conf", "/.composer/auth.json", "/.ssh/config",
    "/.history", "/.viminfo",

    "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
    "/id_rsa.pub", "/.ssh/id_dsa", "/.ssh/id_ecdsa", "/.ssh/id_ed25519",
    "/server.pem", "/certificate.pem", "/cert.pem", "/root.pem",

    "/npm-debug.log", "/yarn-error.log", "/yarn-debug.log",
    "/laravel.log", "/storage/logs/laravel.log",
    "/log/development.log", "/log/production.log", "/log/test.log",
    "/logs/app.log", "/logs/error.log", "/logs/access.log",
    "/logs/debug.log", "/logs/info.log",
    "/web.log", "/system.log",

    "/wp-content/debug.log", "/wp-content/uploads/",
    "/wp-content/themes/", "/wp-content/plugins/",
    "/wp-sitemap.xml", "/wp-sitemap-posts-post-1.xml",
    "/wp-json/wp/v2/settings", "/wp-json/wp/v2/users/1",
    "/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php",

    "/server.js", "/app.js", "/index.js", "/main.js", "/start.js",
    "/.env.development.local", "/.env.test.local",
    "/.next/routes-manifest.json", "/.next/build-manifest.json",
    "/.next/BUILD_ID",

    "/manage.py", "/wsgi.py", "/asgi.py", "/urls.py",
    "/requirements-dev.txt", "/requirements-test.txt",
    "/static/admin/", "/static/rest_framework/",
    "/pytest.ini", "/setup.cfg", "/tox.ini", "/conftest.py",

    "/db/schema.rb", "/db/seeds.rb", "/db/structure.sql",
    "/config/routes.rb", "/config/boot.rb", "/config/environment.rb",
    "/public/system/", "/public/assets/", "/public/uploads/",
    "/Capfile", "/Guardfile",

    "/mvnw", "/gradlew", "/.gradle/",
    "/target/", "/target/classes/",
    "/src/main/resources/application.properties",
    "/src/main/resources/application.yml",

    "/Chart.yaml", "/values.yaml", "/values.yml",
    "/kustomization.yaml", "/kustomization.yml",
    "/terraform.tfstate.backup",
    "/helm/", "/charts/", "/manifests/",
    "/deploy/", "/deployment/", "/deployments/",

    "/.github/workflows/main.yml", "/.github/workflows/ci.yml",
    "/.github/workflows/release.yml", "/.github/CODEOWNERS",
    "/.gitlab-ci.yml", "/bitbucket-pipelines.yml",
    "/azure-pipelines.yml", "/.drone.yml", "/appveyor.yml",

    "/metadata/v1/", "/metadata/v1/id",
    "/computeMetadata/v1/", "/computeMetadata/v1/project/",
    "/openstack/latest/meta_data.json",
    "/latest/meta-data/", "/latest/user-data/",

    "/api/0", "/api/1", "/api/2",
    "/api/1.0", "/api/1.1", "/api/2.0", "/api/3.0",
    "/api/2022", "/api/2023", "/api/2024",

    "/api/ping", "/api/echo", "/api/test",
    "/api/signup", "/api/register", "/api/forgot", "/api/reset",
    "/api/logout", "/api/revoke",
    "/api/verify", "/api/activate", "/api/confirm",
    "/api/session", "/api/sessions",
    "/api/roles", "/api/permissions",
    "/api/groups", "/api/organizations",
    "/api/billing", "/api/subscription", "/api/subscriptions",
    "/api/invoices", "/api/transactions",
    "/api/exports", "/api/imports",
    "/api/jobs", "/api/tasks", "/api/queues",
    "/api/logs", "/api/audit", "/api/activity",
    "/api/comments", "/api/reviews", "/api/ratings",
    "/api/categories", "/api/tags", "/api/labels",
    "/api/images", "/api/documents",
    "/api/support", "/api/tickets", "/api/feedback",
    "/api/announcements", "/api/notifications",
    "/api/features", "/api/flags", "/api/toggles",
    "/api/system", "/api/server", "/api/node",
    "/api/debug", "/api/internal",

    "/oauth/check_token", "/oauth/confirm_access", "/oauth/error",
    "/actuator/prometheus", "/actuator/refresh",
    "/actuator/gateway/routes", "/actuator/gateway/globalfilters",

    "/storage/app/", "/storage/framework/", "/storage/logs/",
    "/_ignition/share-report",
    "/vendor/", "/vendor/phpunit/", "/vendor/laravel/",
    "/bootstrap/cache/",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",

    "/iisstart.htm", "/iisstart.png", "/aspnet_client/",
    "/certsrv/", "/certenroll/", "/exchange/",
    "/owa/", "/ecp/", "/autodiscover/autodiscover.xml",
    "/Microsoft-Server-ActiveSync",
    "/rpc/", "/EWS/Exchange.asmx",

    "/.well-known/oauth-authorization-server",
    "/.well-known/uma2-configuration",
    "/.well-known/saml-configuration",
    "/apple-developer-merchantid-domain-association",
    "/assetlinks.json", "/digital-asset-links.json",

    "/solr/admin/cores", "/solr/admin/info/system",
    "/_nodes", "/_nodes/stats",
    "/_search", "/_cat/health", "/_cat/nodes", "/_cat/shards",
    "/_all/_search", "/_mapping", "/_aliases",

    "/vpn", "/remote", "/rdp", "/citrix", "/globalprotect",
    "/dana-na/auth/url_default/welcome.cgi",
    "/remote/login",

    "/lfm.php", "/fm.php", "/filemanager.php", "/filemanager/",
    "/elfinder.html", "/tiny_mce/", "/tinymce/", "/ckeditor/",

    "/1", "/2", "/3", "/4", "/5",
    "/01", "/02", "/03",
    "/2020", "/2021", "/2022", "/2023", "/2024", "/2025",

    "/503.html", "/503.php", "/503", "/down", "/unavailable",
    "/coming-soon", "/soon", "/maintenance",
    "/upgrade", "/updating",
]

INTERESTING_PATHS = {
    "/.env", "/.git/config", "/.git/HEAD", "/phpinfo.php", "/info.php",
    "/server-status", "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/actuator/configprops", "/actuator/heapdump",
    "/api/v1/users", "/graphql", "/wp-config.php", "/database.yml",
    "/credentials.json", "/.aws/credentials", "/terraform.tfstate",
    "/.ssh/id_rsa", "/config.json", "/secrets.json", "/secrets.yml",
    "/settings.json", "/key.json", "/private.pem", "/docker-compose.yml",
    "/.kube/config", "/sites/default/settings.php",
}

BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".copy", ".backup", "~", ".tmp", ".save", ".1", ".swp"]

RECURSIVE_SUB_PATHS = [
    "/config", "/settings", "/users", "/admin", "/login", "/api",
    "/data", "/export", "/backup", "/logs", "/debug",
    "/index.php", "/index.html", "/upload", "/list",
    "/profile", "/token", "/key", "/secret", "/health", "/status",
]

_JS_PATTERNS = [
    re.compile(
        r'''(?:fetch|axios\.(?:get|post|put|patch|delete|head))\s*\(\s*[`'"](\/[a-zA-Z0-9_\/\.\-]{2,100})[`'"]''',
        re.IGNORECASE,
    ),
    re.compile(
        r'''(?:url|path|endpoint|route|baseUrl|base_url|apiUrl|api_url|API_URL|BASE_URL)\s*[:=]\s*[`'"](\/[a-zA-Z0-9_\/\.\-]{2,100})[`'"]''',
        re.IGNORECASE,
    ),
    re.compile(r'''[`'"](\/(?:api|v\d+|graphql|rest|rpc|gql)\/[a-zA-Z0-9_\/\.\-]{1,100})[`'"]'''),
    re.compile(r'''`(\/[a-zA-Z0-9_\/\.\-]{2,60}(?:\$\{[^`]{1,30}\}[a-zA-Z0-9_\/\.\-]*){0,2})`'''),
]



def _parse_robots_txt(content: str) -> list[str]:
    """Extract Disallow/Allow path entries from robots.txt text."""
    paths: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith(("disallow:", "allow:")):
            parts = line.split(":", 1)
            if len(parts) == 2:
                path = parts[1].split("#")[0].strip()
                if path and path != "/" and "*" not in path and "?" not in path:
                    if not path.startswith("/"):
                        path = "/" + path
                    paths.add(path)
    return list(paths)


def _parse_sitemap_xml(content: str) -> tuple[list[str], list[str]]:
    """
    Parse a sitemap or sitemap-index XML document.
    Returns (page_paths, child_sitemap_urls).
    """
    paths: list[str] = []
    child_sitemaps: list[str] = []
    try:
        root = ET.fromstring(content)
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        for loc_el in root.findall(".//sm:sitemap/sm:loc", ns):
            url = (loc_el.text or "").strip()
            if url:
                child_sitemaps.append(url)
        for loc_el in root.findall(".//sm:url/sm:loc", ns):
            url = (loc_el.text or "").strip()
            if url:
                parsed = urlparse(url)
                path = parsed.path.split("?")[0]
                if path and path != "/":
                    paths.append(path)
    except ET.ParseError:
        pass
    return paths, child_sitemaps


def _extract_paths_from_html(html: str, base_url: str) -> tuple[list[str], list[str]]:
    """
    Mine href, src, and action attribute values from raw HTML.
    Returns (same_domain_paths, js_file_urls).
    """
    base_netloc = urlparse(base_url).netloc
    paths: set[str] = set()
    js_urls: list[str] = []

    for attr_val in re.findall(r'''(?:href|src|action)\s*=\s*["']([^"'#?]{2,200})["']''', html, re.IGNORECASE):
        attr_val = attr_val.strip()
        if attr_val.startswith("/") and not attr_val.startswith("//"):
            clean = attr_val.split("?")[0].split("#")[0]
            if len(clean) > 1:
                paths.add(clean)
        elif attr_val.startswith("http"):
            parsed = urlparse(attr_val)
            if parsed.netloc == base_netloc and parsed.path and parsed.path != "/":
                paths.add(parsed.path.split("?")[0])

    for src in re.findall(r'''<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*)["']''', html, re.IGNORECASE):
        src = src.strip().split("?")[0]
        if src.startswith("//"):
            src = "https:" + src
        if src.startswith("/"):
            js_urls.append(f"{base_url}{src}")
        elif src.startswith("http") and urlparse(src).netloc == base_netloc:
            js_urls.append(src)

    return list(paths)[:300], js_urls[:10]


async def _multi_probe_wildcard(session: aiohttp.ClientSession, base_url: str) -> dict | None:
    """
    Probe 3 uniquely-named non-existent paths to detect catch-all / wildcard servers.
    Builds a baseline of status codes, content-lengths, and body hashes.
    Returns wildcard descriptor if detected, None if server returns proper 404s.
    """
    probe_paths = [
        f"/rnd_{uuid.uuid4().hex[:8]}",
        f"/fake_dir_{uuid.uuid4().hex[:8]}/index.html",
        f"/nonexistent_{uuid.uuid4().hex[:8]}.php",
    ]
    signatures: list[dict] = []
    for path in probe_paths:
        url = f"{base_url}{path}"
        try:
            async with session.get(
                url, ssl=False, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status == 404:
                    continue
                content_length = resp.headers.get("Content-Length")
                location = resp.headers.get("Location")
                try:
                    chunk = await asyncio.wait_for(resp.content.read(512), timeout=2.0)
                    body_hash = hashlib.md5(chunk).hexdigest()
                except Exception:
                    body_hash = None
                signatures.append({
                    "status": resp.status,
                    "content_length": int(content_length) if content_length and content_length.isdigit() else None,
                    "location": location,
                    "body_hash": body_hash,
                })
        except Exception:
            continue

    if len(signatures) < 2:
        return None

    statuses = [s["status"] for s in signatures]
    common_status = max(set(statuses), key=statuses.count)
    common_sigs = [s for s in signatures if s["status"] == common_status]
    body_hashes = {s["body_hash"] for s in signatures if s.get("body_hash")}

    return {
        "status": common_status,
        "content_length": common_sigs[0]["content_length"],
        "location": common_sigs[0].get("location"),
        "body_hashes": body_hashes,
    }


async def _fetch_discovery_data(
    session: aiohttp.ClientSession, base_url: str,
) -> tuple[list[str], list[str], list[str], list[str]]:
    """
    Run robots.txt parsing, sitemap crawling, and homepage crawling concurrently.
    Returns (robots_paths, sitemap_paths, html_paths, js_urls).
    """
    robots_paths: list[str] = []
    sitemap_paths: list[str] = []
    html_paths: list[str] = []
    js_urls: list[str] = []

    async def fetch_robots() -> None:
        nonlocal robots_paths
        try:
            async with session.get(
                f"{base_url}/robots.txt", ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status == 200:
                    text = await asyncio.wait_for(resp.text(errors="replace"), timeout=3.0)
                    robots_paths = _parse_robots_txt(text)
        except Exception:
            pass

    async def fetch_sitemaps() -> None:
        nonlocal sitemap_paths
        sitemap_queue = [f"{base_url}/sitemap.xml", f"{base_url}/sitemap_index.xml"]
        visited: set[str] = set()
        collected: list[str] = []
        for sitemap_url in sitemap_queue[:6]:
            if sitemap_url in visited:
                continue
            visited.add(sitemap_url)
            try:
                async with session.get(
                    sitemap_url, ssl=False, allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    if resp.status == 200:
                        text = await asyncio.wait_for(resp.text(errors="replace"), timeout=3.0)
                        paths, children = _parse_sitemap_xml(text)
                        collected.extend(paths)
                        for child in children[:5]:
                            if child not in visited:
                                sitemap_queue.append(child)
            except Exception:
                continue
        sitemap_paths = list(set(collected))[:200]

    async def crawl_homepage() -> None:
        nonlocal html_paths, js_urls
        try:
            async with session.get(
                base_url, ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status == 200:
                    html = await asyncio.wait_for(resp.text(errors="replace"), timeout=4.0)
                    html_paths, js_urls = _extract_paths_from_html(html, base_url)
        except Exception:
            pass

    try:
        await asyncio.wait_for(
            asyncio.gather(fetch_robots(), fetch_sitemaps(), crawl_homepage(), return_exceptions=True),
            timeout=18.0,
        )
    except asyncio.TimeoutError:
        pass

    return robots_paths, sitemap_paths, html_paths, js_urls


async def _mine_js_endpoints(session: aiohttp.ClientSession, js_urls: list[str]) -> list[str]:
    """
    Download up to 5 JS files and regex-extract embedded API route strings.
    Returns a deduplicated list of discovered endpoint paths.
    """
    endpoints: set[str] = set()

    async def mine_one(js_url: str) -> None:
        try:
            async with session.get(
                js_url, ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status == 200:
                    content = await asyncio.wait_for(resp.content.read(512 * 1024), timeout=5.0)
                    text = content.decode("utf-8", errors="ignore")
                    for pattern in _JS_PATTERNS:
                        for match in pattern.findall(text):
                            clean = re.sub(r"\$\{[^}]+\}", "*", match).split("?")[0].split("#")[0]
                            if len(clean) > 2 and not clean.endswith((".js", ".css", ".png", ".jpg")):
                                endpoints.add(clean)
        except Exception:
            pass

    try:
        await asyncio.wait_for(
            asyncio.gather(*[mine_one(url) for url in js_urls[:5]], return_exceptions=True),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        pass

    return sorted(endpoints)


async def _check_path(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    wildcard: dict | None = None,
) -> dict | None:
    """
    Fetch a single path and decide whether it represents a real finding.
    Applies wildcard filtering using status code, content-length, and body hash.
    Grabs a content snippet for sensitive paths when found open (200).
    """
    url = f"{base_url}{path}"
    body_chunk: bytes | None = None

    try:
        async with session.get(
            url, ssl=False, allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=4),
        ) as response:
            status = response.status
            if status == 404:
                return None

            content_length = response.headers.get("Content-Length")
            content_type = response.headers.get("Content-Type", "")
            location = response.headers.get("Location")

            if wildcard and status == wildcard["status"]:
                if status in (301, 302, 303, 307, 308):
                    if wildcard.get("location") and location == wildcard.get("location"):
                        return None
                else:
                    wildcard_len = wildcard.get("content_length")
                    curr_len = int(content_length) if content_length and content_length.isdigit() else None
                    if wildcard_len is not None and curr_len is not None:
                        if abs(wildcard_len - curr_len) < 50:
                            return None
                    elif wildcard_len is None and curr_len is None:
                        wildcard_hashes = wildcard.get("body_hashes", set())
                        if wildcard_hashes:
                            try:
                                body_chunk = await asyncio.wait_for(response.content.read(512), timeout=2.0)
                                if hashlib.md5(body_chunk).hexdigest() in wildcard_hashes:
                                    return None
                            except Exception:
                                return None

            result: dict = {
                "path": path,
                "status": status,
                "content_type": content_type.split(";")[0].strip() if content_type else None,
                "content_length": int(content_length) if content_length and content_length.isdigit() else None,
                "url": url,
                "interesting": path in INTERESTING_PATHS,
            }
            if location:
                result["redirect_to"] = location

            if status == 200 and path in INTERESTING_PATHS:
                try:
                    if body_chunk is None:
                        body_chunk = await asyncio.wait_for(response.content.read(512), timeout=2.0)
                    result["body_snippet"] = body_chunk.decode("utf-8", errors="ignore").strip()[:200]
                except Exception:
                    pass

            return result

    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return None
    except Exception:
        return None


async def _probe_backup_extensions(
    session: aiohttp.ClientSession,
    base_url: str,
    found_items: list[dict],
    wildcard: dict | None,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    """
    For each found file (status 200, has a named extension), probe backup variants.
    Limited to 20 files to keep request count manageable.
    """
    file_items = [
        item for item in found_items
        if item["status"] == 200
        and "." in item["path"].split("/")[-1]
        and not item["path"].endswith("/")
    ][:20]

    async def check_backup(base_path: str, ext: str) -> dict | None:
        async with semaphore:
            return await _check_path(session, base_url, base_path + ext, wildcard)

    tasks = [check_backup(item["path"], ext) for item in file_items for ext in BACKUP_EXTENSIONS]
    if not tasks:
        return []

    backup_results: list[dict] = []
    try:
        raw = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=15.0)
        backup_results = [r for r in raw if r and not isinstance(r, Exception)]
    except asyncio.TimeoutError:
        pass
    return backup_results


async def _recursive_scan(
    session: aiohttp.ClientSession,
    base_url: str,
    found_items: list[dict],
    wildcard: dict | None,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    """
    For the top 5 found directories (status 200/403, no file extension),
    probe RECURSIVE_SUB_PATHS 1 level deep to discover deeper endpoints.
    """
    dir_items = [
        item for item in found_items
        if item["status"] in (200, 403)
        and (item["path"].endswith("/") or "." not in item["path"].split("/")[-1])
        and len(item["path"]) > 1
    ][:5]

    async def check_sub(dir_path: str, sub_path: str) -> dict | None:
        async with semaphore:
            return await _check_path(session, base_url, dir_path.rstrip("/") + sub_path, wildcard)

    tasks = [check_sub(item["path"], sub) for item in dir_items for sub in RECURSIVE_SUB_PATHS]
    if not tasks:
        return []

    recursive_results: list[dict] = []
    try:
        raw = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=18.0)
        recursive_results = [r for r in raw if r and not isinstance(r, Exception)]
    except asyncio.TimeoutError:
        pass
    return recursive_results


async def _find_base_url(target: str) -> str | None:
    """Probes HTTPS then HTTP to find the active base URL for the target."""
    timeout = aiohttp.ClientTimeout(total=4)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for url in [f"https://{target}", f"http://{target}"]:
                try:
                    async with session.get(url, ssl=False, allow_redirects=True) as resp:
                        if resp.status < 500:
                            return url
                except Exception:
                    continue
    except Exception:
        pass
    return f"http://{target}"


async def enumerate(target: str) -> dict[str, Any]:
    """
    Multi-stage directory and endpoint discovery pipeline.
    All phases are bounded by individual timeouts within the global 120s limit.
    """
    target = target.replace("https://", "").replace("http://", "").split("/")[0]

    base_url = await _find_base_url(target)
    if not base_url:
        return error_response(
            ScanError.API_UNREACHABLE,
            "Target is not reachable on HTTP or HTTPS — directory enum skipped",
            found=[], paths_checked=0,
        )

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    }

    try:
        connector = aiohttp.TCPConnector(limit=80)
        async with aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=TIMEOUTS["directories"]),
        ) as session:

            try:
                wildcard = await asyncio.wait_for(_multi_probe_wildcard(session, base_url), timeout=12.0)
            except asyncio.TimeoutError:
                wildcard = None

            robots_paths, sitemap_paths, html_paths, js_urls = await _fetch_discovery_data(session, base_url)

            all_paths = list({*COMMON_PATHS, *robots_paths, *sitemap_paths, *html_paths})

            semaphore = asyncio.Semaphore(35)

            await asyncio.sleep(0.1)

            async def check_one(path: str) -> dict | None:
                return await _check_path(session, base_url, path, wildcard)

            raw_results, _ = await run_bounded(all_paths, check_one, 35, 70.0)

            found: list[dict] = [r for r in raw_results if r and not isinstance(r, Exception)]

            js_endpoints: list[str] = []
            backup_results: list[dict] = []
            recursive_results: list[dict] = []

            post_tasks = [
                _mine_js_endpoints(session, js_urls) if js_urls else asyncio.sleep(0),
                _probe_backup_extensions(session, base_url, found, wildcard, semaphore),
                _recursive_scan(session, base_url, found, wildcard, semaphore),
            ]

            try:
                phase_out = await asyncio.wait_for(
                    asyncio.gather(*post_tasks, return_exceptions=True),
                    timeout=25.0,
                )
                if isinstance(phase_out[0], list):
                    js_endpoints = phase_out[0]
                if isinstance(phase_out[1], list):
                    backup_results = phase_out[1]
                if isinstance(phase_out[2], list):
                    recursive_results = phase_out[2]
            except asyncio.TimeoutError:
                pass

    except Exception as e:
        return error_response(
            ScanError.UNKNOWN_ERROR,
            f"Directory enum failed: {type(e).__name__}: {str(e)[:120]}",
            found=[],
        )

    all_found = list({r["url"]: r for r in found + backup_results + recursive_results}.values())

    by_status: dict[str, int] = {}
    interesting_found: list[str] = []
    for item in all_found:
        s = str(item["status"])
        by_status.setdefault(s, 0)
        by_status[s] += 1
        if item.get("interesting"):
            interesting_found.append(item["path"])

    return {
        "status": "ok",
        "base_url": base_url,
        "paths_checked": len(all_paths),
        "paths_found": len(all_found),
        "by_status_code": by_status,
        "interesting_findings": interesting_found,
        "discovery_sources": {
            "static_wordlist": len(COMMON_PATHS),
            "from_robots_txt": len(robots_paths),
            "from_sitemap": len(sitemap_paths),
            "from_html_crawl": len(html_paths),
        },
        "js_endpoints": sorted(set(js_endpoints)) if js_endpoints else [],
        "wildcard_detected": wildcard is not None,
        "found": sorted(all_found, key=lambda x: x["status"]),
    }

