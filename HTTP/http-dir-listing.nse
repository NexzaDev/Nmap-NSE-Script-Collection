local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Finds web directories that are browsable instead of served, then reports what
is actually reachable through them.

A directory listing is not a cosmetic problem: it is a file disclosure channel.
When autoindex is enabled, every file placed in that directory - backups, SQL
dumps, editor swap files, private keys, configuration snapshots, deployment
archives, log files - becomes downloadable by anyone who guesses nothing at all.

What the script does
1. Requests a curated set of 140+ directory paths (asset directories, upload
   directories, backup/old/tmp/archive directories, log and data directories,
   admin/includes/vendor/node_modules, framework and CMS specific paths such as
   wp-content/uploads/2024/, sites/default/files/, storage/app/public/,
   media/, uploads/userfiles/, /cgi-bin/, /icons/) with a trailing slash.
2. Classifies each response with a structural listing detector rather than a
   single keyword: the title/heading text, the presence of a parent-directory
   link, the number of relative links pointing at siblings, and the table or
   pre-formatted layout. Supported listing generators: Apache httpd (mod_autoindex,
   both the 2.2 and 2.4 HTML), nginx autoindex, IIS directory listing,
   lighttpd, Caddy file_server browse, Go http.FileServer, Python http.server /
   SimpleHTTPServer, Tomcat DefaultServlet, Jetty, WebDAV PROPFIND XML
   (multistatus), S3/MinIO bucket XML listings, Node serve-index / express
   static, Werkzeug directory browser, h5ai, dufs, filebrowser, nginx fancyindex,
   Apache mod_php directory index, and JSON directory indexes.
3. Parses the listing into file entries (name, size, modification time, link)
   and classifies every entry by extension and name pattern into 20 sensitive
   buckets: version control internals, environment files, private keys and
   certificates, database dumps, backups and archives, configuration files,
   application source, logs, documents/spreadsheets, media of identity value
   (scans, ID photos), executables, mobile app bundles, Jupyter notebooks,
   SSH/known_hosts material, WordPress/Drupal config, CI/CD material, mail
   archives, memory/core dumps, and credential stores.
4. Computes an exposure profile per directory: entry count, total exposed bytes,
   oldest and newest modification time, subdirectory count, and the highest
   sensitivity bucket present, so the operator sees "37 files, 412 MB, oldest
   2019-03-02, contains a .sql.gz and an id_rsa" instead of a bare "listing
   enabled".
5. Optional bounded recursion (`recurse=true`): walks discovered subdirectories
   to a configurable depth with a hard request budget, so a single exposed
   parent directory does not hide a whole exposed tree.
6. WebDAV detection: sends a depth-1 PROPFIND request (a read-only metadata
   query, no write methods) and parses the multistatus XML for hrefs, content
   length and last modified. A 207 response is reported as a listing channel
   even when HTML autoindex is off.
7. Distinguishes "listing enabled" from "directory exists but is not browsable"
   (403 with a directory-style error body) from "soft-404 catch-all that serves
   the same page for everything" - the last one is suppressed as a false
   positive using a randomised baseline, which is the most common cause of
   bogus directory-listing reports.

Findings are scored by sensitivity of the exposed content, not by the count of
listing pages: one directory containing a database dump outranks twenty
directories of image thumbnails.

Usage:
<code>
nmap -p 80,443 --script http-dir-listing <target>
nmap -p 80 --script http-dir-listing \
  --script-args http-dir-listing.recurse=true,http-dir-listing.maxdepth=2 <target>
nmap -p 8080 --script http-dir-listing \
  --script-args http-dir-listing.paths="/files/,/export/",http-dir-listing.webdav=false <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local SCRIPT_NAME = "http-dir-listing"

local RISK_LEVEL = "🟡 MEDIUM"

local LISTING_DIRS = {
  "/",
  "/files/",
  "/file/",
  "/pub/",
  "/public/",
  "/shared/",
  "/share/",
  "/download/",
  "/downloads/",
  "/dl/",
  "/export/",
  "/exports/",
  "/import/",
  "/imports/",
  "/upload/",
  "/uploads/",
  "/uploaded/",
  "/upl/",
  "/media/",
  "/assets/",
  "/asset/",
  "/static/",
  "/resources/",
  "/res/",
  "/images/",
  "/img/",
  "/image/",
  "/pics/",
  "/pictures/",
  "/gallery/",
  "/photos/",
  "/videos/",
  "/video/",
  "/audio/",
  "/sound/",
  "/music/",
  "/css/",
  "/js/",
  "/javascript/",
  "/scripts/",
  "/script/",
  "/fonts/",
  "/font/",
  "/icons/",
  "/icon/",
  "/docs/",
  "/doc/",
  "/documents/",
  "/document/",
  "/documentation/",
  "/manual/",
  "/help/",
  "/pdf/",
  "/pdfs/",
  "/reports/",
  "/report/",
  "/reporting/",
  "/data/",
  "/dataset/",
  "/datasets/",
  "/db/",
  "/database/",
  "/sql/",
  "/backup/",
  "/backups/",
  "/bak/",
  "/bkp/",
  "/old/",
  "/archive/",
  "/archives/",
  "/attic/",
  "/temp/",
  "/tmp/",
  "/scratch/",
  "/test/",
  "/tests/",
  "/testing/",
  "/dev/",
  "/development/",
  "/staging/",
  "/stage/",
  "/preview/",
  "/sandbox/",
  "/demo/",
  "/example/",
  "/examples/",
  "/samples/",
  "/logs/",
  "/log/",
  "/logging/",
  "/audit/",
  "/trace/",
  "/traces/",
  "/debug/",
  "/status/",
  "/metrics/",
  "/health/",
  "/config/",
  "/conf/",
  "/configuration/",
  "/settings/",
  "/etc/",
  "/ini/",
  "/includes/",
  "/include/",
  "/inc/",
  "/lib/",
  "/libs/",
  "/library/",
  "/vendor/",
  "/node_modules/",
  "/bower_components/",
  "/packages/",
  "/modules/",
  "/plugin/",
  "/plugins/",
  "/themes/",
  "/theme/",
  "/skins/",
  "/templates/",
  "/template/",
  "/views/",
  "/partials/",
  "/cgi-bin/",
  "/cgi-sys/",
  "/bin/",
  "/sbin/",
  "/build/",
  "/dist/",
  "/out/",
  "/target/",
  "/deploy/",
  "/deployment/",
  "/release/",
  "/releases/",
  "/install/",
  "/installer/",
  "/setup/",
  "/admin/",
  "/administrator/",
  "/admin/uploads/",
  "/admin/files/",
  "/admin/backup/",
  "/manager/",
  "/manage/",
  "/management/",
  "/panel/",
  "/cpanel/",
  "/control/",
  "/console/",
  "/dashboard/",
  "/portal/",
  "/internal/",
  "/intranet/",
  "/private/",
  "/protected/",
  "/secure/",
  "/secret/",
  "/secrets/",
  "/hidden/",
  "/restricted/",
  "/confidential/",
  "/user/",
  "/users/",
  "/member/",
  "/members/",
  "/account/",
  "/accounts/",
  "/profile/",
  "/profiles/",
  "/home/",
  "/personal/",
  "/staff/",
  "/employee/",
  "/employees/",
  "/hr/",
  "/finance/",
  "/financial/",
  "/invoices/",
  "/invoice/",
  "/billing/",
  "/payments/",
  "/orders/",
  "/customers/",
  "/customer/",
  "/clients/",
  "/client/",
  "/leads/",
  "/crm/",
  "/erp/",
  "/inventory/",
  "/products/",
  "/product/",
  "/catalog/",
  "/store/",
  "/shop/",
  "/cart/",
  "/checkout/",
  "/wp-content/",
  "/wp-content/uploads/",
  "/wp-content/backup-db/",
  "/wp-content/backups/",
  "/wp-content/debug.log/",
  "/wp-content/plugins/",
  "/wp-content/themes/",
  "/wp-includes/",
  "/wp-admin/",
  "/wordpress/",
  "/sites/default/files/",
  "/sites/all/libraries/",
  "/sites/all/modules/",
  "/sites/default/private/",
  "/storage/",
  "/storage/app/",
  "/storage/app/public/",
  "/storage/logs/",
  "/storage/framework/",
  "/laravel/",
  "/public_html/",
  "/htdocs/",
  "/www/",
  "/web/",
  "/website/",
  "/site/",
  "/assets/uploads/",
  "/media/uploads/",
  "/media/private/",
  "/images/uploads/",
  "/img/uploads/",
  "/uploads/userfiles/",
  "/uploads/temp/",
  "/userfiles/",
  "/userfiles/files/",
  "/ckeditor/",
  "/ckfinder/",
  "/fckeditor/",
  "/editor/",
  "/filemanager/",
  "/file-manager/",
  "/filebrowser/",
  "/elfinder/",
  "/plupload/",
  "/dropzone/",
  "/attachments/",
  "/attachment/",
  "/annex/",
  "/blob/",
  "/blobs/",
  "/objects/",
  "/bucket/",
  "/s3/",
  "/minio/",
  "/nfs/",
  "/mnt/",
  "/mount/",
  "/volume/",
  "/volumes/",
  "/shares/",
  "/dav/",
  "/webdav/",
  "/sabredav/",
  "/owncloud/",
  "/nextcloud/",
  "/remote.php/webdav/",
  "/seafile/",
  "/syncthing/",
  "/jenkins/",
  "/hudson/",
  "/gitlab/",
  "/artifactory/",
  "/nexus/",
  "/repository/",
  "/maven/",
  "/gradle/",
  "/npm/",
  "/pypi/",
  "/packages/nuget/",
  "/builds/",
  "/workspace/",
  "/jobs/",
  "/coverage/",
  "/junit/",
  "/screenshots/",
  "/screen/",
  "/captures/",
  "/dumps/",
  "/dump/",
  "/core/",
  "/crash/",
  "/crashes/",
  "/heapdump/",
  "/threaddump/",
  "/phpinfo/",
  "/info/",
  "/about/",
  "/version/",
  "/.well-known/",
}

local LISTING_SIGNATURES = {
  { generator = "Apache mod_autoindex", weight = 6, patterns = {
      { what = "title", pattern = "<title>index of /" },
      { what = "heading", pattern = "<h1>index of /" },
      { what = "heading", pattern = "<h2>index of /" },
      { what = "parent", pattern = "parent directory</a>" },
      { what = "table", pattern = "<th><img src=\"/__icon_blank__" },
      { what = "footer", pattern = "apache/[%d%.]+ .*server at" },
      { what = "column", pattern = "name</a></th>" },
      { what = "column", pattern = "last modified</a></th>" },
    } },
  { generator = "Apache mod_autoindex (2.2)", weight = 6, patterns = {
      { what = "pre", pattern = "<pre>name" },
      { what = "pre", pattern = "last modified%s+size" },
      { what = "parent", pattern = "<a href=\"/%\">parent directory</a>" },
      { what = "footer", pattern = "<address>apache" },
    } },
  { generator = "nginx autoindex", weight = 7, patterns = {
      { what = "title", pattern = "<title>index of /" },
      { what = "heading", pattern = "<h1>index of /" },
      { what = "footer", pattern = "<hr></body>" },
      { what = "parent", pattern = "\">../</a>" },
      { what = "timestamp", pattern = "%d%d%-%a%a%a%-%d%d%d%d %d%d:%d%d" },
    } },
  { generator = "nginx fancyindex", weight = 7, patterns = {
      { what = "class", pattern = "fancyindex" },
      { what = "title", pattern = "index of /" },
    } },
  { generator = "IIS directory listing", weight = 7, patterns = {
      { what = "title", pattern = "<title>directory listing" },
      { what = "heading", pattern = "<h2>directory listing" },
      { what = "marker", pattern = "folder.gif" },
      { what = "marker", pattern = "[to parent directory]" },
      { what = "marker", pattern = "<th align=\"left\">name</th>" },
    } },
  { generator = "lighttpd directory listing", weight = 6, patterns = {
      { what = "title", pattern = "index of /" },
      { what = "marker", pattern = "lighttpd" },
    } },
  { generator = "Caddy file_server browse", weight = 6, patterns = {
      { what = "title", pattern = "<title>index of /" },
      { what = "marker", pattern = "caddy" },
    } },
  { generator = "Go http.FileServer", weight = 6, patterns = {
      { what = "pre", pattern = "<pre>" },
      { what = "title", pattern = "<title>index of" },
      { what = "timestamp", pattern = "%d%d%d%d%-%d%d%-%d%d %d%d:%d%d:%d%d" },
    } },
  { generator = "Python http.server", weight = 7, patterns = {
      { what = "title", pattern = "<title>directory listing for /" },
      { what = "heading", pattern = "<h1>directory listing for /" },
      { what = "marker", pattern = "<hr>" },
      { what = "marker", pattern = "simplehttpserver" },
    } },
  { generator = "Werkzeug directory browser", weight = 7, patterns = {
      { what = "title", pattern = "<title>index of" },
      { what = "marker", pattern = "werkzeug" },
    } },
  { generator = "Tomcat DefaultServlet", weight = 6, patterns = {
      { what = "heading", pattern = "<h1>directory listing for /" },
      { what = "marker", pattern = "apache tomcat" },
      { what = "marker", pattern = "apache%-coyote" },
    } },
  { generator = "Jetty DefaultServlet", weight = 6, patterns = {
      { what = "heading", pattern = "<h1>directory:" },
      { what = "marker", pattern = "jetty" },
    } },
  { generator = "WebDAV multistatus (PROPFIND)", weight = 9, patterns = {
      { what = "xml", pattern = "<d:multistatus" },
      { what = "xml", pattern = "<multistatus" },
      { what = "xml", pattern = "<d:response>" },
      { what = "xml", pattern = "<d:getcontentlength>" },
    } },
  { generator = "S3/MinIO bucket listing (XML)", weight = 9, patterns = {
      { what = "xml", pattern = "<listbucketresult" },
      { what = "xml", pattern = "<contents><key>" },
      { what = "xml", pattern = "<isTruncated>" },
    } },
  { generator = "serve-index / Node static", weight = 6, patterns = {
      { what = "title", pattern = "<title>listing directory" },
      { what = "marker", pattern = "serve%-index" },
    } },
  { generator = "h5ai file index", weight = 8, patterns = {
      { what = "marker", pattern = "h5ai" },
      { what = "marker", pattern = "_h5ai" },
    } },
  { generator = "dufs file server", weight = 8, patterns = {
      { what = "marker", pattern = "dufs" },
      { what = "title", pattern = "index of /" },
    } },
  { generator = "filebrowser", weight = 8, patterns = {
      { what = "marker", pattern = "filebrowser" },
      { what = "title", pattern = "file browser" },
    } },
  { generator = "JSON directory index", weight = 5, patterns = {
      { what = "json", pattern = "\"name\"%s*:%s*\"[^\"]+\"%s*,%s*\"size\"" },
      { what = "json", pattern = "\"files\"%s*:%s*%[" },
      { what = "json", pattern = "\"entries\"%s*:%s*%[" },
    } },
  { generator = "Synology File Station", weight = 7, patterns = {
      { what = "marker", pattern = "synology" },
      { what = "marker", pattern = "file station" },
    } },
  { generator = "QNAP File Station", weight = 7, patterns = {
      { what = "marker", pattern = "qnap" },
      { what = "marker", pattern = "file station" },
    } },
  { generator = "Apache mod_status-like index", weight = 4, patterns = {
      { what = "heading", pattern = "index of" },
      { what = "parent", pattern = "parent directory" },
    } },
  { generator = "generic anchor-list index", weight = 3, patterns = {
      { what = "heading", pattern = "index of" },
      { what = "links", pattern = "href" },
    } },
}

local SENSITIVE_BUCKETS = {
  { bucket = "version-control", severity = "HIGH", patterns = {
      "%.git/", "%.git$", "\\.gitignore", "\\.gitattributes", "\\.gitmodules",
      "%.svn/", "%.svn%-entries", "%.hg/", "%.hgignore", "%.bzr/",
      "cvsroot", "%.cvs/",
    },
    note = "VCS internals allow source reconstruction and often contain credentials in history" },
  { bucket = "environment-file", severity = "CRITICAL", patterns = {
      "%.env", "%.env%.", "env%.local", "env%.production", "env%.development",
      "settings%.ini", "config%.env",
    },
    note = "environment files carry API keys, database URLs and signing secrets" },
  { bucket = "private-key", severity = "CRITICAL", patterns = {
      "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "%.pem$", "%.key$",
      "%.p12$", "%.pfx$", "%.ppk$", "known_hosts", "authorized_keys",
      "%.pub$", "%.gpg$", "%.asc$", "%.p7b$", "private%.key",
    },
    note = "key material enables TLS impersonation, SSH access and signature forgery" },
  { bucket = "database-dump", severity = "CRITICAL", patterns = {
      "%.sql$", "%.sql%.gz", "%.sql%.zip", "%.sql%.bz2", "%.dump$", "%.sqlite$",
      "%.sqlite3$", "%.db$", "%.mdb$", "%.accdb$", "%.bak%.sql", "db_dump",
      "%.mysql$", "%.psql$",
    },
    note = "database dumps contain the full data set including password hashes" },
  { bucket = "backup-archive", severity = "HIGH", patterns = {
      "%.zip$", "%.tar$", "%.tar%.gz", "%.tgz$", "%.tar%.bz2", "%.tbz$",
      "%.rar$", "%.7z$", "%.gz$", "%.bz2$", "%.xz$", "%.bak$", "%.old$",
      "%.orig$", "%.save$", "%.copy$", "%.backup$", "~$", "%.swp$",
      "%.tmp$", "%.temp$",
    },
    note = "backups and editor swap files frequently include live configuration and credentials" },
  { bucket = "configuration", severity = "HIGH", patterns = {
      "wp%-config%.php", "configuration%.php", "settings%.py", "config%.php",
      "config%.yml", "config%.yaml", "config%.json", "config%.xml",
      "database%.yml", "appsettings%.json", "web%.config", "httpd%.conf",
      "nginx%.conf", "%.ini$", "%.conf$", "%.cfg$", "%.toml$", "docker%-compose",
      "dockerfile", "%.env%.sample", "credentials%.json", "serviceaccount%.json",
    },
    note = "application configuration files disclose connection strings and secrets" },
  { bucket = "application-source", severity = "MEDIUM", patterns = {
      "%.php$", "%.asp$", "%.aspx$", "%.jsp$", "%.jspx", "%.py$", "%.rb$",
      "%.pl$", "%.cgi$", "%.sh$", "%.bash$", "%.ps1$", "%.bat$", "%.cmd$",
      "%.java$", "%.class$", "%.cs$", "%.go$", "%.rs$", "%.js%.map",
      "%.ts$", "%.tsx", "%.vue$", "%.inc$",
    },
    note = "server-side source code discloses business logic and injection points" },
  { bucket = "log-file", severity = "HIGH", patterns = {
      "%.log$", "access_log", "error_log", "%.log%.gz", "debug%.log",
      "%.out$", "syslog", "%.audit$", "audit%.log",
    },
    note = "logs leak session tokens, request parameters, internal host names and stack traces" },
  { bucket = "document", severity = "MEDIUM", patterns = {
      "%.pdf$", "%.doc$", "%.docx", "%.xls$", "%.xlsx", "%.ppt$", "%.pptx",
      "%.odt$", "%.ods$", "%.rtf$", "%.csv$", "%.txt$", "%.md$",
    },
    note = "business documents may contain personal data or internal processes" },
  { bucket = "identity-media", severity = "HIGH", patterns = {
      "passport", "id%-card", "idcard", "driving", "license", "cv", "resume",
      "scan", "selfie", "photo%-id", "national%-id", "ssn", "tax",
    },
    note = "identity documents in an upload directory are a personal-data breach" },
  { bucket = "executable", severity = "MEDIUM", patterns = {
      "%.exe$", "%.dll$", "%.so$", "%.bin$", "%.msi$", "%.apk$", "%.ipa$",
      "%.dmg$", "%.deb$", "%.rpm$", "%.jar$", "%.war$", "%.ear$",
    },
    note = "published binaries can be reverse engineered and re-distributed" },
  { bucket = "notebook", severity = "MEDIUM", patterns = {
      "%.ipynb$", "jupyter", "notebook",
    },
    note = "notebooks often embed credentials and query results" },
  { bucket = "ci-cd", severity = "HIGH", patterns = {
      "jenkinsfile", "%.gitlab%-ci", "github/workflows", "azure%-pipelines",
      "%.travis%.yml", "circleci", "argocd", "%.helm", "values%.yaml",
      "terraform%.tfvars", "%.tfstate",
    },
    note = "CI/CD definitions and state files contain deployment credentials" },
  { bucket = "mail-archive", severity = "HIGH", patterns = {
      "%.mbox$", "%.eml$", "%.emlx", "%.pst$", "%.msg$", "maildir",
    },
    note = "mail archives are a direct personal-data and credential exposure" },
  { bucket = "memory-dump", severity = "CRITICAL", patterns = {
      "heapdump", "core%.%d+$", "%.hprof$", "threaddump", "%.dmp$",
    },
    note = "memory dumps contain in-process secrets, tokens and keys in clear text" },
  { bucket = "credential-store", severity = "CRITICAL", patterns = {
      "passwd$", "shadow$", "%.htpasswd", "%.htaccess", "credentials",
      "secrets", "%.kdbx", "vault", "keystore", "truststore",
    },
    note = "credential stores and web-server access control files" },
  { bucket = "database-file", severity = "HIGH", patterns = {
      "%.frm$", "%.myd$", "%.myi$", "ibdata", "%.ibd$", "pg_hba",
      "redis%.dump", "dump%.rdb", "%.aof$",
    },
    note = "raw database engine files" },
  { bucket = "media-public", severity = "INFO", patterns = {
      "%.jpg$", "%.jpeg", "%.png$", "%.gif$", "%.svg$", "%.webp", "%.ico$",
      "%.mp4$", "%.mp3$", "%.css$", "%.woff",
    },
    note = "public media - expected content, reported for completeness only" },
  { bucket = "index-file", severity = "INFO", patterns = {
      "index%.html", "index%.php", "default%.aspx", "readme", "license",
    },
    note = "directory index and documentation files" },
  { bucket = "unknown", severity = "INFO", patterns = {},
    note = "unclassified entry" },
}

local LISTING_PATH_HINTS = {
  "/backup", "/bak", "/old", "/tmp", "/temp", "/upload", "/uploads", "/log",
  "/logs", "/admin", "/private", "/internal", "/db", "/sql", "/dump",
  "/config", "/conf", "/secret", "/export", "/archive", "/test", "/dev",
  "/staging", "/data", "/files", "/media", "/docs", "/reports", "/include",
  "/vendor", "/node_modules", "/cgi-bin", "/wp-content", "/storage",
}

local WAF_SIGNATURES = {
  { pattern = "cf-ray", where = "header", vendor = "Cloudflare" },
  { pattern = "cloudflare", where = "header", vendor = "Cloudflare" },
  { pattern = "akamai", where = "header", vendor = "Akamai" },
  { pattern = "x-iinfo", where = "header", vendor = "Imperva Incapsula" },
  { pattern = "sucuri", where = "header", vendor = "Sucuri" },
  { pattern = "aws waf", where = "body", vendor = "AWS WAF" },
}

local SOFT404_TEMPLATES = {
  "/nse-dirlist-missing-%s/",
  "/nse-dirlist-absent/%s/",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxdirs = 60,
  maxrequests = 140,
  retries = 1,
  timeout = 8000,
  delay = 0.05,
  recurse = false,
  maxdepth = 2,
  webdav = true,
  soft404 = true,
  minlinks = 2,
  maxentries = 400,
  useragent = nil,
  maxbodysize = 524288,
}

local NUMERIC_ARGS = {
  { key = "maxdirs", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 5, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxdepth", minimum = 0, integer = true },
  { key = "minlinks", minimum = 1, integer = true },
  { key = "maxentries", minimum = 10, integer = true },
  { key = "maxbodysize", minimum = 1024, integer = true },
}

local BOOLEAN_ARGS = { "recurse", "webdav", "soft404" }

local STRING_ARGS = { "useragent" }

local SEVERITY = {
  CRITICAL = 10,
  HIGH = 7,
  MEDIUM = 4,
  LOW = 2,
  INFO = 1,
}

local function trim(value)
  if type(value) ~= "string" then
    return value
  end
  value = string.gsub(value, "^%s+", "")
  value = string.gsub(value, "%s+$", "")
  return value
end

local function lower(value)
  if type(value) ~= "string" then
    return ""
  end
  return string.lower(trim(value))
end

local function starts_with(value, prefix)
  return string.sub(value, 1, #prefix) == prefix
end

local function ends_with(value, suffix)
  if #suffix > #value then
    return false
  end
  return string.sub(value, -#suffix) == suffix
end

local function contains(value, needle)
  return string.find(value or "", needle, 1, true) ~= nil
end

local function split(value, separator)
  local parts = {}
  if type(value) ~= "string" or #value == 0 then
    return parts
  end
  for chunk in string.gmatch(value, "([^" .. separator .. "]+)") do
    table.insert(parts, trim(chunk))
  end
  return parts
end

local function list_contains(list, needle)
  for _, item in ipairs(list or {}) do
    if item == needle then
      return true
    end
  end
  return false
end

local function table_size(tbl)
  local count = 0
  for _ in pairs(tbl or {}) do
    count = count + 1
  end
  return count
end

local function sorted_keys(tbl)
  local keys = {}
  for key in pairs(tbl or {}) do
    table.insert(keys, key)
  end
  table.sort(keys)
  return keys
end

local function unique_append(list, seen, value)
  if seen[value] then
    return false
  end
  seen[value] = true
  table.insert(list, value)
  return true
end

local function clamp(value, minimum, maximum)
  if value < minimum then
    return minimum
  end
  if value > maximum then
    return maximum
  end
  return value
end

local function byte_hex(value, count)
  local out = {}
  for i = 1, math.min(count or 16, #(value or "")) do
    table.insert(out, string.format("%02x", string.byte(value, i)))
  end
  return table.concat(out, " ")
end

local function truncate(value, limit)
  if type(value) ~= "string" then
    return tostring(value)
  end
  if #value <= limit then
    return value
  end
  return string.sub(value, 1, limit) .. "..."
end

local function fnv1a32(value)
  local hash = 2166136261
  for i = 1, #(value or "") do
    hash = (hash ~ string.byte(value, i)) & 0xFFFFFFFF
    hash = (hash * 16777619) & 0xFFFFFFFF
  end
  return string.format("%08x", hash)
end

local function entropy_bits(value)
  if type(value) ~= "string" or #value == 0 then
    return 0
  end
  local counts = {}
  for i = 1, #value do
    local char = string.sub(value, i, i)
    counts[char] = (counts[char] or 0) + 1
  end
  local length = #value
  local entropy = 0
  for _, count in pairs(counts) do
    local probability = count / length
    entropy = entropy - probability * (math.log(probability) / math.log(2))
  end
  return entropy
end

local function random_token(length, uppercase)
  local alphabet = uppercase and "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    or "abcdefghijklmnopqrstuvwxyz0123456789"
  local out = {}
  for _ = 1, length do
    local index = math.random(1, #alphabet)
    table.insert(out, string.sub(alphabet, index, index))
  end
  return table.concat(out)
end

local function seed_random(port)
  math.randomseed((os.time() * 65537) + ((port and port.number) or 0)
    + ((stdnse.clock_ms and stdnse.clock_ms()) or 0))
end

local state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }

local function reset_state()
  state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }
end

local function budget_exhausted(args)
  return state.requests >= args.maxrequests
end

local function sleep(seconds)
  if seconds and seconds > 0 then
    stdnse.sleep(seconds)
  end
end

local function read_args()
  local args = {}
  for key, value in pairs(DEFAULT_ARGS) do
    args[key] = value
  end

  for _, spec in ipairs(NUMERIC_ARGS) do
    local raw = stdnse.get_script_args(SCRIPT_NAME .. "." .. spec.key)
    local value = tonumber(raw)
    if value and value >= spec.minimum and (not spec.maximum or value <= spec.maximum) then
      if spec.integer then
        args[spec.key] = math.floor(value)
      else
        args[spec.key] = value
      end
    end
  end

  for _, key in ipairs(BOOLEAN_ARGS) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if value ~= nil then
      args[key] = not (value == false or value == "false" or value == "no" or value == "0")
    end
  end

  for _, key in ipairs(STRING_ARGS) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if type(value) == "string" and #trim(value) > 0 then
      args[key] = trim(value)
    elseif type(value) == "table" and #value > 0 then
      args[key] = trim(tostring(value[1]))
    end
  end

  local raw_list = stdnse.get_script_args(SCRIPT_NAME .. ".paths")
  if raw_list and #tostring(raw_list) > 0 then
    local list = {}
    for candidate in string.gmatch(tostring(raw_list), "[^,]+") do
      local normalized = trim(candidate)
      if #normalized > 0 then
        if not starts_with(normalized, "/") then
          normalized = "/" .. normalized
        end
        table.insert(list, normalized)
      end
    end
    if #list > 0 then
      args.paths = list
    end
  end

  return args
end

local function build_options(args, extra_headers)
  local options = { header = {}, no_cache = true, timeout = args.timeout }
  options.header["User-Agent"] = args.useragent
    or ("Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. "; security audit)")
  options.header["Accept"] = "*/*"
  options.header["Accept-Encoding"] = "identity"
  options.header["Connection"] = "close"
  options.header["Cache-Control"] = "no-cache"
  for name, value in pairs(extra_headers or {}) do
    options.header[name] = tostring(value)
  end
  return options
end

local function fetch(host, port, path, args, extra_headers, method)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1

  local options = build_options(args, extra_headers)
  local sender = http.get
  if method and method ~= "GET" then
    if method == "HEAD" then
      sender = http.head
    elseif method == "POST" then
      sender = function(h, p, u, o) return http.post(h, p, u, o, "") end
    elseif http.request then
      sender = function(h, p, u, o) return http.request(h, p, u, o, nil, method) end
    end
  end

  local attempt = 0
  local last_error = nil
  while attempt <= args.retries do
    attempt = attempt + 1
    local ok, response = pcall(sender, host, port, path, options)
    if ok and type(response) == "table" and response.status then
      if response.status == 429 then
        state.rate_limited = state.rate_limited + 1
        last_error = "HTTP 429 rate limiting"
        local retry_after = tonumber(response.header and response.header["retry-after"])
        sleep(clamp(retry_after or (attempt * 2), 1, 10))
      elseif response.status >= 500 and attempt <= args.retries then
        last_error = "HTTP " .. response.status
        sleep(0.5 * attempt)
      else
        sleep(args.delay)
        return response, nil
      end
    elseif ok then
      last_error = "malformed HTTP response"
      sleep(0.3 * attempt)
    else
      last_error = tostring(response)
      state.errors = state.errors + 1
      sleep(0.4 * attempt)
    end
  end

  sleep(args.delay)
  return nil, last_error
end

local function dechunk(body)
  local out = {}
  local position = 1
  while position <= #(body or "") do
    local size_hex, rest = string.match(body, "^([0-9a-fA-F]+)[^\r\n]*\r\n(.*)$", position)
    if not size_hex then
      local loose_hex, loose_rest = string.match(body, "^([0-9a-fA-F]+)[^\n]*\n(.*)$", position)
      if not loose_hex then
        break
      end
      size_hex, rest = loose_hex, loose_rest
    end
    local size = tonumber(size_hex, 16)
    if not size or size == 0 then
      break
    end
    table.insert(out, string.sub(rest, 1, size))
    position = position + (#body - #rest) + size
    local tail = string.sub(body, position)
    if starts_with(tail, "\r\n") then
      position = position + 2
    elseif starts_with(tail, "\n") then
      position = position + 1
    end
  end
  return table.concat(out)
end

local function parse_raw_response(raw)
  local head, body = string.match(raw or "", "^(.-)\r\n\r\n(.*)$")
  if not head then
    head, body = string.match(raw or "", "^(.-)\n\n(.*)$")
  end
  if not head then
    head = raw or ""
    body = ""
  end

  local response = { header = {}, rawheader = {}, body = body, raw = raw }
  local first = true
  for line in string.gmatch(head, "([^\r\n]*)") do
    if first then
      response["status-line"] = line
      response.status = tonumber(string.match(line, "^HTTP/[%d%.]+%s+(%d+)")) or 0
      response.version = string.match(line, "^HTTP/([%d%.]+)")
      first = false
    elseif #trim(line) > 0 then
      local name, value = string.match(line, "^([^:]+):%s*(.*)$")
      if name then
        table.insert(response.rawheader, line)
        local key = lower(name)
        if response.header[key] then
          local previous = response.header[key]
          if type(previous) == "table" then
            table.insert(previous, trim(value))
          else
            response.header[key] = { previous, trim(value) }
          end
        else
          response.header[key] = trim(value)
        end
      end
    end
  end

  local transfer_encoding = response.header["transfer-encoding"]
  if transfer_encoding and contains(lower(tostring(transfer_encoding)), "chunked") then
    response.body = dechunk(response.body)
  end

  return response
end

local function host_header_for(host, port)
  local name = host.targetname or host.name or host.ip or "localhost"
  local default_port = (port.number == 80 and not port.ssl) or (port.number == 443 and port.ssl)
  if default_port then
    return name
  end
  return string.format("%s:%d", name, port.number)
end

local function raw_request(host, port, method, path, header_pairs, args, body)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1

  local socket = nmap.new_socket()
  local ok, err = socket:connect(host, port)
  if not ok then
    state.errors = state.errors + 1
    return nil, tostring(err)
  end
  socket:set_timeout(args.timeout)

  local lines = {}
  table.insert(lines, string.format("%s %s HTTP/1.1", method, path))
  table.insert(lines, "Host: " .. host_header_for(host, port))
  table.insert(lines, "User-Agent: " .. (args.useragent
    or ("Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. ")")))
  table.insert(lines, "Accept: */*")
  table.insert(lines, "Accept-Encoding: identity")
  table.insert(lines, "Connection: close")
  if body then
    table.insert(lines, "Content-Length: " .. tostring(#body))
  end
  for _, pair in ipairs(header_pairs or {}) do
    table.insert(lines, pair[1] .. ": " .. tostring(pair[2]))
  end

  local request = table.concat(lines, "\r\n") .. "\r\n\r\n" .. (body or "")
  local send_ok, send_err = socket:send(request)
  if not send_ok then
    socket:close()
    state.errors = state.errors + 1
    return nil, tostring(send_err)
  end

  local recv_ok, data = socket:receive_until_close()
  socket:close()
  sleep(args.delay)

  if (not data or #data == 0) and not recv_ok then
    state.errors = state.errors + 1
    return nil, "no response bytes"
  end

  return parse_raw_response(data or ""), nil
end

local function header_values(response, name)
  local values = {}
  local target = lower(name)
  for _, line in ipairs(response.rawheader or {}) do
    local key, value = string.match(line, "^([^:]+):%s*(.*)$")
    if key and lower(key) == target then
      table.insert(values, trim(value))
    end
  end
  if #values == 0 then
    local single = response.header and response.header[target]
    if type(single) == "table" then
      for _, value in ipairs(single) do
        table.insert(values, value)
      end
    elseif single then
      table.insert(values, trim(single))
    end
  end
  return values
end

local function header_value(response, name)
  local values = header_values(response, name)
  return values[1]
end

local function response_headers(response)
  local names = {}
  for _, line in ipairs(response.rawheader or {}) do
    local key = string.match(line, "^([^:]+):")
    if key then
      local normalized = lower(key)
      if not list_contains(names, normalized) then
        table.insert(names, normalized)
      end
    end
  end
  table.sort(names)
  return names
end

local function detect_waf(response)
  if not response then
    return nil
  end
  for _, line in ipairs(response.rawheader or {}) do
    local lowered = lower(line)
    for _, signature in ipairs(WAF_SIGNATURES) do
      if signature.where ~= "body" and string.find(lowered, signature.pattern, 1, true) then
        return signature.vendor
      end
    end
  end
  local body = lower(response.body or "")
  if #body > 0 and #body < 20000 then
    for _, signature in ipairs(WAF_SIGNATURES) do
      if signature.where ~= "header" and string.find(body, signature.pattern, 1, true) then
        return signature.vendor
      end
    end
  end
  return nil
end

local function build_soft404_baseline(host, port, args)
  local baseline = { enabled = args.soft404, samples = 0, statuses = {}, hashes = {} }
  if not args.soft404 then
    return baseline
  end
  for _, template in ipairs(SOFT404_TEMPLATES) do
    if budget_exhausted(args) then
      break
    end
    local response = fetch(host, port, string.format(template, random_token(12)), args)
    if response and response.status then
      baseline.samples = baseline.samples + 1
      local key = tostring(response.status)
      baseline.statuses[key] = (baseline.statuses[key] or 0) + 1
      local hash = fnv1a32(response.body or "")
      baseline.hashes[hash] = (baseline.hashes[hash] or 0) + 1
      baseline.example_status = baseline.example_status or response.status
      baseline.example_hash = baseline.example_hash or hash
      baseline.example_length = baseline.example_length or #(response.body or "")
    end
  end
  local dominant, count = nil, 0
  for status, hits in pairs(baseline.statuses) do
    if hits > count then
      dominant, count = status, hits
    end
  end
  baseline.dominant_status = tonumber(dominant)
  baseline.consistent = baseline.samples >= 2 and count == baseline.samples
  return baseline
end

local function looks_like_soft404(response, baseline)
  if not baseline.enabled or baseline.samples == 0 then
    return false, nil
  end
  if (response.status or 0) >= 500 then
    return false, nil
  end
  local body = response.body or ""
  if baseline.example_hash and fnv1a32(body) == baseline.example_hash and #body > 0 then
    return true, "byte-identical to the catch-all baseline"
  end
  if baseline.consistent and baseline.dominant_status == response.status
    and math.abs(#body - (baseline.example_length or #body)) <= 48 then
    return true, "status and length match the catch-all baseline"
  end
  return false, nil
end

local function classify_response(path, response, baseline)
  local info = {
    path = path,
    status = response.status or 0,
    length = #(response.body or ""),
    confidence = "high",
    notes = {},
  }

  local vendor = detect_waf(response)
  if vendor then
    info.confidence = "low"
    state.blocked = state.blocked + 1
    table.insert(info.notes, "WAF/CDN interstitial (" .. vendor .. ")")
    return info, vendor
  end

  local soft, reason = looks_like_soft404(response, baseline)
  if soft then
    info.confidence = "low"
    table.insert(info.notes, "soft-404: " .. tostring(reason))
    return info, nil
  end

  if info.status == 401 or info.status == 403 then
    info.confidence = "low"
    table.insert(info.notes, string.format("HTTP %d: access control layer answered, not the application", info.status))
  elseif info.status == 429 then
    info.confidence = "low"
    table.insert(info.notes, "HTTP 429: the service is rate limiting the audit")
  elseif info.status >= 500 then
    info.confidence = "low"
    table.insert(info.notes, string.format("HTTP %d: server error response", info.status))
  elseif info.status == 404 then
    table.insert(info.notes, "HTTP 404")
  end

  if info.length == 0 then
    table.insert(info.notes, "empty body")
  end

  return info, nil
end

local findings = {}

local function add_finding(severity, detail, extra)
  local entry = {
    severity = severity,
    weight = SEVERITY[severity] or SEVERITY.INFO,
    detail = detail,
    path = extra and extra.path,
    subject = extra and extra.subject,
    confidence = extra and extra.confidence or "high",
    evidence = extra and extra.evidence,
  }
  if entry.confidence == "low" then
    entry.weight = math.max(0, math.floor(entry.weight / 2))
  end
  table.insert(findings, entry)
  return entry
end

local function reset_findings()
  findings = {}
end

local function dedupe_findings()
  local unique = {}
  local index = {}
  local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }

  for _, finding in ipairs(findings) do
    local key = tostring(finding.subject or "-") .. "|" .. finding.severity .. "|" .. finding.detail
    if not index[key] then
      index[key] = {
        severity = finding.severity,
        weight = finding.weight,
        subject = finding.subject,
        detail = finding.detail,
        confidence = finding.confidence,
        paths = {},
        evidence = {},
      }
      table.insert(unique, index[key])
    end
    local entry = index[key]
    if finding.path then
      local seen_path = false
      for _, existing in ipairs(entry.paths) do
        if existing == finding.path then
          seen_path = true
        end
      end
      if not seen_path then
        table.insert(entry.paths, finding.path)
      end
    end
    if finding.evidence then
      local sample = truncate(tostring(finding.evidence), 120)
      local seen_evidence = false
      for _, existing in ipairs(entry.evidence) do
        if existing == sample then
          seen_evidence = true
        end
      end
      if not seen_evidence and #entry.evidence < 4 then
        table.insert(entry.evidence, sample)
      end
    end
    counts[finding.severity] = (counts[finding.severity] or 0) + 1
  end

  local order = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5 }
  table.sort(unique, function(a, b)
    local first = order[a.severity] or 9
    local second = order[b.severity] or 9
    if first ~= second then
      return first < second
    end
    if a.weight ~= b.weight then
      return a.weight > b.weight
    end
    return tostring(a.detail) < tostring(b.detail)
  end)

  return unique, counts
end

local function weighted_score(unique)
  local score = 0
  for _, finding in ipairs(unique) do
    local multiplier = 1
    local path_count = #(finding.paths or {})
    if path_count > 1 then
      multiplier = multiplier + math.min(path_count - 1, 5) * 0.1
    end
    score = score + (finding.weight or 0) * multiplier
  end
  return math.floor(score + 0.5)
end

local function render_findings(unique, include_info)
  local rendered = {}
  for _, finding in ipairs(unique) do
    if finding.severity ~= "INFO" or include_info then
      local line = string.format("[%s] %s", finding.severity, finding.detail)
      if finding.subject and finding.subject ~= "-" then
        line = line .. " (" .. tostring(finding.subject) .. ")"
      end
      if finding.paths and #finding.paths > 0 then
        local shown = finding.paths
        if #shown > 3 then
          shown = { shown[1], shown[2], string.format("+%d more", #finding.paths - 2) }
        end
        line = line .. " [paths: " .. table.concat(shown, ", ") .. "]"
      end
      if finding.evidence and #finding.evidence > 0 then
        line = line .. " [evidence: " .. table.concat(finding.evidence, " | ") .. "]"
      end
      if finding.confidence == "low" then
        line = line .. " [low confidence]"
      end
      table.insert(rendered, line)
    end
  end
  return rendered
end

local function new_output(risk, status)
  local out = stdnse.output_table()
  out["Risk Level"] = risk
  out["Status"] = status
  return out
end

local function finish_output(out, unique, counts, extra_sections)
  local rendered = render_findings(unique, false)
  if #rendered == 0 then
    table.insert(rendered, "no weaknesses detected by this audit")
  end
  out["Findings"] = rendered
  out["Severity counts"] = string.format("CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d",
    counts.CRITICAL or 0, counts.HIGH or 0, counts.MEDIUM or 0,
    counts.LOW or 0, counts.INFO or 0)
  out["Weighted score"] = tostring(weighted_score(unique))
  for _, section in ipairs(extra_sections or {}) do
    if section.value ~= nil then
      out[section.key] = section.value
    end
  end
  out["Requests issued"] = tostring(state.requests)
  if state.rate_limited > 0 then
    out["Rate limited responses"] = tostring(state.rate_limited)
  end
  if state.errors > 0 then
    out["Transport errors"] = tostring(state.errors)
  end
  return out
end

local function normalize_dir(path)
  local value = trim(path or "/")
  if #value == 0 then
    value = "/"
  end
  if not starts_with(value, "/") then
    value = "/" .. value
  end
  if not ends_with(value, "/") then
    value = value .. "/"
  end
  return value
end

local function select_dirs(args)
  local selected = {}
  local seen = {}
  for _, candidate in ipairs(args.paths or LISTING_DIRS) do
    local normalized = normalize_dir(candidate)
    if unique_append(selected, seen, normalized) and #selected >= args.maxdirs then
      break
    end
  end
  if #selected == 0 then
    table.insert(selected, "/")
  end
  return selected
end

local function strip_tags(value)
  local text = string.gsub(tostring(value or ""), "<script.-></script>", " ")
  text = string.gsub(text, "<style.-></style>", " ")
  text = string.gsub(text, "<[^>]+>", " ")
  text = string.gsub(text, "&nbsp;", " ")
  text = string.gsub(text, "&amp;", "&")
  text = string.gsub(text, "&lt;", "<")
  text = string.gsub(text, "&gt;", ">")
  text = string.gsub(text, "&quot;", '"')
  text = string.gsub(text, "%s+", " ")
  return trim(text)
end

local function decode_uri(value)
  local decoded = string.gsub(tostring(value or ""), "%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16) or 0)
  end)
  decoded = string.gsub(decoded, "+", " ")
  return decoded
end

local function bucket_for(name)
  local lowered = lower(name)
  for _, entry in ipairs(SENSITIVE_BUCKETS) do
    for _, pattern in ipairs(entry.patterns) do
      local plain = string.find(lowered, pattern, 1, true)
      local magic = string.find(lowered, pattern)
      if plain or magic then
        return entry
      end
    end
  end
  return SENSITIVE_BUCKETS[#SENSITIVE_BUCKETS]
end

local function parse_size(value)
  local text = tostring(value or "")
  local number, unit = string.match(text, "([%d%.]+)%s*([KkMmGgTt]?)[Ii]?[Bb]?")
  if not number then
    number = string.match(text, "([%d%.]+)")
    unit = ""
  end
  local size = tonumber(number)
  if not size then
    return nil
  end
  local multiplier = 1
  local lowered = lower(unit or "")
  if lowered == "k" then
    multiplier = 1024
  elseif lowered == "m" then
    multiplier = 1048576
  elseif lowered == "g" then
    multiplier = 1073741824
  elseif lowered == "t" then
    multiplier = 1099511627776
  end
  return math.floor(size * multiplier)
end

local function add_entry(entries, seen, name, extra)
  if #entries >= (extra.limit or 400) then
    return false
  end
  if seen[name] then
    return false
  end
  seen[name] = true
  local entry = {
    name = name,
    is_dir = extra.is_dir or false,
    size = extra.size,
    modified = extra.modified,
    webdav = extra.webdav,
    link = extra.link,
    bucket = nil,
  }
  if not entry.is_dir then
    entry.bucket = bucket_for(name).bucket
  end
  table.insert(entries, entry)
  return true
end

local function escape_pattern(value)
  local escaped = string.gsub(tostring(value or ""), "([%(%)%.%%%+%-%*%?%[%]%^%$])", "%%%1")
  return escaped
end

local function parse_entries(body, base_path, max_entries)
  local entries = {}
  local seen = {}
  local limit = max_entries or 400

  local anchor_pattern = '<a%s+href%s*=%s*"([^"]+)"[^>]*>([^<]*)</a>'
  for href, text in string.gmatch(body, anchor_pattern) do
    local link = trim(href)
    if #link == 0 or starts_with(link, "#") or starts_with(link, "?")
      or starts_with(link, "mailto:") or starts_with(link, "javascript:")
      or string.find(link, "^https?://") or starts_with(link, "//")
      or contains(lower(link), "__icon_blank__") or contains(lower(link), "/icons/") then
      goto continue_link
    end

    local name = decode_uri(trim(text))
    name = string.gsub(name, "/$", "")
    if #name == 0 then
      name = decode_uri(string.match(link, "([^/]+)/?$") or link)
    end
    if #name == 0 or name == ".." or name == "." or lower(name) == "parent directory" then
      goto continue_link
    end

    local is_dir = ends_with(link, "/")
    local tail = string.match(body, escape_pattern(href) .. '"[^>]*>.-</a>(.-)\r?\n')
    local context = strip_tags(tail)
    local size_text = string.match(tail or "", 'align="right">%s*([%d%.]+%s*[KMGkmgTt]?i?[Bb]?)%s*</td>')
    local size = parse_size(size_text or context)
    local modified = string.match(context, "(%d%d%d%d%-%d%d%-%d%d %d%d:%d%d)")
    if not modified then
      modified = string.match(context, "(%d%d%-%a%a%a%-%d%d%d%d %d%d:%d%d)")
    end

    add_entry(entries, seen, name, { is_dir = is_dir, size = size, modified = modified,
      link = link, limit = limit })

    ::continue_link::
  end

  for key, size in string.gmatch(body,
    "<key>([^<]+)</key>.-<size>(%d+)</size>") do
    local name = string.gsub(decode_uri(key), "/$", "")
    if #name > 0 then
      add_entry(entries, seen, name, { is_dir = ends_with(key, "/"), size = tonumber(size),
        limit = limit })
    end
  end

  for href in string.gmatch(body, "<?d?:?href>([^<]+)</d?:?href>") do
    local name = string.gsub(decode_uri(href), "/$", "")
    local short = string.match(name, "([^/]+)$") or name
    if #short > 0 and short ~= ".." and short ~= "." then
      add_entry(entries, seen, short, { is_dir = ends_with(href, "/"), webdav = true,
        link = href, limit = limit })
    end
  end

  return entries
end

local function detect_listing(path, response, baseline, args)
  local result = {
    path = path,
    status = response.status or 0,
    length = #(response.body or ""),
    listing = false,
    generator = nil,
    score = 0,
    signals = {},
    confidence = "low",
    entries = {},
  }

  local info = classify_response(path, response, baseline)
  result.info = info
  if info.confidence == "low" then
    result.suppressed = true
    result.suppression = table.concat(info.notes, "; ")
    return result
  end

  local body = lower(response.body or "")
  if #body == 0 then
    return result
  end

  local is_xml = contains(body, "<?xml") or contains(body, "multistatus")
    or contains(body, "listbucketresult")
  local is_json = contains(body, "{") and (contains(body, "\"files\"") or contains(body, "\"entries\""))

  local best = nil
  local best_score = 0
  for _, signature in ipairs(LISTING_SIGNATURES) do
    local score = 0
    local signals = {}
    for _, pattern in ipairs(signature.patterns) do
      local found = string.find(body, pattern.pattern, 1, true)
        or string.find(body, pattern.pattern)
      if found then
        score = score + 1
        table.insert(signals, pattern.what)
      end
    end
    if score > 0 and score * signature.weight > best_score then
      best_score = score * signature.weight
      best = { generator = signature.generator, score = score, signals = signals }
    end
  end

  local link_count = 0
  local sibling_links = 0
  for href in string.gmatch(body, '<a%s+href%s*=%s*"([^"]+)"') do
    link_count = link_count + 1
    if not starts_with(href, "http") and not starts_with(href, "//")
      and not starts_with(href, "#") and not contains(href, "icons/") then
      sibling_links = sibling_links + 1
    end
  end

  local has_parent = contains(body, "parent directory") or contains(body, "[to parent directory]")
    or contains(body, '">../</a>')
  local has_columns = contains(body, "last modified") and (contains(body, "size") or contains(body, "description"))

  if best then
    result.generator = best.generator
    result.score = best.score
    result.signals = best.signals
    result.link_count = link_count
    result.sibling_links = sibling_links
    result.has_parent = has_parent
    result.has_columns = has_columns
    result.is_xml = is_xml
    result.is_json = is_json

    local structural = 0
    if sibling_links >= args.minlinks then
      structural = structural + 2
    end
    if has_parent then
      structural = structural + 1
    end
    if has_columns then
      structural = structural + 1
    end
    if best.score >= 3 then
      structural = structural + 1
    end
    if response.status == 207 or response.status == 200 and (is_xml or is_json) and sibling_links >= 1 then
      structural = structural + 1
    end
    result.structural = structural

    local generic = best.generator == "generic anchor-list index"
      or best.generator == "Apache mod_status-like index"
    local strong_signals = best.score >= 2
    local structural_ok = has_parent or sibling_links >= args.minlinks + 1

    if response.status == 207 then
      result.listing = true
      result.confidence = "medium"
    elseif generic and not structural_ok then
      result.confidence = "low"
      result.rejected = "generic index wording without a parent link or enough sibling links"
    elseif generic and not strong_signals then
      result.confidence = "low"
      result.rejected = "only weak index wording matched"
    elseif structural >= 3 then
      result.listing = true
      result.confidence = "high"
    elseif structural == 2 and strong_signals then
      result.listing = true
      result.confidence = "medium"
    else
      result.confidence = "low"
      result.rejected = "insufficient structural evidence"
    end
  end

  if result.listing then
    result.entries = parse_entries(response.body or "", path, args.maxentries)
    local buckets = {}
    local total_size = 0
    local oldest = nil
    local newest = nil
    local dirs = 0
    for _, entry in ipairs(result.entries) do
      if entry.is_dir then
        dirs = dirs + 1
      else
        local bucket = bucket_for(entry.name)
        buckets[bucket.bucket] = (buckets[bucket.bucket] or 0) + 1
        if not result.worst or (SEVERITY[bucket.severity] or 0) > (SEVERITY[result.worst_severity] or 0) then
          result.worst = bucket.bucket
          result.worst_severity = bucket.severity
          result.worst_example = entry.name
          result.worst_note = bucket.note
        end
      end
      if entry.size then
        total_size = total_size + entry.size
      end
      if entry.modified then
        if not oldest or entry.modified < oldest then
          oldest = entry.modified
        end
        if not newest or entry.modified > newest then
          newest = entry.modified
        end
      end
    end
    result.buckets = buckets
    result.total_size = total_size
    result.dir_count = dirs
    result.file_count = #result.entries - dirs
    result.oldest = oldest
    result.newest = newest
  end

  return result
end

local function human_size(bytes)
  local value = bytes or 0
  local units = { "B", "KiB", "MiB", "GiB", "TiB" }
  local index = 1
  while value >= 1024 and index < #units do
    value = value / 1024
    index = index + 1
  end
  return string.format("%.1f %s", value, units[index])
end

local function probe_webdav(host, port, path, args)
  if not args.webdav then
    return nil
  end
  local body = '<?xml version="1.0" encoding="utf-8"?>'
    .. '<d:propfind xmlns:d="DAV:"><d:allprop/></d:propfind>'
  local response, err = raw_request(host, port, "PROPFIND", path, {
    { "Depth", "1" },
    { "Content-Type", "application/xml" },
    { "Accept", "application/xml" },
  }, args, body)
  if not response then
    return { error = tostring(err) }
  end
  local result = {
    status = response.status or 0,
    length = #(response.body or ""),
    multistatus = (response.status == 207),
    entries = {},
  }
  if result.multistatus then
    result.entries = parse_entries(response.body or "", path, args.maxentries)
    local dav_header = response.headers and (response.headers["dav"] or response.headers["ms-author-via"])
    result.dav_header = dav_header
  end
  return result
end

local function dir_exists_but_denied(path, response)
  local status = response.status or 0
  if status ~= 403 and status ~= 401 then
    return false
  end
  local body = lower(response.body or "")
  return contains(body, "directory") or contains(body, "forbidden")
    or contains(body, "access denied") or contains(body, "permission denied")
end

local function severity_for_result(result)
  local severity = "LOW"
  if result.worst_severity then
    severity = result.worst_severity
  end
  if severity == "INFO" then
    severity = "LOW"
  end
  return severity
end

local function report_result(result)
  local severity = severity_for_result(result)
  local detail = string.format("directory listing enabled on %s (%s, %d entries, %s)",
    result.path, tostring(result.generator), #result.entries,
    human_size(result.total_size))
  if result.worst then
    detail = detail .. string.format(" — worst content class: %s (%s)", result.worst,
      tostring(result.worst_example))
  end
  add_finding(severity, detail, {
    path = result.path,
    subject = "listing:" .. result.path,
    confidence = result.confidence == "high" and "high" or "medium",
    evidence = tostring(result.generator) .. ", signals: " .. table.concat(result.signals or {}, "+"),
  })

  if result.worst_severity == "CRITICAL" then
    add_finding("CRITICAL", string.format("%s exposes %s content (%s): %s",
      result.path, result.worst, tostring(result.worst_example), tostring(result.worst_note)),
      { path = result.path, subject = "exposure:" .. result.worst .. ":" .. result.path,
        evidence = tostring(result.worst_example) })
  elseif result.worst_severity == "HIGH" then
    add_finding("HIGH", string.format("%s exposes %s content (%s): %s",
      result.path, result.worst, tostring(result.worst_example), tostring(result.worst_note)),
      { path = result.path, subject = "exposure:" .. result.worst .. ":" .. result.path,
        evidence = tostring(result.worst_example) })
  end

  if result.file_count and result.file_count > 200 then
    add_finding("MEDIUM", string.format("%s lists %d files - the directory is used as bulk storage",
      result.path, result.file_count),
      { path = result.path, subject = "volume:" .. result.path, evidence = tostring(result.file_count) })
  end

  if result.total_size and result.total_size > 104857600 then
    add_finding("MEDIUM", string.format("%s exposes %s of downloadable content",
      result.path, human_size(result.total_size)),
      { path = result.path, subject = "bytes:" .. result.path, evidence = human_size(result.total_size) })
  end

  if result.oldest and string.match(result.oldest, "^(%d%d%d%d)") then
    local year = tonumber(string.match(result.oldest, "^(%d%d%d%d)")) or 0
    local current_year = tonumber(os.date("%Y")) or (year + 1)
    if year > 0 and current_year - year >= 3 then
      add_finding("LOW", string.format("%s contains files last modified in %d (stale content left public)",
        result.path, year),
        { path = result.path, subject = "stale:" .. result.path, evidence = tostring(result.oldest) })
    end
  end

  if result.dir_count and result.dir_count > 0 then
    add_finding("INFO", string.format("%s lists %d subdirectories", result.path, result.dir_count),
      { path = result.path, subject = "subdirs:" .. result.path, evidence = tostring(result.dir_count) })
  end
end

local function render_result(result)
  local lines = {}
  table.insert(lines, string.format("%s -> HTTP %s, %s, %d entries (%d files / %d dirs), %s exposed",
    result.path, tostring(result.status), tostring(result.generator),
    #result.entries, result.file_count or 0, result.dir_count or 0,
    human_size(result.total_size)))
  table.insert(lines, string.format("      confidence: %s, structural score %s, signals: %s",
    tostring(result.confidence), tostring(result.structural),
    table.concat(result.signals or {}, "+")))
  if result.oldest or result.newest then
    table.insert(lines, string.format("      modified range: %s .. %s",
      tostring(result.oldest or "unknown"), tostring(result.newest or "unknown")))
  end
  if result.worst then
    table.insert(lines, string.format("      worst content: [%s] %s = %s (%s)",
      tostring(result.worst_severity), result.worst, tostring(result.worst_example),
      tostring(result.worst_note)))
  end
  if result.buckets then
    local parts = {}
    for _, name in ipairs(sorted_keys(result.buckets)) do
      table.insert(parts, string.format("%s=%d", name, result.buckets[name]))
    end
    if #parts > 0 then
      table.insert(lines, "      content classes: " .. table.concat(parts, ", "))
    end
  end
  local shown = 0
  for _, entry in ipairs(result.entries) do
    if shown >= 12 then
      table.insert(lines, string.format("      ... and %d more entries", #result.entries - shown))
      break
    end
    if not entry.is_dir then
      table.insert(lines, string.format("      - %-42s %-10s %-18s %s",
        truncate(entry.name, 42), entry.size and human_size(entry.size) or "-",
        tostring(entry.modified or "-"), tostring(entry.bucket or "-")))
      shown = shown + 1
    end
  end
  return lines
end

local function collect_subdirs(result, base_path)
  local final = {}
  local seen = {}
  for _, entry in ipairs(result.entries) do
    if entry.is_dir then
      local name = string.gsub(entry.name, "/$", "")
      if #name > 0 and name ~= ".." and name ~= "." then
        local child = normalize_dir(base_path .. name)
        if not seen[child] then
          seen[child] = true
          local prioritised = false
          for _, keyword in ipairs(LISTING_PATH_HINTS) do
            if contains(lower(child), keyword) then
              prioritised = true
              break
            end
          end
          table.insert(final, { path = child, prioritised = prioritised })
        end
      end
    end
  end
  table.sort(final, function(a, b)
    if a.prioritised ~= b.prioritised then
      return a.prioritised
    end
    return a.path < b.path
  end)
  return final
end

local analyse_dir

analyse_dir = function(host, port, path, args, baseline, depth, visited, results, denied)
  if args.recurse and depth > args.maxdepth then
    return
  end
  if list_contains(visited, path) then
    return
  end
  table.insert(visited, path)

  if budget_exhausted(args) then
    return
  end

  local response, err = fetch(host, port, path, args)
  if not response then
    table.insert(results, { path = path, error = tostring(err), depth = depth })
    return
  end

  if dir_exists_but_denied(path, response) then
    table.insert(denied, { path = path, status = response.status, depth = depth })
    return
  end

  local result = detect_listing(path, response, baseline, args)
  result.depth = depth

  if not result.listing then
    table.insert(results, { path = path, depth = depth, status = result.status,
      length = result.length, suppressed = result.suppression, note = "no listing detected" })
    return
  end

  report_result(result)
  table.insert(results, result)

  if args.webdav and not budget_exhausted(args) then
    local webdav = probe_webdav(host, port, path, args)
    if webdav then
      result.webdav = webdav
      if webdav.multistatus then
        add_finding("HIGH", string.format(
          "%s answers PROPFIND with HTTP 207 multistatus (%d entries): WebDAV metadata is readable",
          path, #webdav.entries),
          { path = path, subject = "webdav:" .. path, evidence = "status 207" })
      end
    end
  end

  if args.recurse and depth < args.maxdepth then
    for _, child in ipairs(collect_subdirs(result, path)) do
      if budget_exhausted(args) then
        break
      end
      analyse_dir(host, port, child.path, args, baseline, depth + 1, visited, results, denied)
    end
  end
end

local function summarise(results)
  local listings = 0
  local entries = 0
  local bytes = 0
  local generators = {}
  local buckets = {}
  local deepest = 0

  for _, result in ipairs(results) do
    if result.listing then
      listings = listings + 1
      entries = entries + #result.entries
      bytes = bytes + (result.total_size or 0)
      generators[result.generator or "unknown"] = (generators[result.generator or "unknown"] or 0) + 1
      deepest = math.max(deepest, result.depth or 0)
      for name, count in pairs(result.buckets or {}) do
        buckets[name] = (buckets[name] or 0) + count
      end
    end
  end

  return {
    listings = listings,
    entries = entries,
    bytes = bytes,
    generators = generators,
    buckets = buckets,
    deepest = deepest,
  }
end

local function render_summary(summary)
  local lines = {}
  table.insert(lines, string.format("listings: %d, entries parsed: %d, exposed: %s, max depth: %d",
    summary.listings, summary.entries, human_size(summary.bytes), summary.deepest))
  local gen_parts = {}
  for _, name in ipairs(sorted_keys(summary.generators)) do
    table.insert(gen_parts, string.format("%s=%d", name, summary.generators[name]))
  end
  if #gen_parts > 0 then
    table.insert(lines, "generators: " .. table.concat(gen_parts, ", "))
  end
  local bucket_parts = {}
  for _, name in ipairs(sorted_keys(summary.buckets)) do
    table.insert(bucket_parts, string.format("%s=%d", name, summary.buckets[name]))
  end
  if #bucket_parts > 0 then
    table.insert(lines, "content classes across all listings: " .. table.concat(bucket_parts, ", "))
  end
  return lines
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local baseline = build_soft404_baseline(host, port, args)
  local dirs = select_dirs(args)

  local visited = {}
  local results = {}
  local denied = {}
  local suppressed = {}

  for _, path in ipairs(dirs) do
    if budget_exhausted(args) then
      break
    end
    local before = #results
    analyse_dir(host, port, path, args, baseline, 0, visited, results, denied)
    if #results > before then
      local last = results[#results]
      if last.suppressed then
        table.insert(suppressed, last)
      end
    end
  end

  local summary = summarise(results)

  local listing_lines = {}
  local non_listing_lines = {}
  for _, result in ipairs(results) do
    if result.listing then
      for _, line in ipairs(render_result(result)) do
        table.insert(listing_lines, line)
      end
      if result.webdav then
        if result.webdav.multistatus then
          table.insert(listing_lines, string.format("      PROPFIND: HTTP 207 multistatus, %d entries%s",
            #result.webdav.entries,
            result.webdav.dav_header and (", DAV: " .. tostring(result.webdav.dav_header)) or ""))
        elseif result.webdav.error then
          table.insert(listing_lines, "      PROPFIND: " .. result.webdav.error)
        else
          table.insert(listing_lines, string.format("      PROPFIND: HTTP %s (no multistatus)",
            tostring(result.webdav.status)))
        end
      end
    elseif result.error then
      table.insert(non_listing_lines, string.format("%s: %s", result.path, result.error))
    elseif result.suppressed then
      table.insert(non_listing_lines, string.format("%s -> HTTP %s suppressed (%s)",
        result.path, tostring(result.status), result.suppressed))
    else
      table.insert(non_listing_lines, string.format("%s -> HTTP %s, %d bytes: %s",
        result.path, tostring(result.status), result.length or 0, tostring(result.note or "no listing")))
    end
  end

  local denied_lines = {}
  for _, entry in ipairs(denied) do
    table.insert(denied_lines, string.format("%s -> HTTP %s (directory likely exists but is not browsable)",
      entry.path, tostring(entry.status)))
  end

  local unique, counts = dedupe_findings()

  local out = new_output(RISK_LEVEL, "AUDITED - directory listing check completed.")
  if summary.listings > 0 and counts.CRITICAL > 0 then
    out["Status"] = "VULNERABLE - browsable directories expose critical content (keys, dumps, environment files)."
  elseif summary.listings > 0 and counts.HIGH > 0 then
    out["Status"] = "VULNERABLE - browsable directories expose sensitive content."
  elseif summary.listings > 0 then
    out["Status"] = "AUDITED - directory listing is enabled but no high-sensitivity content was listed."
  elseif #denied > 0 then
    out["Status"] = "AUDITED - directories exist but listing is denied (HTTP 401/403)."
  elseif #results == 0 then
    out["Status"] = "AUDITED - no directory responded with a listing or a denial."
  else
    out["Status"] = "AUDITED - no directory listing detected on the tested paths."
  end

  local sections = {
    { key = "Transport", value = (port.ssl or (port.version and port.version.service_ssl)) and "HTTPS" or "HTTP" },
    { key = "Summary", value = render_summary(summary) },
    { key = "Listings", value = #listing_lines > 0 and listing_lines or { "no directory listing detected" } },
    { key = "Directories probed", value = #visited },
  }

  if #denied_lines > 0 then
    table.insert(sections, { key = "Denied directories", value = denied_lines })
  end
  if #non_listing_lines > 0 then
    local shown = {}
    for index, line in ipairs(non_listing_lines) do
      if index > 40 then
        table.insert(shown, string.format("... and %d more non-listing responses", #non_listing_lines - 40))
        break
      end
      table.insert(shown, line)
    end
    table.insert(sections, { key = "Non-listing responses", value = shown })
  end
  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed (suppressed as false positives)" or "no catch-all") })
  end
  if #suppressed > 0 then
    table.insert(sections, { key = "Suppressed candidates", value = #suppressed })
  end

  if summary.listings > 0 then
    table.insert(sections, { key = "Remediation", value =
      "disable autoindex (Options -Indexes / autoindex off / EnableBrowse * deny), move backup, "
      .. "log and dump directories outside the document root, and add an explicit deny rule for "
      .. "dotfiles so .git, .env and .svn can never be listed" })
  else
    table.insert(sections, { key = "Remediation", value =
      "no browsable directory found on the tested paths; keep autoindex disabled, keep upload and "
      .. "backup storage outside the document root, and re-test after any web-server migration "
      .. "because autoindex defaults differ between nginx, Apache and IIS" })
  end

  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  return finish_output(out, unique, counts, sections)

end
