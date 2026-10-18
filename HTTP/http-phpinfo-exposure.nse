local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Finds publicly reachable phpinfo() pages and extracts the security-relevant
configuration from them. A phpinfo() page is a single-file disclosure of the
whole PHP runtime: exact version and build date, the loaded configuration file,
every ini directive with its local and master value, the complete server
environment, the HTTP headers of the request that produced the page, the loaded
extension list, and often the database defaults and include paths.

Why it matters
Attackers use the exact PHP version to pick an exploit, use `disable_functions`
to know which post-exploitation primitives remain, use `allow_url_include`,
`enable_dl` or `open_basedir` to decide whether an LFI is upgradeable to RCE,
and read secrets straight out of the Environment section - a phpinfo() page on a
container or a misconfigured host frequently prints `DATABASE_URL`,
`AWS_SECRET_ACCESS_KEY`, `APP_KEY` or session signing secrets because PHP
populates `$_ENV` from the process environment. The HTTP Headers section also
echoes back whatever the visitor sent, so a phpinfo() page that a crawler or a
monitoring probe hits with an Authorization header stores that credential in the
page it returns.

What the script fetches
70 candidate paths covering the common names (`phpinfo.php`, `info.php`, `i.php`,
`test.php`, `p.php`, `php-info.php`, `phpversion.php`, `pi.php`, `_phpinfo.php`,
`apc.php`, `xdebug.php`), framework and stack locations (`admin/phpinfo.php`,
`_profiler/phpinfo`, `symfony/web/app_dev.php`, `laravel/public/index.php`
style probes, `wp-admin/phpinfo.php`, `vendor/phpinfo.php`), deployment
leftovers (`install.php`, `install/info.php`, `setup/phpinfo.php`,
`tmp/phpinfo.php`, `dev/info.php`), and any operator-supplied path. Each
candidate is also probed with a `.php` suffix when the supplied path has none.

How a page is confirmed
A response only counts as phpinfo() when it carries at least two independent
markers from: the `phpinfo()` heading, the `PHP Version` table title, the
`Configuration` section with a `Directive / Local Value / Master Value` header,
the Zend Engine line, the `allow_url_fopen` directive name, the
`PHP License` footer, the `phpinfo()` CSS class names (`v`, `e`, `h`, `center`
with the specific purple header colour `#9999cc` / `#666699` / `#cccccc`), and
the `Registered PHP Streams` / `Zend Extension` rows. Single-marker pages are
reported as suspected, not confirmed, and catch-all 200 answers are filtered
with the soft-404 baseline built from two random paths before any candidate is
requested.

What the script extracts and how it judges each value
* Core identity: PHP version, Zend Engine version, build date, server API
  (cgi-fpm, fpm-fcgi, apache2handler, litespeed, cli), loaded configuration
  file and scanned .d directory, include_path, DOCUMENT_ROOT, session
  save_path, sys temp dir, extension dir, and every `Loaded Configuration`
  path - these tell an auditor which files to review and whether the runtime is
  a container or a hand-built install.
* Directive policy: each of ~55 security-relevant directives is compared with
  its secure default and scored - `allow_url_include=On` and `enable_dl=On` are
  CRITICAL, `display_errors=On` with a non-cli SAPI is HIGH, `expose_php`,
  `session.cookie_httponly=0`, `session.cookie_secure=0`,
  `session.use_strict_mode=0`, `session.use_only_cookies=0`,
  `file_uploads=On` without `upload_max_filesize` limits, `allow_url_fopen`,
  `log_errors=Off`, `open_basedir` empty, `disable_functions` empty,
  `cgi.force_redirect=0`, `cgi.fix_pathinfo=1`, `zend.assertions=1`,
  `opcache.validate_timestamps`, `max_execution_time`, `memory_limit`,
  `post_max_size`, `error_reporting=E_ALL` with display on, `soap.wsdl_cache`,
  `mbstring.func_overload`, `always_populate_raw_post_data`, `magic_quotes_*`
  (legacy directives that indicate an abandoned build), `safe_mode` (removed in
  PHP 5.4 - its presence dates the runtime), `register_globals` (removed in 5.4
  - CRITICAL when present and On).
* Environment: every `$_ENV` row is classified - a key matching a secret marker
  (`KEY`, `SECRET`, `TOKEN`, `PASS`, `PWD`, `CREDENTIAL`, `PRIVATE`, `AWS`,
  `AZURE`, `GCP`, `DATABASE_URL`, `REDIS`, `MONGO`, `SMTP`, `API`, `SALT`,
  `CERT`, `DSN`, `AUTH`, `SIGN`, `HMAC`, `OAUTH`, `WEBHOOK`) with a value that
  is not a placeholder (`***`, `no value`, `not set`, `null`, `none`, `-`) is a
  CRITICAL credential exposure, and the value is masked in the report while the
  finding records the key name and length; infrastructure keys (hostnames,
  container IDs, orchestrator variables) are MEDIUM disclosure; benign keys
  (`PATH`, `LANG`, `HOME`, `PWD`, `TERM`, `SHELL`, `USER`, `HOSTNAME`, `SHLVL`,
  `_`, `LC_*`, `TZ`, `TMPDIR`) are listed without a finding.
* HTTP headers echoed by the page: an `Authorization`, `Cookie`,
  `X-Api-Key`, `Proxy-Authorization` or `X-Forwarded-*` row means the page
  reflects client credentials back to whoever can read it - HIGH for
  Authorization/Cookie/API key, MEDIUM for forwarding headers that also reveal
  the internal topology.
* Extensions: the loaded module list is scanned for debug and loader extensions
  (`xdebug` with `xdebug.remote_enable=1` is CRITICAL remote code execution
  surface, `Zend Debugger`, `ionCube Loader`, `SourceGuardian`, `suhosin`,
  `uploadprogress`, `apc`, `eaccelerator`, `winbinder`, `dbase`, `mssql`,
  `pdo_dblib`, `snmp`, `imap`, `ssh2`, `pdo_firebird`, `oci8`) and for the
  absence of expected hardening (`sodium`/`openssl` for crypto, `mbstring`).
* Database defaults: `mysql.default_host`, `mysql.default_user`,
  `mysql.default_password`, `mysqli.default_*`, `pdo_mysql.default_socket`,
  `pgsql.*`, `odbc.default*`, `sybase.*` - a non-empty default password is
  CRITICAL, a non-empty default user/host is MEDIUM.
* Streams and wrappers: `Registered PHP Streams` shows which URL wrappers exist
  (`compress.zlib`, `php`, `file`, `glob`, `data`, `http`, `https`, `ftp`,
  `ftps`, `zip`, `phar`) - `http`/`https`/`ftp`/`data` present together with
  `allow_url_fopen=On` means SSRF-capable file functions; `phar` present means
  phar deserialization is a candidate vector for any file-upload path.

Output
The report gives a per-page block: identity lines, the scored directives with
their local/master values and why the value is wrong, masked credential rows,
echoed header rows, extension warnings, database defaults, stream wrappers, and
the section inventory (which phpinfo sections are present, so a reader knows
what else is exposed). Findings are deduplicated by directive name and page
path. Where no phpinfo page is reachable the script says so explicitly and
reports how many candidates were tested and whether the site answers with a
catch-all page (which would have hidden one).

Usage:
<code>
nmap -p 80,443 --script http-phpinfo-exposure <target>
nmap -p 80 --script http-phpinfo-exposure \
  --script-args http-phpinfo-exposure.paths="/phpinfo.php,/info.php,/admin/info.php" <target>
nmap -p 443 --script http-phpinfo-exposure \
  --script-args http-phpinfo-exposure.maxrequests=200,http-phpinfo-exposure.mask=false <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local SCRIPT_NAME = "http-phpinfo-exposure"

local RISK_LEVEL = "🟠 HIGH"

local CANDIDATE_PATHS = {
  "/phpinfo.php", "/info.php", "/i.php", "/test.php", "/p.php", "/pi.php",
  "/php-info.php", "/php_version.php", "/phpversion.php", "/_phpinfo.php",
  "/php.php", "/infophp.php", "/php_info.php", "/xdebug.php", "/apc.php",
  "/admin/phpinfo.php", "/admin/info.php", "/admin/test.php",
  "/administrator/phpinfo.php", "/manage/phpinfo.php", "/manager/phpinfo.php",
  "/panel/phpinfo.php", "/dashboard/phpinfo.php", "/backend/phpinfo.php",
  "/internal/phpinfo.php", "/debug/phpinfo.php", "/dev/phpinfo.php",
  "/dev/info.php", "/development/phpinfo.php", "/staging/phpinfo.php",
  "/tools/phpinfo.php", "/tool/phpinfo.php", "/utils/phpinfo.php",
  "/support/phpinfo.php", "/status/phpinfo.php", "/health/phpinfo.php",
  "/_profiler/phpinfo", "/_profiler/empty/search/results?q=phpinfo",
  "/symfony/web/app_dev.php", "/app_dev.php/_profiler/phpinfo",
  "/phpmyadmin/phpinfo.php", "/pma/phpinfo.php", "/myadmin/phpinfo.php",
  "/wp-admin/phpinfo.php", "/wp-content/phpinfo.php", "/wordpress/phpinfo.php",
  "/laravel/public/phpinfo.php", "/public/phpinfo.php", "/public/info.php",
  "/vendor/phpinfo.php", "/site/phpinfo.php", "/web/phpinfo.php",
  "/www/phpinfo.php", "/htdocs/phpinfo.php", "/http/phpinfo.php",
  "/install.php", "/install/info.php", "/install/phpinfo.php",
  "/installer/phpinfo.php", "/setup/phpinfo.php", "/setup/info.php",
  "/tmp/phpinfo.php", "/temp/phpinfo.php", "/backup/phpinfo.php",
  "/uploads/phpinfo.php", "/media/phpinfo.php", "/files/phpinfo.php",
  "/assets/phpinfo.php", "/static/phpinfo.php", "/cgi-bin/phpinfo.php",
  "/server-status/phpinfo.php", "/api/phpinfo.php", "/api/info.php",
  "/v1/phpinfo.php", "/v2/phpinfo.php", "/php/phpinfo.php", "/php5/phpinfo.php",
  "/php7/phpinfo.php", "/php8/phpinfo.php", "/x.php", "/t.php", "/info",
  "/phpinfo", "/phpinfo.html", "/phpinfo.txt", "/env.php", "/config.php",
  "/server.php", "/sysinfo.php", "/systeminfo.php", "/check.php",
}

local PHPINFO_MARKERS = {
  { pattern = "phpinfo()", weight = 3, note = "phpinfo() heading" },
  { pattern = "PHP Version", weight = 2, note = "PHP Version title" },
  { pattern = "Directive", weight = 1, note = "directive table" },
  { pattern = "Local Value", weight = 2, note = "Local Value column" },
  { pattern = "Master Value", weight = 2, note = "Master Value column" },
  { pattern = "Zend Engine", weight = 3, note = "Zend Engine line" },
  { pattern = "allow_url_fopen", weight = 3, note = "core directive name" },
  { pattern = "PHP License", weight = 3, note = "license footer" },
  { pattern = "Registered PHP Streams", weight = 3, note = "streams section" },
  { pattern = "Zend Extension Build", weight = 2, note = "build line" },
  { pattern = "PHP Extension Build", weight = 2, note = "build line" },
  { pattern = "#9999cc", weight = 1, note = "phpinfo header colour" },
  { pattern = "#666699", weight = 1, note = "phpinfo header colour" },
  { pattern = "disable_functions", weight = 2, note = "core directive name" },
  { pattern = "Loaded Configuration File", weight = 3, note = "configuration line" },
  { pattern = "Configuration File (php.ini) Path", weight = 3, note = "ini path line" },
  { pattern = "SERVER_SOFTWARE", weight = 1, note = "environment row" },
  { pattern = "DOCUMENT_ROOT", weight = 1, note = "environment row" },
  { pattern = "session.save_path", weight = 2, note = "session directive" },
  { pattern = "open_basedir", weight = 2, note = "filesystem directive" },
}

local DIRECTIVE_POLICY = {
  ["allow_url_include"] = {
    secure = { "off", "0", "" },
    severity = "CRITICAL",
    detail = "remote files can be included: any request that reaches an include() with "
      .. "attacker input becomes remote code execution",
  },
  ["enable_dl"] = {
    secure = { "off", "0", "" },
    severity = "CRITICAL",
    detail = "dl() can load an arbitrary extension at runtime, bypassing every PHP sandbox",
  },
  ["register_globals"] = {
    secure = { "off", "0", "", nil },
    severity = "CRITICAL",
    detail = "request parameters become global variables; this directive was removed in PHP 5.4, "
      .. "so its presence also dates the runtime",
  },
  ["safe_mode"] = {
    secure = { "off", "0", "", nil },
    severity = "LOW",
    detail = "safe_mode was removed in PHP 5.4; when the row exists the runtime predates it",
  },
  ["display_errors"] = {
    secure = { "off", "0", "", "stderr" },
    severity = "HIGH",
    detail = "errors are rendered to the client, leaking paths, queries, versions and stack traces",
  },
  ["display_startup_errors"] = {
    secure = { "off", "0", "", "stderr" },
    severity = "MEDIUM",
    detail = "startup errors are rendered to the client",
  },
  ["log_errors"] = {
    secure = { "on", "1" },
    severity = "MEDIUM",
    detail = "errors are not logged, so incidents leave no server-side record",
  },
  ["expose_php"] = {
    secure = { "off", "0" },
    severity = "MEDIUM",
    detail = "the X-Powered-By header advertises the exact PHP version",
  },
  ["open_basedir"] = {
    secure_nonempty = true,
    severity = "MEDIUM",
    detail = "no filesystem jail: any file-read primitive reaches the whole disk the worker can read",
  },
  ["disable_functions"] = {
    secure_nonempty = true,
    severity = "MEDIUM",
    detail = "no dangerous function is disabled (exec, system, passthru, shell_exec, popen, proc_open, "
      .. "pcntl_*, putenv are all available)",
  },
  ["session.cookie_httponly"] = {
    secure = { "on", "1" },
    severity = "MEDIUM",
    detail = "the session cookie is readable by script, so any XSS becomes session theft",
  },
  ["session.cookie_secure"] = {
    secure = { "on", "1" },
    severity = "MEDIUM",
    detail = "the session cookie is sent over plain HTTP as well",
  },
  ["session.cookie_samesite"] = {
    secure_nonempty = true,
    severity = "LOW",
    detail = "no SameSite attribute: the session cookie rides along on cross-site requests",
  },
  ["session.use_strict_mode"] = {
    secure = { "on", "1" },
    severity = "MEDIUM",
    detail = "the server accepts an uninitialized session id from the client (session fixation)",
  },
  ["session.use_only_cookies"] = {
    secure = { "on", "1" },
    severity = "MEDIUM",
    detail = "the session id may travel in the URL, which leaks it through logs and Referer headers",
  },
  ["session.use_trans_sid"] = {
    secure = { "off", "0", "" },
    severity = "MEDIUM",
    detail = "session ids are rewritten into URLs",
  },
  ["session.save_path"] = {
    severity = "LOW",
    detail = "session storage location is disclosed",
    disclose = true,
  },
  ["allow_url_fopen"] = {
    secure = { "off", "0" },
    severity = "MEDIUM",
    detail = "file functions accept URLs, so any user-controlled path is an SSRF candidate",
  },
  ["cgi.force_redirect"] = {
    secure = { "on", "1" },
    severity = "HIGH",
    detail = "CGI redirect protection is off; on a CGI SAPI this is the classic source-disclosure "
      .. "and forced-handler vector",
  },
  ["cgi.fix_pathinfo"] = {
    secure = { "off", "0" },
    severity = "HIGH",
    detail = "PATH_INFO fallback is on: an uploaded file such as image.jpg can be executed as PHP "
      .. "when the request is image.jpg/x.php (nginx + php-fpm)",
  },
  ["cgi.discard_path"] = {
    secure = { "on", "1" },
    severity = "MEDIUM",
    detail = "the CGI SAPI keeps PATH_INFO in the script filename",
  },
  ["cgi.rfc2616_headers"] = {
    severity = "INFO",
    detail = "header generation mode disclosed",
    disclose = true,
  },
  ["file_uploads"] = {
    secure = { "off", "0" },
    severity = "LOW",
    detail = "file uploads are enabled runtime-wide",
  },
  ["upload_max_filesize"] = {
    severity = "LOW",
    detail = "upload size limit disclosed",
    disclose = true,
  },
  ["post_max_size"] = {
    severity = "LOW",
    detail = "POST size limit disclosed",
    disclose = true,
  },
  ["max_execution_time"] = {
    severity = "INFO",
    detail = "execution time limit disclosed (useful for timing side channels and DoS sizing)",
    disclose = true,
  },
  ["memory_limit"] = {
    severity = "INFO",
    detail = "memory limit disclosed",
    disclose = true,
  },
  ["max_input_vars"] = {
    severity = "INFO",
    detail = "input variable limit disclosed",
    disclose = true,
  },
  ["error_reporting"] = {
    severity = "LOW",
    detail = "the runtime reports every error class",
    disclose = true,
  },
  ["error_log"] = {
    severity = "LOW",
    detail = "the error log path is disclosed",
    disclose = true,
  },
  ["include_path"] = {
    severity = "LOW",
    detail = "the include search path is disclosed (absolute server paths)",
    disclose = true,
  },
  ["sendmail_path"] = {
    severity = "LOW",
    detail = "the mail transport command is disclosed and may contain arguments",
    disclose = true,
  },
  ["zend.assertions"] = {
    secure = { "-1", "0" },
    severity = "MEDIUM",
    detail = "assertions are compiled and evaluated: a development build is in production",
  },
  ["opcache.validate_timestamps"] = {
    secure = { "off", "0" },
    severity = "LOW",
    detail = "the opcache re-reads source on every request (performance) - the setting also tells an "
      .. "attacker whether a written file executes immediately",
  },
  ["opcache.enable"] = {
    severity = "INFO",
    detail = "opcache state disclosed",
    disclose = true,
  },
  ["xdebug.remote_enable"] = {
    secure = { "off", "0", "" },
    severity = "CRITICAL",
    detail = "Xdebug remote debugging is enabled: an attacker who reaches the debug port executes "
      .. "arbitrary code as the web user",
  },
  ["xdebug.mode"] = {
    severity = "HIGH",
    detail = "Xdebug is loaded with a non-off mode",
    insecure_values = { "debug", "develop", "trace", "profile", "coverage" },
  },
  ["xdebug.remote_autostart"] = {
    secure = { "off", "0", "" },
    severity = "HIGH",
    detail = "Xdebug starts a debug session on every request without a trigger",
  },
  ["xdebug.remote_connect_back"] = {
    secure = { "off", "0", "" },
    severity = "CRITICAL",
    detail = "Xdebug connects back to whoever made the HTTP request: unauthenticated remote code "
      .. "execution for any client that can reach the page",
  },
  ["xdebug.profiler_enable"] = {
    secure = { "off", "0", "" },
    severity = "MEDIUM",
    detail = "the profiler writes call graphs to disk on trigger",
  },
  ["xdebug.remote_host"] = {
    severity = "MEDIUM",
    detail = "the Xdebug callback host is disclosed",
    disclose = true,
  },
  ["mysql.default_password"] = {
    secure = { "", "off", "0" },
    severity = "CRITICAL",
    detail = "a default MySQL password is compiled into the runtime configuration",
  },
  ["mysql.default_user"] = {
    secure = { "", "off", "0" },
    severity = "MEDIUM",
    detail = "a default MySQL user is configured",
  },
  ["mysql.default_host"] = {
    secure = { "", "off", "0" },
    severity = "LOW",
    detail = "a default MySQL host is configured",
  },
  ["mysqli.default_pw"] = {
    secure = { "", "off", "0" },
    severity = "CRITICAL",
    detail = "a default mysqli password is configured",
  },
  ["mysqli.default_user"] = {
    secure = { "", "off", "0" },
    severity = "MEDIUM",
    detail = "a default mysqli user is configured",
  },
  ["mysqli.default_host"] = {
    secure = { "", "off", "0" },
    severity = "LOW",
    detail = "a default mysqli host is configured",
  },
  ["mysqli.default_socket"] = {
    severity = "LOW",
    detail = "the database socket path is disclosed",
    disclose = true,
  },
  ["pdo_mysql.default_socket"] = {
    severity = "LOW",
    detail = "the PDO MySQL socket path is disclosed",
    disclose = true,
  },
  ["pgsql.log_notice"] = {
    severity = "INFO",
    detail = "PostgreSQL notice logging state disclosed",
    disclose = true,
  },
  ["odbc.default_user"] = {
    secure = { "", "off", "0" },
    severity = "MEDIUM",
    detail = "a default ODBC user is configured",
  },
  ["odbc.default_pw"] = {
    secure = { "", "off", "0" },
    severity = "CRITICAL",
    detail = "a default ODBC password is configured",
  },
  ["sybct.timeout"] = {
    severity = "INFO",
    detail = "Sybase timeout disclosed",
    disclose = true,
  },
  ["soap.wsdl_cache_dir"] = {
    severity = "LOW",
    detail = "the WSDL cache directory is disclosed and is writable by the runtime",
    disclose = true,
  },
  ["mbstring.func_overload"] = {
    secure = { "0", "", "off" },
    severity = "MEDIUM",
    detail = "string functions are overloaded, which historically breaks length checks in security code",
  },
  ["always_populate_raw_post_data"] = {
    secure = { "-1", "off", "0" },
    severity = "LOW",
    detail = "raw POST data is populated in a global (deprecated behaviour, indicates an old build)",
  },
  ["magic_quotes_gpc"] = {
    secure = { "off", "0", "" },
    severity = "LOW",
    detail = "magic quotes present: the runtime predates PHP 5.4",
  },
  ["magic_quotes_runtime"] = {
    secure = { "off", "0", "" },
    severity = "LOW",
    detail = "magic quotes present: the runtime predates PHP 5.4",
  },
  ["magic_quotes_sybase"] = {
    secure = { "off", "0", "" },
    severity = "LOW",
    detail = "magic quotes present: the runtime predates PHP 5.4",
  },
  ["short_open_tag"] = {
    severity = "INFO",
    detail = "short open tags state disclosed (affects template injection reachability)",
    disclose = true,
  },
  ["asp_tags"] = {
    secure = { "off", "0", "" },
    severity = "LOW",
    detail = "ASP-style tags enabled: the runtime predates PHP 7",
  },
  ["auto_prepend_file"] = {
    secure = { "", "off", "0" },
    severity = "MEDIUM",
    detail = "a file is prepended to every request; its path is disclosed and it is a persistence hook",
  },
  ["auto_append_file"] = {
    secure = { "", "off", "0" },
    severity = "MEDIUM",
    detail = "a file is appended to every request; its path is disclosed and it is a persistence hook",
  },
  ["user_ini.filename"] = {
    severity = "LOW",
    detail = "the per-directory ini filename is disclosed (.user.ini upload override vector)",
    disclose = true,
  },
  ["docref_root"] = {
    severity = "INFO",
    detail = "documentation reference root disclosed",
    disclose = true,
  },
  ["suhosin.session.encrypt"] = {
    severity = "INFO",
    detail = "Suhosin session encryption state disclosed",
    disclose = true,
  },
  ["imap.enable_insecure_rsh"] = {
    secure = { "off", "0", "" },
    severity = "HIGH",
    detail = "insecure rsh is enabled for the IMAP extension (command injection surface)",
  },
  ["session.sid_length"] = {
    severity = "INFO",
    detail = "session id length disclosed",
    disclose = true,
  },
  ["session.sid_bits_per_character"] = {
    severity = "INFO",
    detail = "session id entropy per character disclosed",
    disclose = true,
  },
}

local SECRET_KEY_MARKERS = {
  "key", "secret", "token", "pass", "pwd", "credential", "private", "aws",
  "azure", "gcp", "google", "database_url", "db_url", "redis", "mongo",
  "smtp", "api", "salt", "cert", "dsn", "auth", "sign", "hmac", "oauth",
  "webhook", "stripe", "twilio", "sendgrid", "mailgun", "slack", "github",
  "gitlab", "bitbucket", "npm", "composer", "docker", "registry", "vault",
  "consul", "rabbitmq", "kafka", "amqp", "jdbc", "connection_string",
  "encryption", "cipher", "pem", "p12", "keystore", "access", "identity",
}

local BENIGN_ENV_KEYS = {
  "path", "lang", "home", "term", "shell", "user", "hostname", "shlvl", "_",
  "tz", "tmpdir", "pwd", "oldpwd", "ls_colors", "less", "editor", "mail",
  "logname", "hosttype", "ostype", "machtype", "group", "display", "xpc_",
  "systemd_", "invocation_id", "journal_stream", "notify_socket", "container",
}

local INFRA_ENV_KEYS = {
  "server_name", "server_addr", "server_port", "remote_addr", "remote_port",
  "gateway_interface", "server_protocol", "server_signature", "server_software",
  "document_root", "script_filename", "script_name", "script_uri", "script_url",
  "request_uri", "request_method", "query_string", "php_self", "path_translated",
  "path_info", "context_prefix", "context_document_root", "fcgi_role",
  "request_scheme", "https", "proxy", "uniqid", "kubernetes", "kube_", "docker",
  "host", "hostname", "pod_", "node_", "instance", "region", "zone", "stack",
  "environment", "env", "app_env", "runtime_env", "deploy", "revision",
  "release", "build", "commit", "branch", "ci_", "git_", "svn_",
  "http_x_forwarded_for", "http_x_forwarded_host", "http_x_forwarded_proto",
  "http_via", "http_forwarded", "http_x_real_ip", "http_client_ip",
}

local CREDENTIAL_HEADERS = {
  "http_authorization", "authorization", "http_proxy_authorization",
  "proxy_authorization", "http_cookie", "cookie", "http_x_api_key",
  "x_api_key", "http_x_auth_token", "x_auth_token", "http_x_csrf_token",
  "http_x_aws_", "http_x_goog_", "http_x_amz_", "http_api_key",
  "http_x_auth", "http_x_token", "http_set_cookie",
}

local TOPOLOGY_HEADERS = {
  "http_x_forwarded_for", "http_x_forwarded_host", "http_x_forwarded_proto",
  "http_via", "http_forwarded", "http_x_real_ip", "http_client_ip",
  "http_x_original_url", "http_x_rewrite_url", "http_x_forwarded_server",
  "http_x_cluster_client_ip", "http_true_client_ip", "http_cdn_src_ip",
  "http_cf_connecting_ip", "http_x_amzn_trace_id",
}

local RISKY_EXTENSIONS = {
  { name = "xdebug", severity = "HIGH", note = "the Xdebug debugger is loaded" },
  { name = "zend debugger", severity = "HIGH", note = "Zend Debugger is loaded",
    tokens = { "zend", "debugger" } },
  { name = "ioncube loader", severity = "MEDIUM", note = "ionCube encoded code is in use (commercial build)",
    tokens = { "ioncube", "loader" } },
  { name = "sourceguardian", severity = "MEDIUM", note = "SourceGuardian encoded code is in use" },
  { name = "suhosin", severity = "LOW", note = "Suhosin hardening extension present" },
  { name = "eaccelerator", severity = "MEDIUM", note = "eAccelerator present: abandoned, and its cache is "
    .. "a known code-injection target" },
  { name = "apc", severity = "LOW", note = "APC present (replaced by opcache in PHP 5.5)" },
  { name = "uploadprogress", severity = "LOW", note = "the uploadprogress extension is present" },
  { name = "ssh2", severity = "MEDIUM", note = "the SSH2 extension is loaded (outbound SSH from PHP)" },
  { name = "snmp", severity = "LOW", note = "the SNMP extension is loaded" },
  { name = "imap", severity = "LOW", note = "the IMAP extension is loaded" },
  { name = "mssql", severity = "MEDIUM", note = "the MSSQL extension is loaded (legacy, no prepared statements)" },
  { name = "pdo_dblib", severity = "LOW", note = "the FreeTDS/MSSQL PDO driver is loaded" },
  { name = "oci8", severity = "LOW", note = "the Oracle extension is loaded" },
  { name = "pdo_firebird", severity = "LOW", note = "the Firebird PDO driver is loaded" },
  { name = "dbase", severity = "LOW", note = "the dBase extension is loaded" },
  { name = "winbinder", severity = "MEDIUM", note = "WinBinder is loaded on a Windows runtime" },
  { name = "pcntl", severity = "LOW", note = "pcntl process control is available" },
  { name = "posix", severity = "LOW", note = "posix functions are available" },
  { name = "shmop", severity = "LOW", note = "shared memory functions are available" },
  { name = "sysvshm", severity = "LOW", note = "System V shared memory is available" },
  { name = "sysvsem", severity = "LOW", note = "System V semaphores are available" },
  { name = "ffi", severity = "MEDIUM", note = "FFI is loaded: native code can be called from PHP" },
  { name = "expect", severity = "HIGH", note = "the expect extension is loaded (interactive process control)" },
  { name = "v8js", severity = "HIGH", note = "the V8 JavaScript engine extension is loaded" },
  { name = "lua", severity = "MEDIUM", note = "the Lua extension is loaded" },
  { name = "perl", severity = "MEDIUM", note = "the Perl extension is loaded" },
  { name = "python", severity = "MEDIUM", note = "the Python extension is loaded" },
  { name = "radius", severity = "LOW", note = "the RADIUS extension is loaded" },
  { name = "ldap", severity = "INFO", note = "the LDAP extension is loaded" },
  { name = "soap", severity = "INFO", note = "the SOAP extension is loaded" },
  { name = "phar", severity = "INFO", note = "the Phar extension is loaded (phar deserialization candidate)" },
  { name = "gd", severity = "INFO", note = "GD image handling is loaded" },
  { name = "imagick", severity = "MEDIUM", note = "ImageMagick is loaded (historically a delegation/RCE surface)" },
  { name = "redis", severity = "INFO", note = "the Redis client extension is loaded" },
  { name = "memcached", severity = "INFO", note = "the Memcached extension is loaded" },
  { name = "amqp", severity = "INFO", note = "the AMQP extension is loaded" },
  { name = "oauth", severity = "INFO", note = "the OAuth extension is loaded" },
}

local SSRF_WRAPPERS = { "http", "https", "ftp", "ftps", "data", "php", "glob", "zip", "phar",
  "compress.zlib", "compress.bzip2", "rar", "expect" }

local SOFT404_TEMPLATES = {
  "/nse-phpinfo-missing-%s.php",
  "/nse-phpinfo-absent/%s/info.php",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 90,
  maxrequests = 160,
  retries = 1,
  timeout = 10000,
  delay = 0.05,
  soft404 = true,
  mask = true,
  maxbodysize = 1048576,
  useragent = nil,
  probe_suffix = true,
}

local NUMERIC_ARGS = {
  { key = "maxpaths", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 4, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxbodysize", minimum = 4096, integer = true },
}

local BOOLEAN_ARGS = { "soft404", "mask", "probe_suffix" }

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

local function host_label(host)
  return host.targetname or host.name or host.ip or "unknown"
end

local function select_paths(args)
  local selected = {}
  local seen = {}
  for _, candidate in ipairs(args.paths or CANDIDATE_PATHS) do
    local normalized = trim(candidate)
    if #normalized == 0 then
      normalized = "/"
    end
    if not starts_with(normalized, "/") then
      normalized = "/" .. normalized
    end
    if unique_append(selected, seen, normalized) then
      if args.probe_suffix and not ends_with(lower(normalized), ".php")
        and not contains(normalized, "?") then
        unique_append(selected, seen, normalized .. ".php")
      end
      if #selected >= args.maxpaths then
        break
      end
    end
  end
  if #selected == 0 then
    table.insert(selected, "/phpinfo.php")
  end
  return selected
end

local function unescape_html(value)
  local text = tostring(value or "")
  text = string.gsub(text, "&lt;", "<")
  text = string.gsub(text, "&gt;", ">")
  text = string.gsub(text, "&quot;", '"')
  text = string.gsub(text, "&#039;", "'")
  text = string.gsub(text, "&apos;", "'")
  text = string.gsub(text, "&nbsp;", " ")
  text = string.gsub(text, "&#(%d+);", function(code)
    local number = tonumber(code)
    if not number or number < 32 or number > 126 then
      return " "
    end
    return string.char(number)
  end)
  text = string.gsub(text, "&amp;", "&")
  return trim(text)
end

local function strip_tags_keep_text(value)
  local text = string.gsub(tostring(value or ""), "<[^>]*>", " ")
  return trim(unescape_html(text))
end

local function marker_score(body)
  local hits = {}
  local hit_seen = {}
  local score = 0
  for _, marker in ipairs(PHPINFO_MARKERS) do
    if contains(body, marker.pattern) then
      score = score + marker.weight
      unique_append(hits, hit_seen, marker.note)
    end
  end
  return score, hits
end

local function table_rows(body)
  local rows = {}
  for row in string.gmatch(body, "<tr[^>]*>(.-)</tr>") do
    local cells = {}
    local is_header = false
    for tag, cell in string.gmatch(row, "<(t[dh])([^>]*)>(.-)</t[dh]>") do
      local unused = tag
      if unused == "th" or contains(cell, 'class="h"') then
        is_header = true
      end
    end
    if not is_header then
      for cell in string.gmatch(row, "<t[dh][^>]*>(.-)</t[dh]>") do
        table.insert(cells, strip_tags_keep_text(cell))
      end
      if #cells > 0 then
        table.insert(rows, cells)
      end
    end
  end
  return rows
end

local function directive_tables(body)
  local tables = {}
  for chunk in string.gmatch(body, "<table[^>]*>(.-)</table>") do
    local header = string.match(chunk, "<tr[^>]*class=[\"']h[\"'][^>]*>(.-)</tr>")
    if header and contains(strip_tags_keep_text(header), "Directive") then
      table.insert(tables, chunk)
    end
  end
  return tables
end

local function section_index(body)
  local sections = {}
  local order = {}
  for title in string.gmatch(body, "<h2[^>]*>(.-)</h2>") do
    local name = trim(strip_tags_keep_text(title))
    if #name > 0 and not list_contains(order, name) then
      table.insert(order, name)
    end
  end
  for title in string.gmatch(body, "<h1[^>]*>(.-)</h1>") do
    local name = trim(strip_tags_keep_text(title))
    if #name > 0 and not list_contains(order, name) then
      table.insert(order, name)
    end
  end
  for name in string.gmatch(body, "<th[^>]*colspan[^>]*>(.-)</th>") do
    local clean = trim(strip_tags_keep_text(name))
    if #clean > 0 and #clean < 60 and not list_contains(order, clean) then
      table.insert(sections, clean)
      table.insert(order, clean)
    end
  end
  return order, sections
end

local function extract_identity(body)
  local identity = {}
  local version = string.match(body, "PHP Version%s*</td><td[^>]*>([^<]+)<")
    or string.match(body, "<h1[^>]*>PHP Version ([^<]+)</h1>")
    or string.match(body, "<title>phpinfo%(%)[^<]*PHP Version ([^<]*)")
  if version then
    identity.version = trim(strip_tags_keep_text(version))
  end
  local engine = string.match(body, "Zend Engine%s*v?([%d%.]+)")
  if engine then
    identity.zend_engine = trim(engine)
  end
  local built = string.match(body, "built:%s*([^<\r\n]+)")
  if built then
    identity.built = truncate(trim(strip_tags_keep_text(built)), 120)
  end
  local sapi = string.match(body, "Server API%s*</td><td[^>]*>([^<]+)<")
  if sapi then
    identity.sapi = trim(strip_tags_keep_text(sapi))
  end
  local ini_path = string.match(body, "Configuration File %(php%.ini%) Path%s*</td><td[^>]*>([^<]*)<")
  if ini_path then
    identity.ini_path = trim(strip_tags_keep_text(ini_path))
  end
  local loaded_ini = string.match(body, "Loaded Configuration File%s*</td><td[^>]*>([^<]*)<")
  if loaded_ini then
    identity.loaded_ini = trim(strip_tags_keep_text(loaded_ini))
  end
  local scanned = string.match(body, "Scan for additional %.ini files in%s*</td><td[^>]*>([^<]*)<")
  if scanned then
    identity.scanned_ini_dir = trim(strip_tags_keep_text(scanned))
  end
  local document_root = string.match(body, "DOCUMENT_ROOT%s*</td><td[^>]*>([^<]*)<")
  if document_root then
    identity.document_root = trim(strip_tags_keep_text(document_root))
  end
  local streams = string.match(body, "Registered PHP Streams%s*</td><td[^>]*>([^<]*)<")
  if streams then
    identity.streams = trim(strip_tags_keep_text(streams))
  end
  local stream_handlers = string.match(body, "Registered Stream Socket Transports%s*</td><td[^>]*>([^<]*)<")
  if stream_handlers then
    identity.socket_transports = trim(strip_tags_keep_text(stream_handlers))
  end
  local extension_dir = string.match(body, "extension_dir%s*</td><td[^>]*>([^<]*)<")
  if extension_dir then
    identity.extension_dir = trim(strip_tags_keep_text(extension_dir))
  end
  return identity
end

local function mask_value(value)
  local text = tostring(value or "")
  if #text <= 4 then
    return string.rep("*", #text)
  end
  return string.sub(text, 1, 2) .. string.rep("*", math.min(#text - 4, 24))
    .. string.sub(text, -2) .. " (" .. #text .. " chars)"
end

local function is_placeholder(value)
  local text = lower(trim(tostring(value or "")))
  if #text == 0 then
    return true
  end
  local placeholders = { "no value", "not set", "none", "null", "nil", "-",
    "undefined", "***", "*****", "redacted", "hidden", "n/a", "unknown",
    "(none)", "off", "disabled" }
  for _, candidate in ipairs(placeholders) do
    if text == candidate then
      return true
    end
  end
  if string.match(text, "^%*+$") then
    return true
  end
  return false
end

local function env_class(key)
  local lowered = lower(tostring(key or ""))
  for _, benign in ipairs(BENIGN_ENV_KEYS) do
    if lowered == benign then
      return "benign"
    end
  end
  for _, marker in ipairs(SECRET_KEY_MARKERS) do
    if contains(lowered, marker) then
      return "secret"
    end
  end
  for _, marker in ipairs(INFRA_ENV_KEYS) do
    if contains(lowered, marker) then
      return "infrastructure"
    end
  end
  if starts_with(lowered, "http_") then
    return "http"
  end
  return "other"
end

local function parse_directives(body, page)
  local directives = {}
  local seen = {}
  local rows = {}
  for _, chunk in ipairs(directive_tables(body)) do
    for _, cells in ipairs(table_rows(chunk)) do
      table.insert(rows, cells)
    end
  end
  for _, cells in ipairs(rows) do
    if #cells >= 2 then
      local name = trim(cells[1])
      if #name > 0 and #name < 90 and not contains(name, "Directive")
        and (contains(name, ".") or contains(lower(name), "_") or #name < 30) then
        local local_value = #cells >= 2 and trim(cells[2]) or ""
        local master_value = #cells >= 3 and trim(cells[3]) or local_value
        local key = page .. "|" .. lower(name)
        if not seen[key] then
          seen[key] = true
          table.insert(directives, {
            name = name,
            local_value = local_value,
            master_value = master_value,
            page = page,
          })
        end
      end
    end
  end
  return directives
end

local function value_is_insecure(value, policy)
  local text = lower(trim(tostring(value or "")))
  if policy.secure then
    for _, allowed in ipairs(policy.secure) do
      if allowed == nil then
        if text == "" or text == "no value" then
          return false
        end
      elseif lower(tostring(allowed)) == text then
        return false
      end
    end
    return true
  end
  if policy.insecure_values then
    for _, candidate in ipairs(policy.insecure_values) do
      if contains(text, lower(candidate)) then
        return true
      end
    end
    return false
  end
  if policy.secure_nonempty then
    return text == "" or text == "no value" or text == "off" or text == "none"
  end
  return false
end

local function parse_pairs(rows)
  local pairs = {}
  local seen = {}
  for _, cells in ipairs(rows) do
    local key = trim(cells[1] or "")
    local value = #cells >= 2 and trim(cells[2]) or ""
    local rejected = #key == 0 or #key > 120
      or contains(lower(key), "variable")
      or contains(lower(key), "request header")
      or (lower(key) == "directive")
      or (lower(key) == "master value") or (lower(key) == "local value")
    if not rejected and not seen[lower(key) .. "|" .. lower(value)] then
      seen[lower(key) .. "|" .. lower(value)] = true
      table.insert(pairs, { key = key, value = value })
    end
  end
  return pairs
end

local function section_pairs(body, section_names)
  local results = {}
  for _, name in ipairs(section_names) do
    local pattern = name .. "(.-)<h2"
    local chunk = string.match(body, pattern)
    if not chunk then
      chunk = string.match(body, name .. "(.*)$")
    end
    if chunk then
      results[name] = parse_pairs(table_rows(chunk))
    end
  end
  return results
end

local function find_section_chunk(body, wanted)
  local index = string.find(lower(body), lower(wanted), 1, true)
  if not index then
    return nil
  end
  local rest = string.sub(body, index)
  local next_section = string.find(lower(rest), "<h2", 10, true)
  if next_section then
    return string.sub(rest, 1, next_section - 1)
  end
  return string.sub(rest, 1, math.min(#rest, 200000))
end

local function parse_streams(identity)
  local streams = {}
  for token in string.gmatch(tostring(identity.streams or ""), "[^,%s]+") do
    table.insert(streams, lower(token))
  end
  return streams
end

local function analyse_page(path, response, baseline, args, target_host)
  local body = response.body or ""
  local page = {
    path = path,
    status = response.status or 0,
    length = #body,
    content_type = lower(header_value(response, "content-type") or "unknown"),
    server = header_value(response, "server"),
    powered_by = header_value(response, "x-powered-by"),
    hash = fnv1a32(body),
    entropy = entropy_bits(body),
    findings = {},
    directives = {},
    environment = {},
    headers = {},
    identity = {},
    sections = {},
    streams = {},
    extensions = {},
    notes = {},
  }

  page.score, page.marker_hits = marker_score(body)
  page.confirmed = page.score >= 5
  page.suspected = not page.confirmed and page.score >= 2

  if not page.confirmed and not page.suspected then
    return page
  end

  local rows = table_rows(body)
  page.sections = section_index(body)
  page.identity = extract_identity(body)
  page.directives = parse_directives(body, path)
  page.streams = parse_streams(page.identity)

  local env_chunk = find_section_chunk(body, "Environment")
  if env_chunk then
    page.environment = parse_pairs(table_rows(env_chunk))
  end
  local php_env_chunk = find_section_chunk(body, "PHP Variables")
  if php_env_chunk then
    page.php_variables = parse_pairs(table_rows(php_env_chunk))
  end
  local header_chunk = find_section_chunk(body, "HTTP Headers Information")
  if header_chunk then
    page.headers = parse_pairs(table_rows(header_chunk))
  elseif find_section_chunk(body, "Request Headers") then
    page.headers = parse_pairs(table_rows(find_section_chunk(body, "Request Headers")))
  end

  local module_chunk = find_section_chunk(body, "PHP Modules")
  if module_chunk then
    page.notes.module_chunk = truncate(strip_tags_keep_text(module_chunk), 200)
  end

  local module_names = {}
  for token in string.gmatch(strip_tags_keep_text(body), "[A-Za-z][A-Za-z0-9_%.%-]+") do
    local lowered = lower(token)
    if #lowered >= 3 and #lowered <= 24 then
      module_names[lowered] = true
    end
  end
  local lowered_body = lower(body)
  for _, extension in ipairs(RISKY_EXTENSIONS) do
    local needle = string.gsub(extension.name, " ", "")
    local found = module_names[lower(needle)] or contains(lowered_body, extension.name)
    if not found and extension.tokens then
      found = true
      for _, token in ipairs(extension.tokens) do
        if not contains(lowered_body, token) then
          found = false
          break
        end
      end
    end
    if found then
      local duplicate = false
      for _, existing in ipairs(page.extensions) do
        if existing.name == extension.name then
          duplicate = true
        end
      end
      if not duplicate then
        table.insert(page.extensions, extension)
      end
    end
  end

  local catchall = false
  if baseline.enabled and baseline.samples > 0 then
    catchall = looks_like_soft404(response, baseline)
  end
  if catchall and page.score < 8 then
    page.notes.catchall = "the catch-all page also matches phpinfo markers; treated as unconfirmed"
    page.confirmed = false
    page.suspected = false
    return page
  end

  return page
end

local function score_directive(directive)
  local policy = DIRECTIVE_POLICY[lower(directive.name)]
  if not policy then
    return nil
  end
  local local_value = directive.local_value
  local master_value = directive.master_value
  local insecure = value_is_insecure(local_value, policy)
    or value_is_insecure(master_value, policy)
  if policy.disclose and not insecure then
    if is_placeholder(local_value) then
      return nil
    end
    return {
      severity = policy.severity,
      detail = string.format("%s discloses %s (local=%s, master=%s)", directive.name,
        policy.detail, truncate(local_value, 40), truncate(master_value, 40)),
      subject = "directive:" .. lower(directive.name) .. ":" .. directive.page,
    }
  end
  if insecure then
    return {
      severity = policy.severity,
      detail = string.format("%s is set to a dangerous value (local=%s, master=%s): %s",
        directive.name, truncate(local_value, 40), truncate(master_value, 40), policy.detail),
      subject = "directive:" .. lower(directive.name) .. ":" .. directive.page,
    }
  end
  return nil
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local baseline = build_soft404_baseline(host, port, args)
  local paths = select_paths(args)
  local target_host = host_label(host)

  local pages = {}
  local fetch_log = {}
  local tested = 0

  for _, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(fetch_log, path .. ": request budget exhausted, remaining candidates skipped")
      break
    end

    local response, err = fetch(host, port, path, args)
    tested = tested + 1
    if not response then
      table.insert(fetch_log, string.format("%s -> %s", path, tostring(err)))
      goto continue_path
    end

    local status = response.status or 0
    if status == 404 or status == 410 then
      goto continue_path
    end
    if status == 401 or status == 403 then
      table.insert(fetch_log, string.format("%s -> HTTP %s (protected)", path, tostring(status)))
      add_finding("INFO", string.format("%s answers HTTP %s, so a phpinfo page may exist behind "
        .. "authentication", path, tostring(status)),
        { path = path, subject = "protected:" .. path, evidence = "HTTP " .. tostring(status) })
      goto continue_path
    end
    if status == 405 or status == 501 then
      table.insert(fetch_log, string.format("%s -> HTTP %s (method rejected)", path, tostring(status)))
      goto continue_path
    end

    local page = analyse_page(path, response, baseline, args, target_host)
    if not page.confirmed and not page.suspected then
      if status == 200 and page.length > 0 then
        table.insert(fetch_log, string.format("%s -> HTTP %s, %d bytes, not a phpinfo page",
          path, tostring(status), page.length))
      end
      goto continue_path
    end

    table.insert(pages, page)
    table.insert(fetch_log, string.format(
      "%s -> HTTP %s, %d bytes, marker score %d, %s, %d directives, %d environment rows",
      path, tostring(status), page.length, page.score,
      page.confirmed and "CONFIRMED phpinfo()" or "suspected phpinfo()",
      #page.directives, #page.environment))

    if page.confirmed then
      add_finding("HIGH", string.format(
        "a reachable phpinfo() page at %s discloses the PHP %s runtime configuration (%d directives, "
        .. "%d environment rows, %d request header rows)",
        path, tostring(page.identity.version or "unknown"), #page.directives,
        #page.environment, #page.headers),
        { path = path, subject = "page:" .. path,
          evidence = truncate(table.concat(page.marker_hits, ", "), 110) })
    else
      add_finding("MEDIUM", string.format(
        "%s looks like a phpinfo() page (marker score %d) but not enough independent markers matched; "
        .. "verify it manually", path, page.score),
        { path = path, subject = "suspected:" .. path,
          evidence = truncate(table.concat(page.marker_hits, ", "), 110) })
    end

    if page.identity.version then
      local version = page.identity.version
      local major, minor = string.match(version, "^(%d+)%.(%d+)")
      if major and minor then
        local number = tonumber(major) * 100 + tonumber(minor)
        if number < 704 then
          add_finding("HIGH", string.format(
            "the runtime is PHP %s, which is past end of life and receives no security fixes", version),
            { path = path, subject = "eol:" .. version .. ":" .. path,
              evidence = "PHP " .. version })
        elseif number < 801 then
          add_finding("MEDIUM", string.format(
            "the runtime is PHP %s, whose active support window has closed (security fixes only or none "
            .. "depending on the exact release)", version),
            { path = path, subject = "aging:" .. version .. ":" .. path,
              evidence = "PHP " .. version })
        end
      end
      if page.identity.sapi and contains(lower(page.identity.sapi), "cgi") then
        add_finding("MEDIUM", string.format("the runtime uses the %s SAPI, which exposes the CGI "
          .. "query-string handler surface (cgi.force_redirect and cgi.fix_pathinfo matter)",
          page.identity.sapi),
          { path = path, subject = "sapi:" .. path, evidence = page.identity.sapi })
      end
    end

    for _, directive in ipairs(page.directives) do
      local scored = score_directive(directive)
      if scored then
        add_finding(scored.severity, scored.detail,
          { path = path, subject = scored.subject,
            evidence = truncate(directive.local_value .. " / " .. directive.master_value, 90) })
      end
    end

    for _, entry in ipairs(page.environment) do
      local class = env_class(entry.key)
      if class == "secret" and not is_placeholder(entry.value) then
        add_finding("CRITICAL", string.format(
          "the phpinfo Environment section prints %s = %s: a secret is readable by anyone who can "
          .. "reach this page", entry.key, args.mask and mask_value(entry.value)
            or truncate(entry.value, 40)),
          { path = path, subject = "env-secret:" .. lower(entry.key) .. ":" .. path,
            evidence = string.format("%s (%d chars)", entry.key, #entry.value) })
        page.credential_rows = (page.credential_rows or 0) + 1
      elseif class == "http" then
        local lowered = lower(entry.key)
        local is_credential = false
        for _, candidate in ipairs(CREDENTIAL_HEADERS) do
          if contains(lowered, candidate) then
            is_credential = true
          end
        end
        if is_credential and not is_placeholder(entry.value) then
          add_finding("HIGH", string.format(
            "the Environment section echoes the request header %s = %s, so credentials sent to this "
            .. "page are reflected to any reader", entry.key,
            args.mask and mask_value(entry.value) or truncate(entry.value, 40)),
            { path = path, subject = "env-header:" .. lowered .. ":" .. path,
              evidence = entry.key })
        end
      elseif class == "infrastructure" and not is_placeholder(entry.value) then
        add_finding("MEDIUM", string.format(
          "the Environment section discloses %s = %s (internal topology or build metadata)",
          entry.key, truncate(entry.value, 60)),
          { path = path, subject = "env-infra:" .. lower(entry.key) .. ":" .. path,
            evidence = truncate(entry.value, 60) })
      elseif class == "other" and not is_placeholder(entry.value) then
        table.insert(page.notes, string.format("environment row %s = %s", entry.key,
          truncate(entry.value, 40)))
      end
    end

    for _, entry in ipairs(page.headers) do
      local lowered = lower(entry.key)
      if not is_placeholder(entry.value) then
        local credential = false
        for _, candidate in ipairs(CREDENTIAL_HEADERS) do
          if contains(lowered, candidate) then
            credential = true
          end
        end
        local topology = false
        for _, candidate in ipairs(TOPOLOGY_HEADERS) do
          if contains(lowered, candidate) then
            topology = true
          end
        end
        if credential then
          add_finding("HIGH", string.format(
            "the HTTP Headers section reflects %s = %s back to any reader of the page", entry.key,
            args.mask and mask_value(entry.value) or truncate(entry.value, 40)),
            { path = path, subject = "header:" .. lowered .. ":" .. path, evidence = entry.key })
        elseif topology then
          add_finding("MEDIUM", string.format(
            "the HTTP Headers section reveals the internal request path: %s = %s", entry.key,
            truncate(entry.value, 60)),
            { path = path, subject = "header-topology:" .. lowered .. ":" .. path,
              evidence = truncate(entry.value, 60) })
        end
      end
    end

    for _, extension in ipairs(page.extensions) do
      add_finding(extension.severity, string.format("%s: %s (seen at %s)",
        extension.name, extension.note, path),
        { path = path, subject = "extension:" .. extension.name .. ":" .. path,
          evidence = extension.name })
    end

    local ssrf = {}
    for _, stream in ipairs(page.streams) do
      if list_contains(SSRF_WRAPPERS, stream) and (stream == "http" or stream == "https"
        or stream == "ftp" or stream == "ftps" or stream == "data" or stream == "expect") then
        table.insert(ssrf, stream)
      end
    end
    if #ssrf > 0 then
      local fopen = nil
      for _, directive in ipairs(page.directives) do
        if lower(directive.name) == "allow_url_fopen" then
          fopen = directive
        end
      end
      local fopen_on = fopen and (contains(lower(fopen.local_value), "on")
        or trim(fopen.local_value) == "1")
      if fopen_on then
        add_finding("MEDIUM", string.format(
          "allow_url_fopen is On and the runtime registers the %s wrappers, so any file function with "
          .. "attacker-controlled input can reach internal HTTP endpoints", table.concat(ssrf, ", ")),
          { path = path, subject = "ssrf:" .. path, evidence = table.concat(ssrf, ", ") })
      end
      if list_contains(page.streams, "phar") then
        add_finding("LOW", string.format(
          "the phar stream wrapper is registered at %s: any code path that opens a user-supplied file "
          .. "with a phar:// prefix triggers deserialization", path),
          { path = path, subject = "phar:" .. path, evidence = "phar wrapper registered" })
      end
    end

    ::continue_path::
  end

  local unique, counts = dedupe_findings()

  local out = new_output(RISK_LEVEL, "AUDITED - phpinfo() exposure probe completed.")
  if counts.CRITICAL > 0 then
    out["Status"] = "VULNERABLE - a public phpinfo() page prints secrets or enables remote debugging."
  elseif counts.HIGH > 0 then
    out["Status"] = "VULNERABLE - a public phpinfo() page discloses the runtime configuration."
  elseif counts.MEDIUM > 0 then
    out["Status"] = "AUDITED - a suspected phpinfo() page or configuration disclosure was found."
  elseif tested > 0 then
    out["Status"] = "AUDITED - no phpinfo() page is reachable at the tested paths."
  else
    out["Status"] = "AUDITED - no request could be completed."
  end

  local sections = {
    { key = "Target host", value = target_host },
    { key = "Candidates tested", value = tested },
    { key = "phpinfo pages found", value = #pages },
  }

  local confirmed = 0
  for _, page in ipairs(pages) do
    if page.confirmed then
      confirmed = confirmed + 1
    end
  end
  table.insert(sections, { key = "Confirmed pages", value = confirmed })

  for _, page in ipairs(pages) do
    local block = {}
    table.insert(block, string.format("page: %s (%s, HTTP %s, %d bytes, marker score %d)",
      page.path, page.confirmed and "CONFIRMED" or "suspected", tostring(page.status),
      page.length, page.score))
    table.insert(block, string.format("      markers: %s", truncate(table.concat(page.marker_hits, ", "), 150)))
    local identity = page.identity
    local identity_lines = {}
    if identity.version then table.insert(identity_lines, "PHP Version = " .. identity.version) end
    if identity.zend_engine then table.insert(identity_lines, "Zend Engine = " .. identity.zend_engine) end
    if identity.sapi then table.insert(identity_lines, "Server API = " .. identity.sapi) end
    if identity.built then table.insert(identity_lines, "Built = " .. identity.built) end
    if identity.ini_path then table.insert(identity_lines, "php.ini path = " .. identity.ini_path) end
    if identity.loaded_ini then table.insert(identity_lines, "Loaded php.ini = " .. identity.loaded_ini) end
    if identity.scanned_ini_dir then
      table.insert(identity_lines, "Scanned .ini dir = " .. identity.scanned_ini_dir)
    end
    if identity.document_root then table.insert(identity_lines, "DOCUMENT_ROOT = " .. identity.document_root) end
    if identity.extension_dir then table.insert(identity_lines, "extension_dir = " .. identity.extension_dir) end
    if identity.streams then table.insert(identity_lines, "Registered streams = " .. identity.streams) end
    if identity.socket_transports then
      table.insert(identity_lines, "Socket transports = " .. identity.socket_transports)
    end
    if page.server then table.insert(identity_lines, "Server header = " .. page.server) end
    if page.powered_by then table.insert(identity_lines, "X-Powered-By = " .. page.powered_by) end
    for _, line in ipairs(identity_lines) do
      table.insert(block, "      " .. line)
    end

    if #page.directives > 0 then
      local scored_lines = {}
      for _, directive in ipairs(page.directives) do
        local scored = score_directive(directive)
        if scored then
          table.insert(scored_lines, string.format("      [%s] %s: local=%s master=%s",
            scored.severity, directive.name, truncate(directive.local_value, 30),
            truncate(directive.master_value, 30)))
        end
      end
      if #scored_lines > 0 then
        table.insert(block, string.format("      scored directives (%d of %d):",
          #scored_lines, #page.directives))
        for _, line in ipairs(scored_lines) do
          table.insert(block, line)
        end
      else
        table.insert(block, string.format("      %d directives parsed, none scored against policy",
          #page.directives))
      end
    end

    if #page.environment > 0 then
      local secret_rows = {}
      local infra_rows = {}
      for _, entry in ipairs(page.environment) do
        local class = env_class(entry.key)
        if class == "secret" and not is_placeholder(entry.value) then
          table.insert(secret_rows, string.format("      [SECRET] %s = %s",
            entry.key, args.mask and mask_value(entry.value) or truncate(entry.value, 40)))
        elseif class == "infrastructure" and not is_placeholder(entry.value) then
          table.insert(infra_rows, string.format("      %s = %s", entry.key,
            truncate(entry.value, 48)))
        end
      end
      table.insert(block, string.format("      environment rows: %d total, %d secret-shaped, %d infrastructure",
        #page.environment, #secret_rows, #infra_rows))
      for _, line in ipairs(secret_rows) do
        table.insert(block, line)
      end
      for _, line in ipairs(infra_rows) do
        table.insert(block, line)
      end
    end

    if #page.headers > 0 then
      table.insert(block, string.format("      reflected request header rows: %d", #page.headers))
      for _, entry in ipairs(page.headers) do
        table.insert(block, string.format("      %s = %s", entry.key,
          args.mask and mask_value(entry.value) or truncate(entry.value, 40)))
      end
    end

    if #page.extensions > 0 then
      table.insert(block, string.format("      notable extensions: %d", #page.extensions))
      for _, extension in ipairs(page.extensions) do
        table.insert(block, string.format("      [%s] %s - %s", extension.severity, extension.name,
          extension.note))
      end
    end

    if #page.sections > 0 then
      table.insert(block, string.format("      phpinfo sections exposed: %s",
        truncate(table.concat(page.sections, " | "), 240)))
    end

    if page.notes.catchall then
      table.insert(block, "      note: " .. page.notes.catchall)
    end
    for _, note in ipairs(page.notes) do
      table.insert(block, "      note: " .. note)
    end

    table.insert(sections, { key = "Page " .. page.path, value = block })
  end

  table.insert(sections, { key = "Fetch log", value = fetch_log })
  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end

  if confirmed > 0 then
    table.insert(sections, { key = "Remediation", value =
      "delete every phpinfo()/info/test script from the document root (they are usually deployment "
      .. "leftovers), keep them out of version control, and if one is genuinely needed restrict it to "
      .. "an authenticated admin location that is not served by the public vhost. Then rotate every "
      .. "secret that appeared in the Environment section, because the page was world-readable and "
      .. "was probably indexed or scraped, and fix the scored directives (allow_url_include, enable_dl, "
      .. "display_errors, cgi.fix_pathinfo, session cookie flags, open_basedir, disable_functions)." })
  else
    table.insert(sections, { key = "Remediation", value =
      "no phpinfo() page was reachable at the tested paths; keep deployment probes out of the web root, "
      .. "and if this is a PHP service re-run with a larger path list or after any change that adds "
      .. "diagnostic endpoints" })
  end

  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  return finish_output(out, unique, counts, sections)

end
