local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Triggers application and server error conditions with benign, read-only
requests, then decides whether the resulting error pages disclose internal
detail: source paths, stack traces, framework and database identities, SQL
syntax, environment variables, host names, IP addresses, versions, and whether
a debugger console is attached.

How it works
1. A baseline is captured first (the normal response for "/"), so an error page
   can be distinguished from a themed 404 page that the application serves for
   everything. A soft-404 baseline from two randomised paths suppresses
   catch-all behaviour, and a WAF/CDN interstitial detector suppresses block
   pages, which is the most common source of false "verbose error" reports.
2. 45 trigger requests are sent. None of them exploits anything: they are
   malformed or unusual inputs that a robust application should reject with a
   generic message - a non-existent path, a path with a benign SQL token, an
   oversized parameter, a null byte in the extension, a deeply encoded
   traversal sequence, an invalid JSON POST body, an invalid query string
   encoding, a HEAD/OPTIONS request to a random path, a request with an invalid
   HTTP version over a raw socket, a request with a header that is too long, a
   Content-Length mismatch, and a request for a file name that the stack will
   try to parse (index.php?id=1 with a benign quote token, ?format=xml on a
   JSON endpoint, /api/v1/<huge number>).
3. Every response is matched against 180+ stack-specific disclosure signatures
   covering PHP (fatal/warning/notice/parse error, uncaught exception, xdebug,
   "on line N", DOCUMENT_ROOT), Java (exception, "at package.Class.method",
   Caused by, Spring, Hibernate, MyBatis, Tomcat Jasper, Struts), .NET (yellow
   screen "Server Error in '/' Application", "Stack Trace:", __VIEWSTATE errors,
   "An unhandled exception", customErrors off indicator), Python (Traceback,
   Django technical 500 with settings dump, Flask/Werkzeug debugger console,
   Pyramid, Tornado), Ruby (ActionView::Template::Error, WEBrick backtrace,
   Sinatra), Node.js (TypeError: Cannot read property, "at Object.<anonymous>",
   unhandledRejection, MODULE_NOT_FOUND, Sequelize/Mongoose/Prisma errors),
   Go (goroutine stack, runtime error: invalid memory address, nil pointer),
   Rust/Perl/ColdFusion, and database engines identified from their own error
   text: MySQL/MariaDB ("You have an error in your SQL syntax", error 1064,
   "Unknown column"), PostgreSQL ("ERROR: syntax error at or near",
   "pg_query"), MSSQL ("Microsoft OLE DB Provider", "Incorrect syntax near",
   "Msg 102, Level 15"), Oracle (ORA-00933, ORA-00942, "PLS-00"),
   SQLite ("near \\"\\"": syntax error", "SQLITE_ERROR"), MongoDB
   ("MongoServerError", "$where"), Redis, Elasticsearch ("parsing_exception",
   "query_shard_exception"), LDAP ("invalidDNSyntax").
4. Structured disclosure extraction: absolute filesystem paths
   (/var/www/..., C:\\inetpub\\..., /home/<user>/, /usr/share/..., /app/...),
   private IPv4 ranges (10/8, 172.16/12, 192.168/16, 169.254/16 including the
   metadata address), internal host names (something.internal, *.local,
   build agents), version tokens next to a product name, environment variable
   dumps (KEY=VALUE blocks, $_ENV / $_SERVER tables, os.environ), and debug
   consoles (Werkzeug PIN console, xdebug profiler, Laravel Ignition/Telescope,
   Symfony profiler, Django DEBUG=True, whoops, Symfony VarDumper,
   Spring Boot Actuator error attributes, ASP.NET trace.axd, ColdFusion
   administrator).
5. Severity is driven by what was leaked, not by the HTTP status: an attached
   debugger console or a raw SQL statement with a schema name is CRITICAL, a
   stack trace or a database engine identity is HIGH, a filesystem path or an
   internal host name is MEDIUM, a version token or a framework identity is LOW,
   and a generic error page with no internal detail is INFO (reported as good
   behaviour).

Every finding carries the trigger that produced it and the exact evidence
snippet, so a report can be reproduced and handed to a developer without
guesswork.

Usage:
<code>
nmap -p 80,443 --script http-error-disclosure <target>
nmap -p 8080 --script http-error-disclosure \
  --script-args http-error-disclosure.triggers=45,http-error-disclosure.raw=false <target>
nmap -p 443 --script http-error-disclosure \
  --script-args http-error-disclosure.paths="/,/api,/portal" <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local SCRIPT_NAME = "http-error-disclosure"

local RISK_LEVEL = "🟡 MEDIUM"

local BASE_PATHS = {
  "/",
  "/index.php",
  "/api",
}

local TRIGGER_PATHS = {
  { name = "missing-path", kind = "path", value = "/nse-err-missing-{TOKEN}",
    note = "a path that cannot exist" },
  { name = "deep-missing-path", kind = "path", value = "/a/b/c/d/e/nse-err-{TOKEN}",
    note = "a deeply nested path that cannot exist" },
  { name = "sql-token", kind = "path", value = "/index.php?id=1%20and%20nse_audit=1",
    note = "a benign SQL keyword in a query parameter" },
  { name = "sql-quote", kind = "path", value = "/index.php?id=1'nse",
    note = "an unbalanced quote in a query parameter" },
  { name = "sql-union-word", kind = "path", value = "/search?q=nse%20union%20select%20nothing",
    note = "the word UNION in a search parameter" },
  { name = "script-token", kind = "path", value = "/search?q=%3Cscript%3Ense%3C/script%3E",
    note = "an inert script tag in a query parameter" },
  { name = "template-token", kind = "path", value = "/?page=%7B%7Bnse%7D%7D",
    note = "template expression braces in a parameter" },
  { name = "null-byte", kind = "path", value = "/index.html%00.jpg",
    note = "a null byte in the file extension" },
  { name = "encoded-traversal", kind = "path", value = "/..%2f..%2f..%2fetc%2fpasswd",
    note = "an encoded traversal sequence (read-only)" },
  { name = "oversized-param", kind = "path", value = "/index.php?id={BIG}",
    note = "an oversized parameter value (10000 characters)" },
  { name = "huge-integer", kind = "path", value = "/api/v1/99999999999999999999999999",
    note = "an integer beyond 64-bit range in a route parameter" },
  { name = "negative-id", kind = "path", value = "/api/user/-1",
    note = "a negative identifier in a route parameter" },
  { name = "array-param", kind = "path", value = "/?id[]=1&id[]=2",
    note = "an array where a scalar is expected" },
  { name = "bad-encoding", kind = "path", value = "/?q=%E0%A4%A",
    note = "a truncated percent-encoded sequence" },
  { name = "bad-charset", kind = "path", value = "/?charset={CHARSET}",
    note = "an invalid character set name" },
  { name = "debug-flag", kind = "path", value = "/?debug=true",
    note = "a debug query flag" },
  { name = "trace-flag", kind = "path", value = "/?XDEBUG_SESSION_START=nse",
    note = "an xdebug session trigger parameter" },
  { name = "verbose-flags", kind = "path", value = "/?test=1&debug=1&verbose=1&trace=1",
    note = "several verbose flags at once" },
  { name = "format-mismatch", kind = "path", value = "/api?format=xml",
    note = "an unexpected response format request" },
  { name = "content-type-json", kind = "path", value = "/api",
    note = "a JSON content type on a non-JSON endpoint" },
  { name = "invalid-json", kind = "post", value = "/api",
    note = "a malformed JSON body" },
  { name = "empty-json", kind = "post", value = "/api",
    note = "an empty JSON object body" },
  { name = "xml-body", kind = "postxml", value = "/api",
    note = "an XML body with an undefined entity reference" },
  { name = "long-uri", kind = "path", value = "/{LONG}",
    note = "an extremely long URI" },
  { name = "double-slash", kind = "path", value = "//",
    note = "a double slash root path" },
  { name = "dot-segment", kind = "path", value = "/./././",
    note = "redundant dot segments" },
  { name = "semicolon-path", kind = "path", value = "/;nse",
    note = "a semicolon path parameter (Tomcat/Jetty routing)" },
  { name = "matrix-param", kind = "path", value = "/api;jsessionid=nse",
    note = "a jsessionid path parameter" },
  { name = "uppercase-ext", kind = "path", value = "/INDEX.PHP",
    note = "an uppercase file extension" },
  { name = "backup-ext", kind = "path", value = "/index.php.bak",
    note = "a backup extension of an existing file" },
  { name = "source-ext", kind = "path", value = "/index.php~",
    note = "an editor backup extension" },
  { name = "htaccess", kind = "path", value = "/.htaccess",
    note = "a request for the web-server access control file" },
  { name = "htpasswd", kind = "path", value = "/.htpasswd",
    note = "a request for the basic-auth password file" },
  { name = "dot-env", kind = "path", value = "/.env",
    note = "a request for the environment file" },
  { name = "git-head", kind = "path", value = "/.git/HEAD",
    note = "a request for a version control metadata file" },
  { name = "server-status", kind = "path", value = "/server-status",
    note = "Apache mod_status" },
  { name = "server-info", kind = "path", value = "/server-info",
    note = "Apache mod_info" },
  { name = "php-status", kind = "path", value = "/status.php",
    note = "PHP-FPM status" },
  { name = "actuator-error", kind = "path", value = "/actuator/httptrace",
    note = "Spring Boot Actuator trace endpoint" },
  { name = "elmah", kind = "path", value = "/elmah.axd",
    note = "ASP.NET ELMAH error log handler" },
  { name = "trace-axd", kind = "path", value = "/trace.axd",
    note = "ASP.NET tracing" },
  { name = "console", kind = "path", value = "/console/",
    note = "Werkzeug/Flask interactive console path" },
  { name = "debug-default", kind = "path", value = "/_debug/",
    note = "framework debug namespace" },
  { name = "phpinfo", kind = "path", value = "/phpinfo.php",
    note = "phpinfo() diagnostic script" },
  { name = "test-php", kind = "path", value = "/test.php",
    note = "leftover test script" },
}

local RAW_TRIGGERS = {
  { name = "invalid-http-version", method = "GET", path = "/ HTTP/9.9",
    note = "an unsupported HTTP version in the request line" },
  { name = "oversized-header", method = "GET", path = "/",
    note = "a header value of 16 KiB", header = { "X-NSE-Oversized", 16384 } },
  { name = "content-length-mismatch", method = "POST", path = "/",
    note = "Content-Length larger than the body actually sent", mismatch = true },
  { name = "bare-lf-injection", method = "GET", path = "/%0d%0aX-NSE:%20test",
    note = "an encoded CRLF sequence in the request target" },
  { name = "absolute-uri", method = "GET", path = "http://target.example.com/",
    note = "an absolute-form request target (proxy style)" },
  { name = "unknown-method", method = "NSEPROBE", path = "/",
    note = "a method the server has never seen" },
  { name = "options-wildcard", method = "OPTIONS", path = "*",
    note = "an OPTIONS request to the wildcard target" },
  { name = "head-root", method = "HEAD", path = "/",
    note = "a HEAD request (no body to disclose, but status matters)" },
  { name = "trace-root", method = "TRACE", path = "/",
    note = "a TRACE request (echo behaviour)" },
}

local DISCLOSURE_SIGNATURES = {
  { stack = "php", pattern = "fatal error:", what = "PHP fatal error", severity = "HIGH",
    detail = "unhandled PHP fatal error with file and line" },
  { stack = "php", pattern = "uncaught error", what = "PHP uncaught error", severity = "HIGH",
    detail = "uncaught PHP error (PHP 7+)" },
  { stack = "php", pattern = "uncaught exception", what = "PHP uncaught exception", severity = "HIGH",
    detail = "uncaught PHP exception" },
  { stack = "php", pattern = "parse error:", what = "PHP parse error", severity = "HIGH",
    detail = "PHP syntax error disclosed" },
  { stack = "php", pattern = "warning:</b> ", what = "PHP warning", severity = "MEDIUM",
    detail = "PHP warning with display_errors enabled" },
  { stack = "php", pattern = "warning: ", what = "PHP warning", severity = "MEDIUM",
    detail = "PHP warning with display_errors enabled" },
  { stack = "php", pattern = "notice:</b>", what = "PHP notice", severity = "LOW",
    detail = "PHP notice disclosed" },
  { stack = "php", pattern = "deprecated:</b>", what = "PHP deprecation", severity = "LOW",
    detail = "PHP deprecation notice disclosed" },
  { stack = "php", pattern = "on line <b>%d+", what = "PHP file/line disclosure", severity = "HIGH",
    detail = "PHP error reveals source file and line number" },
  { stack = "php", pattern = "in /[%w_%-%./]+%.php", what = "PHP source path", severity = "HIGH",
    detail = "PHP error reveals an absolute source path" },
  { stack = "php", pattern = "stack trace:", what = "PHP stack trace", severity = "HIGH",
    detail = "PHP stack trace printed (display_errors=On)" },
  { stack = "php", pattern = "#0 /", what = "PHP stack frame", severity = "HIGH",
    detail = "PHP stack frame with absolute path" },
  { stack = "php", pattern = "xdebug", what = "Xdebug present", severity = "CRITICAL",
    detail = "Xdebug is loaded; the remote debugger can be attached" },
  { stack = "php", pattern = "whoops", what = "Whoops error page", severity = "HIGH",
    detail = "Whoops debug handler renders full application state" },
  { stack = "php", pattern = "ignition", what = "Laravel Ignition", severity = "HIGH",
    detail = "Laravel Ignition error page (APP_DEBUG=true)" },
  { stack = "php", pattern = "laravel", what = "Laravel framework", severity = "LOW",
    detail = "Laravel identified from the error page" },
  { stack = "php", pattern = "symfony", what = "Symfony framework", severity = "LOW",
    detail = "Symfony identified from the error page" },
  { stack = "php", pattern = "drupal", what = "Drupal", severity = "LOW",
    detail = "Drupal identified from the error page" },
  { stack = "php", pattern = "wordpress", what = "WordPress", severity = "LOW",
    detail = "WordPress identified from the error page" },
  { stack = "php", pattern = "wpdb", what = "WordPress database layer", severity = "HIGH",
    detail = "wpdb error discloses SQL and connection detail" },
  { stack = "php", pattern = "document_root", what = "document root disclosed", severity = "MEDIUM",
    detail = "$_SERVER['DOCUMENT_ROOT'] rendered in output" },
  { stack = "php", pattern = "allow_url_fopen", what = "phpinfo directive", severity = "MEDIUM",
    detail = "PHP configuration directive disclosed" },
  { stack = "php", pattern = "php version", what = "phpinfo page", severity = "MEDIUM",
    detail = "phpinfo()-style page exposed" },

  { stack = "java", pattern = "java%.lang%.[%w]+exception", what = "Java exception", severity = "HIGH",
    detail = "Java exception class name disclosed" },
  { stack = "java", pattern = "exception in thread", what = "Java thread exception", severity = "HIGH",
    detail = "uncaught Java exception printed" },
  { stack = "java", pattern = "at [%w%.$_]+%.[%w$_]+%([%w%.]+:%d+%)", what = "Java stack frame",
    severity = "HIGH", detail = "Java stack frame with class, file and line" },
  { stack = "java", pattern = "caused by:", what = "Java exception chain", severity = "HIGH",
    detail = "full exception chain disclosed" },
  { stack = "java", pattern = "httpservletreport", what = "Servlet error report", severity = "HIGH",
    detail = "container error report page" },
  { stack = "java", pattern = "apache tomcat/", what = "Tomcat version", severity = "MEDIUM",
    detail = "Tomcat error page discloses the exact version" },
  { stack = "java", pattern = "jasperexception", what = "JSP compilation error", severity = "HIGH",
    detail = "JSP source and compilation error disclosed" },
  { stack = "java", pattern = "springframework", what = "Spring framework", severity = "MEDIUM",
    detail = "Spring identified from the error page" },
  { stack = "java", pattern = "whitelabel error page", what = "Spring Boot Whitelabel", severity = "LOW",
    detail = "Spring Boot default error page" },
  { stack = "java", pattern = "there was an unexpected error %(type=", what = "Spring Boot error attributes",
    severity = "MEDIUM", detail = "Spring Boot exposes exception type and message" },
  { stack = "java", pattern = "hibernate", what = "Hibernate", severity = "MEDIUM",
    detail = "Hibernate/HQL error disclosed (often includes the query)" },
  { stack = "java", pattern = "hqlqueryexception", what = "HQL query error", severity = "HIGH",
    detail = "HQL statement printed in the error page" },
  { stack = "java", pattern = "mybatis", what = "MyBatis", severity = "MEDIUM",
    detail = "MyBatis mapper error disclosed" },
  { stack = "java", pattern = "struts", what = "Apache Struts", severity = "MEDIUM",
    detail = "Struts identified from the error page (devMode prints the value stack)" },
  { stack = "java", pattern = "devmode", what = "Struts devMode", severity = "CRITICAL",
    detail = "Struts devMode is enabled: the OGNL value stack is printable" },
  { stack = "java", pattern = "ognl", what = "OGNL expression", severity = "CRITICAL",
    detail = "OGNL expression content disclosed (Struts RCE surface)" },
  { stack = "java", pattern = "weblogic", what = "WebLogic", severity = "MEDIUM",
    detail = "WebLogic identified from the error page" },
  { stack = "java", pattern = "jboss", what = "JBoss/WildFly", severity = "MEDIUM",
    detail = "JBoss/WildFly identified from the error page" },
  { stack = "java", pattern = "stack trace:", what = "stack trace heading", severity = "HIGH",
    detail = "explicit stack trace section rendered" },

  { stack = "dotnet", pattern = "server error in '/' application", what = "ASP.NET yellow screen",
    severity = "CRITICAL", detail = "customErrors is Off: full .NET exception disclosed" },
  { stack = "dotnet", pattern = "server error in ", what = "ASP.NET application error",
    severity = "HIGH", detail = "ASP.NET application error page" },
  { stack = "dotnet", pattern = "description: http 1.1", what = "ASP.NET error description",
    severity = "HIGH", detail = "ASP.NET detailed error description" },
  { stack = "dotnet", pattern = "exception details:", what = "ASP.NET exception details",
    severity = "HIGH", detail = "exception type and message printed" },
  { stack = "dotnet", pattern = "stack trace:", what = "ASP.NET stack trace", severity = "HIGH",
    detail = ".NET stack trace printed" },
  { stack = "dotnet", pattern = "at [%w%.]+%.[%w]+%(", what = ".NET stack frame", severity = "HIGH",
    detail = ".NET stack frame with assembly and method" },
  { stack = "dotnet", pattern = "source error:", what = "ASP.NET source error", severity = "CRITICAL",
    detail = "the offending source line is rendered in the browser" },
  { stack = "dotnet", pattern = "an unhandled exception", what = "unhandled .NET exception",
    severity = "HIGH", detail = "unhandled exception disclosed" },
  { stack = "dotnet", pattern = "request is not recognized", what = "ASP.NET error text",
    severity = "MEDIUM", detail = "ASP.NET error wording identifies the stack" },
  { stack = "dotnet", pattern = "version information: microsoft %.net framework version",
    what = ".NET version disclosure", severity = "MEDIUM", detail = "exact .NET Framework version printed" },
  { stack = "dotnet", pattern = "asp%.net version:", what = "ASP.NET version disclosure",
    severity = "MEDIUM", detail = "exact ASP.NET version printed" },
  { stack = "dotnet", pattern = "viewstate", what = "ViewState error", severity = "MEDIUM",
    detail = "ViewState validation error discloses the machineKey configuration state" },
  { stack = "dotnet", pattern = "validation of viewstate mac failed", what = "ViewState MAC failure",
    severity = "HIGH", detail = "ViewState MAC validation disabled or failing (deserialisation surface)" },
  { stack = "dotnet", pattern = "yellow screen", what = "ASP.NET yellow screen", severity = "HIGH",
    detail = "yellow screen of death rendered" },
  { stack = "dotnet", pattern = "sharepoint", what = "SharePoint", severity = "MEDIUM",
    detail = "SharePoint identified from the error page" },

  { stack = "python", pattern = "traceback %(most recent call last%)", what = "Python traceback",
    severity = "HIGH", detail = "Python traceback with file paths and line numbers" },
  { stack = "python", pattern = 'file "/[%w_%-%./]+%.py"', what = "Python source path",
    severity = "HIGH", detail = "absolute Python source path disclosed" },
  { stack = "python", pattern = "django", what = "Django", severity = "MEDIUM",
    detail = "Django identified from the error page" },
  { stack = "python", pattern = "you're seeing this error because you have <code>debug",
    what = "Django DEBUG=True", severity = "CRITICAL",
    detail = "Django DEBUG=True: settings, environment and SQL are rendered" },
  { stack = "python", pattern = "settings.py", what = "Django settings path", severity = "HIGH",
    detail = "Django settings module path disclosed" },
  { stack = "python", pattern = "werkzeug debugger", what = "Werkzeug debugger", severity = "CRITICAL",
    detail = "Flask/Werkzeug interactive debugger is reachable - console code execution" },
  { stack = "python", pattern = "pin:", what = "debugger PIN prompt", severity = "CRITICAL",
    detail = "interactive debugger PIN prompt rendered" },
  { stack = "python", pattern = "flask", what = "Flask", severity = "LOW",
    detail = "Flask identified from the error page" },
  { stack = "python", pattern = "fastapi", what = "FastAPI", severity = "LOW",
    detail = "FastAPI identified from the error page" },
  { stack = "python", pattern = "tornado", what = "Tornado", severity = "LOW",
    detail = "Tornado identified from the error page" },
  { stack = "python", pattern = "pyramid", what = "Pyramid", severity = "LOW",
    detail = "Pyramid identified from the error page" },
  { stack = "python", pattern = "zope", what = "Zope/Plone", severity = "LOW",
    detail = "Zope/Plone identified from the error page" },
  { stack = "python", pattern = "supervisor", what = "Supervisor", severity = "LOW",
    detail = "Supervisor XML-RPC error disclosed" },
  { stack = "python", pattern = "airflow", what = "Apache Airflow", severity = "MEDIUM",
    detail = "Airflow identified from the error page" },
  { stack = "python", pattern = "ansible", what = "Ansible", severity = "MEDIUM",
    detail = "Ansible/AWX identified from the error page" },

  { stack = "ruby", pattern = "actionview::template::error", what = "Rails template error",
    severity = "HIGH", detail = "Rails template error with backtrace" },
  { stack = "ruby", pattern = "activerecord::", what = "ActiveRecord error", severity = "HIGH",
    detail = "ActiveRecord error discloses model and SQL" },
  { stack = "ruby", pattern = "undefined method", what = "Ruby NoMethodError", severity = "MEDIUM",
    detail = "Ruby NoMethodError disclosed" },
  { stack = "ruby", pattern = "nomethoderror", what = "Ruby NoMethodError", severity = "MEDIUM",
    detail = "Ruby NoMethodError class disclosed" },
  { stack = "ruby", pattern = "webrick", what = "WEBrick server", severity = "MEDIUM",
    detail = "WEBrick (development server) is exposed publicly" },
  { stack = "ruby", pattern = "puma", what = "Puma", severity = "LOW", detail = "Puma identified" },
  { stack = "ruby", pattern = "rails", what = "Ruby on Rails", severity = "LOW",
    detail = "Rails identified from the error page" },
  { stack = "ruby", pattern = "sinatra", what = "Sinatra", severity = "LOW",
    detail = "Sinatra identified from the error page" },
  { stack = "ruby", pattern = "gitlab", what = "GitLab", severity = "MEDIUM",
    detail = "GitLab identified from the error page" },
  { stack = "ruby", pattern = "discourse", what = "Discourse", severity = "MEDIUM",
    detail = "Discourse identified from the error page" },

  { stack = "node", pattern = "typeerror: cannot read propert", what = "Node TypeError",
    severity = "MEDIUM", detail = "unhandled Node TypeError disclosed" },
  { stack = "node", pattern = "at object%.<anonymous>", what = "Node stack frame", severity = "HIGH",
    detail = "Node stack frame with module path" },
  { stack = "node", pattern = "at module%._compile", what = "Node stack frame", severity = "HIGH",
    detail = "Node module loader frame disclosed" },
  { stack = "node", pattern = "node_modules/", what = "Node dependency path", severity = "MEDIUM",
    detail = "dependency paths disclosed (package inventory readable)" },
  { stack = "node", pattern = "unhandledpromiserejectionwarning", what = "unhandled rejection",
    severity = "MEDIUM", detail = "unhandled promise rejection printed" },
  { stack = "node", pattern = "module_not_found", what = "missing module", severity = "MEDIUM",
    detail = "module resolution error discloses the file system layout" },
  { stack = "node", pattern = "sequelize", what = "Sequelize ORM", severity = "HIGH",
    detail = "Sequelize error discloses SQL and dialect" },
  { stack = "node", pattern = "mongooseerror", what = "Mongoose", severity = "HIGH",
    detail = "Mongoose/MongoDB error discloses schema" },
  { stack = "node", pattern = "prisma", what = "Prisma ORM", severity = "HIGH",
    detail = "Prisma error discloses schema and query" },
  { stack = "node", pattern = "express", what = "Express", severity = "LOW",
    detail = "Express identified from the error page" },
  { stack = "node", pattern = "next%.js", what = "Next.js", severity = "LOW",
    detail = "Next.js identified from the error page" },
  { stack = "node", pattern = "nestjs", what = "NestJS", severity = "LOW",
    detail = "NestJS identified from the error page" },
  { stack = "node", pattern = "strapi", what = "Strapi", severity = "MEDIUM",
    detail = "Strapi identified from the error page" },
  { stack = "node", pattern = "ghost", what = "Ghost", severity = "LOW",
    detail = "Ghost identified from the error page" },

  { stack = "go", pattern = "goroutine %d+ %[running%]", what = "Go goroutine dump", severity = "HIGH",
    detail = "Go panic with full goroutine stack" },
  { stack = "go", pattern = "runtime error: invalid memory address", what = "Go nil dereference",
    severity = "HIGH", detail = "Go runtime panic disclosed" },
  { stack = "go", pattern = "panic: %[recovered%]", what = "Go panic", severity = "HIGH",
    detail = "Go panic recovered and printed" },
  { stack = "go", pattern = "go%d+%.%d+", what = "Go toolchain version", severity = "LOW",
    detail = "Go toolchain version disclosed" },
  { stack = "go", pattern = "gin%.context", what = "Gin framework", severity = "MEDIUM",
    detail = "Gin identified from the panic frame" },
  { stack = "go", pattern = "traefik", what = "Traefik", severity = "MEDIUM",
    detail = "Traefik identified from the error page" },

  { stack = "mysql", pattern = "you have an error in your sql syntax", what = "MySQL syntax error",
    severity = "CRITICAL", detail = "raw SQL statement and MySQL version disclosed" },
  { stack = "mysql", pattern = "check the manual that corresponds to your mysql server version",
    what = "MySQL version disclosure", severity = "CRITICAL",
    detail = "the MySQL/MariaDB server version is printed in the error" },
  { stack = "mysql", pattern = "unknown column '[^']+' in", what = "MySQL schema disclosure",
    severity = "CRITICAL", detail = "column and table names disclosed" },
  { stack = "mysql", pattern = "sqlstate%[", what = "PDO SQLSTATE", severity = "HIGH",
    detail = "PDO SQLSTATE and driver message disclosed" },
  { stack = "mysql", pattern = "mysql_fetch", what = "mysql_* function error", severity = "HIGH",
    detail = "legacy mysql_* function error (PHP < 7 API)" },
  { stack = "mysql", pattern = "mariadb", what = "MariaDB", severity = "MEDIUM",
    detail = "MariaDB identified from the error text" },
  { stack = "mysql", pattern = "warning: mysqli", what = "mysqli warning", severity = "HIGH",
    detail = "mysqli error with connection detail" },

  { stack = "postgresql", pattern = "pg_query", what = "PostgreSQL query error", severity = "CRITICAL",
    detail = "PostgreSQL query function error discloses the statement" },
  { stack = "postgresql", pattern = "error:  syntax error at or near", what = "PostgreSQL syntax error",
    severity = "CRITICAL", detail = "PostgreSQL parser error with the offending token" },
  { stack = "postgresql", pattern = "pq%:", what = "libpq error", severity = "HIGH",
    detail = "libpq driver error disclosed" },
  { stack = "postgresql", pattern = "psycopg2", what = "psycopg2 error", severity = "HIGH",
    detail = "psycopg2 exception discloses the query" },
  { stack = "postgresql", pattern = "postgresql query failed", what = "PostgreSQL failure",
    severity = "HIGH", detail = "PostgreSQL failure message disclosed" },
  { stack = "postgresql", pattern = "relation .* does not exist", what = "PostgreSQL schema disclosure",
    severity = "HIGH", detail = "table/relation name disclosed" },

  { stack = "mssql", pattern = "microsoft ole db provider", what = "MSSQL OLE DB provider",
    severity = "CRITICAL", detail = "SQL Server provider error discloses the statement and server" },
  { stack = "mssql", pattern = "incorrect syntax near", what = "MSSQL syntax error", severity = "CRITICAL",
    detail = "T-SQL syntax error with the offending fragment" },
  { stack = "mssql", pattern = "msg %d+, level %d+, state %d+", what = "MSSQL error number",
    severity = "HIGH", detail = "SQL Server error numbering (message/level/state)" },
  { stack = "mssql", pattern = "sql server does not exist", what = "MSSQL connectivity error",
    severity = "HIGH", detail = "SQL Server connection detail disclosed" },
  { stack = "mssql", pattern = "unclosed quotation mark", what = "MSSQL quote error", severity = "CRITICAL",
    detail = "unbalanced quote error - injection point confirmed" },
  { stack = "mssql", pattern = "sqloledb", what = "SQLOLEDB driver", severity = "HIGH",
    detail = "SQLOLEDB driver identified" },
  { stack = "mssql", pattern = "microsoft sql server", what = "SQL Server identity", severity = "MEDIUM",
    detail = "SQL Server identified from the error text" },

  { stack = "oracle", pattern = "ora%-%d%d%d%d%d", what = "Oracle error code", severity = "HIGH",
    detail = "Oracle error code disclosed (ORA-xxxxx)" },
  { stack = "oracle", pattern = "pls%-%d%d%d%d%d", what = "PL/SQL error code", severity = "HIGH",
    detail = "PL/SQL compilation error disclosed" },
  { stack = "oracle", pattern = "oracle%.jdbc", what = "Oracle JDBC", severity = "HIGH",
    detail = "Oracle JDBC driver error disclosed" },
  { stack = "oracle", pattern = "invalid identifier", what = "Oracle schema disclosure", severity = "HIGH",
    detail = "Oracle 'invalid identifier' discloses column expectations" },
  { stack = "oracle", pattern = "table or view does not exist", what = "Oracle object disclosure",
    severity = "HIGH", detail = "Oracle object existence oracle" },

  { stack = "sqlite", pattern = "sqlite3%.operationalerror", what = "SQLite error", severity = "HIGH",
    detail = "SQLite operational error discloses the query" },
  { stack = "sqlite", pattern = "sqlite_error", what = "SQLite error", severity = "HIGH",
    detail = "SQLite error code disclosed" },
  { stack = "sqlite", pattern = "no such table:", what = "SQLite schema disclosure", severity = "HIGH",
    detail = "SQLite table name disclosed" },
  { stack = "sqlite", pattern = "near .*: syntax error", what = "SQLite syntax error", severity = "HIGH",
    detail = "SQLite parser error with the offending token" },

  { stack = "mongodb", pattern = "mongoservererror", what = "MongoDB server error", severity = "HIGH",
    detail = "MongoDB error discloses the query and collection" },
  { stack = "mongodb", pattern = "mongodb%.bulkwriteerror", what = "MongoDB write error",
    severity = "HIGH", detail = "MongoDB bulk write error disclosed" },
  { stack = "mongodb", pattern = "%$where", what = "MongoDB $where", severity = "CRITICAL",
    detail = "JavaScript $where clause visible in the error (server-side JS execution)" },
  { stack = "mongodb", pattern = "bson", what = "BSON error", severity = "MEDIUM",
    detail = "BSON decoding error disclosed" },

  { stack = "elasticsearch", pattern = "parsing_exception", what = "Elasticsearch parse error",
    severity = "HIGH", detail = "Elasticsearch query parser error with index detail" },
  { stack = "elasticsearch", pattern = "query_shard_exception", what = "Elasticsearch shard error",
    severity = "HIGH", detail = "Elasticsearch shard error discloses index and mapping" },
  { stack = "elasticsearch", pattern = "index_not_found_exception", what = "Elasticsearch index disclosure",
    severity = "MEDIUM", detail = "index existence oracle" },
  { stack = "elasticsearch", pattern = "illegal_argument_exception", what = "Elasticsearch argument error",
    severity = "MEDIUM", detail = "Elasticsearch argument validation error" },

  { stack = "redis", pattern = "rediscommandexecutionexception", what = "Redis command error",
    severity = "HIGH", detail = "Redis command error discloses accepted commands" },
  { stack = "redis", pattern = "wrong number of arguments for '", what = "Redis arity error",
    severity = "MEDIUM", detail = "Redis command arity error (command name disclosed)" },
  { stack = "redis", pattern = "noauth authentication required", what = "Redis auth error",
    severity = "MEDIUM", detail = "Redis requires authentication (service reachable)" },

  { stack = "ldap", pattern = "invaliddnsyntax", what = "LDAP filter error", severity = "MEDIUM",
    detail = "LDAP filter syntax error discloses the directory query" },
  { stack = "ldap", pattern = "ldap%.INVALID", what = "LDAP result code", severity = "MEDIUM",
    detail = "LDAP result code disclosed" },

  { stack = "generic", pattern = "internal server error", what = "500 body", severity = "LOW",
    detail = "generic 500 body" },
  { stack = "generic", pattern = "debug", what = "debug marker", severity = "MEDIUM",
    detail = "the word debug appears in an error response" },
  { stack = "generic", pattern = "exception", what = "exception marker", severity = "MEDIUM",
    detail = "an exception object is named in the response" },
  { stack = "generic", pattern = "stack trace", what = "stack trace marker", severity = "HIGH",
    detail = "a stack trace section is present" },
  { stack = "generic", pattern = "line %d+ in ", what = "file/line marker", severity = "HIGH",
    detail = "source file and line number are printed" },
  { stack = "generic", pattern = "syntax error", what = "syntax error marker", severity = "HIGH",
    detail = "a parser/syntax error is echoed back" },
  { stack = "generic", pattern = "uncaught", what = "uncaught marker", severity = "HIGH",
    detail = "an uncaught error reached the client" },
  { stack = "generic", pattern = "core dumped", what = "crash marker", severity = "HIGH",
    detail = "the backend crashed (core dumped)" },
  { stack = "generic", pattern = "segmentation fault", what = "crash marker", severity = "HIGH",
    detail = "segmentation fault disclosed" },
  { stack = "generic", pattern = "out of memory", what = "resource exhaustion", severity = "MEDIUM",
    detail = "memory exhaustion disclosed" },
  { stack = "generic", pattern = "connection refused", what = "upstream failure", severity = "MEDIUM",
    detail = "an upstream/backend connection failure is echoed to the client" },
  { stack = "generic", pattern = "connection timed out", what = "upstream timeout", severity = "LOW",
    detail = "an upstream timeout is echoed to the client" },
  { stack = "generic", pattern = "backend", what = "backend reference", severity = "LOW",
    detail = "the response refers to a backend component" },
  { stack = "generic", pattern = "upstream", what = "upstream reference", severity = "LOW",
    detail = "the response refers to an upstream component" },
  { stack = "generic", pattern = "permission denied", what = "OS permission error", severity = "MEDIUM",
    detail = "an operating-system permission error is echoed (often with the path)" },
  { stack = "generic", pattern = "no such file or directory", what = "OS file error", severity = "MEDIUM",
    detail = "an operating-system file error is echoed (often with the path)" },
  { stack = "generic", pattern = "failed to open stream", what = "PHP stream error", severity = "HIGH",
    detail = "PHP stream error discloses the attempted file path" },
  { stack = "generic", pattern = "file_get_contents", what = "PHP file function", severity = "HIGH",
    detail = "PHP file function error discloses the target path" },
  { stack = "generic", pattern = "include%(", what = "PHP include error", severity = "HIGH",
    detail = "PHP include/require error discloses the path" },
  { stack = "generic", pattern = "undefined index", what = "PHP undefined index", severity = "LOW",
    detail = "PHP undefined index notice" },
  { stack = "generic", pattern = "undefined variable", what = "PHP undefined variable", severity = "LOW",
    detail = "PHP undefined variable notice" },
  { stack = "generic", pattern = "nullpointerexception", what = "null dereference", severity = "HIGH",
    detail = "null pointer dereference disclosed" },
  { stack = "generic", pattern = "classnotfoundexception", what = "class loading failure",
    severity = "HIGH", detail = "class loading failure discloses the class path" },
  { stack = "generic", pattern = "ioexception", what = "I/O failure", severity = "MEDIUM",
    detail = "I/O failure disclosed" },
  { stack = "generic", pattern = "sqlexception", what = "SQL failure", severity = "HIGH",
    detail = "JDBC SQLException disclosed" },
  { stack = "generic", pattern = "deadlock found", what = "database deadlock", severity = "MEDIUM",
    detail = "a database deadlock is reported to the client" },
  { stack = "generic", pattern = "duplicate entry", what = "unique constraint", severity = "MEDIUM",
    detail = "a unique constraint violation discloses key values" },
  { stack = "generic", pattern = "foreign key constraint", what = "FK constraint", severity = "MEDIUM",
    detail = "a foreign key constraint error discloses relationships" },
  { stack = "generic", pattern = "cannot add or update a child row", what = "FK constraint",
    severity = "MEDIUM", detail = "MySQL FK constraint error" },
  { stack = "generic", pattern = "authentication failed", what = "auth failure text", severity = "LOW",
    detail = "authentication failure wording (enumeration aid)" },
  { stack = "generic", pattern = "invalid credentials", what = "auth failure text", severity = "LOW",
    detail = "credential validation wording (enumeration aid)" },
  { stack = "generic", pattern = "user .* already exists", what = "user enumeration", severity = "MEDIUM",
    detail = "user existence oracle" },
  { stack = "generic", pattern = "no such user", what = "user enumeration", severity = "MEDIUM",
    detail = "user existence oracle" },
  { stack = "generic", pattern = "license", what = "license text", severity = "LOW",
    detail = "licence validation error discloses product/licence state" },
  { stack = "generic", pattern = "docker", what = "Docker reference", severity = "MEDIUM",
    detail = "container runtime referenced in the error" },
  { stack = "generic", pattern = "kubernetes", what = "Kubernetes reference", severity = "MEDIUM",
    detail = "orchestrator referenced in the error" },
  { stack = "generic", pattern = "helm", what = "Helm reference", severity = "MEDIUM",
    detail = "Helm/release tooling referenced in the error" },
}

local DEBUG_CONSOLE_SIGNATURES = {
  { pattern = "werkzeug debugger", product = "Werkzeug (Flask)", severity = "CRITICAL",
    note = "interactive Python console: arbitrary code execution from the browser" },
  { pattern = "console pin", product = "Werkzeug (Flask)", severity = "CRITICAL",
    note = "debugger PIN prompt" },
  { pattern = "xdebug", product = "Xdebug", severity = "CRITICAL",
    note = "remote PHP debugger loaded; the IDE key/DBGP port can be driven" },
  { pattern = "ignition", product = "Laravel Ignition", severity = "CRITICAL",
    note = "Ignition can expose environment, config and (historically) RCE gadgets" },
  { pattern = "telescope", product = "Laravel Telescope", severity = "CRITICAL",
    note = "Telescope exposes requests, queries, jobs and environment" },
  { pattern = "symfony profiler", product = "Symfony profiler", severity = "HIGH",
    note = "profiler exposes request/response, queries and environment" },
  { pattern = "_profiler", product = "Symfony profiler", severity = "HIGH",
    note = "profiler token namespace reachable" },
  { pattern = "django debug", product = "Django DEBUG", severity = "CRITICAL",
    note = "DEBUG=True renders settings, environment variables and SQL" },
  { pattern = "you're seeing this error because you have", product = "Django DEBUG", severity = "CRITICAL",
    note = "Django technical 500 page" },
  { pattern = "whoops", product = "Whoops", severity = "HIGH",
    note = "Whoops renders source, environment and superglobals" },
  { pattern = "php info", product = "phpinfo()", severity = "HIGH",
    note = "phpinfo() renders configuration, environment and loaded modules" },
  { pattern = "phpinfo()", product = "phpinfo()", severity = "HIGH",
    note = "phpinfo() page" },
  { pattern = "actuator", product = "Spring Boot Actuator", severity = "HIGH",
    note = "Actuator endpoints expose environment, heapdump and mappings" },
  { pattern = "trace%.axd", product = "ASP.NET tracing", severity = "HIGH",
    note = "trace.axd exposes per-request details including session state" },
  { pattern = "elmah", product = "ASP.NET ELMAH", severity = "HIGH",
    note = "ELMAH exposes the stored exception log" },
  { pattern = "server%-status", product = "Apache mod_status", severity = "MEDIUM",
    note = "mod_status exposes client IPs, requests and vhosts" },
  { pattern = "server%-info", product = "Apache mod_info", severity = "MEDIUM",
    note = "mod_info exposes the compiled configuration" },
  { pattern = "php%-fpm status", product = "PHP-FPM status", severity = "MEDIUM",
    note = "FPM pool status exposed" },
  { pattern = "devmode", product = "Struts devMode", severity = "CRITICAL",
    note = "devMode prints the OGNL value stack and enables debugging URLs" },
  { pattern = "rails console", product = "Rails console", severity = "CRITICAL",
    note = "a Rails console surface is reachable" },
  { pattern = "jupyter", product = "Jupyter", severity = "CRITICAL",
    note = "Jupyter notebook/lab interface reachable" },
  { pattern = "phpmyadmin", product = "phpMyAdmin", severity = "HIGH",
    note = "database administration interface reachable" },
  { pattern = "adminer", product = "Adminer", severity = "HIGH",
    note = "Adminer database interface reachable (also an SSRF vector)" },
  { pattern = "grafana", product = "Grafana", severity = "MEDIUM",
    note = "Grafana reachable from this endpoint" },
  { pattern = "kibana", product = "Kibana", severity = "MEDIUM",
    note = "Kibana reachable from this endpoint" },
  { pattern = "swagger", product = "Swagger UI", severity = "MEDIUM",
    note = "API documentation UI reachable" },
}

local PATH_PATTERNS = {
  { pattern = "/var/www/[%w_%-%./]+", kind = "unix-web-root" },
  { pattern = "/var/log/[%w_%-%./]+", kind = "unix-log" },
  { pattern = "/home/[%w_%-%./]+", kind = "unix-home" },
  { pattern = "/usr/share/[%w_%-%./]+", kind = "unix-share" },
  { pattern = "/usr/local/[%w_%-%./]+", kind = "unix-local" },
  { pattern = "/usr/lib/[%w_%-%./]+", kind = "unix-lib" },
  { pattern = "/opt/[%w_%-%./]+", kind = "unix-opt" },
  { pattern = "/srv/[%w_%-%./]+", kind = "unix-srv" },
  { pattern = "/app/[%w_%-%./]+", kind = "container-app" },
  { pattern = "/etc/[%w_%-%./]+", kind = "unix-etc" },
  { pattern = "/tmp/[%w_%-%./]+", kind = "unix-tmp" },
  { pattern = "/proc/[%w_%-%./]+", kind = "procfs" },
  { pattern = "/data/[%w_%-%./]+", kind = "container-data" },
  { pattern = "/code/[%w_%-%./]+", kind = "container-code" },
  { pattern = "c:/inetpub/[%w_%-%./]+", kind = "windows-iis" },
  { pattern = "c:/program files[%w_%-%./]*", kind = "windows-programfiles" },
  { pattern = "c:/users/[%w_%-%./]+", kind = "windows-users" },
  { pattern = "c:/windows/[%w_%-%./]+", kind = "windows-dir" },
  { pattern = "d:/wwwroot/[%w_%-%./]+", kind = "windows-web" },
  { pattern = "d:/inetpub/[%w_%-%./]+", kind = "windows-iis" },
}

local WAF_SIGNATURES = {
  { pattern = "cf-ray", where = "header", vendor = "Cloudflare" },
  { pattern = "cloudflare", where = "header", vendor = "Cloudflare" },
  { pattern = "akamai", where = "header", vendor = "Akamai" },
  { pattern = "x-iinfo", where = "header", vendor = "Imperva Incapsula" },
  { pattern = "sucuri", where = "header", vendor = "Sucuri" },
  { pattern = "aws waf", where = "body", vendor = "AWS WAF" },
  { pattern = "attention required", where = "body", vendor = "Cloudflare" },
  { pattern = "request blocked", where = "body", vendor = "generic WAF" },
}

local SOFT404_TEMPLATES = {
  "/nse-err-baseline-%s",
  "/nse-err-nothing/%s/index.html",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 3,
  triggers = 45,
  maxrequests = 120,
  retries = 1,
  timeout = 8000,
  delay = 0.05,
  raw = true,
  soft404 = true,
  useragent = nil,
  maxbodysize = 262144,
}

local NUMERIC_ARGS = {
  { key = "maxpaths", minimum = 1, integer = true },
  { key = "triggers", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 5, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxbodysize", minimum = 1024, integer = true },
}

local BOOLEAN_ARGS = { "raw", "soft404" }

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

local function build_trigger_list(args)
  local triggers = {}
  local count = 0
  for _, trigger in ipairs(TRIGGER_PATHS) do
    if count >= args.triggers then
      break
    end
    local value = trigger.value or "/"
    if contains(value, "{BIG}") then
      value = string.gsub(value, "{BIG}", string.rep("A", 10000))
    elseif contains(value, "{LONG}") then
      value = string.gsub(value, "{LONG}", string.rep("a", 6000))
    elseif contains(value, "{CHARSET}") then
      value = string.gsub(value, "{CHARSET}", "nse-invalid-charset")
    elseif contains(value, "{TOKEN}") then
      value = string.gsub(value, "{TOKEN}", lower(random_token(8)))
    end
    table.insert(triggers, {
      name = trigger.name,
      kind = trigger.kind,
      path = value,
      note = trigger.note,
    })
    count = count + 1
  end
  return triggers
end

local function build_raw_triggers(args)
  if not args.raw then
    return {}
  end
  local triggers = {}
  for _, trigger in ipairs(RAW_TRIGGERS) do
    local headers = {}
    local body = nil
    if trigger.header then
      table.insert(headers, { trigger.header[1], string.rep("A", trigger.header[2]) })
    end
    if trigger.mismatch then
      table.insert(headers, { "Content-Length", "4096" })
      body = "short"
    end
    table.insert(triggers, {
      name = trigger.name,
      method = trigger.method,
      path = trigger.path,
      headers = headers,
      body = body,
      note = trigger.note,
    })
  end
  return triggers
end

local function is_private_ip(value)
  local a, b = string.match(tostring(value), "^(%d+)%.(%d+)%.")
  if not a then
    return false
  end
  local first = tonumber(a)
  local second = tonumber(b)
  if first == 10 or first == 127 then
    return true
  end
  if first == 172 and second >= 16 and second <= 31 then
    return true
  end
  if first == 192 and second == 168 then
    return true
  end
  if first == 169 and second == 254 then
    return true
  end
  if first == 100 and second >= 64 and second <= 127 then
    return true
  end
  return false
end

local function extract_paths(body)
  local result = {}
  local seen = {}
  for _, entry in ipairs(PATH_PATTERNS) do
    for match in string.gmatch(body, entry.pattern) do
      local cleaned = string.gsub(match, [[[%.,;:'"<>)%%]+$]], "")
      if #cleaned > 5 and not seen[cleaned] then
        seen[cleaned] = true
        table.insert(result, { path = cleaned, kind = entry.kind })
      end
    end
  end
  return result
end

local function extract_hosts_and_ips(body)
  local ips = {}
  local seen_ips = {}
  for ip in string.gmatch(body, "(%d+%.%d+%.%d+%.%d+)") do
    local valid = true
    local parts = 0
    for octet in string.gmatch(ip, "(%d+)") do
      local value = tonumber(octet)
      if not value or value > 255 then
        valid = false
      end
      parts = parts + 1
    end
    if valid and parts == 4 and is_private_ip(ip) and not seen_ips[ip] then
      seen_ips[ip] = true
      table.insert(ips, { ip = ip, private = true })
    end
  end

  local hosts = {}
  local seen_hosts = {}
  local lowered = lower(body)
  for host in string.gmatch(lowered, "([%w%-]+%.internal)") do
    if not seen_hosts[host] then
      seen_hosts[host] = true
      table.insert(hosts, host)
    end
  end
  for host in string.gmatch(lowered, "([%w%-]+%.local)") do
    if not contains(host, "localhost") and not seen_hosts[host] then
      seen_hosts[host] = true
      table.insert(hosts, host)
    end
  end
  for host in string.gmatch(lowered, "([%w%-]+%.corp%.[%w%.]+)") do
    if not seen_hosts[host] then
      seen_hosts[host] = true
      table.insert(hosts, host)
    end
  end
  for host in string.gmatch(lowered, "([%w%-]+%.lan)") do
    if not seen_hosts[host] then
      seen_hosts[host] = true
      table.insert(hosts, host)
    end
  end
  for host in string.gmatch(lowered, "([%w%-]+%.svc%.cluster%.local)") do
    if not seen_hosts[host] then
      seen_hosts[host] = true
      table.insert(hosts, host)
    end
  end

  return ips, hosts
end

local function extract_versions(body)
  local versions = {}
  local seen = {}
  local lowered = lower(body)
  local products = {
    { name = "php", pattern = "php[/ ]([%d%.]+)" },
    { name = "mysql", pattern = "mysql server version[: ]+([%d%.]+)" },
    { name = "mariadb", pattern = "mariadb[- ]([%d%.]+)" },
    { name = "postgresql", pattern = "postgresql ([%d%.]+)" },
    { name = "sql server", pattern = "microsoft sql server%s*([%d%.]+)" },
    { name = "oracle", pattern = "oracle database ([%d%.]+)" },
    { name = "mongodb", pattern = "mongodb server version: ([%d%.]+)" },
    { name = "apache", pattern = "apache/([%d%.]+)" },
    { name = "nginx", pattern = "nginx/([%d%.]+)" },
    { name = "tomcat", pattern = "apache tomcat/([%d%.]+)" },
    { name = "jetty", pattern = "jetty[(/]([%d%.]+)" },
    { name = "iis", pattern = "microsoft-iis/([%d%.]+)" },
    { name = "dotnet", pattern = "%.net framework version:([%d%.]+)" },
    { name = "aspnet", pattern = "asp%.net version:([%d%.]+)" },
    { name = "python", pattern = "python ([%d%.]+)" },
    { name = "ruby", pattern = "ruby ([%d%.]+)" },
    { name = "node", pattern = "node%.js/v([%d%.]+)" },
    { name = "go", pattern = "go(%d+%.%d+%.?%d*)" },
    { name = "openssl", pattern = "openssl[/ ]([%d%.]+%a?)" },
    { name = "java", pattern = 'java version "([%d%._]+)' },
    { name = "laravel", pattern = "laravel ([%d%.]+)" },
    { name = "django", pattern = "django ([%d%.]+)" },
    { name = "spring", pattern = "spring boot ([%d%.]+)" },
    { name = "wordpress", pattern = "wordpress ([%d%.]+)" },
    { name = "elasticsearch", pattern = "elasticsearch[/ ]([%d%.]+)" },
    { name = "redis", pattern = "redis server v=([%d%.]+)" },
    { name = "haproxy", pattern = "haproxy/([%d%.]+)" },
    { name = "varnish", pattern = "varnish/([%d%.]+)" },
  }
  for _, entry in ipairs(products) do
    local version = string.match(lowered, entry.pattern)
    if version then
      local key = entry.name .. "|" .. version
      if not seen[key] then
        seen[key] = true
        table.insert(versions, { product = entry.name, version = version })
      end
    end
  end
  return versions
end

local function extract_environment(body)
  local hits = {}
  local lowered = lower(body)
  local markers = {
    { pattern = "_server", label = "PHP $_SERVER superglobal" },
    { pattern = "_env", label = "PHP $_ENV superglobal" },
    { pattern = "_get", label = "PHP $_GET superglobal" },
    { pattern = "_post", label = "PHP $_POST superglobal" },
    { pattern = "_cookies", label = "PHP $_COOKIE superglobal" },
    { pattern = "_session", label = "PHP $_SESSION superglobal" },
    { pattern = "os%.environ", label = "Python os.environ dump" },
    { pattern = "process%.env", label = "Node process.env dump" },
    { pattern = "environment variables", label = "environment variable table" },
    { pattern = "env vars", label = "environment variable list" },
    { pattern = "system properties", label = "Java system properties" },
    { pattern = "system%.getenv", label = "Java System.getenv() output" },
    { pattern = "app_debug", label = "Laravel APP_DEBUG value" },
    { pattern = "app_key", label = "Laravel APP_KEY value" },
    { pattern = "db_password", label = "database password setting" },
    { pattern = "db_host", label = "database host setting" },
    { pattern = "secret_key", label = "framework secret key setting" },
    { pattern = "aws_access_key", label = "AWS access key material" },
    { pattern = "aws_secret", label = "AWS secret key material" },
    { pattern = "private_key", label = "private key material" },
    { pattern = "api_key", label = "API key material" },
    { pattern = "smtp_password", label = "mail credential setting" },
    { pattern = "redis_password", label = "Redis credential setting" },
    { pattern = "settings", label = "settings dump heading" },
  }
  for _, marker in ipairs(markers) do
    if string.find(lowered, marker.pattern, 1, true) or string.find(lowered, marker.pattern) then
      table.insert(hits, marker.label)
    end
  end
  local deduped = {}
  local seen = {}
  for _, hit in ipairs(hits) do
    unique_append(deduped, seen, hit)
  end
  return deduped
end

local function extract_sql(body)
  local statements = {}
  local seen = {}
  local lowered = lower(body)
  local kinds = {
    { kind = "SELECT", pattern = [[select%s+[%w%*%,%s%._'"%-]-from%s+[%w_%.%-]+]] },
    { kind = "INSERT", pattern = "insert%s+into%s+[%w_%.%-]+" },
    { kind = "UPDATE", pattern = "update%s+[%w_%.%-]+%s+set%s+" },
    { kind = "DELETE", pattern = "delete%s+from%s+[%w_%.%-]+" },
    { kind = "SHOW", pattern = "show%s+[%w_%.%-]+" },
    { kind = "DESCRIBE", pattern = "describe%s+[%w_%.%-]+" },
  }
  for _, entry in ipairs(kinds) do
    for statement in string.gmatch(lowered, entry.pattern) do
      local cleaned = truncate(trim(statement), 150)
      if #cleaned > 16 and not seen[cleaned] then
        seen[cleaned] = true
        table.insert(statements, { statement = cleaned, kind = entry.kind })
      end
    end
  end
  return statements
end

local function strip_control(value)
  local text = string.gsub(tostring(value or ""), "<script.-></script>", " ")
  text = string.gsub(text, "<style.-></style>", " ")
  text = string.gsub(text, "<[^>]+>", " ")
  text = string.gsub(text, "[\r\n\t]+", " ")
  text = string.gsub(text, "%s+", " ")
  return trim(text)
end

local function analyse_body(trigger_name, path, response, baseline)
  local body = response.body or ""
  if #body == 0 then
    return nil
  end

  local info = classify_response(path, response, baseline)
  local suppressed = {}
  for _, note in ipairs(info.notes or {}) do
    if contains(lower(note), "soft-404") or contains(lower(note), "interstitial")
      or contains(lower(note), "rate limiting") then
      table.insert(suppressed, note)
    end
  end
  if #suppressed > 0 then
    return {
      trigger = trigger_name,
      path = path,
      status = info.status,
      length = #body,
      suppressed = table.concat(suppressed, "; "),
      matches = {},
      consoles = {},
      paths = {},
      ips = {},
      hosts = {},
      versions = {},
      environment = {},
      sql = {},
      stacks = {},
      worst = "INFO",
      sample = truncate(strip_control(body), 120),
    }
  end

  local lowered = lower(body)
  local matches = {}
  local seen = {}
  local stacks = {}

  for _, entry in ipairs(DISCLOSURE_SIGNATURES) do
    local plain = string.find(lowered, entry.pattern, 1, true)
    local magic = string.find(lowered, entry.pattern)
    if plain or magic then
      local key = entry.stack .. "|" .. entry.what
      if unique_append(matches, seen, key) then
        local last = matches[#matches]
        if type(last) == "string" then
          matches[#matches] = {
            stack = entry.stack,
            what = entry.what,
            severity = entry.severity,
            detail = entry.detail,
          }
        end
      end
      stacks[entry.stack] = (stacks[entry.stack] or 0) + 1
    end
  end

  local normalized = {}
  for _, entry in ipairs(matches) do
    if type(entry) == "table" then
      table.insert(normalized, entry)
    end
  end

  local consoles = {}
  local console_seen = {}
  for _, entry in ipairs(DEBUG_CONSOLE_SIGNATURES) do
    if string.find(lowered, entry.pattern, 1, true) or string.find(lowered, entry.pattern) then
      if unique_append(consoles, console_seen, entry.product) then
        local last = consoles[#consoles]
        if type(last) == "string" then
          consoles[#consoles] = {
            product = last,
            severity = entry.severity,
            note = entry.note,
          }
        end
      end
    end
  end
  local console_list = {}
  for _, entry in ipairs(consoles) do
    if type(entry) == "table" then
      table.insert(console_list, entry)
    end
  end

  local paths = extract_paths(body)
  local ips, hosts = extract_hosts_and_ips(body)
  local versions = extract_versions(body)
  local environment = extract_environment(body)
  local sql = extract_sql(body)

  local worst = "INFO"
  for _, entry in ipairs(normalized) do
    if (SEVERITY[entry.severity] or 0) > (SEVERITY[worst] or 0) then
      worst = entry.severity
    end
  end
  for _, entry in ipairs(console_list) do
    if (SEVERITY[entry.severity] or 0) > (SEVERITY[worst] or 0) then
      worst = entry.severity
    end
  end
  if #sql > 0 and (SEVERITY[worst] or 0) < (SEVERITY.CRITICAL or 0) then
    worst = "CRITICAL"
  end
  if #paths > 0 and (SEVERITY[worst] or 0) < (SEVERITY.MEDIUM or 0) then
    worst = "MEDIUM"
  end

  return {
    trigger = trigger_name,
    path = path,
    status = info.status,
    length = #body,
    matches = normalized,
    consoles = console_list,
    paths = paths,
    ips = ips,
    hosts = hosts,
    versions = versions,
    environment = environment,
    sql = sql,
    stacks = stacks,
    worst = worst,
    sample = truncate(strip_control(body), 160),
  }
end

local function report_analysis(analysis)
  if analysis.suppressed then
    return
  end
  if #analysis.matches == 0 and #analysis.paths == 0 and #analysis.consoles == 0
    and #analysis.sql == 0 and #analysis.environment == 0 and #analysis.versions == 0
    and #analysis.ips == 0 and #analysis.hosts == 0 then
    return
  end

  local short_path = truncate(analysis.path, 60)

  local signature_key = {}
  for _, entry in ipairs(analysis.matches) do
    table.insert(signature_key, entry.stack .. "/" .. entry.what)
  end
  table.sort(signature_key)

  add_finding(analysis.worst, string.format(
    "HTTP %s responses disclose %d stack signature(s): %s",
    tostring(analysis.status), #signature_key, table.concat(signature_key, ", ")),
    { path = short_path,
      subject = "disclosure:" .. table.concat(signature_key, ",") .. ":" .. tostring(analysis.status),
      confidence = #analysis.matches >= 2 and "high" or "medium",
      evidence = analysis.sample })

  for _, entry in ipairs(analysis.consoles) do
    add_finding(entry.severity, string.format("%s debug/diagnostic surface is reachable: %s",
      entry.product, entry.note),
      { path = short_path, subject = "console:" .. lower(entry.product),
        evidence = analysis.sample })
  end

  for _, statement in ipairs(analysis.sql) do
    add_finding("CRITICAL", string.format("a raw %s statement is printed in the error response",
      statement.kind),
      { path = short_path, subject = "sql:" .. statement.kind,
        evidence = statement.statement })
  end

  for _, entry in ipairs(analysis.paths) do
    add_finding("MEDIUM", string.format("the response discloses a %s path on the server", entry.kind),
      { path = short_path, subject = "path:" .. entry.kind,
        evidence = truncate(entry.path, 100) })
  end

  for _, entry in ipairs(analysis.ips) do
    add_finding("MEDIUM", "the response discloses a private IP address",
      { path = short_path, subject = "ip:" .. entry.ip, evidence = entry.ip })
  end

  for _, host in ipairs(analysis.hosts) do
    add_finding("LOW", "the response discloses an internal host name",
      { path = short_path, subject = "host:" .. host, evidence = host })
  end

  for _, entry in ipairs(analysis.versions) do
    add_finding("LOW", string.format("the response discloses a %s version (%s)",
      entry.product, entry.version),
      { path = short_path, subject = "version:" .. entry.product .. ":" .. entry.version,
        evidence = entry.product .. " " .. entry.version })
  end

  for _, label in ipairs(analysis.environment) do
    add_finding("HIGH", string.format("the response includes application environment material (%s)", label),
      { path = short_path, subject = "env:" .. lower(label), evidence = label })
  end

  local shown = 0
  for _, entry in ipairs(analysis.matches) do
    if shown >= 6 then
      break
    end
    add_finding(entry.severity, string.format("[%s] %s: %s", entry.stack, entry.what, entry.detail),
      { path = short_path, subject = "sig:" .. entry.stack .. ":" .. entry.what,
        evidence = truncate(entry.detail, 90) })
    shown = shown + 1
  end
end

local function render_analysis(analysis)
  local lines = {}
  if analysis.suppressed then
    table.insert(lines, string.format("%-24s %s -> HTTP %s suppressed (%s)",
      analysis.trigger, truncate(analysis.path, 60), tostring(analysis.status), analysis.suppressed))
    return lines
  end
  if #analysis.matches == 0 and #analysis.paths == 0 and #analysis.consoles == 0
    and #analysis.sql == 0 and #analysis.environment == 0 and #analysis.versions == 0
    and #analysis.ips == 0 and #analysis.hosts == 0 then
    table.insert(lines, string.format("%-24s %s -> HTTP %s, %d bytes: no internal detail disclosed",
      analysis.trigger, truncate(analysis.path, 60), tostring(analysis.status),
      analysis.length or 0))
    return lines
  end

  table.insert(lines, string.format("%-24s %s -> HTTP %s, %d bytes, worst %s",
    analysis.trigger, truncate(analysis.path, 60), tostring(analysis.status),
    analysis.length or 0, tostring(analysis.worst)))
  for _, entry in ipairs(analysis.consoles) do
    table.insert(lines, string.format("      [%s] console/diagnostic: %s - %s",
      entry.severity, entry.product, entry.note))
  end
  for _, statement in ipairs(analysis.sql) do
    table.insert(lines, "      [CRITICAL] SQL: " .. truncate(statement.statement, 110))
  end
  for _, entry in ipairs(analysis.matches) do
    table.insert(lines, string.format("      [%s] %s: %s (%s)", entry.severity, entry.stack,
      entry.what, entry.detail))
  end
  for _, entry in ipairs(analysis.paths) do
    table.insert(lines, string.format("      path (%s): %s", entry.kind, truncate(entry.path, 100)))
  end
  for _, entry in ipairs(analysis.ips) do
    table.insert(lines, "      private IP: " .. entry.ip)
  end
  for _, host in ipairs(analysis.hosts) do
    table.insert(lines, "      internal host: " .. host)
  end
  for _, entry in ipairs(analysis.versions) do
    table.insert(lines, string.format("      version: %s %s", entry.product, entry.version))
  end
  for _, label in ipairs(analysis.environment) do
    table.insert(lines, "      environment: " .. label)
  end
  table.insert(lines, "      evidence: " .. truncate(analysis.sample, 120))
  return lines
end

local function aggregate(analyses)
  local stacks = {}
  local consoles = {}
  local paths = {}
  local ips = {}
  local hosts = {}
  local versions = {}
  local environment = {}
  local sql_count = 0
  local disclosing = 0
  local suppressed = 0
  local clean = 0

  for _, analysis in ipairs(analyses) do
    if analysis.suppressed then
      suppressed = suppressed + 1
      goto continue
    end
    local disclosed = false
    for stack in pairs(analysis.stacks or {}) do
      stacks[stack] = (stacks[stack] or 0) + 1
      disclosed = true
    end
    for _, entry in ipairs(analysis.consoles or {}) do
      consoles[entry.product] = (consoles[entry.product] or 0) + 1
      disclosed = true
    end
    for _, entry in ipairs(analysis.paths or {}) do
      paths[entry.path] = entry.kind
      disclosed = true
    end
    for _, entry in ipairs(analysis.ips or {}) do
      ips[entry.ip] = true
      disclosed = true
    end
    for _, host in ipairs(analysis.hosts or {}) do
      hosts[host] = true
      disclosed = true
    end
    for _, entry in ipairs(analysis.versions or {}) do
      versions[entry.product .. " " .. entry.version] = true
      disclosed = true
    end
    for _, label in ipairs(analysis.environment or {}) do
      environment[label] = true
      disclosed = true
    end
    sql_count = sql_count + #(analysis.sql or {})
    if disclosed or sql_count > 0 then
      disclosing = disclosing + 1
    else
      clean = clean + 1
    end
    ::continue::
  end

  return {
    stacks = stacks,
    consoles = consoles,
    paths = paths,
    ips = ips,
    hosts = hosts,
    versions = versions,
    environment = environment,
    sql_count = sql_count,
    disclosing = disclosing,
    suppressed = suppressed,
    clean = clean,
  }
end

local function render_aggregate(agg)
  local lines = {}
  table.insert(lines, string.format(
    "disclosing responses: %d, clean responses: %d, suppressed: %d, SQL statements printed: %d",
    agg.disclosing, agg.clean, agg.suppressed, agg.sql_count))
  local stack_parts = {}
  for _, name in ipairs(sorted_keys(agg.stacks)) do
    table.insert(stack_parts, string.format("%s=%d", name, agg.stacks[name]))
  end
  if #stack_parts > 0 then
    table.insert(lines, "stacks identified: " .. table.concat(stack_parts, ", "))
  end
  if table_size(agg.consoles) > 0 then
    local parts = {}
    for _, name in ipairs(sorted_keys(agg.consoles)) do
      table.insert(parts, name)
    end
    table.insert(lines, "debug/diagnostic surfaces: " .. table.concat(parts, ", "))
  end
  if table_size(agg.versions) > 0 then
    local parts = {}
    for _, name in ipairs(sorted_keys(agg.versions)) do
      table.insert(parts, name)
    end
    table.insert(lines, "versions printed: " .. table.concat(parts, ", "))
  end
  return lines
end

local function select_base_paths(args)
  local selected = {}
  local seen = {}
  for _, candidate in ipairs(args.paths or BASE_PATHS) do
    local normalized = trim(candidate)
    if #normalized == 0 then
      normalized = "/"
    end
    if not starts_with(normalized, "/") then
      normalized = "/" .. normalized
    end
    if unique_append(selected, seen, normalized) and #selected >= args.maxpaths then
      break
    end
  end
  if #selected == 0 then
    table.insert(selected, "/")
  end
  return selected
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local baseline = build_soft404_baseline(host, port, args)
  local base_paths = select_base_paths(args)
  local triggers = build_trigger_list(args)
  local raw_triggers = build_raw_triggers(args)

  local analyses = {}
  local suppressed_count = 0

  for _, base in ipairs(base_paths) do
    if budget_exhausted(args) then
      break
    end
    local base_response, base_err = fetch(host, port, base, args)
    if not base_response then
      table.insert(analyses, { trigger = "baseline", path = base, status = 0,
        matches = {}, consoles = {}, paths = {}, ips = {}, hosts = {}, versions = {},
        environment = {}, sql = {}, stacks = {}, worst = "INFO",
        sample = "baseline request failed: " .. tostring(base_err), suppressed = tostring(base_err) })
      goto continue_base
    end

    local base_analysis = analyse_body("baseline", base, base_response, baseline)
    if base_analysis then
      base_analysis.baseline = true
      table.insert(analyses, base_analysis)
      report_analysis(base_analysis)
    end

    ::continue_base::
  end

  for _, trigger in ipairs(triggers) do
    if budget_exhausted(args) then
      break
    end

    local target = trigger.path
    if trigger.kind == "post" then
      local body = trigger.name == "invalid-json" and '{"nse": ' or "{}"
      local response, err = fetch(host, port, target, args,
        { ["Content-Type"] = "application/json" }, "POST")
      if response then
        local analysis = analyse_body(trigger.name, target, response, baseline)
        if analysis then
          analysis.body_sent = body
          table.insert(analyses, analysis)
          report_analysis(analysis)
        end
      else
        table.insert(analyses, { trigger = trigger.name, path = target, status = 0,
          matches = {}, consoles = {}, paths = {}, ips = {}, hosts = {}, versions = {},
          environment = {}, sql = {}, stacks = {}, worst = "INFO",
          sample = "request failed: " .. tostring(err), suppressed = tostring(err) })
      end
      goto continue_trigger
    end

    local extra = {}
    if trigger.kind == "postxml" then
      extra["Content-Type"] = "application/xml"
    elseif trigger.name == "content-type-json" then
      extra["Content-Type"] = "application/json"
      extra["Accept"] = "application/json"
    end

    local response, err = fetch(host, port, target, args, extra,
      trigger.kind == "postxml" and "POST" or "GET")
    if not response then
      table.insert(analyses, { trigger = trigger.name, path = target, status = 0,
        matches = {}, consoles = {}, paths = {}, ips = {}, hosts = {}, versions = {},
        environment = {}, sql = {}, stacks = {}, worst = "INFO",
        sample = "request failed: " .. tostring(err), suppressed = tostring(err) })
      goto continue_trigger
    end

    local analysis = analyse_body(trigger.name, target, response, baseline)
    if analysis then
      if analysis.suppressed then
        suppressed_count = suppressed_count + 1
      end
      table.insert(analyses, analysis)
      report_analysis(analysis)
    end

    ::continue_trigger::
  end

  for _, trigger in ipairs(raw_triggers) do
    if budget_exhausted(args) then
      break
    end
    local headers = {}
    for _, pair in ipairs(trigger.headers or {}) do
      table.insert(headers, { pair[1], pair[2] })
    end
    local response, err = raw_request(host, port, trigger.method, trigger.path, headers, args, trigger.body)
    if not response then
      table.insert(analyses, { trigger = "raw:" .. trigger.name, path = trigger.path, status = 0,
        matches = {}, consoles = {}, paths = {}, ips = {}, hosts = {}, versions = {},
        environment = {}, sql = {}, stacks = {}, worst = "INFO",
        sample = "raw request failed: " .. tostring(err), suppressed = tostring(err) })
      goto continue_raw
    end

    local synthetic = {
      status = response.status or 0,
      body = response.body or "",
      rawheader = response.rawheader or {},
      header = response.headers or {},
    }
    local analysis = analyse_body("raw:" .. trigger.name, trigger.path, synthetic, baseline)
    if analysis then
      if analysis.suppressed then
        suppressed_count = suppressed_count + 1
      end
      analysis.raw = true
      table.insert(analyses, analysis)
      report_analysis(analysis)
    end

    ::continue_raw::
  end

  local agg = aggregate(analyses)

  local detail_lines = {}
  for _, analysis in ipairs(analyses) do
    for _, line in ipairs(render_analysis(analysis)) do
      if #detail_lines < 240 then
        table.insert(detail_lines, line)
      end
    end
  end

  local path_lines = {}
  for _, name in ipairs(sorted_keys(agg.paths)) do
    table.insert(path_lines, string.format("%s (%s)", truncate(name, 110), agg.paths[name]))
  end
  local ip_lines = {}
  for _, name in ipairs(sorted_keys(agg.ips)) do
    table.insert(ip_lines, name)
  end
  local host_lines = {}
  for _, name in ipairs(sorted_keys(agg.hosts)) do
    table.insert(host_lines, name)
  end
  local version_lines = {}
  for _, name in ipairs(sorted_keys(agg.versions)) do
    table.insert(version_lines, name)
  end
  local env_lines = {}
  for _, name in ipairs(sorted_keys(agg.environment)) do
    table.insert(env_lines, name)
  end
  local console_lines = {}
  for _, name in ipairs(sorted_keys(agg.consoles)) do
    table.insert(console_lines, string.format("%s (seen %d time(s))", name, agg.consoles[name]))
  end

  local unique, counts = dedupe_findings()

  local out = new_output(RISK_LEVEL, "AUDITED - error handling reviewed across "
    .. tostring(#analyses) .. " requests.")
  if counts.CRITICAL > 0 then
    out["Status"] = "VULNERABLE - error responses disclose critical internals (debug console, SQL or environment)."
  elseif counts.HIGH > 0 then
    out["Status"] = "VULNERABLE - error responses disclose stack traces or environment material."
  elseif counts.MEDIUM > 0 then
    out["Status"] = "AUDITED - error responses disclose file system paths, versions or internal hosts."
  elseif counts.LOW > 0 then
    out["Status"] = "AUDITED - only low-impact stack identity details are disclosed."
  elseif agg.disclosing == 0 then
    out["Status"] = "AUDITED - every error response was generic; no internal detail disclosed."
  else
    out["Status"] = "AUDITED - no informational disclosure detected in the error responses."
  end

  local sections = {
    { key = "Transport", value = (port.ssl or (port.version and port.version.service_ssl)) and "HTTPS" or "HTTP" },
    { key = "Summary", value = render_aggregate(agg) },
    { key = "Triggers", value = #triggers .. " HTTP triggers + " .. #raw_triggers .. " raw-socket triggers" },
  }

  if #console_lines > 0 then
    table.insert(sections, { key = "Debug surfaces", value = console_lines })
  end
  if #version_lines > 0 then
    table.insert(sections, { key = "Versions disclosed", value = version_lines })
  end
  if #path_lines > 0 then
    table.insert(sections, { key = "File system paths", value = path_lines })
  end
  if #ip_lines > 0 or #host_lines > 0 then
    local net_lines = {}
    for _, line in ipairs(ip_lines) do
      table.insert(net_lines, "private IP " .. line)
    end
    for _, line in ipairs(host_lines) do
      table.insert(net_lines, "internal host " .. line)
    end
    table.insert(sections, { key = "Network disclosure", value = net_lines })
  end
  if #env_lines > 0 then
    table.insert(sections, { key = "Environment material", value = env_lines })
  end

  table.insert(sections, { key = "Per-trigger detail", value = detail_lines })

  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end
  if suppressed_count > 0 then
    table.insert(sections, { key = "Suppressed responses", value =
      suppressed_count .. " responses matched the catch-all/WAF baseline and were not counted as disclosure" })
  end

  if counts.CRITICAL > 0 or counts.HIGH > 0 then
    table.insert(sections, { key = "Remediation", value =
      "turn off debug output in production (display_errors=Off, APP_DEBUG=false, DEBUG=False, "
      .. "customErrors mode=RemoteOnly, server.error-pages, server.errorlog without browser echo), "
      .. "attach a generic error handler that logs internally and returns a stable message, and never "
      .. "ship a debugger console or diagnostic page on a public listener" })
  elseif counts.MEDIUM > 0 then
    table.insert(sections, { key = "Remediation", value =
      "suppress absolute paths, private addresses and version tokens from error output; normalise the "
      .. "error body so a 500 and a 404 are indistinguishable to an unauthenticated client" })
  else
    table.insert(sections, { key = "Remediation", value =
      "error handling is already generic - keep it that way: verify after every framework upgrade that "
      .. "the default debug page is not restored, and keep server-side logging detailed while the "
      .. "client-side message stays stable" })
  end

  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  return finish_output(out, unique, counts, sections)

end
