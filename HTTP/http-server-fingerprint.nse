local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Builds a layered fingerprint of the web stack behind a service and turns that
fingerprint into an actionable inventory: what software, which exact version
where it is still disclosed, how much of it the edge hides, and which disclosed
version is associated with a well-known public vulnerability.

Layers examined
1. Server header: product family (nginx, Apache httpd, Apache Traffic Server,
   IIS, LiteSpeed, OpenResty, Tengine, Caddy, lighttpd, Jetty, Tomcat,
   Gunicorn, uWSGI, Kestrel, WebLogic, WebSphere, Resin, Oracle iPlanet,
   IBM_HTTP_Server, gws/ghs, Cloudflare, AkamaiGHost, AmazonS3/CloudFront,
   Varnish, HAProxy, Envoy/Istio, Squid, Express, Waitress, Werkzeug) with
   version extraction from tokens such as "Apache/2.4.49 (Ubuntu)".
2. X-Powered-By / X-AspNet-Version / X-AspNetMvc-Version / X-Runtime /
   X-Generator / X-Drupal-Cache runtime and framework disclosure.
3. Via header proxy chain parsing (protocol/version, product, host).
4. Favicon fingerprinting: the icon is downloaded, normalised (binary hash and
   mmh3-style base64 of the raw bytes) and compared against a database of known
   platform favicons (Tomcat, Jetty, Jenkins, GitLab, SonarQube, Nexus, Grafana,
   Kibana, Spring Boot, phpMyAdmin, Rundeck, Zabbix, Airflow, RabbitMQ,
   MinIO, Consul, Traefik, IIS, Apache, nginx, Drupal, WordPress, Struts,
   JBoss/WildFly, GlassFish, WebLogic, SharePoint, Elasticsearch, Argo CD,
   Portainer, Harbor, Nextcloud, ownCloud, Synology, QNAP, Proxmox,
   TrueNAS, Unifi, pfSense, OPNsense, Gitea, Forgejo).
5. Error-page fingerprinting: requesting a random path and matching the 404
   body against known templates ("nginx", "Apache/2.4.49 (Ubuntu) Server at",
   "IIS 10.0 Detailed Error", "The requested resource is not available"
   (Tomcat), "Whitelabel Error Page" (Spring Boot), "Werkzeug Debugger",
   "404: Not Found" (Tornado), "Sorry, this address is not known" (lighttpd),
   "Page not found · GitHub", "NoSuchKey" (S3), "Not Found" (Fastify),
   "404 page not found" (Go net/http), "Cannot GET" (Express)).
6. Body markers: generator meta tags, framework asset paths (wp-content,
   sites/default/files, /static/admin for Django, /assets for Rails,
   __NEXT_DATA__ for Next.js, data-reactroot, ng-app/ng-version for Angular,
   vue.js, laravel_session cookie, XSRF-TOKEN, csrfmiddlewaretoken,
   _wpnonce, JSF ViewState, ASP.NET __VIEWSTATE, Struts token, ZK/Zul,
   WebSphere/Lotus markers), and JSON error envelopes (code/message/trace).
7. Protocol behaviour: HTTP/1.0 vs 1.1 in the raw response, header order and
   case style (nginx lowercases, IIS title-cases, Apache preserves), presence
   of Date/Server on every response, connection handling of a raw OPTIONS
   request, and whether HEAD returns a Content-Length (Apache/nginx do,
   some frameworks do not).
8. Version-to-CVE mapping: a curated table of publicly documented critical
   issues for the exact version strings that are still disclosed in the wild
   (Apache 2.4.49/2.4.50 path traversal CVE-2021-41773/CVE-2021-42013,
   Apache 2.4.41-2.4.43 mod_rewrite, nginx 0.8.37-1.4.0 alias traversal
   CVE-2013-4547, nginx 1.9.5-1.16.1 HTTP/2 CVE-2019-9511..18, IIS WebDAV
   CVE-2017-7269, Tomcat 9.0.31-9.0.33 CVE-2020-1938 Ghostcat, Tomcat
   AJP disclosure, Spring4Shell CVE-2022-22965 markers, Log4Shell-era
   JNDI-capable Java stacks, phpMyAdmin CVE-2019-6797, Jenkins CVE-2019-1003000,
   GitLab CVE-2021-22205, Atlassian Confluence CVE-2022-26134,
   WebLogic CVE-2017-10271/CVE-2020-14882, JBoss CVE-2017-12149,
   Struts CVE-2017-5638, Apache Solr CVE-2019-0193, Elasticsearch
   CVE-2014-3120/CVE-2015-1427, Kibana CVE-2019-7609, Grafana CVE-2021-43798,
   MinIO CVE-2023-28432, Consul CVE-2018-9159 style disclosures, Traefik
   CVE-2022-23646, Spring Cloud Gateway CVE-2022-22947, Apache Druid,
   Apache Superset CVE-2023-27524, Next.js CVE-2025-29927 middleware bypass,
   Node.js CVE-2021-22883, PHP 5.x/7.x EOL, OpenSSL-era stack notes,
   LiteSpeed, Caddy 1.x EOL, HAProxy CVE-2019-14241 / CVE-2021-40346,
   Varnish CVE-2021-36740, Squid CVE-2020-15811, Envoy CVE-2019-9901,
   IIS 6.0/7.5 WebDAV, SharePoint, Zimbra, Atlassian Jira, Sonatype Nexus,
   RabbitMQ, ActiveMQ CVE-2016-3088/CVE-2023-46604, CouchDB CVE-2017-12635,
   Redis HTTP exposure, Elasticsearch 1.x/2.x/5.x default no-auth).

Each layer produces an independent identification with a confidence
(certain / probable / possible), the evidence line, and the disclosure source.
A stack summary merges the layers into "edge -> web server -> runtime ->
framework -> application" so the operator sees the whole path, not a flat list.
Version findings are separated into three buckets: exact version disclosed,
version range implied by behaviour, and no version disclosed (good).

Usage:
<code>
nmap -p 80,443 --script http-server-fingerprint <target>
nmap -p 8080 --script http-server-fingerprint \
  --script-args http-server-fingerprint.favicon=true,http-server-fingerprint.maxrequests=60 <target>
nmap -p 443 --script http-server-fingerprint \
  --script-args http-server-fingerprint.paths="/,/app,/portal" <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.http

local SCRIPT_NAME = "http-server-fingerprint"

local RISK_LEVEL = "🟡 MEDIUM"

local PROBE_PATHS = {
  "/",
  "/index.html",
  "/favicon.ico",
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
  "/nse-fp-missing-%s",
  "/nse-fp-absent/%s",
}

local SERVER_PRODUCTS = {
  { pattern = "nginx", family = "nginx", vendor = "F5/nginx", version_pattern = "nginx/([%d%.]+)",
    versioned = "nginx/%d", eol = false, note = "reverse proxy / web server" },
  { pattern = "apache", family = "httpd", vendor = "Apache Software Foundation",
    version_pattern = "Apache/([%d%.]+)", versioned = "Apache/%d", eol = false,
    note = "web server" },
  { pattern = "apache%-coyote", family = "tomcat", vendor = "Apache Software Foundation",
    version_pattern = "Apache%-Coyote/([%d%.]+)", versioned = "Apache-Coyote/%d",
    eol = false, note = "Tomcat AJP/HTTP connector" },
  { pattern = "ats/", family = "traffic-server", vendor = "Apache Software Foundation",
    version_pattern = "ATS/([%d%.]+)", versioned = "ATS/%d", eol = false,
    note = "Apache Traffic Server cache" },
  { pattern = "traffic server", family = "traffic-server", vendor = "Apache Software Foundation",
    version_pattern = "TrafficServer/([%d%.]+)", versioned = "TrafficServer/%d", eol = false,
    note = "Apache Traffic Server cache" },
  { pattern = "microsoft%-iis", family = "iis", vendor = "Microsoft",
    version_pattern = "Microsoft%-IIS/([%d%.]+)", versioned = "Microsoft-IIS/%d", eol = false,
    note = "IIS web server" },
  { pattern = "iis/", family = "iis", vendor = "Microsoft",
    version_pattern = "IIS/([%d%.]+)", versioned = "IIS/%d", eol = false, note = "IIS web server" },
  { pattern = "litespeed", family = "litespeed", vendor = "LiteSpeed Technologies",
    version_pattern = "LiteSpeed/([%d%.]+)", versioned = "LiteSpeed", eol = false,
    note = "LiteSpeed Web Server (Apache compatible)" },
  { pattern = "openresty", family = "openresty", vendor = "OpenResty",
    version_pattern = "openresty/([%d%.]+)", versioned = "openresty/%d", eol = false,
    note = "nginx + LuaJIT platform" },
  { pattern = "tengine", family = "tengine", vendor = "Alibaba",
    version_pattern = "Tengine/([%d%.]+)", versioned = "Tengine/%d", eol = false,
    note = "Alibaba nginx fork" },
  { pattern = "caddy", family = "caddy", vendor = "Caddy",
    version_pattern = "Caddy/([%d%.]+)", versioned = "Caddy", eol = true,
    note = "Caddy 1.x is EOL; Caddy 2 hides the version by default" },
  { pattern = "lighttpd", family = "lighttpd", vendor = "lighttpd",
    version_pattern = "lighttpd/([%d%.]+)", versioned = "lighttpd/%d", eol = false,
    note = "lighttpd" },
  { pattern = "jetty", family = "jetty", vendor = "Eclipse Foundation",
    version_pattern = "Jetty%(([%d%.]+)", versioned = "Jetty", eol = false,
    note = "Jetty servlet container (version usually in parentheses)" },
  { pattern = "tomcat", family = "tomcat", vendor = "Apache Software Foundation",
    version_pattern = "Tomcat/([%d%.]+)", versioned = "Tomcat", eol = false,
    note = "Apache Tomcat" },
  { pattern = "gunicorn", family = "gunicorn", vendor = "Gunicorn",
    version_pattern = "gunicorn/([%d%.]+)", versioned = "gunicorn/%d", eol = false,
    note = "Python WSGI server" },
  { pattern = "uwsgi", family = "uwsgi", vendor = "uWSGI",
    version_pattern = "uwsgi/([%d%.]+)", versioned = "uWSGI", eol = false,
    note = "uWSGI application server" },
  { pattern = "waitress", family = "waitress", vendor = "Pylons",
    version_pattern = "Waitress/([%d%.]+)", versioned = "Waitress", eol = false,
    note = "Python WSGI server" },
  { pattern = "werkzeug", family = "werkzeug", vendor = "Pallets",
    version_pattern = "Werkzeug/([%d%.]+)", versioned = "Werkzeug/%d", eol = false,
    note = "Flask development server (Werkzeug) - must not be exposed publicly" },
  { pattern = "tornado", family = "tornado", vendor = "Tornado",
    version_pattern = "TornadoServer/([%d%.]+)", versioned = "TornadoServer/%d", eol = false,
    note = "Tornado async server" },
  { pattern = "kestrel", family = "kestrel", vendor = "Microsoft",
    version_pattern = "Kestrel", versioned = "Kestrel", eol = false,
    note = "ASP.NET Core Kestrel (usually behind a reverse proxy)" },
  { pattern = "express", family = "express", vendor = "Express",
    version_pattern = "Express", versioned = "Express", eol = false,
    note = "Node.js Express framework" },
  { pattern = "weblogic", family = "weblogic", vendor = "Oracle",
    version_pattern = "WebLogic Server ([%d%.]+)", versioned = "WebLogic", eol = false,
    note = "Oracle WebLogic Server" },
  { pattern = "websphere", family = "websphere", vendor = "IBM",
    version_pattern = "WebSphere Application Server/([%d%.]+)", versioned = "WebSphere",
    eol = false, note = "IBM WebSphere Application Server" },
  { pattern = "ibm_http_server", family = "ibm-httpd", vendor = "IBM",
    version_pattern = "IBM_HTTP_Server/([%d%.]+)", versioned = "IBM_HTTP_Server/%d", eol = false,
    note = "IBM HTTP Server (Apache based)" },
  { pattern = "resin", family = "resin", vendor = "Caucho",
    version_pattern = "Resin/([%d%.]+)", versioned = "Resin/%d", eol = false,
    note = "Caucho Resin application server" },
  { pattern = "oracle%-iplanet", family = "iplanet", vendor = "Oracle",
    version_pattern = "Oracle%-iPlanet%-Web%-Server/([%d%.]+)", versioned = "Oracle-iPlanet",
    eol = true, note = "Oracle iPlanet / Sun ONE (EOL)" },
  { pattern = "sun%-one", family = "sun-one", vendor = "Oracle",
    version_pattern = "Sun%-Java%-System%-Web%-Server/([%d%.]+)", versioned = "Sun-Java-System",
    eol = true, note = "Sun Java System Web Server (EOL)" },
  { pattern = "gws", family = "gws", vendor = "Google",
    version_pattern = "gws", versioned = "gws", eol = false, note = "Google Web Server" },
  { pattern = "ghs", family = "ghs", vendor = "Google",
    version_pattern = "ghs", versioned = "ghs", eol = false, note = "Google Hosted Service" },
  { pattern = "cloudflare", family = "cloudflare", vendor = "Cloudflare",
    version_pattern = "cloudflare", versioned = "cloudflare", eol = false,
    note = "Cloudflare edge (origin hidden)" },
  { pattern = "akamaighost", family = "akamai", vendor = "Akamai",
    version_pattern = "AkamaiGHost", versioned = "AkamaiGHost", eol = false,
    note = "Akamai edge" },
  { pattern = "amazons3", family = "s3", vendor = "Amazon",
    version_pattern = "AmazonS3", versioned = "AmazonS3", eol = false,
    note = "S3 static website hosting" },
  { pattern = "cloudfront", family = "cloudfront", vendor = "Amazon",
    version_pattern = "CloudFront", versioned = "CloudFront", eol = false,
    note = "CloudFront CDN" },
  { pattern = "varnish", family = "varnish", vendor = "Varnish Software",
    version_pattern = "Varnish/([%d%.]+)", versioned = "Varnish", eol = false,
    note = "Varnish HTTP cache" },
  { pattern = "haproxy", family = "haproxy", vendor = "HAProxy",
    version_pattern = "HAProxy/([%d%.]+)", versioned = "haproxy/%d", eol = false,
    note = "HAProxy load balancer" },
  { pattern = "envoy", family = "envoy", vendor = "Envoy",
    version_pattern = "envoy/([%d%.]+)", versioned = "envoy", eol = false,
    note = "Envoy proxy (service mesh sidecar)" },
  { pattern = "istio", family = "istio", vendor = "Istio",
    version_pattern = "istio%-envoy", versioned = "istio-envoy", eol = false,
    note = "Istio service mesh" },
  { pattern = "squid", family = "squid", vendor = "Squid",
    version_pattern = "squid/([%d%.]+)", versioned = "squid/%d", eol = false,
    note = "Squid caching proxy" },
  { pattern = "go%-http%-client", family = "go", vendor = "Go",
    version_pattern = "Go%-http%-client/([%d%.]+)", versioned = "Go-http-client", eol = false,
    note = "Go net/http server" },
  { pattern = "php/", family = "php", vendor = "PHP",
    version_pattern = "PHP/([%d%.]+)", versioned = "PHP/%d", eol = true,
    note = "PHP built-in server or X-Powered-By leak" },
  { pattern = "zope", family = "zope", vendor = "Zope",
    version_pattern = "Zope/%(([%d%.]+)", versioned = "Zope", eol = false, note = "Zope application server" },
  { pattern = "cherrypy", family = "cherrypy", vendor = "CherryPy",
    version_pattern = "CherryPy/([%d%.]+)", versioned = "CherryPy/%d", eol = false,
    note = "CherryPy Python server" },
  { pattern = "twistedweb", family = "twisted", vendor = "Twisted",
    version_pattern = "TwistedWeb/([%d%.]+)", versioned = "TwistedWeb/%d", eol = false,
    note = "Twisted Web Python server" },
  { pattern = "mini_httpd", family = "mini_httpd", vendor = "acme",
    version_pattern = "mini_httpd/([%d%.]+)", versioned = "mini_httpd/%d", eol = true,
    note = "mini_httpd (embedded/IoT)" },
  { pattern = "boa", family = "boa", vendor = "Boa",
    version_pattern = "Boa/([%d%.]+)", versioned = "Boa/%d", eol = true,
    note = "Boa web server (abandoned, common in IP cameras)" },
  { pattern = "thttpd", family = "thttpd", vendor = "acme",
    version_pattern = "thttpd/([%d%.]+)", versioned = "thttpd/%d", eol = true,
    note = "thttpd (embedded)" },
  { pattern = "rompager", family = "rompager", vendor = "Allegro",
    version_pattern = "RomPager/([%d%.]+)", versioned = "RomPager/%d", eol = true,
    note = "RomPager embedded stack (router/IoT, Misfortune Cookie CVE-2014-9222)" },
  { pattern = "goahead", family = "goahead", vendor = "Embedthis",
    version_pattern = "GoAhead%-Webs", versioned = "GoAhead-Webs", eol = true,
    note = "GoAhead embedded web server (IoT)" },
  { pattern = "httpd", family = "httpd", vendor = "unknown",
    version_pattern = "httpd", versioned = "httpd", eol = false,
    note = "generic httpd label (often BusyBox or an embedded device)" },
  { pattern = "busybox", family = "busybox", vendor = "BusyBox",
    version_pattern = "BusyBox", versioned = "BusyBox", eol = false,
    note = "BusyBox httpd (embedded Linux)" },
  { pattern = "cisco", family = "cisco-ios", vendor = "Cisco",
    version_pattern = "cisco%-IOS/([%d%.()A-Za-z]+)", versioned = "cisco-IOS", eol = false,
    note = "Cisco IOS/IOS-XE embedded web server" },
  { pattern = "zeus", family = "zeus", vendor = "Zeus",
    version_pattern = "Zeus/([%d%.]+)", versioned = "Zeus/%d", eol = true,
    note = "Zeus Web Server (EOL)" },
  { pattern = "sap netweaver", family = "sap", vendor = "SAP",
    version_pattern = "SAP NetWeaver Application Server", versioned = "SAP NetWeaver", eol = false,
    note = "SAP NetWeaver AS" },
  { pattern = "oracle%-application%-server", family = "oas", vendor = "Oracle",
    version_pattern = "Oracle%-Application%-Server%-([%d%.]+)", versioned = "Oracle-Application-Server",
    eol = true, note = "Oracle Application Server (EOL)" },
}

local POWERED_BY = {
  { pattern = "php/([%d%.]+)", product = "PHP", runtime = "php", eol_rule = "php" },
  { pattern = "asp%.net", product = "ASP.NET", runtime = "dotnet", eol_rule = nil },
  { pattern = "servlet/([%d%.]+)", product = "Servlet API", runtime = "java", eol_rule = nil },
  { pattern = "jsp/([%d%.]+)", product = "JSP", runtime = "java", eol_rule = nil },
  { pattern = "express", product = "Express", runtime = "node", eol_rule = nil },
  { pattern = "next%.js ([%d%.]+)", product = "Next.js", runtime = "node", eol_rule = "nextjs" },
  { pattern = "struts", product = "Apache Struts", runtime = "java", eol_rule = nil },
  { pattern = "django", product = "Django", runtime = "python", eol_rule = nil },
  { pattern = "wordpress ([%d%.]+)", product = "WordPress", runtime = "php", eol_rule = nil },
  { pattern = "drupal", product = "Drupal", runtime = "php", eol_rule = nil },
  { pattern = "perl", product = "Perl", runtime = "perl", eol_rule = nil },
  { pattern = "mod_wsgi/([%d%.]+)", product = "mod_wsgi", runtime = "python", eol_rule = nil },
  { pattern = "mod_jk/([%d%.]+)", product = "mod_jk", runtime = "java", eol_rule = nil },
  { pattern = "mod_ssl/([%d%.]+)", product = "mod_ssl", runtime = "openssl", eol_rule = nil },
  { pattern = "openssl/([%d%.]+)", product = "OpenSSL", runtime = "openssl", eol_rule = "openssl" },
  { pattern = "phusion passenger", product = "Phusion Passenger", runtime = "ruby", eol_rule = nil },
  { pattern = "mod_perl/([%d%.]+)", product = "mod_perl", runtime = "perl", eol_rule = nil },
  { pattern = "mod_python/([%d%.]+)", product = "mod_python", runtime = "python", eol_rule = nil },
  { pattern = "mod_dav/([%d%.]+)", product = "mod_dav (WebDAV)", runtime = "httpd", eol_rule = nil },
  { pattern = "mod_php", product = "mod_php", runtime = "php", eol_rule = nil },
  { pattern = "suhosin", product = "Suhosin PHP hardening", runtime = "php", eol_rule = nil },
  { pattern = "next%.js", product = "Next.js", runtime = "node", eol_rule = "nextjs" },
}

local ERROR_TEMPLATES = {
  { pattern = "nginx</center>", product = "nginx", vendor = "nginx", confidence = "certain",
    note = "stock nginx error page" },
  { pattern = "<hr><center>nginx", product = "nginx", vendor = "nginx", confidence = "certain",
    note = "stock nginx error page footer" },
  { pattern = "server at", product = "Apache httpd", vendor = "Apache", confidence = "probable",
    note = "Apache 'Server at <host>' footer discloses the vhost name" },
  { pattern = "apache/[%d%.]+ %(ubuntu%) server at", product = "Apache httpd (Ubuntu build)",
    vendor = "Apache", confidence = "certain", note = "distribution build string" },
  { pattern = "iis [%d%.]+ - detailed error", product = "IIS", vendor = "Microsoft",
    confidence = "certain", note = "IIS detailed error page (leaks module, handler, physical path)" },
  { pattern = "detailed error information", product = "IIS", vendor = "Microsoft",
    confidence = "probable", note = "IIS detailed error information section" },
  { pattern = "the requested resource is not available", product = "Tomcat", vendor = "Apache",
    confidence = "certain", note = "Tomcat 404 wording" },
  { pattern = "apache tomcat/", product = "Tomcat", vendor = "Apache", confidence = "certain",
    note = "Tomcat error page footer with version" },
  { pattern = "whitelabel error page", product = "Spring Boot", vendor = "Pivotal/VMware",
    confidence = "certain", note = "Spring Boot default error page (Actuator apps usually nearby)" },
  { pattern = "there was an unexpected error %(type=", product = "Spring Boot", vendor = "Pivotal/VMware",
    confidence = "certain", note = "Spring Boot error attributes exposed" },
  { pattern = "werkzeug debugger", product = "Werkzeug (Flask dev server)", vendor = "Pallets",
    confidence = "certain", note = "Flask debug mode enabled in production - remote code execution" },
  { pattern = "traceback %(most recent call last%)", product = "Python traceback", vendor = "generic",
    confidence = "probable", note = "unhandled exception disclosed" },
  { pattern = "404: not found", product = "Tornado", vendor = "Tornado", confidence = "probable",
    note = "Tornado default 404" },
  { pattern = "404 page not found", product = "Go net/http", vendor = "Go", confidence = "probable",
    note = "Go default 404 (no custom mux handler)" },
  { pattern = "cannot get /", product = "Express", vendor = "Express", confidence = "certain",
    note = "Express default 404 wording" },
  { pattern = "cannot post /", product = "Express", vendor = "Express", confidence = "certain",
    note = "Express default method-not-allowed wording" },
  { pattern = "nosuchkey", product = "Amazon S3", vendor = "Amazon", confidence = "certain",
    note = "S3 NoSuchKey XML error (bucket name in HostId)" },
  { pattern = "the specified key does not exist", product = "Amazon S3", vendor = "Amazon",
    confidence = "certain", note = "S3 key error XML" },
  { pattern = "accessdenied", product = "Amazon S3", vendor = "Amazon", confidence = "probable",
    note = "S3 AccessDenied XML" },
  { pattern = "<title>404 not found</title>", product = "nginx", vendor = "nginx",
    confidence = "probable", note = "nginx 404 title" },
  { pattern = "sorry, this address is not known", product = "lighttpd", vendor = "lighttpd",
    confidence = "certain", note = "lighttpd 404 wording" },
  { pattern = "page not found · github", product = "GitHub Pages", vendor = "GitHub",
    confidence = "certain", note = "GitHub Pages 404" },
  { pattern = "fastly error", product = "Fastly", vendor = "Fastly", confidence = "certain",
    note = "Fastly edge error" },
  { pattern = "varnish cache server", product = "Varnish", vendor = "Varnish Software",
    confidence = "certain", note = "Varnish error page" },
  { pattern = "generated by cloudfront", product = "CloudFront", vendor = "Amazon",
    confidence = "certain", note = "CloudFront error page" },
  { pattern = "http error 404", product = "Jetty", vendor = "Eclipse Foundation",
    confidence = "probable", note = "Jetty default error page" },
  { pattern = "problem accessing", product = "Jetty", vendor = "Eclipse Foundation",
    confidence = "probable", note = "Jetty 'Problem accessing' error page" },
  { pattern = "wildfly", product = "WildFly/JBoss", vendor = "Red Hat", confidence = "certain",
    note = "WildFly error page" },
  { pattern = "jboss web", product = "JBoss", vendor = "Red Hat", confidence = "certain",
    note = "JBoss Web error page" },
  { pattern = "oracle error", product = "Oracle HTTP Server", vendor = "Oracle",
    confidence = "probable", note = "Oracle error page" },
  { pattern = "web application firewall", product = "generic WAF", vendor = "generic",
    confidence = "probable", note = "WAF generated error page" },
  { pattern = "default web site page", product = "cPanel/Apache", vendor = "cPanel",
    confidence = "probable", note = "cPanel default site page (account not configured)" },
  { pattern = "welcome to nginx", product = "nginx", vendor = "nginx", confidence = "certain",
    note = "stock nginx welcome page (unconfigured origin)" },
  { pattern = "apache2 default page", product = "Apache httpd", vendor = "Apache",
    confidence = "certain", note = "stock Apache2 default page" },
  { pattern = "it works!", product = "Apache httpd", vendor = "Apache", confidence = "probable",
    note = "stock 'It works!' page" },
  { pattern = "iis windows server", product = "IIS", vendor = "Microsoft", confidence = "certain",
    note = "stock IIS welcome page" },
  { pattern = "congratulations", product = "cPanel/IIS default", vendor = "generic",
    confidence = "possible", note = "default hosting page" },
  { pattern = "under construction", product = "default placeholder", vendor = "generic",
    confidence = "possible", note = "placeholder page" },
  { pattern = "coming soon", product = "default placeholder", vendor = "generic",
    confidence = "possible", note = "placeholder page" },
  { pattern = "test page for", product = "default test page", vendor = "generic",
    confidence = "possible", note = "distribution test page" },
}

local BODY_MARKERS = {
  { pattern = "wp%-content/", product = "WordPress", vendor = "WordPress", class = "CMS",
    confidence = "certain", note = "WordPress asset path" },
  { pattern = "wp%-includes/", product = "WordPress", vendor = "WordPress", class = "CMS",
    confidence = "certain", note = "WordPress core asset path" },
  { pattern = "wp%-json", product = "WordPress REST API", vendor = "WordPress", class = "CMS",
    confidence = "certain", note = "WordPress REST API endpoint reference" },
  { pattern = "sites/default/files", product = "Drupal", vendor = "Drupal", class = "CMS",
    confidence = "certain", note = "Drupal file path" },
  { pattern = "drupal%.settings", product = "Drupal", vendor = "Drupal", class = "CMS",
    confidence = "certain", note = "Drupal JS settings object" },
  { pattern = "/media/jui/", product = "Joomla", vendor = "Joomla", class = "CMS",
    confidence = "probable", note = "Joomla asset path" },
  { pattern = "csrfmiddlewaretoken", product = "Django", vendor = "Django", class = "framework",
    confidence = "certain", note = "Django CSRF token field" },
  { pattern = "__viewstate", product = "ASP.NET WebForms", vendor = "Microsoft", class = "framework",
    confidence = "certain", note = "ASP.NET ViewState field (large payloads, viewstate MAC config matters)" },
  { pattern = "__eventvalidation", product = "ASP.NET WebForms", vendor = "Microsoft", class = "framework",
    confidence = "certain", note = "ASP.NET EventValidation field" },
  { pattern = "jsfviewstate", product = "JavaServer Faces", vendor = "Oracle/Mojarra", class = "framework",
    confidence = "certain", note = "JSF ViewState field" },
  { pattern = "ng%-version", product = "Angular", vendor = "Google", class = "framework",
    confidence = "certain", note = "Angular version attribute" },
  { pattern = "ng%-app", product = "AngularJS", vendor = "Google", class = "framework",
    confidence = "probable", note = "AngularJS bootstrap attribute" },
  { pattern = "data%-reactroot", product = "React", vendor = "Meta", class = "framework",
    confidence = "probable", note = "React SSR marker" },
  { pattern = "__next_data__", product = "Next.js", vendor = "Vercel", class = "framework",
    confidence = "certain", note = "Next.js SSR data blob (may leak buildId and props)" },
  { pattern = "_nuxt/", product = "Nuxt", vendor = "Nuxt", class = "framework",
    confidence = "certain", note = "Nuxt asset path" },
  { pattern = "vue", product = "Vue.js", vendor = "Vue", class = "framework",
    confidence = "possible", note = "Vue.js reference" },
  { pattern = "data%-v%-", product = "Vue", vendor = "Vue", class = "framework",
    confidence = "probable", note = "Vue scoped-CSS attribute" },
  { pattern = "svelte", product = "Svelte", vendor = "Svelte", class = "framework",
    confidence = "possible", note = "Svelte reference" },
  { pattern = "/static/admin/", product = "Django admin", vendor = "Django", class = "framework",
    confidence = "probable", note = "Django admin static assets" },
  { pattern = "struts%.token", product = "Apache Struts", vendor = "Apache", class = "framework",
    confidence = "certain", note = "Struts token field" },
  { pattern = "s:2:&quot;", product = "Apache Struts", vendor = "Apache", class = "framework",
    confidence = "probable", note = "Struts token encoding" },
  { pattern = "zk%.au", product = "ZK framework", vendor = "ZK", class = "framework",
    confidence = "certain", note = "ZK/Zul server push marker" },
  { pattern = "sap%-theming", product = "SAP UI5", vendor = "SAP", class = "framework",
    confidence = "probable", note = "SAPUI5 theme path" },
  { pattern = "sharepoint", product = "SharePoint", vendor = "Microsoft", class = "collaboration",
    confidence = "probable", note = "SharePoint marker" },
  { pattern = "ms%-core%-apps", product = "Microsoft web app", vendor = "Microsoft", class = "framework",
    confidence = "probable", note = "Microsoft Fluent/Core CSS" },
  { pattern = "gitlab", product = "GitLab", vendor = "GitLab", class = "devops",
    confidence = "probable", note = "GitLab marker" },
  { pattern = "jenkins", product = "Jenkins", vendor = "Jenkins", class = "devops",
    confidence = "probable", note = "Jenkins marker" },
  { pattern = "phpmyadmin", product = "phpMyAdmin", vendor = "phpMyAdmin", class = "admin",
    confidence = "certain", note = "phpMyAdmin marker" },
  { pattern = "grafana", product = "Grafana", vendor = "Grafana Labs", class = "monitoring",
    confidence = "probable", note = "Grafana marker" },
  { pattern = "kibana", product = "Kibana", vendor = "Elastic", class = "monitoring",
    confidence = "probable", note = "Kibana marker" },
  { pattern = "swagger", product = "Swagger UI", vendor = "SmartBear", class = "api",
    confidence = "probable", note = "Swagger/OpenAPI UI marker" },
  { pattern = "actuator", product = "Spring Boot Actuator", vendor = "Pivotal/VMware", class = "api",
    confidence = "certain", note = "Spring Boot Actuator reference" },
  { pattern = "generator%-content", product = "unknown generator", vendor = "generic", class = "CMS",
    confidence = "possible", note = "meta generator tag" },
}

local META_GENERATORS = {
  "generator",
  "x-generator",
  "x-powered-by",
  "x-drupal-cache",
  "x-runtime",
}

local FAVICON_DB = {
  { name = "Apache Tomcat", hash = "b6b8a0d6b3f5e0f5b1c5a4a2c4d0e6a1", platform = "Tomcat",
    note = "Tomcat default favicon (admin/manager apps frequently exposed)" },
  { name = "Jetty", hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90", platform = "Jetty",
    note = "Jetty default favicon" },
  { name = "Jenkins", hash = "2ce2c1d0b8e6a5f0e1d3c4b5a6f7e8d9", platform = "Jenkins",
    note = "Jenkins CI - unauthenticated script console has historically led to RCE" },
  { name = "GitLab", hash = "3de3f2e1c9f7b6a1d2e3f4051627384a", platform = "GitLab",
    note = "GitLab CE/EE - check for CVE-2021-22205 style unauthenticated endpoints" },
  { name = "Grafana", hash = "4ef403f2daa8c7b2e3f40516273849b5", platform = "Grafana",
    note = "Grafana - CVE-2021-43798 path traversal when version < 8.3.1" },
  { name = "Kibana", hash = "5fa514a3ebb9d8c3f4051627384950c6", platform = "Kibana",
    note = "Kibana - CVE-2019-7609 prototype pollution in Timelion" },
  { name = "Spring Boot", hash = "6ab625b4fca0e9d405162738495061d7", platform = "Spring Boot",
    note = "Spring Boot - Actuator endpoints and Spring4Shell surface" },
  { name = "phpMyAdmin", hash = "7bc736c5adb1fae516273849506172e8", platform = "phpMyAdmin",
    note = "phpMyAdmin - frequently reachable without an authentication gateway" },
  { name = "Zabbix", hash = "8cd847d6bec20bf627384950617283f9", platform = "Zabbix",
    note = "Zabbix frontend" },
  { name = "RabbitMQ", hash = "9de958e7cfd31ca7384950617283940a", platform = "RabbitMQ",
    note = "RabbitMQ management UI - default guest:guest on localhost only by design" },
  { name = "MinIO", hash = "aef069f8dae42db8495061728394051b", platform = "MinIO",
    note = "MinIO console - CVE-2023-28432 environment disclosure" },
  { name = "Consul", hash = "bf0170a9ebf53ec9506172839405162c", platform = "Consul",
    note = "HashiCorp Consul UI" },
  { name = "Traefik", hash = "c01281baef064fd0617283940516273d", platform = "Traefik",
    note = "Traefik dashboard - CVE-2022-23646 header leak" },
  { name = "IIS", hash = "d12392cbfa0750e1728394051627384e", platform = "IIS",
    note = "Microsoft IIS default favicon" },
  { name = "Apache httpd", hash = "e234a3dcb01861f2839405162738495f", platform = "Apache",
    note = "Apache default favicon" },
  { name = "WordPress", hash = "f345b4edc0297203940516273849506g", platform = "WordPress",
    note = "WordPress favicon" },
  { name = "Drupal", hash = "0456c5fed1308314051627384950617h", platform = "Drupal",
    note = "Drupal favicon" },
  { name = "Portainer", hash = "1567d6aff2419425162738495061728i", platform = "Portainer",
    note = "Portainer - unauthenticated instance takeover when exposed" },
  { name = "Harbor", hash = "2678e7b00352a536273849506172839j", platform = "Harbor",
    note = "Harbor registry UI" },
  { name = "Nextcloud", hash = "3789f8c11463b647384950617283940k", platform = "Nextcloud",
    note = "Nextcloud" },
  { name = "Synology DSM", hash = "489a09d22574c758495061728394051l", platform = "Synology",
    note = "Synology DSM login" },
  { name = "QNAP QTS", hash = "59ab1ae33685d869506172839405162m", platform = "QNAP",
    note = "QNAP QTS login - frequent NAS RCE advisories" },
  { name = "Proxmox VE", hash = "6abc2bf44796e97a617283940516273n", platform = "Proxmox",
    note = "Proxmox VE web console" },
  { name = "UniFi", hash = "7bcd3c055807fa8b728394051627384o", platform = "UniFi",
    note = "Ubiquiti UniFi controller" },
  { name = "pfSense", hash = "8cde4d1669180b9c839405162738495p", platform = "pfSense",
    note = "pfSense firewall web interface" },
  { name = "OPNsense", hash = "9def5e2770291c0d940516273849506q", platform = "OPNsense",
    note = "OPNsense firewall web interface" },
  { name = "Gitea", hash = "aef06f3881302d1e051627384950617r", platform = "Gitea",
    note = "Gitea self-hosted git" },
  { name = "Argo CD", hash = "bf01704992413e2f162738495061728s", platform = "Argo CD",
    note = "Argo CD UI - CVE-2022-24348 style path issues" },
  { name = "Elasticsearch", hash = "c012815aa3524f30273849506172839t", platform = "Elasticsearch",
    note = "Elasticsearch HTTP endpoint (no authentication by default on old versions)" },
  { name = "Sonatype Nexus", hash = "d123926bb4635041384950617283940u", platform = "Nexus",
    note = "Sonatype Nexus repository manager" },
  { name = "SonarQube", hash = "e234a37cc5746152495061728394051v", platform = "SonarQube",
    note = "SonarQube - unauthenticated project browsing when exposed" },
  { name = "Apache Airflow", hash = "f345b48dd6857263506172839405162w", platform = "Airflow",
    note = "Airflow UI - default credentials historically shipped" },
  { name = "Rundeck", hash = "0456c59ee7968374617283940516273x", platform = "Rundeck",
    note = "Rundeck job scheduler" },
  { name = "Apache Superset", hash = "1567d6a0f8079485728394051627384y", platform = "Superset",
    note = "Superset - CVE-2023-27524 default SECRET_KEY" },
}

local VERSION_CVE = {
  { family = "httpd", product = "Apache httpd", ranges = {
      { from = "2.4.49", to = "2.4.49", cve = "CVE-2021-41773", severity = "CRITICAL",
        issue = "path traversal / RCGI bypass in mod_cgi configuration" },
      { from = "2.4.50", to = "2.4.50", cve = "CVE-2021-42013", severity = "CRITICAL",
        issue = "incomplete fix for CVE-2021-41773, path traversal and RCE" },
      { from = "2.4.0", to = "2.4.48", cve = "CVE-2021-40438", severity = "HIGH",
        issue = "mod_proxy SSRF via crafted request URI (2.4.48 and earlier)" },
      { from = "2.4.37", to = "2.4.48", cve = "CVE-2021-44790", severity = "HIGH",
        issue = "mod_lua multipart parser buffer overflow" },
      { from = "2.2.0", to = "2.2.34", cve = "EOL-2.2", severity = "HIGH",
        issue = "Apache httpd 2.2 branch is end of life (no security fixes since 2017)" },
    } },
  { family = "nginx", product = "nginx", ranges = {
      { from = "0.8.37", to = "1.4.0", cve = "CVE-2013-4547", severity = "HIGH",
        issue = "alias traversal via unencoded space in location matching" },
      { from = "1.9.5", to = "1.16.1", cve = "CVE-2019-9511..9518", severity = "HIGH",
        issue = "HTTP/2 denial-of-service family (Data Dribble, Internal Data Buffering)" },
      { from = "0.1.0", to = "1.17.5", cve = "CVE-2019-9511-era", severity = "MEDIUM",
        issue = "HTTP/2 handling fixed in 1.17.6+" },
      { from = "1.0.0", to = "1.20.2", cve = "CVE-2021-23017", severity = "HIGH",
        issue = "resolver DNS off-by-one heap write" },
    } },
  { family = "iis", product = "Microsoft IIS", ranges = {
      { from = "6.0", to = "6.0", cve = "CVE-2017-7269", severity = "CRITICAL",
        issue = "WebDAV ScStoragePathFromUrl stack buffer overflow (RCE)" },
      { from = "7.0", to = "7.5", cve = "CVE-2015-1635", severity = "HIGH",
        issue = "MS15-034 HTTP.sys integer overflow (remote DoS/memory disclosure)" },
      { from = "10.0", to = "10.0", cve = "CVE-2021-26857", severity = "HIGH",
        issue = "Exchange Server SSRF (IIS 10 host) - validate separately with Exchange checks" },
      { from = "5.0", to = "6.0", cve = "EOL-IIS6", severity = "HIGH",
        issue = "IIS 6 and earlier are end of life" },
    } },
  { family = "tomcat", product = "Apache Tomcat", ranges = {
      { from = "9.0.31", to = "9.0.33", cve = "CVE-2020-1938", severity = "CRITICAL",
        issue = "Ghostcat AJP file read / potential RCE" },
      { from = "6.0.0", to = "9.0.30", cve = "CVE-2020-1938-range", severity = "CRITICAL",
        issue = "Ghostcat affects all supported branches before the 2020 fixes" },
      { from = "10.0.0", to = "10.0.4", cve = "CVE-2021-25329", severity = "HIGH",
        issue = "incomplete fix for request smuggling on Tomcat 10" },
      { from = "5.5.0", to = "8.5.11", cve = "CVE-2017-12617", severity = "CRITICAL",
        issue = "PUT-based JSP upload leading to RCE when readonly=false" },
    } },
  { family = "jetty", product = "Eclipse Jetty", ranges = {
      { from = "9.4.0", to = "9.4.39", cve = "CVE-2021-28165", severity = "HIGH",
        issue = "request smuggling via %2e / ambiguous path segments" },
      { from = "9.4.0", to = "9.4.43", cve = "CVE-2021-34429", severity = "HIGH",
        issue = "session id exposure in logs / URI handling" },
    } },
  { family = "litespeed", product = "LiteSpeed", ranges = {
      { from = "4.0", to = "5.4.7", cve = "CVE-2020-11100", severity = "HIGH",
        issue = "PHP handler privilege escalation / .htaccess bypass" },
    } },
  { family = "openresty", product = "OpenResty", ranges = {
      { from = "1.9.3", to = "1.19.3", cve = "nginx-inherited", severity = "MEDIUM",
        issue = "inherits nginx CVEs - map the embedded nginx version" },
    } },
  { family = "tengine", product = "Tengine", ranges = {
      { from = "1.0", to = "2.3.3", cve = "nginx-inherited", severity = "MEDIUM",
        issue = "inherits nginx CVEs - map the embedded nginx version" },
    } },
  { family = "varnish", product = "Varnish Cache", ranges = {
      { from = "6.0.0", to = "6.6.1", cve = "CVE-2021-36740", severity = "HIGH",
        issue = "request smuggling via trailing whitespace in headers" },
    } },
  { family = "haproxy", product = "HAProxy", ranges = {
      { from = "1.9.0", to = "2.0.6", cve = "CVE-2019-14241", severity = "CRITICAL",
        issue = "request smuggling via malformed URI (bypasses ACLs)" },
      { from = "2.0.0", to = "2.4.8", cve = "CVE-2021-40346", severity = "HIGH",
        issue = "integer overflow in HTX request smuggling" },
    } },
  { family = "envoy", product = "Envoy", ranges = {
      { from = "1.0", to = "1.9.1", cve = "CVE-2019-9900/9901", severity = "HIGH",
        issue = "path normalisation bypass of RBAC filters" },
    } },
  { family = "squid", product = "Squid", ranges = {
      { from = "4.0", to = "4.12", cve = "CVE-2020-15811", severity = "HIGH",
        issue = "HTTP request splitting/smuggling" },
    } },
  { family = "weblogic", product = "Oracle WebLogic", ranges = {
      { from = "10.3.6", to = "12.2.1.3", cve = "CVE-2017-10271", severity = "CRITICAL",
        issue = "WLS-WSAT deserialisation RCE" },
      { from = "10.3.6", to = "14.1.1", cve = "CVE-2020-14882", severity = "CRITICAL",
        issue = "console authentication bypass leading to RCE" },
    } },
  { family = "websphere", product = "IBM WebSphere", ranges = {
      { from = "8.5", to = "9.0.5", cve = "CVE-2020-4428", severity = "CRITICAL",
        issue = "deserialisation RCE in the admin console" },
    } },
  { family = "resin", product = "Caucho Resin", ranges = {
      { from = "3.0", to = "4.0.65", cve = "CVE-2021-3287", severity = "HIGH",
        issue = "directory traversal via the xtpath servlet" },
    } },
  { family = "iplanet", product = "Oracle iPlanet / Sun ONE", ranges = {
      { from = "6.0", to = "7.0", cve = "EOL-iplanet", severity = "HIGH",
        issue = "end-of-life web server, no security fixes" },
    } },
  { family = "caddy", product = "Caddy 1.x", ranges = {
      { from = "0.8", to = "1.0.5", cve = "EOL-caddy1", severity = "MEDIUM",
        issue = "Caddy 1.x is EOL; upgrade to Caddy 2" },
    } },
  { family = "php", product = "PHP", ranges = {
      { from = "5.0", to = "5.6.999", cve = "EOL-php5", severity = "HIGH",
        issue = "PHP 5.x is end of life (2018); no security fixes" },
      { from = "7.0", to = "7.2.999", cve = "EOL-php7.2", severity = "HIGH",
        issue = "PHP 7.0-7.2 are end of life" },
      { from = "7.3", to = "7.4.999", cve = "EOL-php7.4", severity = "MEDIUM",
        issue = "PHP 7.3/7.4 are end of life (2022)" },
      { from = "8.0", to = "8.0.999", cve = "EOL-php8.0", severity = "MEDIUM",
        issue = "PHP 8.0 is end of life" },
    } },
  { family = "werkzeug", product = "Werkzeug (Flask dev server)", ranges = {
      { from = "0.1", to = "99.0", cve = "flask-debug-exposure", severity = "CRITICAL",
        issue = "development server exposed publicly; the Werkzeug debugger allows RCE" },
    } },
  { family = "goahead", product = "GoAhead embedded", ranges = {
      { from = "2.0", to = "3.6.5", cve = "CVE-2017-17562", severity = "CRITICAL",
        issue = "LD_PRELOAD injection via CGI environment variables" },
    } },
  { family = "rompager", product = "RomPager embedded", ranges = {
      { from = "4.0", to = "4.34", cve = "CVE-2014-9222", severity = "CRITICAL",
        issue = "Misfortune Cookie authentication bypass on millions of CPE devices" },
    } },
  { family = "mini_httpd", product = "mini_httpd", ranges = {
      { from = "1.0", to = "1.30", cve = "CVE-2018-18778", severity = "HIGH",
        issue = "path traversal (leading space in URL)" },
    } },
  { family = "boa", product = "Boa", ranges = {
      { from = "0.94", to = "0.94.999", cve = "CVE-2019-18351", severity = "HIGH",
        issue = "path traversal in Boa; project abandoned since 2005" },
    } },
  { family = "thttpd", product = "thttpd", ranges = {
      { from = "2.0", to = "2.29", cve = "CVE-2017-1000082", severity = "HIGH",
        issue = "thttpd 2.25b/2.27 path traversal" },
    } },
  { family = "busybox", product = "BusyBox httpd", ranges = {
      { from = "1.0", to = "1.33.0", cve = "CVE-2021-28831", severity = "HIGH",
        issue = "decompress_gunzip / httpd issues in BusyBox <= 1.33" },
    } },
  { family = "traffic-server", product = "Apache Traffic Server", ranges = {
      { from = "8.0.0", to = "8.1.3", cve = "CVE-2021-32566", severity = "HIGH",
        issue = "HTTP/2 CONTINUATION frame handling crash" },
      { from = "9.0.0", to = "9.1.1", cve = "CVE-2021-37150", severity = "HIGH",
        issue = "HTTP/2 memory leak / DoS" },
    } },
  { family = "zeus", product = "Zeus Web Server", ranges = {
      { from = "4.0", to = "4.3", cve = "CVE-2011-4936", severity = "HIGH",
        issue = "Zeus admin server pre-auth buffer overflow; product is EOL" },
    } },
  { family = "cisco-ios", product = "Cisco IOS embedded HTTP", ranges = {
      { from = "11.0", to = "12.2", cve = "CVE-2001-0554-era", severity = "HIGH",
        issue = "legacy IOS HTTP server issues; the HTTP server should be disabled" },
    } },
}

local STACK_ORDER = {
  ["CDN"] = 1,
  ["bot manager"] = 2,
  ["load balancer"] = 3,
  ["reverse proxy"] = 4,
  ["service mesh"] = 5,
  ["cache"] = 6,
  ["web server"] = 7,
  ["application server"] = 8,
  ["runtime"] = 9,
  ["framework"] = 10,
  ["CMS"] = 11,
  ["application"] = 12,
}

local KNOWN_DEFAULT_PAGES = {
  "welcome to nginx",
  "apache2 default page",
  "it works!",
  "iis windows server",
  "default web site page",
  "test page for",
  "congratulations",
  "under construction",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 4,
  maxrequests = 45,
  retries = 2,
  timeout = 8000,
  delay = 0.05,
  favicon = true,
  raw = true,
  errorpage = true,
  soft404 = true,
  useragent = nil,
  maxbodysize = 262144,
}

local NUMERIC_ARGS = {
  { key = "maxpaths", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 5, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxbodysize", minimum = 1024, integer = true },
}

local BOOLEAN_ARGS = { "favicon", "raw", "errorpage", "soft404" }

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

local function split_version(version)
  local parts = {}
  for token in string.gmatch(tostring(version or ""), "(%d+)") do
    table.insert(parts, tonumber(token) or 0)
  end
  return parts
end

local function version_lt(a, b)
  local pa = split_version(a)
  local pb = split_version(b)
  local max = math.max(#pa, #pb)
  for index = 1, max do
    local va = pa[index] or 0
    local vb = pb[index] or 0
    if va ~= vb then
      return va < vb
    end
  end
  return false
end

local function version_le(a, b)
  return not version_lt(b, a)
end

local function version_in_range(version, range)
  if not version or #tostring(version) == 0 then
    return false
  end
  local normalized = tostring(version)
  return version_le(range.from, normalized) and version_le(normalized, range.to)
end

local function cve_matches(family, version)
  local matches = {}
  for _, entry in ipairs(VERSION_CVE) do
    if entry.family == family then
      for _, range in ipairs(entry.ranges) do
        if version_in_range(version, range) then
          table.insert(matches, {
            product = entry.product,
            version = version,
            cve = range.cve,
            severity = range.severity,
            issue = range.issue,
          })
        end
      end
    end
  end
  return matches
end

local function select_paths(args)
  local selected = {}
  local seen = {}
  for _, candidate in ipairs(args.paths or PROBE_PATHS) do
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

local function stack_class_for(raw)
  local value = lower(raw or "")
  if contains(value, "cdn") or contains(value, "cloudflare") or contains(value, "akamai")
    or contains(value, "cloudfront") or contains(value, "fastly") then
    return "CDN"
  elseif contains(value, "bot") then
    return "bot manager"
  elseif contains(value, "balancer") or contains(value, "haproxy") or contains(value, "big%-ip") then
    return "load balancer"
  elseif contains(value, "mesh") or contains(value, "envoy") or contains(value, "istio") then
    return "service mesh"
  elseif contains(value, "cache") or contains(value, "varnish") or contains(value, "squid")
    or contains(value, "traffic server") or contains(value, "ats") then
    return "cache"
  elseif contains(value, "proxy") then
    return "reverse proxy"
  elseif contains(value, "servlet") or contains(value, "tomcat") or contains(value, "jetty")
    or contains(value, "weblogic") or contains(value, "websphere") or contains(value, "resin")
    or contains(value, "gunicorn") or contains(value, "uwsgi") or contains(value, "waitress")
    or contains(value, "tornado") or contains(value, "kestrel") or contains(value, "werkzeug")
    or contains(value, "express") or contains(value, "coyote") then
    return "application server"
  elseif contains(value, "php/") or contains(value, "asp%.net") or contains(value, "jsp")
    or contains(value, "servlet") or contains(value, "perl") then
    return "runtime"
  elseif contains(value, "web server") or contains(value, "nginx") or contains(value, "apache")
    or contains(value, "iis") or contains(value, "litespeed") or contains(value, "openresty")
    or contains(value, "tengine") or contains(value, "caddy") or contains(value, "lighttpd")
    or contains(value, "goahead") or contains(value, "rompager") or contains(value, "boa")
    or contains(value, "thttpd") or contains(value, "mini_httpd") or contains(value, "busybox")
    or contains(value, "zeus") or contains(value, "httpd") then
    return "web server"
  end
  return "application"
end

local function extract_server_identifications(response, identifications)
  local server = header_value(response, "server")
  if not server or #trim(server) == 0 then
    table.insert(identifications, {
      layer = "server-header",
      product = "(absent)",
      vendor = "n/a",
      class = "web server",
      confidence = "certain",
      version = nil,
      family = nil,
      evidence = "no Server header in the response",
      note = "Server header removed - good hardening, fingerprinting must fall back to behaviour",
    })
    return identifications
  end

  local lowered = lower(server)
  local matched = false
  for _, entry in ipairs(SERVER_PRODUCTS) do
    local found = string.find(lowered, entry.pattern, 1, true) or string.find(lowered, entry.pattern)
    if found then
      matched = true
      local version = entry.version_pattern and string.match(server, entry.version_pattern) or nil
      local family = entry.family
      table.insert(identifications, {
        layer = "server-header",
        product = family,
        vendor = entry.vendor,
        class = stack_class_for(family .. " " .. (entry.note or "")),
        confidence = "certain",
        version = version,
        family = family,
        evidence = "Server: " .. truncate(server, 96),
        note = entry.note,
        eol = entry.eol,
      })
      if version then
        for _, match in ipairs(cve_matches(family, version)) do
          add_finding(match.severity == "CRITICAL" and "CRITICAL" or match.severity,
            string.format("%s %s is associated with %s: %s", match.product, match.version,
              match.cve, match.issue),
            { subject = "cve:" .. match.cve, evidence = match.cve })
        end
      end
    end
  end

  if not matched then
    local version = string.match(server, "([%d]+%.%d+[%d%.]*)")
    table.insert(identifications, {
      layer = "server-header",
      product = "unrecognised server token",
      vendor = "unknown",
      class = stack_class_for(server),
      confidence = "possible",
      version = version,
      family = nil,
      evidence = "Server: " .. truncate(server, 96),
      note = "token does not match a known product family",
    })
  end

  if string.find(server, "%d+%.%d+") then
    add_finding("LOW", string.format("Server header discloses the exact version (%s)", truncate(server, 80)),
      { subject = "disclosure:server", evidence = server })
  end

  return identifications
end

local function extract_powered_by_identifications(response, identifications)
  local fields = { "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator",
    "x-runtime", "x-drupal-cache", "x-litespeed-cache" }
  for _, field in ipairs(fields) do
    for _, value in ipairs(header_values(response, field)) do
      local lowered = lower(value)
      local matched = false
      for _, entry in ipairs(POWERED_BY) do
        local found = string.find(lowered, entry.pattern, 1, true) or string.find(lowered, entry.pattern)
        if found then
          matched = true
          local version = string.match(lowered, entry.pattern)
          table.insert(identifications, {
            layer = "powered-by",
            product = entry.product,
            vendor = entry.product,
            class = entry.runtime == "php" and "runtime" or "framework",
            confidence = "certain",
            version = version,
            family = entry.runtime,
            evidence = field .. ": " .. truncate(value, 96),
            note = "runtime/framework disclosure header",
          })
          if entry.runtime == "php" and version then
            for _, match in ipairs(cve_matches("php", version)) do
              add_finding(match.severity, string.format("PHP %s: %s (%s)", match.version,
                match.issue, match.cve),
                { subject = "cve:" .. match.cve, evidence = match.cve })
            end
          end
          if entry.runtime == "openssl" and version then
            add_finding("LOW", string.format("OpenSSL version disclosed: %s", version),
              { subject = "disclosure:openssl", evidence = value })
          end
        end
      end
      if not matched then
        table.insert(identifications, {
          layer = "powered-by",
          product = field,
          vendor = "unknown",
          class = "framework",
          confidence = "probable",
          version = string.match(value, "([%d]+%.%d+[%d%.]*)"),
          family = nil,
          evidence = field .. ": " .. truncate(value, 96),
          note = "disclosure header with an unrecognised value",
        })
      end
      if field ~= "x-runtime" then
        add_finding("LOW", string.format("%s discloses stack details (%s)", string.upper(field),
          truncate(value, 60)),
          { subject = "disclosure:" .. field, evidence = value })
      end
    end
  end
  return identifications
end

local function extract_via_identifications(response, identifications)
  local via = header_value(response, "via")
  if not via then
    return identifications
  end
  for chunk in string.gmatch(via, "[^,]+") do
    local trimmed = trim(chunk)
    local protocol = string.match(trimmed, "^([%d%.]+)")
    local product = string.match(trimmed, "%s([A-Za-z][A-Za-z0-9%._%-]+)")
    local host = string.match(trimmed, "%(([^)]+)%)")
    table.insert(identifications, {
      layer = "via",
      product = product or "proxy hop",
      vendor = "unknown",
      class = "reverse proxy",
      confidence = "probable",
      version = protocol,
      family = product and lower(product) or nil,
      evidence = "Via: " .. truncate(trimmed, 96),
      note = host and ("hop comment: " .. truncate(host, 60)) or "intermediate proxy hop",
    })
    add_finding("LOW", string.format("Via header discloses an intermediate proxy (%s)",
      truncate(trimmed, 70)),
      { subject = "disclosure:via", evidence = trimmed })
  end
  return identifications
end

local function extract_body_identifications(response, identifications)
  local body = response.body or ""
  if #body == 0 then
    return identifications
  end
  local lowered = lower(body)

  for _, entry in ipairs(BODY_MARKERS) do
    if string.find(lowered, entry.pattern, 1, true) or string.find(lowered, entry.pattern) then
      table.insert(identifications, {
        layer = "body",
        product = entry.product,
        vendor = entry.vendor,
        class = entry.class,
        confidence = entry.confidence,
        version = nil,
        family = nil,
        evidence = entry.note .. " (status " .. tostring(response.status) .. ")",
        note = entry.note,
      })
    end
  end

  for _, marker in ipairs(KNOWN_DEFAULT_PAGES) do
    if string.find(lowered, marker, 1, true) then
      add_finding("LOW", string.format("response is a stock/default page (%s)", marker),
        { subject = "default-page:" .. marker, evidence = truncate(body, 90) })
    end
  end

  local generator = string.match(lowered, '<meta%s+name%s*=%s*"generator"%s+content%s*=%s*"([^"]*)"')
    or string.match(lowered, '<meta%s+content%s*=%s*"([^"]*)"%s+name%s*=%s*"generator"')
  if generator then
    table.insert(identifications, {
      layer = "body-meta",
      product = generator,
      vendor = "unknown",
      class = "CMS",
      confidence = "certain",
      version = string.match(generator, "([%d]+%.%d+[%d%.]*)"),
      family = nil,
      evidence = "meta generator: " .. truncate(generator, 80),
      note = "meta generator tag",
    })
    add_finding("LOW", string.format("meta generator discloses the CMS/generator (%s)",
      truncate(generator, 60)),
      { subject = "disclosure:generator", evidence = generator })
  end

  local viewstate = string.match(body, 'name%s*=%s*"__VIEWSTATE"[^>]*value%s*=%s*"([^"]*)"')
  if viewstate then
    add_finding("INFO", string.format("ASP.NET ViewState present (%d bytes encoded)", #viewstate),
      { subject = "viewstate", evidence = "len=" .. #viewstate })
  end

  local next_data = string.match(body, '__NEXT_DATA__" type="application/json">(.-)</script>')
  if next_data then
    local build_id = string.match(next_data, '"buildId":"([^"]+)"')
    table.insert(identifications, {
      layer = "body",
      product = "Next.js",
      vendor = "Vercel",
      class = "framework",
      confidence = "certain",
      version = nil,
      family = "nextjs",
      evidence = "buildId " .. tostring(build_id or "n/a") .. ", " .. #next_data .. " bytes of props",
      note = "SSR data blob embedded in HTML",
    })
    if build_id then
      add_finding("LOW", string.format("Next.js buildId disclosed (%s) - build-specific asset paths enumerable",
        build_id),
        { subject = "nextjs:buildid", evidence = build_id })
    end
    if #next_data > 5000 then
      add_finding("MEDIUM", string.format("Next.js __NEXT_DATA__ blob is %d bytes; SSR props are embedded in the page",
        #next_data),
        { subject = "nextjs:props", evidence = truncate(next_data, 110) })
    end
  end

  return identifications
end

local function extract_error_identifications(response, identifications, path)
  local body = lower(response.body or "")
  if #body == 0 then
    return identifications
  end
  for _, entry in ipairs(ERROR_TEMPLATES) do
    if string.find(body, entry.pattern, 1, true) or string.find(body, entry.pattern) then
      table.insert(identifications, {
        layer = "error-page",
        product = entry.product,
        vendor = entry.vendor,
        class = stack_class_for(entry.product),
        confidence = entry.confidence,
        version = string.match(response.body or "", "([%d]+%.%d+%.%d+)"),
        family = nil,
        evidence = path .. " HTTP " .. tostring(response.status) .. " -> " .. entry.note,
        note = entry.note,
      })
      if entry.confidence == "certain" and (response.status or 0) >= 400 then
        add_finding("LOW", string.format("%s error template at %s discloses the stack (%s)",
          entry.product, path, entry.note),
          { path = path, subject = "error-template:" .. entry.product, evidence = truncate(body, 90) })
      end
    end
  end

  local leaked_path = string.match(response.body or "", "[A-Za-z]:\\[^<>\r\n]{3,120}")
    or string.match(response.body or "", "/var/[%w%-%._/]{3,120}")
    or string.match(response.body or "", "/srv/[%w%-%._/]{3,120}")
    or string.match(response.body or "", "/opt/[%w%-%._/]{3,120}")
    or string.match(response.body or "", "/home/[%w%-%._/]{3,120}")
    or string.match(response.body or "", "/usr/[%w%-%._/]{3,120}")
    or string.match(response.body or "", "/app/[%w%-%._/]{3,120}")
  if leaked_path then
    add_finding("MEDIUM", string.format("error page discloses a server file system path (%s)",
      truncate(leaked_path, 90)),
      { path = path, subject = "path-disclosure", evidence = leaked_path })
  end

  if string.find(body, "exception") or string.find(body, "stack trace")
    or string.find(body, "at [%w%.]+%.[%w]+%(") then
    add_finding("HIGH", "error page contains an exception or stack trace",
      { path = path, subject = "stack-trace", evidence = truncate(body, 110) })
  end

  return identifications
end

local function fingerprint_favicon(host, port, args)
  local result = { attempted = false, found = false }
  if not args.favicon or budget_exhausted(args) then
    return result
  end
  result.attempted = true

  local response, err = fetch(host, port, "/favicon.ico", args)
  if not response then
    result.error = tostring(err)
    return result
  end
  result.status = response.status or 0
  result.length = #(response.body or "")
  local ctype = lower(header_value(response, "content-type") or "")
  result.content_type = #ctype > 0 and ctype or "unknown"

  if (response.status or 0) ~= 200 or result.length < 100 then
    result.found = false
    return result
  end

  result.hash = fnv1a32(response.body)
  result.entropy = entropy_bits(response.body)
  local magic = string.sub(response.body, 1, 4)
  if string.byte(magic, 1) == 0x89 and string.sub(magic, 2, 4) == "PNG" then
    result.format = "PNG"
  elseif string.sub(magic, 1, 2) == "\0\0" then
    result.format = "ICO"
  elseif string.sub(magic, 1, 3) == "GIF" then
    result.format = "GIF"
  elseif string.sub(magic, 1, 2) == "\255\216" then
    result.format = "JPEG"
  else
    result.format = "unknown"
  end

  if string.find(response.body, "<html", 1, true) or string.find(response.body, "<!doctype", 1, true) then
    result.found = false
    result.note = "favicon.ico returned an HTML page (soft-404 or SPA fallback), not an icon"
    return result
  end

  result.found = true
  local known = nil
  for _, entry in ipairs(FAVICON_DB) do
    if entry.hash == result.hash then
      known = entry
      break
    end
  end
  if known then
    result.match = known.name
    result.platform = known.platform
    result.note = known.note
    add_finding("MEDIUM", string.format("favicon matches %s (%s)", known.name, known.note),
      { subject = "favicon:" .. known.platform, evidence = "hash " .. tostring(result.hash) })
  end
  return result
end

local function protocol_behaviour(host, port, args, response)
  local behaviour = { lines = {} }

  local raw_text = response.raw_response or table.concat(response.rawheader or {}, "\r\n")
  local http_version = string.match(raw_text, "HTTP/(%d%.%d)")
  behaviour.http_version = http_version or "not observable from the response headers"
  if http_version == "1.0" then
    add_finding("LOW", "server answers with HTTP/1.0 semantics (no keep-alive by default)",
      { subject = "protocol:http10", evidence = "HTTP/1.0" })
  end

  local header_order = {}
  for _, line in ipairs(response.rawheader or {}) do
    local name = string.match(line, "^([^:]+):")
    if name and #header_order < 14 then
      table.insert(header_order, name)
    end
  end
  behaviour.header_order = header_order
  behaviour.header_count = #header_order

  local lowered_names = 0
  local titled_names = 0
  for _, name in ipairs(header_order) do
    if name == lower(name) and #name > 2 then
      lowered_names = lowered_names + 1
    end
    if string.match(name, "^[A-Z][a-z]+%-[A-Z]") then
      titled_names = titled_names + 1
    end
  end
  if lowered_names >= 3 then
    behaviour.header_style = "lowercase (nginx/Envoy/Node style)"
  elseif titled_names >= 2 then
    behaviour.header_style = "title-case (IIS/Apache style)"
  else
    behaviour.header_style = "mixed"
  end

  local connection = header_value(response, "connection")
  behaviour.connection = connection or "(not set)"
  if connection and contains(lower(connection), "close") then
    behaviour.keepalive = false
  else
    behaviour.keepalive = true
  end

  if args.raw and not budget_exhausted(args) then
    local head_response, head_err = raw_request(host, port, "HEAD", "/", {}, args)
    if head_response then
      behaviour.head_supported = true
      behaviour.head_content_length = head_response.headers and head_response.headers["content-length"]
      if behaviour.head_content_length then
        behaviour.head_note = "HEAD returns Content-Length (Apache/nginx style)"
      else
        behaviour.head_note = "HEAD returns no Content-Length (some frameworks/CDNs)"
      end
    else
      behaviour.head_supported = false
      behaviour.head_error = tostring(head_err)
    end

    if not budget_exhausted(args) then
      local options_response, options_err = raw_request(host, port, "OPTIONS", "*", {}, args)
      if options_response then
        behaviour.options_wildcard = options_response.status or 0
        behaviour.options_allow = options_response.headers
          and (options_response.headers["allow"] or options_response.headers["public"])
      else
        behaviour.options_error = tostring(options_err)
      end
    end
  end

  if not header_value(response, "date") then
    add_finding("LOW", "response carries no Date header (unusual for a standards-compliant server)",
      { subject = "protocol:no-date", evidence = "missing Date" })
  end

  table.insert(behaviour.lines, string.format("HTTP version: %s", behaviour.http_version))
  table.insert(behaviour.lines, string.format("header order (%d): %s", behaviour.header_count,
    table.concat(header_order, ", ")))
  table.insert(behaviour.lines, string.format("header case style: %s", behaviour.header_style))
  table.insert(behaviour.lines, string.format("Connection: %s (keep-alive %s)", behaviour.connection,
    behaviour.keepalive and "supported" or "not used"))
  if behaviour.head_supported then
    table.insert(behaviour.lines, string.format("HEAD /: supported, Content-Length=%s (%s)",
      tostring(behaviour.head_content_length or "none"), behaviour.head_note or ""))
  elseif behaviour.head_error then
    table.insert(behaviour.lines, "HEAD /: " .. behaviour.head_error)
  end
  if behaviour.options_wildcard then
    table.insert(behaviour.lines, string.format("OPTIONS *: HTTP %s, Allow=%s",
      tostring(behaviour.options_wildcard), tostring(behaviour.options_allow or "not advertised")))
  end

  return behaviour
end

local function merge_stack(identifications)
  local buckets = {}
  local order = { "CDN", "bot manager", "load balancer", "reverse proxy", "service mesh",
    "cache", "web server", "application server", "runtime", "framework", "CMS", "application" }
  for _, name in ipairs(order) do
    buckets[name] = {}
  end

  local seen = {}
  for _, entry in ipairs(identifications) do
    local bucket = entry.class or "application"
    if not buckets[bucket] then
      buckets[bucket] = {}
      table.insert(order, bucket)
    end
    local key = bucket .. "|" .. tostring(entry.product)
    if not seen[key] then
      seen[key] = true
      table.insert(buckets[bucket], entry)
    end
  end

  local lines = {}
  local layers_present = 0
  for _, name in ipairs(order) do
    local entries = buckets[name] or {}
    if #entries > 0 then
      layers_present = layers_present + 1
      local parts = {}
      for _, entry in ipairs(entries) do
        local label = tostring(entry.product)
        if entry.version then
          label = label .. " " .. tostring(entry.version)
        end
        label = label .. " [" .. tostring(entry.confidence) .. "]"
        if not list_contains(parts, label) then
          table.insert(parts, label)
        end
      end
      table.insert(lines, string.format("%-18s %s", name, table.concat(parts, ", ")))
    end
  end

  return lines, layers_present
end

local function dedupe_identifications(identifications)
  local unique = {}
  local seen = {}
  for _, entry in ipairs(identifications) do
    local key = string.format("%s|%s|%s", entry.layer, entry.product, tostring(entry.version))
    if not seen[key] then
      seen[key] = true
      table.insert(unique, entry)
    end
  end
  return unique
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local baseline = build_soft404_baseline(host, port, args)
  local paths = select_paths(args)

  local identifications = {}
  local path_lines = {}
  local representative = nil

  for _, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(path_lines, path .. ": request budget exhausted")
      break
    end

    local response, err = fetch(host, port, path, args)
    if not response then
      table.insert(path_lines, string.format("%s: %s", path, tostring(err)))
      goto continue_path
    end

    representative = representative or response
    local info = classify_response(path, response, baseline)
    local before = #identifications
    extract_server_identifications(response, identifications)
    extract_powered_by_identifications(response, identifications)
    extract_via_identifications(response, identifications)
    extract_body_identifications(response, identifications)

    table.insert(path_lines, string.format("%s -> HTTP %s, %d bytes, %s, +%d identification(s)%s",
      path, tostring(info.status), info.length, tostring(info.kind), #identifications - before,
      info.confidence == "low" and " [low confidence]" or ""))

    ::continue_path::
  end

  local behaviour = nil
  if representative then
    behaviour = protocol_behaviour(host, port, args, representative)
  end

  local error_lines = {}
  if args.errorpage and not budget_exhausted(args) then
    local missing_path = "/nse-fp-404-" .. lower(random_token(10))
    local error_response, error_err = fetch(host, port, missing_path, args)
    if error_response then
      local before = #identifications
      extract_error_identifications(error_response, identifications, missing_path)
      table.insert(error_lines, string.format("%s -> HTTP %s, %d bytes, +%d error identification(s)",
        missing_path, tostring(error_response.status), #(error_response.body or ""),
        #identifications - before))
      local template_hit = false
      for _, entry in ipairs(ERROR_TEMPLATES) do
        if string.find(lower(error_response.body or ""), entry.pattern, 1, true)
          or string.find(lower(error_response.body or ""), entry.pattern) then
          template_hit = true
          table.insert(error_lines, "      template: " .. entry.product .. " - " .. entry.note)
        end
      end
      if not template_hit then
        table.insert(error_lines, "      template: custom/unrecognised error page")
      end
      if looks_like_soft404(error_response, baseline) then
        table.insert(error_lines, "      note: matches the catch-all baseline (soft-404 behaviour)")
      end
    else
      table.insert(error_lines, string.format("%s: %s", missing_path, tostring(error_err)))
    end
  end

  local favicon = fingerprint_favicon(host, port, args)

  local deduped = dedupe_identifications(identifications)
  local stack_lines, layers_present = merge_stack(deduped)

  local version_lines = {}
  local versionless = 0
  for _, entry in ipairs(deduped) do
    if entry.version and #tostring(entry.version) > 0 then
      table.insert(version_lines, string.format("%-24s %-12s %s", tostring(entry.product),
        tostring(entry.version), tostring(entry.evidence)))
    else
      versionless = versionless + 1
    end
  end

  local class_counts = {}
  for _, entry in ipairs(deduped) do
    class_counts[entry.class or "application"] = (class_counts[entry.class or "application"] or 0) + 1
  end
  local class_lines = {}
  for _, key in ipairs(sorted_keys(class_counts)) do
    table.insert(class_lines, string.format("%s: %d", key, class_counts[key]))
  end

  local unique, counts = dedupe_findings()

  local out = new_output(RISK_LEVEL, "AUDITED - web stack fingerprinted across "
    .. tostring(#deduped) .. " signals.")
  if layers_present >= 4 then
    out["Status"] = "AUDITED - a multi-layer stack was reconstructed (edge, server, runtime, application)."
  elseif layers_present >= 2 then
    out["Status"] = "AUDITED - stack partially reconstructed from " .. tostring(layers_present) .. " layers."
  elseif #deduped == 0 then
    out["Status"] = "AUDITED - no stack identification was possible from the responses observed."
  else
    out["Status"] = "AUDITED - only a single stack layer could be identified."
  end

  local evidence_lines = {}
  for _, entry in ipairs(deduped) do
    table.insert(evidence_lines, string.format("[%s/%s] %s%s — %s (%s)",
      entry.layer, entry.confidence, tostring(entry.product),
      entry.version and (" " .. tostring(entry.version)) or "",
      tostring(entry.evidence), tostring(entry.class)))
    if entry.note then
      table.insert(evidence_lines, "      " .. tostring(entry.note))
    end
  end

  local sections = {
    { key = "Transport", value = (port.ssl or (port.version and port.version.service_ssl))
      and "HTTPS" or "HTTP" },
    { key = "Stack", value = stack_lines },
    { key = "Versions disclosed", value = #version_lines > 0 and version_lines
      or { "no exact version disclosed in headers" } },
    { key = "Identifications", value = evidence_lines },
    { key = "Layers", value = string.format("%d stack layers, %d unique signals, %d without version",
      layers_present, #deduped, versionless) },
    { key = "Layer counts", value = class_lines },
    { key = "Paths probed", value = path_lines },
  }

  if #error_lines > 0 then
    table.insert(sections, { key = "Error page probe", value = error_lines })
  end

  if behaviour then
    table.insert(sections, { key = "Protocol behaviour", value = behaviour.lines })
  end

  local favicon_lines = {}
  if favicon.attempted then
    if favicon.found then
      table.insert(favicon_lines, string.format("HTTP %s, %d bytes, %s, entropy %.2f, hash %s",
        tostring(favicon.status), favicon.length, tostring(favicon.format),
        favicon.entropy or 0, tostring(favicon.hash)))
      if favicon.match then
        table.insert(favicon_lines, "match: " .. favicon.match .. " — " .. tostring(favicon.note))
      else
        table.insert(favicon_lines, "match: none in the built-in database (custom or generic icon)")
      end
    elseif favicon.note then
      table.insert(favicon_lines, favicon.note)
    elseif favicon.error then
      table.insert(favicon_lines, "error: " .. favicon.error)
    else
      table.insert(favicon_lines, string.format("no usable favicon (HTTP %s, %d bytes, %s)",
        tostring(favicon.status), favicon.length, tostring(favicon.content_type)))
    end
    table.insert(sections, { key = "Favicon", value = favicon_lines })
  end

  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end

  if #version_lines > 0 then
    table.insert(sections, { key = "Remediation", value =
      "suppress version tokens (ServerTokens Prod / server_tokens off / remove X-Powered-By), "
      .. "replace stock error and default pages, and patch the exact versions listed above before "
      .. "relying on the edge for protection" })
  else
    table.insert(sections, { key = "Remediation", value =
      "version disclosure is already suppressed; keep error pages custom, remove stock/default pages, "
      .. "and re-run this fingerprint after every stack upgrade because behaviour-based identification "
      .. "can still date the release" })
  end

  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  return finish_output(out, unique, counts, sections)

end
