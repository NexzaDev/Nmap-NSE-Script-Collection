local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Identifies the Web Application Firewall, reverse proxy, CDN or edge security
product sitting in front of a web service, and reports how that product
behaves instead of only whether it is named in a header.

Detection layers
1. Header fingerprints: vendor specific response headers (cf-ray, x-sucuri-id,
   x-iinfo, x-akamai-*, x-amz-cf-*, x-aws-waf-*, x-powered-by-360wzb,
   x-cdn-forward, x-safe-firewall, x-nginx-cache, x-varnish, x-cache,
   x-proxy-cache, x-envoy-*, x-istio-*, x-istio-envoy, x-amzn-trace-id,
   x-dd-*, x-fastly-*, x-pantheon-*, x-platform-server, x-wix-*, ...) with the
   product, vendor and what the header actually reveals (POP id, request id,
   cache state, backend host).
2. Cookie fingerprints: __cfduid/__cf_bm (Cloudflare), sucuri_cloudproxy_*,
   AWSALB/AWSALBCORS (ELB stickiness), incap_ses_*/visid_incap_* (Imperva),
   ak_bmsc/bm_sz/bm_sv (Akamai Bot Manager), BIGipServer* (F5),
   TS01* (F5 ASM), ARRAffinity (Azure), ns_af (NetScaler),
   lb_idl_*/f5_fullsession (F5), _ga/_gid excluded as analytics noise.
3. Body fingerprints: block/challenge page wording and markup (Cloudflare
   "Attention Required", "cf-error-details", "cf-browser-verification",
   Akamai "Reference #", Imperva "Incapsula incident ID", AWS WAF
   "Request blocked", Sucuri "Access Denied - Sucuri Website Firewall",
   ModSecurity "ModSecurity Action", FortiWeb "FortiWeb", SafeLine,
   Barracuda, F5 BIG-IP ASM "The requested URL was rejected",
   nginx "403 Forbidden" with vendor CSS, Wordfence, SiteLock,
   Astra, dotDefender, Airlock, Radware AppWall, KSOF, WebKnight,
   URLScan, Yunsuo, Anquanbao, Jiasule, Safedog, Knownsec, Baidu Yun,
   Tencent Cloud WAF, Alibaba Cloud WAF, Huawei Cloud WAF, Sangfor,
   Naxsi, Shadow Daemon, OpenResty lua-resty-waf).
4. Server / Via / X-Powered-By product strings and version extraction
   (Apache/2.4.49 + ModSecurity, nginx + naxsi, cloudflare, AkamaiGHost,
   AmazonS3/CloudFront, ATS (Apache Traffic Server), envoy, istio-envoy,
   varnish, haproxy, Squid, LiteSpeed, openresty, Tengine, Caddy,
   gunicorn/uwsgi behind a proxy, Microsoft-IIS + ARR).
5. Status-code fingerprinting: HTTP 403/406/418/419/420/444/520-527/999
   patterns typical of specific products, and the presence of a custom error
   body with an incident id.
6. Behavioural fingerprinting (the useful part): a benign baseline request is
   recorded, then a set of *harmless but suspicious-looking* probes is sent
   (a path with a benign SQL-ish token, a query string with a script tag
   placeholder, a request with an unusual User-Agent, a request with many
   repeated parameters, an oversized header). If the response status, length or
   body hash changes between baseline and probe, the script proves that a
   filtering layer is active even when it hides all of its headers. Every probe
   is read-only and non-destructive: no exploitation payload, no DoS volume,
   no data modification.

Every identification carries a confidence (certain / probable / possible)
derived from how many independent signal classes matched, plus the exact
evidence (header line, cookie name, body excerpt, status delta). Products are
grouped by class (WAF, CDN, reverse proxy, bot manager, load balancer,
service mesh, cache) and the report lists what the product hides (Server
header removed? version stripped? error page replaced?) and what it still
leaks (POP identifier, request id, backend host, cookie scope).

False positives are suppressed by requiring structural evidence: a header that
merely contains the word "cloud" is not a Cloudflare finding, an "Access
denied" body is only attributed to a vendor when the accompanying markup or
incident-id format matches, and analytics cookies are explicitly excluded.

Usage:
<code>
nmap -p 80,443 --script http-waf-detect <target>
nmap -p 443 --script http-waf-detect \
  --script-args http-waf-detect.behaviour=false <target>
nmap -p 80 --script http-waf-detect \
  --script-args http-waf-detect.paths="/,/api,/admin",http-waf-detect.maxrequests=60 \
  <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.http

local SCRIPT_NAME = "http-waf-detect"

local RISK_LEVEL = "🟢 LOW"

local PROBE_PATHS = {
  "/",
  "/index.html",
  "/api",
  "/admin",
  "/login",
  "/static/app.js",
  "/favicon.ico",
}

local WAF_SIGNATURES = {
  { pattern = "cf-ray", where = "header", vendor = "Cloudflare" },
  { pattern = "cloudflare", where = "header", vendor = "Cloudflare" },
  { pattern = "attention required", where = "body", vendor = "Cloudflare" },
  { pattern = "akamai", where = "header", vendor = "Akamai" },
  { pattern = "reference #", where = "body", vendor = "Akamai" },
  { pattern = "x-iinfo", where = "header", vendor = "Imperva Incapsula" },
  { pattern = "incapsula", where = "body", vendor = "Imperva Incapsula" },
  { pattern = "sucuri", where = "header", vendor = "Sucuri" },
  { pattern = "aws waf", where = "body", vendor = "AWS WAF" },
  { pattern = "request blocked", where = "body", vendor = "generic WAF" },
  { pattern = "access denied", where = "body", vendor = "generic WAF" },
  { pattern = "web application firewall", where = "body", vendor = "generic WAF" },
  { pattern = "mod_security", where = "body", vendor = "ModSecurity" },
  { pattern = "fortiweb", where = "body", vendor = "Fortinet FortiWeb" },
  { pattern = "safeline", where = "body", vendor = "SafeLine WAF" },
}

local SOFT404_TEMPLATES = {
  "/nse-waf-probe-%s",
}

local HEADER_FINGERPRINTS = {
  { header = "cf-ray", vendor = "Cloudflare", product = "Cloudflare WAF/CDN", class = "CDN + WAF",
    confidence = "certain", leaks = "edge POP identifier and request hash" },
  { header = "cf-cache-status", vendor = "Cloudflare", product = "Cloudflare cache", class = "CDN",
    confidence = "certain", leaks = "cache state of the object" },
  { header = "cf-mitigated", vendor = "Cloudflare", product = "Cloudflare Bot Fight Mode", class = "bot manager",
    confidence = "certain", leaks = "mitigation action taken" },
  { header = "x-sucuri-id", vendor = "Sucuri", product = "Sucuri Website Firewall", class = "WAF + CDN",
    confidence = "certain", leaks = "edge node identifier" },
  { header = "x-sucuri-cache", vendor = "Sucuri", product = "Sucuri cache", class = "CDN",
    confidence = "certain", leaks = "cache state" },
  { header = "x-iinfo", vendor = "Imperva", product = "Imperva Incapsula", class = "WAF + CDN",
    confidence = "certain", leaks = "internal request telemetry" },
  { header = "x-cdn", vendor = "Imperva", product = "Imperva CDN", class = "CDN",
    confidence = "probable", leaks = "CDN presence" },
  { header = "x-akamai-transformed", vendor = "Akamai", product = "Akamai edge", class = "CDN",
    confidence = "certain", leaks = "edge transformation applied" },
  { header = "x-akamai-request-id", vendor = "Akamai", product = "Akamai edge", class = "CDN",
    confidence = "certain", leaks = "edge request identifier" },
  { header = "akamai-grn", vendor = "Akamai", product = "Akamai edge", class = "CDN",
    confidence = "certain", leaks = "global request number" },
  { header = "x-amz-cf-id", vendor = "Amazon", product = "CloudFront", class = "CDN",
    confidence = "certain", leaks = "CloudFront request identifier" },
  { header = "x-amz-cf-pop", vendor = "Amazon", product = "CloudFront", class = "CDN",
    confidence = "certain", leaks = "edge POP code" },
  { header = "x-amzn-requestid", vendor = "Amazon", product = "API Gateway / ALB", class = "reverse proxy",
    confidence = "probable", leaks = "backend request id" },
  { header = "x-amzn-trace-id", vendor = "Amazon", product = "ALB X-Ray tracing", class = "load balancer",
    confidence = "certain", leaks = "trace root, sample decision and span" },
  { header = "x-aws-waf-rulegroup", vendor = "Amazon", product = "AWS WAF", class = "WAF",
    confidence = "certain", leaks = "rule group that matched" },
  { header = "x-powered-by-360wzb", vendor = "360", product = "360 Wangzhan WAF", class = "WAF",
    confidence = "certain", leaks = "WAF product name" },
  { header = "x-safe-firewall", vendor = "generic", product = "self-labelled firewall", class = "WAF",
    confidence = "probable", leaks = "explicit WAF presence" },
  { header = "x-cdn-forward", vendor = "generic", product = "CDN forwarder", class = "CDN",
    confidence = "possible", leaks = "upstream CDN hop" },
  { header = "x-nginx-cache", vendor = "nginx", product = "nginx proxy_cache", class = "cache",
    confidence = "certain", leaks = "cache state (HIT/MISS/EXPIRED)" },
  { header = "x-varnish", vendor = "Varnish", product = "Varnish Cache", class = "cache",
    confidence = "certain", leaks = "Varnish request number" },
  { header = "x-varnish-cache", vendor = "Varnish", product = "Varnish Cache", class = "cache",
    confidence = "certain", leaks = "cache state" },
  { header = "x-cache", vendor = "generic", product = "caching layer", class = "cache",
    confidence = "probable", leaks = "cache state and node" },
  { header = "x-cache-lookup", vendor = "generic", product = "caching layer", class = "cache",
    confidence = "probable", leaks = "cache lookup result" },
  { header = "x-proxy-cache", vendor = "generic", product = "reverse proxy cache", class = "cache",
    confidence = "probable", leaks = "cache state" },
  { header = "x-envoy-upstream-service-time", vendor = "Envoy", product = "Envoy proxy", class = "service mesh",
    confidence = "certain", leaks = "backend processing time (timing oracle)" },
  { header = "x-envoy-decorator-operation", vendor = "Envoy", product = "Envoy/Istio", class = "service mesh",
    confidence = "certain", leaks = "route decorator name" },
  { header = "x-envoy-attempt-count", vendor = "Envoy", product = "Envoy retry policy", class = "service mesh",
    confidence = "certain", leaks = "number of upstream attempts" },
  { header = "x-istio-envoy", vendor = "Istio", product = "Istio sidecar", class = "service mesh",
    confidence = "certain", leaks = "service mesh presence" },
  { header = "x-request-id", vendor = "generic", product = "edge request tracing", class = "reverse proxy",
    confidence = "possible", leaks = "internal request identifier" },
  { header = "x-served-by", vendor = "Fastly/generic", product = "backend identifier", class = "CDN",
    confidence = "probable", leaks = "backend host name and cache node" },
  { header = "x-fastly-request-id", vendor = "Fastly", product = "Fastly CDN", class = "CDN",
    confidence = "certain", leaks = "edge request identifier" },
  { header = "x-timer", vendor = "Fastly", product = "Fastly CDN", class = "CDN",
    confidence = "probable", leaks = "edge timing breakdown" },
  { header = "x-pantheon-styx-hostname", vendor = "Pantheon", product = "Pantheon Styx proxy", class = "reverse proxy",
    confidence = "certain", leaks = "internal container host name" },
  { header = "x-platform-server", vendor = "Platform.sh", product = "Platform.sh router", class = "reverse proxy",
    confidence = "certain", leaks = "platform router identity" },
  { header = "x-wix-request-id", vendor = "Wix", product = "Wix hosting", class = "reverse proxy",
    confidence = "certain", leaks = "hosting platform" },
  { header = "x-dd-b", vendor = "Datadog", product = "Datadog Synthetics/monitor", class = "monitoring",
    confidence = "probable", leaks = "synthetic probe marker" },
  { header = "x-datadog-trace-id", vendor = "Datadog", product = "Datadog APM", class = "monitoring",
    confidence = "certain", leaks = "distributed trace id" },
  { header = "x-newrelic-app-data", vendor = "New Relic", product = "New Relic APM", class = "monitoring",
    confidence = "certain", leaks = "APM application data blob" },
  { header = "x-runtime", vendor = "Rails/generic", product = "application runtime timer", class = "application",
    confidence = "probable", leaks = "server-side processing time (timing oracle)" },
  { header = "x-drupal-cache", vendor = "Drupal", product = "Drupal page cache", class = "application",
    confidence = "certain", leaks = "CMS and cache state" },
  { header = "x-aspnet-version", vendor = "Microsoft", product = "ASP.NET", class = "application",
    confidence = "certain", leaks = "exact ASP.NET runtime version" },
  { header = "x-aspnetmvc-version", vendor = "Microsoft", product = "ASP.NET MVC", class = "application",
    confidence = "certain", leaks = "exact MVC framework version" },
  { header = "x-aspnetmvc-version-override", vendor = "Microsoft", product = "ASP.NET MVC", class = "application",
    confidence = "probable", leaks = "MVC version override" },
  { header = "x-powered-by", vendor = "generic", product = "application stack", class = "application",
    confidence = "probable", leaks = "framework and version" },
  { header = "x-generator", vendor = "generic", product = "CMS/site builder", class = "application",
    confidence = "probable", leaks = "generator name and version" },
  { header = "x-backend-server", vendor = "generic", product = "origin identifier", class = "reverse proxy",
    confidence = "probable", leaks = "backend host name" },
  { header = "x-server-name", vendor = "generic", product = "origin identifier", class = "reverse proxy",
    confidence = "probable", leaks = "internal server name" },
  { header = "x-correlation-id", vendor = "generic", product = "request correlation", class = "reverse proxy",
    confidence = "possible", leaks = "internal correlation identifier" },
  { header = "x-frame-options", vendor = "generic", product = "security header layer", class = "hardening",
    confidence = "possible", leaks = "nothing (expected header)" },
  { header = "x-content-type-options", vendor = "generic", product = "security header layer", class = "hardening",
    confidence = "possible", leaks = "nothing (expected header)" },
  { header = "x-xss-protection", vendor = "generic", product = "legacy auditor header", class = "hardening",
    confidence = "possible", leaks = "legacy configuration" },
  { header = "x-permitted-cross-domain-policies", vendor = "Adobe", product = "Flash/PDF policy header", class = "hardening",
    confidence = "possible", leaks = "legacy plugin policy" },
  { header = "x-download-options", vendor = "Microsoft", product = "IE download hardening", class = "hardening",
    confidence = "possible", leaks = "legacy IE configuration" },
  { header = "strict-transport-security", vendor = "generic", product = "HSTS", class = "hardening",
    confidence = "possible", leaks = "TLS policy" },
  { header = "nel", vendor = "generic", product = "Network Error Logging", class = "monitoring",
    confidence = "possible", leaks = "reporting endpoint group" },
  { header = "report-to", vendor = "generic", product = "Reporting API", class = "monitoring",
    confidence = "possible", leaks = "reporting endpoint group" },
  { header = "public-key-pins", vendor = "generic", product = "HPKP (deprecated)", class = "hardening",
    confidence = "certain", leaks = "deprecated pinning configuration" },
  { header = "expect-ct", vendor = "generic", product = "Expect-CT (obsolete)", class = "hardening",
    confidence = "certain", leaks = "obsolete CT enforcement" },
  { header = "server-timing", vendor = "generic", product = "Server-Timing instrumentation", class = "monitoring",
    confidence = "probable", leaks = "server-side timing breakdown" },
  { header = "x-hw", vendor = "Huawei", product = "Huawei Cloud CDN", class = "CDN",
    confidence = "probable", leaks = "edge node identifier" },
  { header = "x-nws-log-uuid", vendor = "Tencent", product = "Tencent Cloud CDN/WAF", class = "CDN + WAF",
    confidence = "certain", leaks = "cloud request uuid" },
  { header = "x-daa-tunnel", vendor = "generic", product = "tunnel/edge proxy", class = "reverse proxy",
    confidence = "possible", leaks = "tunnel presence" },
  { header = "x-app-service-id", vendor = "Microsoft", product = "Azure App Service", class = "PaaS",
    confidence = "probable", leaks = "app service identity" },
  { header = "x-arr-log-id", vendor = "Microsoft", product = "Azure Application Request Routing", class = "reverse proxy",
    confidence = "certain", leaks = "ARR request log id" },
  { header = "x-arr-ssl", vendor = "Microsoft", product = "Azure ARR TLS termination", class = "reverse proxy",
    confidence = "certain", leaks = "TLS cipher and certificate used at the edge" },
  { header = "x-azure-ref", vendor = "Microsoft", product = "Azure Front Door", class = "CDN",
    confidence = "certain", leaks = "Front Door reference id" },
  { header = "x-fd-int-roxy-purgeid", vendor = "Microsoft", product = "Azure Front Door purge", class = "CDN",
    confidence = "certain", leaks = "purge identifier" },
  { header = "x-msedge-ref", vendor = "Microsoft", product = "Azure Front Door / Edge", class = "CDN",
    confidence = "probable", leaks = "edge reference" },
  { header = "x-google-cache_control", vendor = "Google", product = "Google Cloud CDN", class = "CDN",
    confidence = "probable", leaks = "cache control applied at the edge" },
  { header = "via", vendor = "generic", product = "intermediate proxy chain", class = "reverse proxy",
    confidence = "probable", leaks = "proxy software and versions" },
  { header = "x-forwarded-for", vendor = "generic", product = "proxy chain echo", class = "reverse proxy",
    confidence = "possible", leaks = "client IP chain (rarely echoed back)" },
  { header = "x-original-url", vendor = "generic", product = "routing override echo", class = "reverse proxy",
    confidence = "probable", leaks = "routing internals" },
}

local SERVER_FINGERPRINTS = {
  { pattern = "cloudflare", vendor = "Cloudflare", product = "Cloudflare edge", class = "CDN + WAF",
    confidence = "certain", version = nil },
  { pattern = "akamaighost", vendor = "Akamai", product = "AkamaiGHost", class = "CDN",
    confidence = "certain", version = true },
  { pattern = "cloudfront", vendor = "Amazon", product = "CloudFront", class = "CDN",
    confidence = "certain", version = false },
  { pattern = "amazons3", vendor = "Amazon", product = "S3 static hosting", class = "storage",
    confidence = "certain", version = false },
  { pattern = "aws", vendor = "Amazon", product = "AWS edge", class = "CDN",
    confidence = "possible", version = false },
  { pattern = "sucuri", vendor = "Sucuri", product = "Sucuri Website Firewall", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "incapsula", vendor = "Imperva", product = "Imperva Incapsula", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "imperva", vendor = "Imperva", product = "Imperva SecureSphere", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "big%-ip", vendor = "F5", product = "F5 BIG-IP", class = "load balancer + WAF",
    confidence = "certain", version = true },
  { pattern = "f5", vendor = "F5", product = "F5", class = "load balancer",
    confidence = "possible", version = false },
  { pattern = "citrix", vendor = "Citrix", product = "Citrix NetScaler/ADC", class = "load balancer + WAF",
    confidence = "certain", version = false },
  { pattern = "netscaler", vendor = "Citrix", product = "NetScaler", class = "load balancer",
    confidence = "certain", version = false },
  { pattern = "barracuda", vendor = "Barracuda", product = "Barracuda WAF", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "fortiweb", vendor = "Fortinet", product = "FortiWeb", class = "WAF",
    confidence = "certain", version = true },
  { pattern = "fortinet", vendor = "Fortinet", product = "Fortinet edge", class = "WAF",
    confidence = "probable", version = false },
  { pattern = "mod_security", vendor = "ModSecurity", product = "ModSecurity", class = "WAF",
    confidence = "certain", version = true },
  { pattern = "modsecurity", vendor = "ModSecurity", product = "ModSecurity", class = "WAF",
    confidence = "certain", version = true },
  { pattern = "webknight", vendor = "AQTRONIX", product = "WebKnight", class = "WAF (IIS ISAPI)",
    confidence = "certain", version = true },
  { pattern = "safeline", vendor = "Chaitin", product = "SafeLine WAF", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "yunsuo", vendor = "Yunsuo", product = "Yunsuo WAF", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "anquanbao", vendor = "Anquanbao", product = "Anquanbao WAF", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "jiasule", vendor = "Jiasule", product = "Jiasule CDN/WAF", class = "WAF + CDN",
    confidence = "certain", version = false },
  { pattern = "safedog", vendor = "Safedog", product = "Safedog WAF", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "knownsec", vendor = "Knownsec", product = "Knownsec WAF", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "sangfor", vendor = "Sangfor", product = "Sangfor NGAF", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "nsfocus", vendor = "NSFOCUS", product = "NSFOCUS WAF", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "waf/2%.0", vendor = "generic", product = "labelled WAF", class = "WAF",
    confidence = "probable", version = true },
  { pattern = "airlock", vendor = "ERCON", product = "Airlock WAF", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "radware", vendor = "Radware", product = "Radware AppWall", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "appwall", vendor = "Radware", product = "Radware AppWall", class = "WAF",
    confidence = "probable", version = false },
  { pattern = "dotdefender", vendor = "Applicure", product = "dotDefender", class = "WAF",
    confidence = "certain", version = false },
  { pattern = "urlscan", vendor = "Microsoft", product = "UrlScan", class = "WAF (IIS)",
    confidence = "certain", version = false },
  { pattern = "naxsi", vendor = "naxsi", product = "Naxsi (nginx)", class = "WAF",
    confidence = "certain", version = true },
  { pattern = "nginx", vendor = "nginx", product = "nginx", class = "web server / reverse proxy",
    confidence = "certain", version = true },
  { pattern = "apache", vendor = "Apache", product = "Apache httpd", class = "web server",
    confidence = "certain", version = true },
  { pattern = "apache%-coyote", vendor = "Apache", product = "Tomcat coyote connector", class = "application server",
    confidence = "certain", version = true },
  { pattern = "traffic server", vendor = "Apache", product = "Apache Traffic Server", class = "cache",
    confidence = "certain", version = true },
  { pattern = "ats/", vendor = "Apache", product = "Apache Traffic Server", class = "cache",
    confidence = "certain", version = true },
  { pattern = "varnish", vendor = "Varnish", product = "Varnish Cache", class = "cache",
    confidence = "certain", version = true },
  { pattern = "haproxy", vendor = "HAProxy", product = "HAProxy", class = "load balancer",
    confidence = "certain", version = true },
  { pattern = "envoy", vendor = "Envoy", product = "Envoy proxy", class = "service mesh / proxy",
    confidence = "certain", version = true },
  { pattern = "istio", vendor = "Istio", product = "Istio", class = "service mesh",
    confidence = "certain", version = true },
  { pattern = "squid", vendor = "Squid", product = "Squid", class = "proxy/cache",
    confidence = "certain", version = true },
  { pattern = "litespeed", vendor = "LiteSpeed", product = "LiteSpeed Web Server", class = "web server",
    confidence = "certain", version = true },
  { pattern = "openresty", vendor = "OpenResty", product = "OpenResty (nginx + Lua)", class = "web server",
    confidence = "certain", version = true },
  { pattern = "tengine", vendor = "Alibaba", product = "Tengine", class = "web server",
    confidence = "certain", version = true },
  { pattern = "caddy", vendor = "Caddy", product = "Caddy", class = "web server",
    confidence = "certain", version = true },
  { pattern = "lighttpd", vendor = "lighttpd", product = "lighttpd", class = "web server",
    confidence = "certain", version = true },
  { pattern = "microsoft%-iis", vendor = "Microsoft", product = "IIS", class = "web server",
    confidence = "certain", version = true },
  { pattern = "iis", vendor = "Microsoft", product = "IIS", class = "web server",
    confidence = "probable", version = true },
  { pattern = "gws", vendor = "Google", product = "Google Web Server", class = "reverse proxy",
    confidence = "certain", version = false },
  { pattern = "ghs", vendor = "Google", product = "Google Hosted Service", class = "reverse proxy",
    confidence = "probable", version = false },
  { pattern = "gse", vendor = "Google", product = "Google Servlet Engine", class = "application server",
    confidence = "probable", version = false },
  { pattern = "gunicorn", vendor = "gunicorn", product = "Gunicorn WSGI server", class = "application server",
    confidence = "certain", version = true },
  { pattern = "uwsgi", vendor = "uWSGI", product = "uWSGI", class = "application server",
    confidence = "certain", version = true },
  { pattern = "waitress", vendor = "Waitress", product = "Waitress WSGI server", class = "application server",
    confidence = "certain", version = false },
  { pattern = "kestrel", vendor = "Microsoft", product = "Kestrel (ASP.NET Core)", class = "application server",
    confidence = "certain", version = false },
  { pattern = "jetty", vendor = "Eclipse", product = "Jetty", class = "application server",
    confidence = "certain", version = true },
  { pattern = "tomcat", vendor = "Apache", product = "Tomcat", class = "application server",
    confidence = "certain", version = true },
  { pattern = "resin", vendor = "Caucho", product = "Resin", class = "application server",
    confidence = "certain", version = true },
  { pattern = "weblogic", vendor = "Oracle", product = "WebLogic", class = "application server",
    confidence = "certain", version = true },
  { pattern = "websphere", vendor = "IBM", product = "WebSphere", class = "application server",
    confidence = "certain", version = true },
  { pattern = "oracle%-application%-server", vendor = "Oracle", product = "Oracle Application Server",
    class = "application server", confidence = "certain", version = true },
  { pattern = "sap netweaver", vendor = "SAP", product = "SAP NetWeaver", class = "application server",
    confidence = "certain", version = false },
  { pattern = "ibm_http_server", vendor = "IBM", product = "IBM HTTP Server", class = "web server",
    confidence = "certain", version = true },
  { pattern = "zeus", vendor = "Zeus", product = "Zeus Web Server", class = "web server",
    confidence = "probable", version = true },
  { pattern = "sun%-one", vendor = "Oracle", product = "Sun ONE / iPlanet", class = "web server",
    confidence = "certain", version = true },
  { pattern = "oracle%-iplanet", vendor = "Oracle", product = "Oracle iPlanet", class = "web server",
    confidence = "certain", version = true },
  { pattern = "express", vendor = "Express", product = "Express (Node.js)", class = "application framework",
    confidence = "certain", version = false },
  { pattern = "php/", vendor = "PHP", product = "PHP", class = "runtime",
    confidence = "certain", version = true },
  { pattern = "asp%.net", vendor = "Microsoft", product = "ASP.NET", class = "runtime",
    confidence = "certain", version = true },
  { pattern = "wordpress", vendor = "WordPress", product = "WordPress", class = "CMS",
    confidence = "probable", version = false },
  { pattern = "drupal", vendor = "Drupal", product = "Drupal", class = "CMS",
    confidence = "probable", version = false },
  { pattern = "joomla", vendor = "Joomla", product = "Joomla", class = "CMS",
    confidence = "probable", version = false },
  { pattern = "shopify", vendor = "Shopify", product = "Shopify", class = "commerce platform",
    confidence = "certain", version = false },
  { pattern = "wix%.com", vendor = "Wix", product = "Wix", class = "site builder",
    confidence = "certain", version = false },
  { pattern = "squid", vendor = "Squid", product = "Squid", class = "proxy",
    confidence = "certain", version = true },
}

local COOKIE_FINGERPRINTS = {
  { pattern = "__cfduid", vendor = "Cloudflare", product = "Cloudflare (legacy id cookie)", class = "CDN",
    confidence = "certain" },
  { pattern = "__cf_bm", vendor = "Cloudflare", product = "Cloudflare Bot Management", class = "bot manager",
    confidence = "certain" },
  { pattern = "__cfruid", vendor = "Cloudflare", product = "Cloudflare rate limiting", class = "WAF",
    confidence = "certain" },
  { pattern = "cf_clearance", vendor = "Cloudflare", product = "Cloudflare challenge clearance", class = "WAF",
    confidence = "certain" },
  { pattern = "sucuri_cloudproxy_cookie", vendor = "Sucuri", product = "Sucuri cloud proxy", class = "WAF",
    confidence = "certain" },
  { pattern = "awsalb", vendor = "Amazon", product = "Application Load Balancer stickiness", class = "load balancer",
    confidence = "certain" },
  { pattern = "awsalbcors", vendor = "Amazon", product = "ALB stickiness (CORS variant)", class = "load balancer",
    confidence = "certain" },
  { pattern = "incap_ses_", vendor = "Imperva", product = "Imperva Incapsula session", class = "WAF",
    confidence = "certain" },
  { pattern = "visid_incap_", vendor = "Imperva", product = "Imperva visitor id", class = "WAF",
    confidence = "certain" },
  { pattern = "ak_bmsc", vendor = "Akamai", product = "Akamai Bot Manager", class = "bot manager",
    confidence = "certain" },
  { pattern = "bm_sz", vendor = "Akamai", product = "Akamai Bot Manager size cookie", class = "bot manager",
    confidence = "certain" },
  { pattern = "bm_sv", vendor = "Akamai", product = "Akamai Bot Manager verification", class = "bot manager",
    confidence = "certain" },
  { pattern = "bm_mi", vendor = "Akamai", product = "Akamai Bot Manager identity", class = "bot manager",
    confidence = "certain" },
  { pattern = "akacd_", vendor = "Akamai", product = "Akamai CDN session", class = "CDN",
    confidence = "probable" },
  { pattern = "bigipserver", vendor = "F5", product = "F5 BIG-IP persistence", class = "load balancer",
    confidence = "certain" },
  { pattern = "ts01", vendor = "F5", product = "F5 ASM/BIG-IP session", class = "WAF",
    confidence = "certain" },
  { pattern = "f5_fullsession", vendor = "F5", product = "F5 full session", class = "load balancer",
    confidence = "probable" },
  { pattern = "arraffinity", vendor = "Microsoft", product = "Azure App Service affinity", class = "load balancer",
    confidence = "certain" },
  { pattern = "arraffinitysame", vendor = "Microsoft", product = "Azure App Service affinity", class = "load balancer",
    confidence = "certain" },
  { pattern = "ns_af", vendor = "Citrix", product = "NetScaler affinity", class = "load balancer",
    confidence = "certain" },
  { pattern = "citrix_ns_id", vendor = "Citrix", product = "NetScaler session", class = "load balancer",
    confidence = "certain" },
  { pattern = "lb_idl_", vendor = "generic", product = "load balancer identifier", class = "load balancer",
    confidence = "possible" },
  { pattern = "jsessionid", vendor = "Java", product = "Java servlet container session", class = "application",
    confidence = "probable" },
  { pattern = "phpsessid", vendor = "PHP", product = "PHP session", class = "application",
    confidence = "probable" },
  { pattern = "asp%.net_sessionid", vendor = "Microsoft", product = "ASP.NET session", class = "application",
    confidence = "probable" },
  { pattern = "wordpress_", vendor = "WordPress", product = "WordPress", class = "CMS",
    confidence = "probable" },
  { pattern = "wp-settings-", vendor = "WordPress", product = "WordPress settings", class = "CMS",
    confidence = "probable" },
  { pattern = "drupal_", vendor = "Drupal", product = "Drupal", class = "CMS",
    confidence = "probable" },
  { pattern = "has_js", vendor = "Drupal", product = "Drupal JS detection", class = "CMS",
    confidence = "probable" },
  { pattern = "mage-", vendor = "Magento", product = "Magento", class = "commerce platform",
    confidence = "probable" },
  { pattern = "shopify", vendor = "Shopify", product = "Shopify", class = "commerce platform",
    confidence = "probable" },
}

local BODY_FINGERPRINTS = {
  { pattern = "cf-error-details", vendor = "Cloudflare", product = "Cloudflare error page", class = "CDN + WAF",
    confidence = "certain" },
  { pattern = "cf-browser-verification", vendor = "Cloudflare", product = "Cloudflare JS challenge", class = "bot manager",
    confidence = "certain" },
  { pattern = "cf-challenge", vendor = "Cloudflare", product = "Cloudflare challenge", class = "bot manager",
    confidence = "certain" },
  { pattern = "attention required! | cloudflare", vendor = "Cloudflare", product = "Cloudflare block page",
    class = "WAF", confidence = "certain" },
  { pattern = "cloudflare ray id", vendor = "Cloudflare", product = "Cloudflare block page", class = "WAF",
    confidence = "certain" },
  { pattern = "cf-ray", vendor = "Cloudflare", product = "Cloudflare marker in body", class = "CDN",
    confidence = "probable" },
  { pattern = "reference #", vendor = "Akamai", product = "Akamai block page", class = "WAF",
    confidence = "certain" },
  { pattern = "akamai", vendor = "Akamai", product = "Akamai marker", class = "CDN",
    confidence = "probable" },
  { pattern = "incapsula incident id", vendor = "Imperva", product = "Imperva Incapsula block page", class = "WAF",
    confidence = "certain" },
  { pattern = "request unsuccessful. incapsula", vendor = "Imperva", product = "Imperva block page", class = "WAF",
    confidence = "certain" },
  { pattern = "_Incapsula_Resource", vendor = "Imperva", product = "Imperva resource script", class = "WAF",
    confidence = "certain" },
  { pattern = "access denied - sucuri", vendor = "Sucuri", product = "Sucuri block page", class = "WAF",
    confidence = "certain" },
  { pattern = "sucuri website firewall", vendor = "Sucuri", product = "Sucuri block page", class = "WAF",
    confidence = "certain" },
  { pattern = "cloudproxy", vendor = "Sucuri", product = "Sucuri cloud proxy marker", class = "WAF",
    confidence = "probable" },
  { pattern = "generated by cloudfront", vendor = "Amazon", product = "CloudFront error page", class = "CDN",
    confidence = "certain" },
  { pattern = "request blocked", vendor = "Amazon", product = "AWS WAF block page", class = "WAF",
    confidence = "probable" },
  { pattern = "aws waf", vendor = "Amazon", product = "AWS WAF marker", class = "WAF",
    confidence = "certain" },
  { pattern = "the requested url was rejected", vendor = "F5", product = "F5 BIG-IP ASM block page", class = "WAF",
    confidence = "certain" },
  { pattern = "your support id is", vendor = "F5", product = "F5 ASM support id page", class = "WAF",
    confidence = "certain" },
  { pattern = "modsecurity action", vendor = "ModSecurity", product = "ModSecurity block page", class = "WAF",
    confidence = "certain" },
  { pattern = "mod_security", vendor = "ModSecurity", product = "ModSecurity marker", class = "WAF",
    confidence = "certain" },
  { pattern = "this site is protected by", vendor = "generic", product = "generic protection banner", class = "WAF",
    confidence = "possible" },
  { pattern = "web application firewall", vendor = "generic", product = "generic WAF page", class = "WAF",
    confidence = "probable" },
  { pattern = "fortiweb", vendor = "Fortinet", product = "FortiWeb block page", class = "WAF",
    confidence = "certain" },
  { pattern = "safeline", vendor = "Chaitin", product = "SafeLine block page", class = "WAF",
    confidence = "certain" },
  { pattern = "wordfence", vendor = "Wordfence", product = "Wordfence WAF (WordPress)", class = "WAF plugin",
    confidence = "certain" },
  { pattern = "sitelock", vendor = "SiteLock", product = "SiteLock TrueShield", class = "WAF",
    confidence = "certain" },
  { pattern = "astra security", vendor = "Astra", product = "Astra WAF", class = "WAF",
    confidence = "certain" },
  { pattern = "webknight", vendor = "AQTRONIX", product = "WebKnight block page", class = "WAF",
    confidence = "certain" },
  { pattern = "naxsi", vendor = "naxsi", product = "Naxsi block page", class = "WAF",
    confidence = "certain" },
  { pattern = "yunsuo", vendor = "Yunsuo", product = "Yunsuo block page", class = "WAF",
    confidence = "certain" },
  { pattern = "anquanbao", vendor = "Anquanbao", product = "Anquanbao block page", class = "WAF",
    confidence = "certain" },
  { pattern = "jiasule", vendor = "Jiasule", product = "Jiasule block page", class = "WAF",
    confidence = "certain" },
  { pattern = "safedog", vendor = "Safedog", product = "Safedog block page", class = "WAF",
    confidence = "certain" },
  { pattern = "knownsec", vendor = "Knownsec", product = "Knownsec block page", class = "WAF",
    confidence = "certain" },
  { pattern = "sangfor", vendor = "Sangfor", product = "Sangfor NGAF block page", class = "WAF",
    confidence = "certain" },
  { pattern = "barracuda", vendor = "Barracuda", product = "Barracuda block page", class = "WAF",
    confidence = "certain" },
  { pattern = "airlock", vendor = "ERCON", product = "Airlock block page", class = "WAF",
    confidence = "certain" },
  { pattern = "radware", vendor = "Radware", product = "Radware AppWall block page", class = "WAF",
    confidence = "certain" },
  { pattern = "dotdefender", vendor = "Applicure", product = "dotDefender block page", class = "WAF",
    confidence = "certain" },
  { pattern = "denied by urlscan", vendor = "Microsoft", product = "UrlScan block page", class = "WAF",
    confidence = "certain" },
  { pattern = "tencent cloud", vendor = "Tencent", product = "Tencent Cloud WAF/CDN page", class = "WAF + CDN",
    confidence = "probable" },
  { pattern = "aliyun", vendor = "Alibaba", product = "Alibaba Cloud WAF/CDN page", class = "WAF + CDN",
    confidence = "probable" },
  { pattern = "huaweicloud", vendor = "Huawei", product = "Huawei Cloud WAF page", class = "WAF",
    confidence = "probable" },
  { pattern = "baidu yunjiasu", vendor = "Baidu", product = "Baidu Yunjiasu CDN/WAF", class = "WAF + CDN",
    confidence = "certain" },
  { pattern = "360wzb", vendor = "360", product = "360 Wangzhan WAF", class = "WAF",
    confidence = "certain" },
  { pattern = "please enable cookies", vendor = "generic", product = "cookie challenge interstitial",
    class = "bot manager", confidence = "possible" },
  { pattern = "checking your browser", vendor = "generic", product = "browser challenge interstitial",
    class = "bot manager", confidence = "probable" },
  { pattern = "verifying you are human", vendor = "generic", product = "human verification interstitial",
    class = "bot manager", confidence = "probable" },
  { pattern = "captcha-delivery", vendor = "DataDome", product = "DataDome captcha", class = "bot manager",
    confidence = "certain" },
  { pattern = "datadome", vendor = "DataDome", product = "DataDome", class = "bot manager",
    confidence = "certain" },
  { pattern = "perimeterx", vendor = "PerimeterX/HUMAN", product = "PerimeterX Bot Defender", class = "bot manager",
    confidence = "certain" },
  { pattern = "px-captcha", vendor = "PerimeterX/HUMAN", product = "PerimeterX captcha", class = "bot manager",
    confidence = "certain" },
  { pattern = "kasada", vendor = "Kasada", product = "Kasada Bot Defense", class = "bot manager",
    confidence = "certain" },
  { pattern = "hapee", vendor = "HAPEE", product = "HAPEE WAF", class = "WAF",
    confidence = "certain" },
  { pattern = "shadow daemon", vendor = "Shadow Daemon", product = "Shadow Daemon", class = "WAF",
    confidence = "certain" },
  { pattern = "lua-resty-waf", vendor = "OpenResty", product = "lua-resty-waf", class = "WAF",
    confidence = "certain" },
}

local STATUS_FINGERPRINTS = {
  { status = 403, vendor = "generic", product = "access control or WAF deny", class = "WAF/ACL",
    confidence = "possible" },
  { status = 406, vendor = "generic", product = "content negotiation rejection (ModSecurity/UrlScan pattern)",
    class = "WAF", confidence = "possible" },
  { status = 418, vendor = "generic", product = "teapot response used as a WAF block signal",
    class = "WAF", confidence = "probable" },
  { status = 419, vendor = "generic", product = "authentication timeout (Laravel/F5 pattern)",
    class = "application", confidence = "possible" },
  { status = 420, vendor = "Twitter/generic", product = "enhance your calm (rate limiting)",
    class = "rate limiting", confidence = "possible" },
  { status = 444, vendor = "nginx", product = "nginx 'close connection without response'",
    class = "web server", confidence = "certain" },
  { status = 499, vendor = "nginx", product = "nginx client closed request", class = "web server",
    confidence = "certain" },
  { status = 520, vendor = "Cloudflare", product = "Cloudflare unknown error", class = "CDN",
    confidence = "certain" },
  { status = 521, vendor = "Cloudflare", product = "Cloudflare web server down", class = "CDN",
    confidence = "certain" },
  { status = 522, vendor = "Cloudflare", product = "Cloudflare connection timed out", class = "CDN",
    confidence = "certain" },
  { status = 523, vendor = "Cloudflare", product = "Cloudflare origin unreachable", class = "CDN",
    confidence = "certain" },
  { status = 524, vendor = "Cloudflare", product = "Cloudflare timeout", class = "CDN",
    confidence = "certain" },
  { status = 525, vendor = "Cloudflare", product = "Cloudflare SSL handshake failed", class = "CDN",
    confidence = "certain" },
  { status = 526, vendor = "Cloudflare", product = "Cloudflare invalid SSL certificate", class = "CDN",
    confidence = "certain" },
  { status = 527, vendor = "Cloudflare", product = "Cloudflare railgun error", class = "CDN",
    confidence = "certain" },
  { status = 530, vendor = "Cloudflare/Amazon", product = "origin DNS error (Cloudflare 1016 / ALB)",
    class = "CDN", confidence = "probable" },
  { status = 999, vendor = "LinkedIn/generic", product = "non-standard block status", class = "WAF",
    confidence = "probable" },
}

local BENIGN_PROBES = {
  { name = "sqlish-query", kind = "query",
    value = "?id=1&sort=name&filter=nse_audit_1%20or%201=1",
    note = "a harmless tautology string in a query parameter" },
  { name = "scriptish-path", kind = "path",
    value = "/nse-audit-<script>alert(1)</script>",
    note = "an inert script tag literal in the URL path" },
  { name = "traversal-ish-path", kind = "path",
    value = "/nse-audit/..%2f..%2fetc/passwd",
    note = "an encoded traversal sequence in the path" },
  { name = "odd-useragent", kind = "header",
    value = "sqlmap/1.7#stable (NSE benign fingerprint probe)",
    note = "a scanner-like User-Agent string" },
  { name = "many-params", kind = "query",
    value = "?a=1&a=2&a=3&a=4&a=5&a=6&a=7&a=8&a=9&a=10&a=11&a=12",
    note = "twelve repeated query parameters (parameter pollution)" },
  { name = "long-header", kind = "header",
    value = nil,
    note = "an oversized custom header value" },
  { name = "admin-path", kind = "path",
    value = "/admin/config.php.bak",
    note = "a path typical of backup-file probing" },
  { name = "nullbyte-path", kind = "path",
    value = "/index.html%00.jpg",
    note = "a null byte in the path extension" },
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 5,
  maxrequests = 70,
  retries = 2,
  timeout = 8000,
  delay = 0.05,
  behaviour = true,
  soft404 = true,
  useragent = nil,
  maxbodysize = 131072,
}

local NUMERIC_ARGS = {
  { key = "maxpaths", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 4, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxbodysize", minimum = 1024, integer = true },
}

local BOOLEAN_ARGS = { "behaviour", "soft404" }

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

local function match_vendor_tables(response, identifications)
  local body = lower(response.body or "")
  local body_preview = trim(string.gsub(string.sub(response.body or "", 1, 4096), "[\r\n\t]+", " "))

  for _, entry in ipairs(HEADER_FINGERPRINTS) do
    local values = header_values(response, entry.header)
    for _, value in ipairs(values) do
      table.insert(identifications, {
        source = "header",
        vendor = entry.vendor,
        product = entry.product,
        class = entry.class,
        confidence = entry.confidence,
        leaks = entry.leaks,
        evidence = entry.header .. ": " .. truncate(value, 96),
      })
    end
  end

  local server = lower(header_value(response, "server") or "")
  if #server > 0 then
    local matched_any = false
    for _, entry in ipairs(SERVER_FINGERPRINTS) do
      local found = string.find(server, entry.pattern, 1, true)
        or string.find(server, entry.pattern)
      if found then
        matched_any = true
        local version = nil
        if entry.version then
          version = string.match(header_value(response, "server") or "", "(%d+%.%d+[%.%d%w%-]*)")
        end
        table.insert(identifications, {
          source = "server-header",
          vendor = entry.vendor,
          product = entry.product,
          class = entry.class,
          confidence = entry.confidence,
          version = version,
          evidence = "Server: " .. truncate(header_value(response, "server"), 96),
        })
      end
    end
    if not matched_any and #server > 0 then
      table.insert(identifications, {
        source = "server-header",
        vendor = "unknown",
        product = "unrecognised Server value",
        class = "web server",
        confidence = "possible",
        evidence = "Server: " .. truncate(server, 96),
      })
    end
    if string.find(server, "%d+%.%d+") then
      add_finding("LOW", string.format("Server header discloses a version string (%s)",
        truncate(header_value(response, "server"), 80)),
        { subject = "version-disclosure", evidence = server })
    end
  end

  local via = header_value(response, "via")
  if via then
    for chunk in string.gmatch(via, "[^,]+") do
      local trimmed = trim(chunk)
      table.insert(identifications, {
        source = "via",
        vendor = "generic",
        product = "proxy hop",
        class = "reverse proxy",
        confidence = "probable",
        leaks = "intermediate proxy software/version",
        evidence = "Via: " .. truncate(trimmed, 96),
      })
    end
  end

  local set_cookies = header_values(response, "set-cookie")
  for _, raw in ipairs(set_cookies) do
    local name = lower(string.match(raw, "^%s*([^=;]+)") or "")
    for _, entry in ipairs(COOKIE_FINGERPRINTS) do
      if string.find(name, entry.pattern, 1, true) or string.find(name, entry.pattern) then
        table.insert(identifications, {
          source = "cookie",
          vendor = entry.vendor,
          product = entry.product,
          class = entry.class,
          confidence = entry.confidence,
          leaks = "cookie name identifies the edge product",
          evidence = "Set-Cookie: " .. truncate(name, 48),
        })
      end
    end
  end

  if #body > 0 and #body < 65536 then
    for _, entry in ipairs(BODY_FINGERPRINTS) do
      if string.find(body, entry.pattern, 1, true) then
        table.insert(identifications, {
          source = "body",
          vendor = entry.vendor,
          product = entry.product,
          class = entry.class,
          confidence = entry.confidence,
          leaks = "block/challenge page content",
          evidence = truncate(body_preview, 110),
        })
      end
    end
  end

  for _, entry in ipairs(STATUS_FINGERPRINTS) do
    if response.status == entry.status then
      table.insert(identifications, {
        source = "status",
        vendor = entry.vendor,
        product = entry.product,
        class = entry.class,
        confidence = entry.confidence,
        evidence = "HTTP " .. tostring(entry.status),
      })
    end
  end

  return identifications
end

local function group_identifications(identifications)
  local grouped = {}
  local order = {}

  for _, entry in ipairs(identifications) do
    local key = string.format("%s|%s|%s", entry.vendor, entry.product, entry.source)
    if not grouped[key] then
      grouped[key] = {
        vendor = entry.vendor,
        product = entry.product,
        class = entry.class or "unclassified",
        confidence = entry.confidence,
        sources = {},
        evidence = {},
        leaks = {},
        version = entry.version,
        count = 0,
      }
      table.insert(order, key)
    end
    local group = grouped[key]
    group.count = group.count + 1
    if entry.source and not list_contains(group.sources, entry.source) then
      table.insert(group.sources, entry.source)
    end
    if entry.evidence then
      local sample = truncate(entry.evidence, 110)
      if not list_contains(group.evidence, sample) and #group.evidence < 4 then
        table.insert(group.evidence, sample)
      end
    end
    if entry.leaks and not list_contains(group.leaks, entry.leaks) then
      table.insert(group.leaks, entry.leaks)
    end
    if entry.version and not group.version then
      group.version = entry.version
    end
    local rank = { certain = 3, probable = 2, possible = 1 }
    if (rank[entry.confidence] or 0) > (rank[group.confidence] or 0) then
      group.confidence = entry.confidence
    end
  end

  local sorted = {}
  for _, key in ipairs(order) do
    table.insert(sorted, grouped[key])
  end
  local rank = { certain = 3, probable = 2, possible = 1 }
  table.sort(sorted, function(a, b)
    local ra = rank[a.confidence] or 0
    local rb = rank[b.confidence] or 0
    if ra ~= rb then
      return ra > rb
    end
    if a.count ~= b.count then
      return a.count > b.count
    end
    return tostring(a.vendor) < tostring(b.vendor)
  end)

  return sorted
end

local function score_confidence(groups)
  local certain = 0
  local probable = 0
  local possible = 0
  for _, group in ipairs(groups) do
    if group.confidence == "certain" then
      certain = certain + 1
    elseif group.confidence == "probable" then
      probable = probable + 1
    else
      possible = possible + 1
    end
  end
  return certain, probable, possible
end

local function run_behavioural_probes(host, port, path, args, baseline)
  local behaviour = {
    path = path,
    probes = 0,
    differences = {},
    baseline = nil,
  }

  local base, base_err = fetch(host, port, path, args)
  if not base then
    behaviour.error = tostring(base_err)
    return behaviour
  end

  behaviour.baseline = {
    status = base.status or 0,
    length = #(base.body or ""),
    hash = fnv1a32(base.body or ""),
    server = header_value(base, "server"),
  }

  local base_info = classify_response(path, base, baseline)
  if base_info.confidence == "low" then
    behaviour.note = "baseline response is low confidence (" .. table.concat(base_info.notes, "; ") .. ")"
  end

  for _, probe in ipairs(BENIGN_PROBES) do
    if budget_exhausted(args) then
      table.insert(behaviour.differences, "budget exhausted before probe '" .. probe.name .. "'")
      break
    end
    behaviour.probes = behaviour.probes + 1

    local target = path
    local extra = {}
    if probe.kind == "query" then
      local separator = contains(path, "?") and "&" or "?"
      target = path .. separator .. string.gsub(probe.value, "^%?", "")
    elseif probe.kind == "path" then
      target = probe.value
    elseif probe.kind == "header" then
      if probe.name == "long-header" then
        extra["X-NSE-Long"] = string.rep("A", 4096)
      elseif probe.name == "odd-useragent" then
        extra["User-Agent"] = probe.value
      else
        extra["X-NSE-Probe"] = probe.value
      end
    end

    local response, err = fetch(host, port, target, args, extra)
    if not response then
      table.insert(behaviour.differences, string.format("%s: %s", probe.name, tostring(err)))
      goto continue_probe
    end

    local info = classify_response(target, response, baseline)
    local probe_hash = fnv1a32(response.body or "")
    local delta = {
      probe = probe.name,
      note = probe.note,
      status_delta = (response.status or 0) - (base.status or 0),
      length_delta = #(response.body or "") - behaviour.baseline.length,
      hash_changed = probe_hash ~= behaviour.baseline.hash,
      confidence = info.confidence,
    }

    if delta.status_delta ~= 0 or delta.hash_changed then
      table.insert(behaviour.differences, delta)
      local severity = "MEDIUM"
      if delta.status_delta == 403 - (base.status or 0) or (response.status == 403 and base.status == 200) then
        severity = "HIGH"
      elseif delta.status_delta == 0 and delta.hash_changed then
        severity = "LOW"
      end
      add_finding(severity, string.format(
        "filtering layer is active: probe '%s' (%s) changed the response from HTTP %d/%d bytes to HTTP %d/%d bytes",
        probe.name, probe.note, base.status or 0, behaviour.baseline.length,
        response.status or 0, #(response.body or "")),
        { path = target, subject = "behaviour:" .. probe.name, confidence = info.confidence,
          evidence = truncate(response.body or "", 90) })

      local identifications = match_vendor_tables(response, {})
      for _, group in ipairs(group_identifications(identifications)) do
        add_finding(group.confidence == "certain" and "INFO" or "INFO",
          string.format("block response for probe '%s' identifies %s (%s)",
            probe.name, group.product, group.vendor),
          { path = target, subject = "behaviour-vendor:" .. group.vendor,
            confidence = info.confidence, evidence = group.evidence[1] })
      end
    end

    ::continue_probe::
  end

  return behaviour
end

local function hiding_analysis(groups, response)
  local notes = {}
  local server = header_value(response, "server")
  if not server then
    table.insert(notes, "Server header is stripped at the edge")
  elseif #server > 0 and not string.find(server, "%d") then
    table.insert(notes, "Server header carries no version (" .. server .. ")")
  end
  if not header_value(response, "x-powered-by") then
    table.insert(notes, "X-Powered-By is not present")
  end
  local wafish = false
  for _, group in ipairs(groups) do
    if contains(lower(group.class or ""), "waf") or contains(lower(group.class or ""), "bot") then
      wafish = true
    end
  end
  if wafish then
    table.insert(notes, "a filtering product is in the path; error pages and status codes may be normalised")
  end
  return notes
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local baseline = build_soft404_baseline(host, port, args)
  local paths = select_paths(args)

  local all_identifications = {}
  local path_lines = {}
  local behaviours = {}
  local representative_response = nil

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

    representative_response = representative_response or response
    local info = classify_response(path, response, baseline)
    local identifications = match_vendor_tables(response, {})
    for _, entry in ipairs(identifications) do
      entry.path = path
      table.insert(all_identifications, entry)
    end

    table.insert(path_lines, string.format("%s -> HTTP %s, %d bytes, %d fingerprint(s)%s",
      path, tostring(info.status), info.length, #identifications,
      info.confidence == "low" and " [low confidence: " .. table.concat(info.notes, "; ") .. "]" or ""))

    if args.behaviour and not budget_exhausted(args) then
      table.insert(behaviours, run_behavioural_probes(host, port, path, args, baseline))
    end

    ::continue_path::
  end

  local groups = group_identifications(all_identifications)
  local certain, probable, possible = score_confidence(groups)

  for _, group in ipairs(groups) do
    local severity = "INFO"
    if contains(lower(group.class or ""), "waf") or contains(lower(group.class or ""), "bot") then
      severity = group.confidence == "certain" and "MEDIUM" or "LOW"
      add_finding(severity, string.format("%s detected (%s, confidence: %s)",
        group.product, group.vendor, group.confidence),
        { subject = group.vendor, evidence = group.evidence[1] })
    else
      add_finding("INFO", string.format("%s detected (%s, confidence: %s)",
        group.product, group.vendor, group.confidence),
        { subject = group.vendor, evidence = group.evidence[1] })
    end
    local edge_class = contains(lower(group.class or ""), "waf")
      or contains(lower(group.class or ""), "cdn")
      or contains(lower(group.class or ""), "bot")
      or contains(lower(group.class or ""), "proxy")
      or contains(lower(group.class or ""), "cache")
      or contains(lower(group.class or ""), "balancer")
      or contains(lower(group.class or ""), "mesh")
    if group.leaks and #group.leaks > 0 and edge_class then
      add_finding("LOW", string.format("%s leaks %s", group.product, table.concat(group.leaks, ", ")),
        { subject = group.vendor .. ":leak", evidence = group.evidence[1] })
    end
    if group.version then
      add_finding("LOW", string.format("%s version token observed: %s", group.product, group.version),
        { subject = group.vendor .. ":version", evidence = group.version })
    end
  end

  local filtered = false
  for _, behaviour in ipairs(behaviours) do
    for _, delta in ipairs(behaviour.differences) do
      if type(delta) == "table" then
        filtered = true
      end
    end
  end

  local unique, counts = dedupe_findings()

  local out = new_output(RISK_LEVEL, "AUDITED - edge/WAF fingerprinting completed.")
  if #groups == 0 then
    out["Status"] = "AUDITED - no WAF, CDN or reverse proxy could be fingerprinted."
  elseif certain > 0 and filtered then
    out["Status"] = "AUDITED - a filtering product is present and demonstrably alters responses."
  elseif certain > 0 then
    out["Status"] = "AUDITED - a filtering/edge product is present (passive fingerprint)."
  elseif probable > 0 then
    out["Status"] = "AUDITED - probable edge/WAF presence from secondary signals."
  else
    out["Status"] = "AUDITED - only weak signals observed; no product could be attributed."
  end

  local group_lines = {}
  for _, group in ipairs(groups) do
    table.insert(group_lines, string.format("[%s] %s — %s (class: %s, signals: %s, hits: %d)",
      group.confidence, group.vendor, group.product, group.class or "?",
      table.concat(group.sources, "+"), group.count))
    for _, evidence in ipairs(group.evidence) do
      table.insert(group_lines, "      " .. evidence)
    end
  end

  local behaviour_lines = {}
  for _, behaviour in ipairs(behaviours) do
    if behaviour.baseline then
      table.insert(behaviour_lines, string.format("%s baseline: HTTP %d / %d bytes / hash %s; %d benign probes",
        behaviour.path, behaviour.baseline.status, behaviour.baseline.length,
        behaviour.baseline.hash, behaviour.probes or 0))
    end
    for _, delta in ipairs(behaviour.differences or {}) do
      if type(delta) == "table" then
        table.insert(behaviour_lines, string.format("      %s: status %+d, length %+d, body %s",
          delta.probe, delta.status_delta, delta.length_delta,
          delta.hash_changed and "changed" or "unchanged"))
      else
        table.insert(behaviour_lines, "      " .. tostring(delta))
      end
    end
    if behaviour.note then
      table.insert(behaviour_lines, "      " .. behaviour.note)
    end
  end

  local classes = {}
  for _, group in ipairs(groups) do
    classes[group.class or "unclassified"] = (classes[group.class or "unclassified"] or 0) + 1
  end
  local class_lines = {}
  for _, key in ipairs(sorted_keys(classes)) do
    table.insert(class_lines, string.format("%s: %d", key, classes[key]))
  end

  local hiding = {}
  if representative_response then
    hiding = hiding_analysis(groups, representative_response)
  end

  local sections = {
    { key = "Transport", value = (port.ssl or (port.version and port.version.service_ssl)) and "HTTPS" or "HTTP" },
    { key = "Identifications", value = string.format("certain=%d probable=%d possible=%d (raw signals: %d)",
      certain, probable, possible, #all_identifications) },
    { key = "Products", value = #group_lines > 0 and group_lines or { "no product fingerprinted" } },
    { key = "Product classes", value = class_lines },
  }

  if #behaviour_lines > 0 then
    table.insert(sections, { key = "Behavioural probing", value = behaviour_lines })
  end
  if #hiding > 0 then
    table.insert(sections, { key = "Edge normalisation", value = hiding })
  end
  table.insert(sections, { key = "Path results", value = path_lines })
  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end

  local baseline_blocked = false
  for _, behaviour in ipairs(behaviours) do
    if behaviour.baseline and (behaviour.baseline.status == 403 or behaviour.baseline.status == 406
      or behaviour.baseline.status == 418 or behaviour.baseline.status >= 520) then
      baseline_blocked = true
    end
  end

  if filtered then
    table.insert(sections, { key = "Interpretation", value =
      "responses differ between benign requests: a filtering layer is active, so every other finding from this "
      .. "collection must be read together with the block/challenge behaviour reported here" })
  elseif baseline_blocked then
    table.insert(sections, { key = "Interpretation", value =
      "every benign request is already denied at the edge: the filtering product enforces by default, so origin "
      .. "behaviour cannot be measured from this position" })
  elseif certain > 0 then
    table.insert(sections, { key = "Interpretation", value =
      "the product announces itself but did not alter any benign probe: it is present, not necessarily enforcing "
      .. "against this traffic profile" })
  else
    table.insert(sections, { key = "Interpretation", value =
      "no edge product fingerprinted; the origin answers directly, so server and framework disclosure findings "
      .. "apply to the real service" })
  end

  table.insert(sections, { key = "Remediation", value =
    "remove edge identifiers that are not required (cf-ray/x-served-by/x-backend-server), normalise error pages, "
    .. "and keep the behavioural probes in your change management: a silent WAF policy change is invisible otherwise" })

  return finish_output(out, unique, counts, sections)

end
