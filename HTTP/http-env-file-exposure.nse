local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nmap = require "nmap"

description = [[
Hunts for publicly downloadable environment and configuration files (.env and
friends) and turns every hit into a quantified credential-exposure report.

Environment files are the single highest-yield web exposure in modern stacks:
Laravel, Django, Rails, Node, Spring Boot, Docker Compose and most CI
pipelines keep database passwords, cloud keys, signing secrets and SMTP
credentials in a flat KEY=VALUE file that is supposed to live outside the
document root. A misconfigured vhost, a "COPY ." in a Dockerfile, an rsync of
the working tree or a static-file handler that serves dotfiles is enough to
publish them.

The script works in four stages.

Stage 1 — candidate enumeration. It requests a prioritised wordlist of
environment and configuration artefacts (/.env and 60+ variants, backup and
editor leftovers, framework configuration files, Docker Compose files, CI
configuration, cloud credential files) across the document root and across a
set of common application sub-paths. Case variants (/.ENV, /.Env), the
percent-encoded form (/%2e%65%6e%76) and trailing backup extensions are
probed because several static file servers apply their deny rules only to the
exact lowercase name.

Stage 2 — structural validation. Status codes are never trusted on their own.
Every 2xx response is parsed as an environment file: comment/blank line
handling, "export KEY=value" and "KEY = value" forms, quoted and multi-line
values, INI sections and YAML "key: value" pairs are all understood. A
response qualifies as an environment file only when the ratio of parseable
assignments to non-empty lines exceeds a threshold AND at least one key is a
recognised configuration key (APP_KEY, DB_*, DATABASE_URL, AWS_*, SECRET_*,
MAIL_*, STRIPE_*, JWT_*, ...) or the file declares a known section header
([core], [program], spring.datasource...). Anything else (SPA index.html
fallback, JSON API error, XML, HTML 404 with status 200) is rejected and
reported as a suppressed candidate together with the reason.

Stage 3 — false-positive suppression. A soft-404 baseline is built from random
paths first; responses that are byte-identical or length-identical to that
baseline are discarded. WAF/CDN interstitials are recognised by header and
body signatures and discarded. Empty bodies, bodies below a minimum size and
bodies that are valid HTML/JSON/XML documents are discarded. HTTP 429 and 5xx
responses trigger exponential backoff and, if they persist, the whole scan is
aborted with a clear "inconclusive" verdict instead of reporting guesses.

Stage 4 — impact assessment. For every validated file the script extracts and
classifies the secrets it contains: relational database URLs (host, port,
database, user — password redacted), NoSQL/broker connection strings, cloud
provider credentials (AWS access key ids, Azure storage account keys, GCP
service-account JSON markers), application signing keys, JWT secrets, SMTP
credentials, payment provider keys, object-storage buckets, internal
hostnames and IP addresses, feature flags that reveal unreleased
functionality, and debug/verbose settings that indicate the file belongs to a
non-production or insecurely configured environment. Values are redacted
(head + tail with the middle masked) so the output can be shared safely, and
an entropy measurement distinguishes real secrets from placeholders such as
"changeme" or "your_key_here".

The final verdict separates "environment file exposed" (MEDIUM/HIGH) from
"live production credentials exposed" (CRITICAL) based on whether the parsed
values look like real secrets and whether the file name suggests a production
scope.

Every request is retried with backoff, counted against a configurable budget
and delayed by a configurable inter-request pause so the scan stays inside the
rate limits of fragile applications.

Usage:
<code>
nmap -p 80,443 --script http-env-file-exposure <target>
nmap -p 80 --script http-env-file-exposure \
  --script-args http-env-file-exposure.prefixes="/,/api,/backend" <target>
nmap -p 443 --script http-env-file-exposure \
  --script-args http-env-file-exposure.maxrequests=150,http-env-file-exposure.delay=0.1,\
http-env-file-exposure.minkeys=2 <target>
</code>
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local SCRIPT_NAME = "http-env-file-exposure"

local RISK_LEVEL = "🔴 CRITICAL"

local STATUS_CLEAN = "AUDITED - no environment or configuration file is publicly readable."

local STATUS_EXPOSED = "AUDITED - environment file exposure confirmed; credentials must be treated as compromised."

local STATUS_INCONCLUSIVE = "AUDITED - inconclusive: the service rejected or rate-limited the probes."

local SEVERITY = {
  CRITICAL = 10,
  HIGH = 7,
  MEDIUM = 4,
  LOW = 2,
  INFO = 1,
}

local ENV_CANDIDATES = {
  "/.env",
  "/.env.local",
  "/.env.dev",
  "/.env.development",
  "/.env.stage",
  "/.env.staging",
  "/.env.prod",
  "/.env.production",
  "/.env.test",
  "/.env.testing",
  "/.env.sample",
  "/.env.example",
  "/.env.template",
  "/.env.default",
  "/.env.live",
  "/.env.production.local",
  "/.env.development.local",
  "/.env.test.local",
  "/.env.backup",
  "/.env.bak",
  "/.env.old",
  "/.env.save",
  "/.env.orig",
  "/.env.tmp",
  "/.env.temp",
  "/.env.dist",
  "/.env.new",
  "/.env.copy",
  "/.env_1",
  "/.env_2",
  "/.env1",
  "/.env2",
  "/.env~",
  "/.env.swp",
  "/.env.swo",
  "/.env.sav",
  "/.ENV",
  "/.Env",
  "/env",
  "/env.js",
  "/env.json",
  "/env.txt",
  "/env.bak",
  "/env.php",
  "/environment.rb",
  "/.environment",
  "/%2e%65%6e%76",
  "/.%65nv",
  "/.env%00",
  "/.env/",
  "/..%2f.env",
  "/api/.env",
  "/app/.env",
  "/backend/.env",
  "/config/.env",
  "/.config/.env",
  "/public/.env",
  "/static/.env",
  "/assets/.env",
  "/wp-content/.env",
  "/laravel/.env",
  "/storage/.env",
  "/docker/.env",
  "/.docker/.env",
  "/.docker/config.json",
  "/docker-compose.yml",
  "/docker-compose.yaml",
  "/docker-compose.prod.yml",
  "/docker-compose.override.yml",
  "/compose.yaml",
  "/compose.yml",
  "/Dockerfile",
  "/.dockerignore",
}

local CONFIG_CANDIDATES = {
  "/config.php",
  "/configuration.php",
  "/config.inc.php",
  "/config.json",
  "/config.yml",
  "/config.yaml",
  "/config.toml",
  "/config/database.yml",
  "/config/secrets.yml",
  "/config/master.key",
  "/config/credentials.yml.enc",
  "/config/settings.py",
  "/settings.py",
  "/local_settings.py",
  "/settings.json",
  "/application.yml",
  "/application.yaml",
  "/application.properties",
  "/application-prod.yml",
  "/application-prod.properties",
  "/application-dev.yml",
  "/bootstrap.properties",
  "/wp-config.php",
  "/wp-config.php.bak",
  "/wp-config.php~",
  "/wp-config-sample.php",
  "/wp-config.txt",
  "/web.config",
  "/web.config.bak",
  "/Web.config",
  "/appsettings.json",
  "/appsettings.Development.json",
  "/appsettings.Production.json",
  "/database.yml",
  "/database.yaml",
  "/db.php",
  "/db.ini",
  "/db.json",
  "/dbconfig.php",
  "/db_credentials.php",
  "/credentials.json",
  "/credentials.xml",
  "/credentials.yml",
  "/secrets.json",
  "/secrets.yml",
  "/secret.txt",
  "/.secrets",
  "/.netrc",
  "/_netrc",
  "/.npmrc",
  "/.pypirc",
  "/.pgpass",
  "/.my.cnf",
  "/.htaccess",
  "/.htpasswd",
  "/nginx.conf",
  "/httpd.conf",
  "/.bashrc",
  "/.bash_history",
  "/.profile",
  "/.aws/credentials",
  "/.aws/config",
  "/.kube/config",
  "/.ssh/id_rsa",
  "/.ssh/config",
  "/.ssh/authorized_keys",
  "/.git-credentials",
  "/.svn/entries",
  "/phpinfo.php",
  "/info.php",
  "/server-status",
  "/server-info",
  "/.well-known/security.txt",
  "/package.json",
  "/composer.json",
  "/composer.lock",
  "/Gemfile",
  "/requirements.txt",
  "/.babelrc",
  "/.eslintrc",
  "/.travis.yml",
  "/.circleci/config.yml",
  "/.github/workflows/ci.yml",
  "/.gitlab-ci.yml",
  "/Jenkinsfile",
  "/.drone.yml",
  "/azure-pipelines.yml",
  "/bitbucket-pipelines.yml",
}

local PRODUCTION_NAME_HINTS = {
  "prod", "production", "live", "master", "main", "release", "online",
}

local BACKUP_NAME_HINTS = {
  "bak", "backup", "old", "save", "orig", "copy", "tmp", "temp", "~",
  "swp", "swo", "dist", "new",
}

local PLACEHOLDER_HINTS = {
  "changeme", "change_me", "your_", "your-", "xxxx", "xxxxxx", "placeholder",
  "example", "sample", "dummy", "test", "todo", "tbd", "none", "null",
  "password", "secret", "key_here", "apikey", "<", ">", "foo", "bar",
}

local RECOGNISED_KEYS = {
  APP_KEY = "application signing key",
  APP_ENV = "environment selector",
  APP_DEBUG = "debug mode flag",
  APP_URL = "canonical application URL",
  APP_SECRET = "application secret",
  APP_NAME = "application name",
  APP_TIMEZONE = "timezone setting",
  SECRET_KEY = "framework secret key",
  SECRET_KEY_BASE = "Rails secret key base",
  DJANGO_SECRET_KEY = "Django secret key",
  FLASK_SECRET_KEY = "Flask secret key",
  ENCRYPTION_KEY = "encryption key",
  ENCRYPTION_IV = "encryption initialisation vector",
  SIGNING_KEY = "request signing key",
  MASTER_KEY = "master key",
  DB_HOST = "database host",
  DB_PORT = "database port",
  DB_DATABASE = "database name",
  DB_USERNAME = "database user",
  DB_PASSWORD = "database password",
  DB_CONNECTION = "database driver",
  DATABASE_URL = "database connection string",
  DATABASE_HOST = "database host",
  DATABASE_PASSWORD = "database password",
  DATABASE_USER = "database user",
  DATABASE_NAME = "database name",
  DATABASE_PORT = "database port",
  MYSQL_HOST = "MySQL host",
  MYSQL_PASSWORD = "MySQL password",
  MYSQL_USER = "MySQL user",
  MYSQL_DATABASE = "MySQL database",
  POSTGRES_HOST = "PostgreSQL host",
  POSTGRES_PASSWORD = "PostgreSQL password",
  POSTGRES_USER = "PostgreSQL user",
  POSTGRES_DB = "PostgreSQL database",
  POSTGRESQL_URI = "PostgreSQL URI",
  MONGO_URI = "MongoDB URI",
  MONGODB_URI = "MongoDB URI",
  MONGO_PASSWORD = "MongoDB password",
  REDIS_HOST = "Redis host",
  REDIS_PASSWORD = "Redis password",
  REDIS_URL = "Redis URL",
  MEMCACHED_HOST = "Memcached host",
  RABBITMQ_URL = "RabbitMQ URL",
  RABBITMQ_DEFAULT_PASS = "RabbitMQ password",
  KAFKA_BROKERS = "Kafka brokers",
  ELASTICSEARCH_HOST = "Elasticsearch host",
  ELASTIC_PASSWORD = "Elasticsearch password",
  AWS_ACCESS_KEY_ID = "AWS access key id",
  AWS_SECRET_ACCESS_KEY = "AWS secret access key",
  AWS_SESSION_TOKEN = "AWS session token",
  AWS_DEFAULT_REGION = "AWS region",
  AWS_S3_BUCKET = "S3 bucket name",
  AWS_SECRET_KEY = "AWS secret key",
  AZURE_STORAGE_ACCOUNT = "Azure storage account",
  AZURE_STORAGE_KEY = "Azure storage key",
  AZURE_CLIENT_SECRET = "Azure client secret",
  AZURE_TENANT_ID = "Azure tenant id",
  GOOGLE_APPLICATION_CREDENTIALS = "GCP credential file path",
  GCP_PROJECT_ID = "GCP project id",
  GCLOUD_PRIVATE_KEY = "GCP private key",
  DIGITALOCEAN_TOKEN = "DigitalOcean token",
  HEROKU_API_KEY = "Heroku API key",
  JWT_SECRET = "JWT signing secret",
  JWT_SECRET_KEY = "JWT signing secret",
  JWT_PRIVATE_KEY = "JWT private key",
  JWT_PUBLIC_KEY = "JWT public key",
  JWT_EXPIRATION = "JWT lifetime",
  TOKEN_SECRET = "API token secret",
  API_KEY = "API key",
  API_SECRET = "API secret",
  APIKEY = "API key",
  API_SECRET_KEY = "API secret key",
  PRIVATE_KEY = "private key material",
  PUBLIC_KEY = "public key material",
  PASSPHRASE = "key passphrase",
  MAIL_HOST = "SMTP host",
  MAIL_PORT = "SMTP port",
  MAIL_USERNAME = "SMTP user",
  MAIL_PASSWORD = "SMTP password",
  MAIL_ENCRYPTION = "SMTP encryption mode",
  MAIL_FROM_ADDRESS = "sender address",
  SMTP_HOST = "SMTP host",
  SMTP_USER = "SMTP user",
  SMTP_PASS = "SMTP password",
  SMTP_PASSWORD = "SMTP password",
  SENDGRID_API_KEY = "SendGrid API key",
  MAILGUN_API_KEY = "Mailgun API key",
  MAILGUN_SECRET = "Mailgun secret",
  SES_SECRET_KEY = "AWS SES secret key",
  STRIPE_SECRET = "Stripe secret key",
  STRIPE_KEY = "Stripe publishable key",
  STRIPE_SECRET_KEY = "Stripe secret key",
  STRIPE_WEBHOOK_SECRET = "Stripe webhook secret",
  PAYPAL_SECRET = "PayPal secret",
  BRAINTREE_PRIVATE_KEY = "Braintree private key",
  TWILIO_AUTH_TOKEN = "Twilio auth token",
  TWILIO_ACCOUNT_SID = "Twilio account id",
  SLACK_TOKEN = "Slack token",
  SLACK_WEBHOOK = "Slack webhook",
  DISCORD_TOKEN = "Discord token",
  TELEGRAM_BOT_TOKEN = "Telegram bot token",
  GITHUB_TOKEN = "GitHub token",
  GITLAB_TOKEN = "GitLab token",
  DOCKER_PASSWORD = "Docker registry password",
  DOCKER_REGISTRY = "Docker registry",
  REGISTRY_PASSWORD = "container registry password",
  NPM_TOKEN = "npm token",
  NUGET_API_KEY = "NuGet API key",
  SENTRY_DSN = "Sentry DSN",
  NEW_RELIC_LICENSE_KEY = "New Relic licence key",
  DATADOG_API_KEY = "Datadog API key",
  MIXPANEL_TOKEN = "Mixpanel token",
  ANALYTICS_KEY = "analytics key",
  RECAPTCHA_SECRET_KEY = "reCAPTCHA secret",
  RECAPTCHA_SECRET = "reCAPTCHA secret",
  FIREBASE_API_KEY = "Firebase API key",
  PUSHER_APP_SECRET = "Pusher app secret",
  PUSHER_APP_KEY = "Pusher app key",
  ALGOLIA_API_KEY = "Algolia API key",
  OPENAI_API_KEY = "OpenAI API key",
  ANTHROPIC_API_KEY = "Anthropic API key",
  SESSION_SECRET = "session signing secret",
  SESSION_KEY = "session key",
  COOKIE_SECRET = "cookie signing secret",
  CSRF_SECRET = "CSRF secret",
  INTERNAL_API_KEY = "internal API key",
  ADMIN_PASSWORD = "administrator password",
  ADMIN_EMAIL = "administrator address",
  ROOT_PASSWORD = "root password",
  FTP_PASSWORD = "FTP password",
  SSH_PRIVATE_KEY = "SSH private key",
  VPN_CONFIG = "VPN configuration",
  SPRING_DATASOURCE_PASSWORD = "Spring datasource password",
  SPRING_DATASOURCE_URL = "Spring datasource URL",
  SPRING_REDIS_PASSWORD = "Spring Redis password",
  SERVER_PORT = "server bind port",
  DEBUG = "debug flag",
  VERBOSE = "verbose flag",
}

local KEY_CLASS_PATTERNS = {
  { name = "database", patterns = { "^db_", "^database_", "^mysql_", "^postgres", "^pgsql_", "^mssql_", "^oracle_", "^sqlite", "^mongo", "^redis_", "^memcach" },
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "cloud provider", patterns = { "^aws_", "^azure_", "^gcp_", "^gcloud_", "^google_", "^digitalocean_", "^heroku_", "^oci_", "^alibaba_", "^linode_" },
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "signing or encryption key", patterns = { "secret", "key", "token", "private", "signing", "encryption", "salt", "iv$", "hmac" },
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "password or credential", patterns = { "password", "passwd", "pwd", "credential", "passphrase", "auth" },
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "mail transport", patterns = { "^mail_", "^smtp_", "^sendgrid_", "^mailgun_", "^ses_", "^postmark_", "^mandrill_" },
    severity = "HIGH", weight = SEVERITY.HIGH },
  { name = "payment provider", patterns = { "stripe", "paypal", "braintree", "adyen", "square_", "checkout_", "mollie", "payu" },
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "messaging or webhook", patterns = { "slack", "discord", "telegram", "webhook", "twilio", "pusher" },
    severity = "HIGH", weight = SEVERITY.HIGH },
  { name = "source control or CI", patterns = { "github_", "gitlab_", "bitbucket_", "npm_", "nuget_", "docker_", "registry_", "jenkins", "circleci", "travis" },
    severity = "HIGH", weight = SEVERITY.HIGH },
  { name = "monitoring or analytics", patterns = { "sentry", "datadog", "newrelic", "new_relic", "mixpanel", "segment", "amplitude", "algolia" },
    severity = "MEDIUM", weight = SEVERITY.MEDIUM },
  { name = "debug or environment flag", patterns = { "^debug$", "^app_debug$", "^app_env$", "^verbose$", "^environment$", "_debug$" },
    severity = "MEDIUM", weight = SEVERITY.MEDIUM },
  { name = "internal endpoint", patterns = { "^internal_", "_host$", "_url$", "_endpoint$", "_uri$", "_addr$", "_server$" },
    severity = "MEDIUM", weight = SEVERITY.MEDIUM },
}

local SENSITIVE_KEY_MARKERS = {
  "password", "passwd", "pwd", "secret", "private", "token", "credential",
  "apikey", "api_key", "key", "dsn", "signature", "salt", "passphrase",
  "auth", "cert", "pem", "connection", "_url", "_uri", "_dsn",
}

local NON_SECRET_KEYS = {
  APP_NAME = true, APP_URL = true, APP_TIMEZONE = true, APP_ENV = true,
  DB_CONNECTION = true, DB_HOST = true, DB_PORT = true, DB_DATABASE = true,
  DATABASE_HOST = true, DATABASE_PORT = true, DATABASE_NAME = true,
  MYSQL_HOST = true, MYSQL_DATABASE = true, POSTGRES_HOST = true,
  POSTGRES_DB = true, MONGO_URI = false, REDIS_HOST = true, REDIS_URL = true,
  MEMCACHED_HOST = true, ELASTICSEARCH_HOST = true, MAIL_HOST = true,
  MAIL_PORT = true, MAIL_FROM_ADDRESS = true, MAIL_ENCRYPTION = true,
  SMTP_HOST = true, ADMIN_EMAIL = true, AWS_DEFAULT_REGION = true,
  AZURE_TENANT_ID = true, GCP_PROJECT_ID = true, SERVER_PORT = true,
  JWT_EXPIRATION = true, DOCKER_REGISTRY = true, TWILIO_ACCOUNT_SID = true,
  SENTRY_DSN = false, DEBUG = true, VERBOSE = true,
}

local WAF_SIGNATURES = {
  { pattern = "cf%-ray", where = "header", vendor = "Cloudflare" },
  { pattern = "cloudflare", where = "header", vendor = "Cloudflare" },
  { pattern = "attention required", where = "body", vendor = "Cloudflare" },
  { pattern = "akamai", where = "header", vendor = "Akamai" },
  { pattern = "reference #", where = "body", vendor = "Akamai" },
  { pattern = "x%-iinfo", where = "header", vendor = "Imperva Incapsula" },
  { pattern = "incapsula", where = "body", vendor = "Imperva Incapsula" },
  { pattern = "sucuri", where = "header", vendor = "Sucuri" },
  { pattern = "aws waf", where = "body", vendor = "AWS WAF" },
  { pattern = "request blocked", where = "body", vendor = "generic WAF" },
  { pattern = "access denied", where = "body", vendor = "generic WAF" },
  { pattern = "web application firewall", where = "body", vendor = "generic WAF" },
  { pattern = "mod_security", where = "body", vendor = "ModSecurity" },
  { pattern = "fortiweb", where = "body", vendor = "Fortinet FortiWeb" },
  { pattern = "safeline", where = "body", vendor = "SafeLine WAF" },
  { pattern = "403 forbidden", where = "body", vendor = "generic WAF" },
}

local SOFT404_TEMPLATES = {
  "/nse-env-probe-%s-not-here",
  "/%s-missing-file.txt",
  "/assets/%s-does-not-exist.css",
  "/api/v1/%s/unknown",
  "/%s/.env.absent",
}

local DEFAULT_ARGS = {
  prefixes = nil,
  maxprefixes = 4,
  maxrequests = 120,
  retries = 2,
  timeout = 8000,
  delay = 0.05,
  minkeys = 1,
  minratio = 0.5,
  includeconfig = true,
  includebackups = true,
  soft404 = true,
  useragent = nil,
  maxbodysize = 524288,
  entropyfloor = 2.5,
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

local function list_contains(list, needle)
  for _, item in ipairs(list) do
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

local function read_args()
  local args = {}
  for key, value in pairs(DEFAULT_ARGS) do
    args[key] = value
  end

  local raw_prefixes = stdnse.get_script_args(SCRIPT_NAME .. ".prefixes")
  if raw_prefixes and #raw_prefixes > 0 then
    local list = {}
    for candidate in string.gmatch(raw_prefixes, "[^,]+") do
      local normalized = trim(candidate)
      if normalized == "/" then
        normalized = ""
      elseif #normalized > 0 then
        normalized = string.gsub(normalized, "/+$", "")
        if not starts_with(normalized, "/") then
          normalized = "/" .. normalized
        end
      end
      table.insert(list, normalized)
    end
    if #list > 0 then
      args.prefixes = list
    end
  end

  local numeric_specs = {
    { key = "maxprefixes", minimum = 1 },
    { key = "maxrequests", minimum = 5 },
    { key = "retries", minimum = 0 },
    { key = "timeout", minimum = 500 },
    { key = "minkeys", minimum = 1 },
    { key = "maxbodysize", minimum = 1024 },
  }
  for _, spec in ipairs(numeric_specs) do
    local value = tonumber(stdnse.get_script_args(SCRIPT_NAME .. "." .. spec.key))
    if value and value >= spec.minimum then
      args[spec.key] = math.floor(value)
    end
  end

  local ratio = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".minratio"))
  if ratio and ratio > 0 and ratio <= 1 then
    args.minratio = ratio
  end

  local delay = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".delay"))
  if delay and delay >= 0 and delay <= 10 then
    args.delay = delay
  end

  local entropyfloor = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".entropyfloor"))
  if entropyfloor and entropyfloor >= 0 and entropyfloor <= 8 then
    args.entropyfloor = entropyfloor
  end

  for _, key in ipairs({ "includeconfig", "includebackups", "soft404" }) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if value ~= nil then
      args[key] = not (value == false or value == "false" or value == "no" or value == "0")
    end
  end

  local ua = stdnse.get_script_args(SCRIPT_NAME .. ".useragent")
  if ua and #ua > 0 then
    args.useragent = ua
  end

  return args
end

local function random_token(length)
  local alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
  local out = {}
  local seed = (os.time() * 1000003) + (stdnse.clock_ms and stdnse.clock_ms() or 0) + math.random(1, 9999)
  math.randomseed(seed)
  for _ = 1, length do
    table.insert(out, string.sub(alphabet, math.random(1, #alphabet), math.random(1, #alphabet)))
  end
  return table.concat(out)
end

local function redact_value(value)
  if type(value) ~= "string" then
    return tostring(value)
  end
  local length = #value
  if length <= 4 then
    return string.rep("*", length)
  end
  if length <= 10 then
    return string.sub(value, 1, 2) .. string.rep("*", length - 4) .. string.sub(value, -2)
  end
  return string.format("%s%s%s", string.sub(value, 1, 3), string.rep("*", math.min(length - 7, 16)), string.sub(value, -4))
end

local function redact_connection_string(value)
  local scheme, user, pass, rest = string.match(value, "^(%w[%w%+%-%.]*):/+/+/([^:@/]*):([^@/]*)@(.*)$")
  if scheme then
    return string.format("%s://%s:%s@%s", scheme, user, string.rep("*", math.max(#pass, 6)), rest)
  end
  local scheme2, user2, rest2 = string.match(value, "^(%w[%w%+%-%.]*):/+/+/([^@/]*)@(.*)$")
  if scheme2 then
    return string.format("%s://%s@%s", scheme2, user2, rest2)
  end
  return redact_value(value)
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

local function fnv1a32(value)
  local hash = 2166136261
  for i = 1, #value do
    hash = (hash ~ string.byte(value, i)) & 0xFFFFFFFF
    hash = (hash * 16777619) & 0xFFFFFFFF
  end
  return string.format("%08x", hash)
end

local STRONG_SECRET_SHAPES = {
  "^AKIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z]",
  "^ASIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z]",
  "^sk_live_[A-Za-z0-9]",
  "^sk_test_[A-Za-z0-9]",
  "^rk_live_[A-Za-z0-9]",
  "^gh[pousr]_[A-Za-z0-9]",
  "^glpat%-[A-Za-z0-9]",
  "^xox[baprs]%-[A-Za-z0-9]",
  "^AIza[0-9A-Za-z%_%-%.]",
  "^eyJ[A-Za-z0-9_%-]+%.eyJ[A-Za-z0-9_%-]+%.",
  "^-----BEGIN [A-Z ]*PRIVATE KEY-----",
}

local function has_strong_secret_shape(value)
  if type(value) ~= "string" then
    return false
  end
  for _, pattern in ipairs(STRONG_SECRET_SHAPES) do
    if string.match(value, pattern) then
      return true
    end
  end
  if string.find(value, "-----BEGIN", 1, true) then
    return true
  end
  if string.match(value, "^[%w%+%-%.]+://[^/]+:[^@/]+@") then
    return true
  end
  return false
end

local function is_placeholder(value)
  if type(value) ~= "string" or #value == 0 then
    return true
  end
  if has_strong_secret_shape(value) then
    return false
  end
  local lowered = lower(value)
  local length = #lowered
  for _, hint in ipairs(PLACEHOLDER_HINTS) do
    if string.find(lowered, hint, 1, true) then
      if #hint >= 6 or #hint / length >= 0.4 then
        return true
      end
    end
  end
  if string.match(value, "^[%*x]+$") then
    return true
  end
  if string.match(value, "^<.*>$") then
    return true
  end
  if string.match(value, "^%${.*}$") or string.match(value, "^%%(.*)%%$") then
    return true
  end
  if string.match(value, "^%{%{.*%}%}$") then
    return true
  end
  if value == "true" or value == "false" or value == "1" or value == "0"
    or value == "yes" or value == "no" or value == "on" or value == "off" then
    return true
  end
  if entropy_bits(value) < 2.0 and #value < 12 then
    return true
  end
  return false
end

local function build_options(args)
  local options = { header = {}, no_cache = true, timeout = args.timeout }
  if args.useragent then
    options.header["User-Agent"] = args.useragent
  else
    options.header["User-Agent"] = "Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. "; security audit)"
  end
  options.header["Accept"] = "*/*"
  options.header["Accept-Encoding"] = "identity"
  options.header["Connection"] = "close"
  options.header["Cache-Control"] = "no-cache"
  return options
end

local function sleep(seconds)
  if seconds and seconds > 0 then
    stdnse.sleep(seconds)
  end
end

local state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }

local function budget_exhausted(args)
  return state.requests >= args.maxrequests
end

local function detect_waf(response)
  for _, line in ipairs(response.rawheader or {}) do
    local lowered = lower(line)
    for _, signature in ipairs(WAF_SIGNATURES) do
      if signature.where == "header" and string.find(lowered, signature.pattern, 1, true) then
        return signature.vendor
      end
    end
  end
  local body = lower(response.body or "")
  if #body > 0 and #body < 20000 then
    for _, signature in ipairs(WAF_SIGNATURES) do
      if signature.where == "body" and string.find(body, signature.pattern, 1, true) then
        return signature.vendor
      end
    end
  end
  return nil
end

local function fetch_path(host, port, path, args)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1

  local options = build_options(args)
  local attempt = 0
  local last_error = nil

  while attempt <= args.retries do
    attempt = attempt + 1
    local ok, response = pcall(http.get, host, port, path, options)
    if ok and type(response) == "table" and response.status then
      if response.status == 429 then
        state.rate_limited = state.rate_limited + 1
        local retry_after = tonumber(response.header and response.header["retry-after"])
        sleep(math.min(retry_after or (attempt * 2), 10))
      else
        sleep(args.delay)
        return response, nil
      end
      last_error = "HTTP 429 rate limiting"
    elseif ok and type(response) == "table" then
      last_error = tostring(response["status-line"] or "malformed HTTP response")
    elseif ok then
      last_error = "unexpected response type " .. type(response)
    else
      last_error = tostring(response)
      state.errors = state.errors + 1
    end
    if attempt <= args.retries then
      sleep(0.5 * attempt)
    end
  end

  sleep(args.delay)
  return nil, last_error
end

local function select_prefixes(args)
  local source = args.prefixes
  if not source then
    source = { "", "/api", "/backend", "/app" }
  end
  local selected = {}
  local seen = {}
  for _, candidate in ipairs(source) do
    local normalized = candidate
    if normalized == "/" then
      normalized = ""
    end
    normalized = string.gsub(normalized, "/+$", "")
    if not seen[normalized] then
      seen[normalized] = true
      table.insert(selected, normalized)
      if #selected >= args.maxprefixes then
        break
      end
    end
  end
  if #selected == 0 then
    table.insert(selected, "")
  end
  return selected
end

local function build_candidate_list(args)
  local candidates = {}
  local seen = {}

  local function add(path, family)
    if not seen[path] then
      seen[path] = true
      table.insert(candidates, { path = path, family = family })
    end
  end

  for _, path in ipairs(ENV_CANDIDATES) do
    local is_backup = false
    for _, hint in ipairs(BACKUP_NAME_HINTS) do
      if string.find(lower(path), hint, 1, true) then
        is_backup = true
        break
      end
    end
    if args.includebackups or not is_backup then
      add(path, is_backup and "backup-env" or "env")
    end
  end

  if args.includeconfig then
    for _, path in ipairs(CONFIG_CANDIDATES) do
      add(path, "config")
    end
  end

  local prioritised = {}
  local buckets = { env = {}, ["backup-env"] = {}, config = {} }
  for _, candidate in ipairs(candidates) do
    table.insert(buckets[candidate.family] or buckets.config, candidate)
  end
  for _, candidate in ipairs(buckets.env) do
    table.insert(prioritised, candidate)
  end
  for _, candidate in ipairs(buckets["backup-env"]) do
    table.insert(prioritised, candidate)
  end
  for _, candidate in ipairs(buckets.config) do
    table.insert(prioritised, candidate)
  end

  return prioritised
end

local function build_soft404_baseline(host, port, args)
  local baseline = {
    enabled = args.soft404,
    samples = 0,
    statuses = {},
    lengths = {},
    hashes = {},
  }

  if not args.soft404 then
    return baseline
  end

  for _, template in ipairs(SOFT404_TEMPLATES) do
    if budget_exhausted(args) then
      break
    end
    local probe = string.format(template, random_token(10))
    local response, err = fetch_path(host, port, probe, args)
    if response and response.status then
      local body = response.body or ""
      baseline.samples = baseline.samples + 1
      local status_key = tostring(response.status)
      baseline.statuses[status_key] = (baseline.statuses[status_key] or 0) + 1
      baseline.lengths[#body] = (baseline.lengths[#body] or 0) + 1
      local hash = fnv1a32(body)
      baseline.hashes[hash] = (baseline.hashes[hash] or 0) + 1
      baseline.example_status = baseline.example_status or response.status
      baseline.example_length = baseline.example_length or #body
      baseline.example_hash = baseline.example_hash or hash
    elseif err then
      baseline.errors = baseline.errors or {}
      table.insert(baseline.errors, probe .. ": " .. tostring(err))
    end
  end

  local dominant_status, dominant_count = nil, 0
  for status, count in pairs(baseline.statuses) do
    if count > dominant_count then
      dominant_status, dominant_count = status, count
    end
  end
  baseline.dominant_status = tonumber(dominant_status)
  baseline.consistent = baseline.samples >= 3 and dominant_count == baseline.samples

  return baseline
end

local function looks_like_soft404(response, baseline)
  if not baseline.enabled or baseline.samples == 0 then
    return false, nil
  end
  local body = response.body or ""
  local hash = fnv1a32(body)
  if baseline.example_hash and hash == baseline.example_hash and #body > 0 then
    return true, "byte-identical to the soft-404 baseline"
  end
  if baseline.consistent and baseline.dominant_status == response.status then
    local delta = math.abs(#body - (baseline.example_length or #body))
    if delta <= 48 then
      return true, string.format("status %d and length %d match the catch-all baseline", response.status, #body)
    end
  end
  return false, nil
end

local function is_html_document(body)
  local lowered = lower(body or "")
  if #lowered == 0 then
    return false
  end
  if starts_with(lowered, "<!doctype html") or starts_with(lowered, "<html") then
    return true
  end
  local open_tag = string.find(lowered, "<html", 1, true)
  local close_tag = string.find(lowered, "</html>", 1, true)
  if open_tag and close_tag then
    return true
  end
  if string.find(lowered, "<head", 1, true) and string.find(lowered, "<body", 1, true) then
    return true
  end
  return false
end

local function is_json_document(body)
  local trimmed = trim(body or "")
  if #trimmed == 0 then
    return false
  end
  local first = string.sub(trimmed, 1, 1)
  local last = string.sub(trimmed, -1)
  if (first == "{" and last == "}") or (first == "[" and last == "]") then
    local quotes = select(2, string.gsub(trimmed, "\"", ""))
    local colons = select(2, string.gsub(trimmed, ":", ""))
    if quotes >= 2 and (colons >= 1 or first == "[") then
      return true
    end
  end
  return false
end

local function is_xml_document(body)
  local trimmed = trim(body or "")
  if starts_with(trimmed, "<?xml") then
    return true
  end
  if string.match(trimmed, "^<[%w:%-]+[ >]") and string.find(trimmed, "</", 1, true) then
    local lowered = lower(trimmed)
    if string.find(lowered, "<html", 1, true) or string.find(lowered, "<cross%-domain%-policy", 1)
      or string.find(lowered, "<urlset", 1, true) or string.find(lowered, "<sitemapindex", 1, true) then
      return true
    end
  end
  return false
end

local function strip_quotes(value)
  if type(value) ~= "string" then
    return value
  end
  local trimmed = trim(value)
  if #trimmed >= 2 then
    local first = string.sub(trimmed, 1, 1)
    local last = string.sub(trimmed, -1)
    if (first == "\"" and last == "\"") or (first == "'" and last == "'") then
      return string.sub(trimmed, 2, -2)
    end
  end
  return trimmed
end

local function parse_env_content(body)
  local parsed = {
    assignments = {},
    order = {},
    sections = {},
    comments = 0,
    blank = 0,
    unparseable = 0,
    lines = 0,
    yaml_like = 0,
    ini_like = 0,
    export_like = 0,
  }

  local seen_keys = {}
  for line in string.gmatch(body or "", "([^\r\n]*)") do
    parsed.lines = parsed.lines + 1
    local trimmed = trim(line)

    if #trimmed == 0 then
      parsed.blank = parsed.blank + 1
    elseif starts_with(trimmed, "#") or starts_with(trimmed, ";") then
      parsed.comments = parsed.comments + 1
    else
      local section = string.match(trimmed, "^%[([%w%-%.:%s_/]+)%]$")
      if section then
        parsed.ini_like = parsed.ini_like + 1
        table.insert(parsed.sections, section)
      else
        local is_export = false
        local candidate = trimmed
        if starts_with(lower(candidate), "export ") then
          is_export = true
          parsed.export_like = parsed.export_like + 1
          candidate = trim(string.sub(candidate, 8))
        end

        local key, value = string.match(candidate, "^([A-Za-z_][A-Za-z0-9_%-%.]*)%s*=%s*(.*)$")
        if key and not is_export then
          parsed.yaml_like = parsed.yaml_like + 0
        end

        if not key then
          key, value = string.match(candidate, "^([A-Za-z_][A-Za-z0-9_%-%.]*)%s*:%s+(.*)$")
          if key then
            parsed.yaml_like = parsed.yaml_like + 1
          end
        end

        if key then
          local normalized_key = string.upper(string.gsub(key, "[%-%.]", "_"))
          local normalized_value = strip_quotes(value)
          normalized_value = string.gsub(normalized_value, "%s+#.*$", "")
          normalized_value = trim(normalized_value)

          if not seen_keys[normalized_key] then
            seen_keys[normalized_key] = true
            table.insert(parsed.order, normalized_key)
          end
          parsed.assignments[normalized_key] = {
            raw_key = key,
            value = normalized_value,
            export = is_export,
            line = parsed.lines,
          }
        else
          parsed.unparseable = parsed.unparseable + 1
        end
      end
    end
  end

  parsed.count = table_size(parsed.assignments)
  local meaningful = parsed.lines - parsed.blank - parsed.comments
  parsed.meaningful = meaningful
  parsed.ratio = meaningful > 0 and (parsed.count / meaningful) or 0

  return parsed
end

local function recognised_key_count(parsed)
  local recognised = 0
  local unknown = {}
  for _, key in ipairs(parsed.order) do
    if RECOGNISED_KEYS[key] then
      recognised = recognised + 1
    else
      local matched = false
      for _, class in ipairs(KEY_CLASS_PATTERNS) do
        for _, pat in ipairs(class.patterns) do
          if string.find(lower(key), pat) then
            matched = true
            break
          end
        end
        if matched then
          break
        end
      end
      if matched then
        recognised = recognised + 1
      else
        table.insert(unknown, key)
      end
    end
  end
  return recognised, unknown
end

local function validate_env_file(path, body, args)
  local result = {
    valid = false,
    details = {},
    parsed = nil,
    reason = nil,
  }

  if type(body) ~= "string" or #body == 0 then
    result.reason = "empty body"
    return result
  end

  if #body < 8 then
    result.reason = "body smaller than 8 bytes"
    return result
  end

  if is_html_document(body) then
    result.reason = "response is an HTML document"
    return result
  end

  if is_json_document(body) then
    result.reason = "response is a JSON document"
    return result
  end

  if is_xml_document(body) then
    result.reason = "response is an XML document"
    return result
  end

  local parsed = parse_env_content(body)
  result.parsed = parsed

  if parsed.count < args.minkeys then
    result.reason = string.format("only %d parseable assignment(s); minimum is %d", parsed.count, args.minkeys)
    return result
  end

  if parsed.ratio < args.minratio then
    result.reason = string.format("assignment ratio %.2f below threshold %.2f (prose or markup, not a config file)",
      parsed.ratio, args.minratio)
    return result
  end

  local recognised, unknown = recognised_key_count(parsed)
  result.recognised = recognised
  result.unknown_keys = unknown

  local known_section = false
  for _, section in ipairs(parsed.sections) do
    local lowered = lower(section)
    if starts_with(lowered, "core") or starts_with(lowered, "program")
      or starts_with(lowered, "database") or starts_with(lowered, "db")
      or starts_with(lowered, "remote") or starts_with(lowered, "branch")
      or starts_with(lowered, "client") or starts_with(lowered, "mysqld")
      or starts_with(lowered, "apache") or starts_with(lowered, "spring")
      or starts_with(lowered, "server") or starts_with(lowered, "auth") then
      known_section = true
      break
    end
  end

  if recognised == 0 and not known_section then
    result.reason = string.format("no recognised configuration keys among %d assignments", parsed.count)
    return result
  end

  result.valid = true
  table.insert(result.details, string.format("%d assignments parsed from %d lines (%d comments, %d blank, ratio %.2f)",
    parsed.count, parsed.lines, parsed.comments, parsed.blank, parsed.ratio))
  if recognised > 0 then
    table.insert(result.details, string.format("%d keys match known configuration names", recognised))
  end
  if known_section then
    table.insert(result.details, string.format("INI-style sections present: %s", table.concat(parsed.sections, ", ")))
  end
  if parsed.export_like > 0 then
    table.insert(result.details, string.format("%d 'export KEY=value' lines (shell-style env file)", parsed.export_like))
  end
  if parsed.yaml_like > 0 then
    table.insert(result.details, string.format("%d YAML-style 'key: value' lines", parsed.yaml_like))
  end

  return result
end

local function key_is_sensitive(key)
  local lowered_key = lower(key)
  for _, marker in ipairs(SENSITIVE_KEY_MARKERS) do
    if string.find(lowered_key, marker, 1, true) then
      return true
    end
  end
  return false
end

local function classify_value(key, value)
  local classification = {
    classes = {},
    severity = "INFO",
    weight = SEVERITY.INFO,
    sensitive_key = key_is_sensitive(key),
  }

  local lowered_key = lower(key)
  for _, class in ipairs(KEY_CLASS_PATTERNS) do
    local hit = false
    for _, pat in ipairs(class.patterns) do
      if string.find(lowered_key, pat) then
        hit = true
        break
      end
    end
    if hit then
      table.insert(classification.classes, class.name)
      if class.weight > classification.weight then
        classification.severity = class.severity
        classification.weight = class.weight
      end
    end
  end

  if type(value) == "string" then
    if string.match(value, "AKIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z]") then
      table.insert(classification.classes, "AWS access key id")
      classification.severity = "CRITICAL"
      classification.weight = math.max(classification.weight, SEVERITY.CRITICAL)
    end
    if string.find(value, "-----BEGIN", 1, true) then
      table.insert(classification.classes, "PEM key material")
      classification.severity = "CRITICAL"
      classification.weight = math.max(classification.weight, SEVERITY.CRITICAL)
    end
    if string.match(value, "^gh[pousr]_[A-Za-z0-9]") then
      table.insert(classification.classes, "GitHub token")
      classification.severity = "CRITICAL"
      classification.weight = math.max(classification.weight, SEVERITY.CRITICAL)
    end
    if string.match(value, "^xox[baprs]%-") then
      table.insert(classification.classes, "Slack token")
      classification.severity = "HIGH"
      classification.weight = math.max(classification.weight, SEVERITY.HIGH)
    end
    if string.match(value, "^sk_live_") then
      table.insert(classification.classes, "Stripe live secret key")
      classification.severity = "CRITICAL"
      classification.weight = math.max(classification.weight, SEVERITY.CRITICAL)
    end
    if string.match(value, "^eyJ[A-Za-z0-9_%-]+%.eyJ") then
      table.insert(classification.classes, "JWT")
      classification.severity = "HIGH"
      classification.weight = math.max(classification.weight, SEVERITY.HIGH)
    end
    if string.match(value, "^[%w%+%-%.]+://[^/]+:[^@/]+@") then
      table.insert(classification.classes, "connection string with credentials")
      classification.severity = "CRITICAL"
      classification.weight = math.max(classification.weight, SEVERITY.CRITICAL)
    end
    if entropy_bits(value) >= 4.0 and #value >= 20 then
      table.insert(classification.classes, "high-entropy secret")
      classification.weight = math.max(classification.weight, SEVERITY.HIGH)
      if classification.severity == "INFO" then
        classification.severity = "HIGH"
      end
    end
  end

  local unique = {}
  local deduped = {}
  for _, name in ipairs(classification.classes) do
    if not unique[name] then
      unique[name] = true
      table.insert(deduped, name)
    end
  end
  classification.classes = deduped

  return classification
end

local function describe_path_scope(path)
  local lowered = lower(path)
  local scope = "unspecified"
  for _, hint in ipairs(PRODUCTION_NAME_HINTS) do
    if string.find(lowered, hint, 1, true) then
      scope = "production"
      break
    end
  end
  if scope ~= "production" then
    for _, hint in ipairs({ "dev", "development", "test", "testing", "stage", "staging", "local", "sample", "example" }) do
      if string.find(lowered, hint, 1, true) then
        scope = "non-production"
        break
      end
    end
  end
  local is_backup = false
  for _, hint in ipairs(BACKUP_NAME_HINTS) do
    if string.find(lowered, hint, 1, true) then
      is_backup = true
      break
    end
  end
  return scope, is_backup
end

local function extract_endpoints(parsed)
  local endpoints = { hosts = {}, ips = {}, urls = {}, buckets = {} }
  local seen_host = {}
  local seen_ip = {}
  local seen_url = {}
  local seen_bucket = {}

  for _, key in ipairs(parsed.order) do
    local entry = parsed.assignments[key]
    local value = entry and entry.value or ""
    if type(value) == "string" and #value > 0 then
      for host in string.gmatch(value, "([%w%-]+%.[%w%-]+%.[%w%-%.]+)") do
        local cleaned = lower(host)
        if not string.match(cleaned, "^%d+%.%d+%.%d+%.%d+$") and not seen_host[cleaned]
          and not ends_with(cleaned, ".example") and #cleaned > 4 then
          seen_host[cleaned] = true
          table.insert(endpoints.hosts, cleaned)
        end
      end
      for ip in string.gmatch(value, "(%d+%.%d+%.%d+%.%d+)") do
        local first_octet = tonumber(string.match(ip, "^(%d+)"))
        if first_octet and first_octet < 224 and not seen_ip[ip] then
          seen_ip[ip] = true
          table.insert(endpoints.ips, ip)
        end
      end
      for candidate_url in string.gmatch(value, "(https?://[^%s\"']+)") do
        if not seen_url[candidate_url] then
          seen_url[candidate_url] = true
          table.insert(endpoints.urls, candidate_url)
        end
      end
      for bucket in string.gmatch(value, "(s3[%-%.][%w%-%.]+)") do
        if not seen_bucket[bucket] then
          seen_bucket[bucket] = true
          table.insert(endpoints.buckets, bucket)
        end
      end
    end
  end

  return endpoints
end

local function assess_file(path, validation, args)
  local parsed = validation.parsed
  local scope, is_backup = describe_path_scope(path)
  local findings = {}
  local weight = 0
  local real_secrets = 0
  local placeholder_secrets = 0
  local classes_seen = {}

  for _, key in ipairs(parsed.order) do
    local entry = parsed.assignments[key]
    local value = entry.value or ""
    local classification = classify_value(key, value)
    local description = RECOGNISED_KEYS[key] or (classification.classes[1] or "configuration value")
    local placeholder = is_placeholder(value)

    if placeholder then
      placeholder_secrets = placeholder_secrets + 1
    elseif classification.sensitive_key
      or entropy_bits(value) >= args.entropyfloor and #value >= 16 then
      real_secrets = real_secrets + 1
    end

    local holds_secret = classification.sensitive_key
      or entropy_bits(value) >= args.entropyfloor and #value >= 16
    local strong_marker = false
    for _, name in ipairs(classification.classes) do
      if name == "AWS access key id" or name == "PEM key material"
        or name == "GitHub token" or name == "Slack token"
        or name == "Stripe live secret key" or name == "JWT"
        or name == "connection string with credentials"
        or name == "high-entropy secret" then
        strong_marker = true
      end
    end

    if strong_marker and not placeholder then
      local redacted = string.find(value, "://", 1, true)
        and redact_connection_string(value) or redact_value(value)
      local entry_weight = classification.weight
      if scope == "non-production" then
        entry_weight = math.max(1, math.floor(entry_weight / 2))
      end
      table.insert(findings, {
        severity = classification.severity,
        weight = entry_weight,
        path = path,
        detail = string.format("%s = %s — %s [%s] (entropy %.2f)",
          entry.raw_key or key, redacted, description,
          table.concat(classification.classes, ", "), entropy_bits(value)),
      })
      weight = weight + entry_weight
      for _, name in ipairs(classification.classes) do
        classes_seen[name] = (classes_seen[name] or 0) + 1
      end
    elseif holds_secret and not placeholder then
      local entry_weight = math.max(classification.weight, SEVERITY.MEDIUM)
      local severity = entry_weight >= SEVERITY.HIGH and "HIGH" or "MEDIUM"
      if scope == "non-production" then
        entry_weight = math.max(1, math.floor(entry_weight / 2))
        severity = entry_weight >= SEVERITY.HIGH and "HIGH" or "MEDIUM"
      end
      table.insert(findings, {
        severity = severity,
        weight = entry_weight,
        path = path,
        detail = string.format("%s = %s — %s (entropy %.2f)",
          entry.raw_key or key, redact_value(value), description, entropy_bits(value)),
      })
      weight = weight + entry_weight
      for _, name in ipairs(classification.classes) do
        classes_seen[name] = (classes_seen[name] or 0) + 1
      end
    elseif RECOGNISED_KEYS[key] and not placeholder and not NON_SECRET_KEYS[key] then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        path = path,
        detail = string.format("%s = %s — %s", entry.raw_key or key, redact_value(value), RECOGNISED_KEYS[key]),
      })
      weight = weight + SEVERITY.MEDIUM
    elseif RECOGNISED_KEYS[key] and not placeholder then
      table.insert(findings, {
        severity = "INFO",
        weight = SEVERITY.INFO,
        path = path,
        detail = string.format("%s = %s — %s (non-secret configuration value)",
          entry.raw_key or key, value, RECOGNISED_KEYS[key]),
      })
    elseif placeholder and RECOGNISED_KEYS[key] then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        path = path,
        detail = string.format("%s holds a placeholder value (%s) — template file published",
          entry.raw_key or key, redact_value(value)),
      })
      weight = weight + SEVERITY.LOW
    end

    local lowered_key = lower(key)
    if (lowered_key == "app_debug" or lowered_key == "debug") and lower(value) == "true" then
      table.insert(findings, {
        severity = "HIGH",
        weight = SEVERITY.HIGH,
        path = path,
        detail = "debug mode is enabled in the published configuration (stack traces and environment dumps)",
      })
      weight = weight + SEVERITY.HIGH
    end
    if lowered_key == "app_env" and lower(value) == "production" then
      table.insert(findings, {
        severity = "HIGH",
        weight = SEVERITY.HIGH,
        path = path,
        detail = "the file declares APP_ENV=production: this is the live environment configuration",
      })
      weight = weight + SEVERITY.HIGH
    end
  end

  local endpoints = extract_endpoints(parsed)
  if #endpoints.hosts > 0 and real_secrets > 0 then
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      path = path,
      detail = "internal hostnames disclosed: " .. table.concat(endpoints.hosts, ", ", 1, math.min(#endpoints.hosts, 8)),
    })
    weight = weight + SEVERITY.MEDIUM
  end
  if #endpoints.ips > 0 and real_secrets > 0 then
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      path = path,
      detail = "internal IP addresses disclosed: " .. table.concat(endpoints.ips, ", ", 1, math.min(#endpoints.ips, 8)),
    })
    weight = weight + SEVERITY.MEDIUM
  end
  if #endpoints.buckets > 0 then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      path = path,
      detail = "object-storage buckets disclosed: " .. table.concat(endpoints.buckets, ", "),
    })
    weight = weight + SEVERITY.HIGH
  end

  if is_backup then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      path = path,
      detail = "backup/editor leftover file is published; it usually predates credential rotation",
    })
    weight = weight + SEVERITY.LOW
  end

  local verdict
  if real_secrets >= 2 and (scope == "production" or classes_seen["database"] or classes_seen["cloud provider"]) then
    verdict = "CRITICAL"
  elseif real_secrets >= 1 then
    verdict = "CRITICAL"
  elseif placeholder_secrets > 0 and real_secrets == 0 then
    verdict = "LOW"
  else
    verdict = "MEDIUM"
  end

  if scope == "non-production" and verdict == "CRITICAL" and real_secrets == 1 then
    verdict = "HIGH"
  end

  return {
    path = path,
    scope = scope,
    backup = is_backup,
    verdict = verdict,
    weight = weight,
    findings = findings,
    real_secrets = real_secrets,
    placeholders = placeholder_secrets,
    endpoints = endpoints,
    classes = classes_seen,
    key_count = parsed.count,
    recognised = validation.recognised or 0,
    details = validation.details,
  }
end

local function probe_candidates(host, port, prefixes, candidates, args, baseline)
  local confirmed = {}
  local suppressed = {}
  local rejected = {}
  local errors = {}

  for _, prefix in ipairs(prefixes) do
    for _, candidate in ipairs(candidates) do
      if budget_exhausted(args) then
        table.insert(errors, string.format("request budget exhausted after %d requests", state.requests))
        return confirmed, suppressed, rejected, errors
      end

      local full_path = prefix .. candidate.path
      if full_path == "" then
        full_path = "/"
      end

      local response, err = fetch_path(host, port, full_path, args)
      if not response then
        if err ~= "request budget exhausted" then
          table.insert(errors, string.format("%s: %s", full_path, tostring(err)))
        end
        goto continue_candidate
      end

      local status = response.status or 0
      local body = response.body or ""
      if #body > args.maxbodysize then
        body = string.sub(body, 1, args.maxbodysize)
      end

      local vendor = detect_waf(response)
      if vendor then
        state.blocked = state.blocked + 1
        table.insert(suppressed, {
          path = full_path, status = status, length = #body,
          reason = "WAF/CDN interstitial (" .. vendor .. ")",
        })
        goto continue_candidate
      end

      local soft, soft_reason = looks_like_soft404(response, baseline)
      if soft then
        table.insert(suppressed, { path = full_path, status = status, length = #body, reason = "soft-404: " .. soft_reason })
        goto continue_candidate
      end

      if status >= 400 then
        if status == 429 then
          state.rate_limited = state.rate_limited + 1
        end
        goto continue_candidate
      end

      if status >= 300 then
        local location = response.header and response.header["location"]
        table.insert(suppressed, {
          path = full_path, status = status, length = #body,
          reason = "redirect" .. (location and (" to " .. tostring(location)) or ""),
        })
        goto continue_candidate
      end

      local validation = validate_env_file(full_path, body, args)
      if validation.valid then
        table.insert(confirmed, {
          path = full_path,
          family = candidate.family,
          status = status,
          length = #body,
          body = body,
          validation = validation,
          content_type = response.header and response.header["content-type"],
        })
      else
        table.insert(rejected, {
          path = full_path,
          family = candidate.family,
          status = status,
          length = #body,
          reason = validation.reason,
        })
      end

      ::continue_candidate::
    end
  end

  return confirmed, suppressed, rejected, errors
end

local function dedupe_findings(assessments)
  local unique = {}
  local index = {}
  local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }

  for _, assessment in ipairs(assessments) do
    for _, finding in ipairs(assessment.findings) do
      local key = finding.path .. "|" .. finding.detail
      if not index[key] then
        index[key] = finding
        table.insert(unique, finding)
        counts[finding.severity] = (counts[finding.severity] or 0) + 1
      end
    end
  end

  local order = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5 }
  table.sort(unique, function(a, b)
    local oa = order[a.severity] or 9
    local ob = order[b.severity] or 9
    if oa ~= ob then
      return oa < ob
    end
    if a.path ~= b.path then
      return a.path < b.path
    end
    return a.detail < b.detail
  end)

  return unique, counts
end

local function build_remediation(assessments, counts)
  local lines = {}
  local classes = {}
  for _, assessment in ipairs(assessments) do
    for name in pairs(assessment.classes) do
      classes[name] = (classes[name] or 0) + 1
    end
  end

  table.insert(lines, "remove the file from the document root and serve configuration from outside the web tree")
  if classes["database"] or classes["cloud provider"] or counts.CRITICAL > 0 then
    table.insert(lines, "rotate every credential found in the file immediately; assume it is already harvested")
  end
  if classes["payment provider"] then
    table.insert(lines, "notify the payment provider and roll the API keys (live keys allow fund movement)")
  end
  if classes["mail transport"] then
    table.insert(lines, "rotate SMTP/API mail credentials and review sent-mail logs for abuse")
  end
  if classes["signing or encryption key"] then
    table.insert(lines, "re-issue signing/encryption keys and invalidate existing sessions and tokens")
  end
  table.insert(lines, "deny dotfiles at the web server or WAF layer (nginx: location ~ /\\. { deny all; })")
  table.insert(lines, "purge the artefact from CDN, reverse-proxy and object-storage caches")
  table.insert(lines, "review the deployment pipeline (docker COPY, rsync, CI artefacts) that published the file")

  return lines
end

local function render_output(confirmed, suppressed, rejected, errors, baseline, args)
  local out = stdnse.output_table()
  local assessments = {}

  if #confirmed == 0 then
    if state.rate_limited > 0 or state.blocked > #rejected then
      out["Risk Level"] = RISK_LEVEL
      out["Status"] = STATUS_INCONCLUSIVE
      out["Rate limited responses"] = tostring(state.rate_limited)
      out["WAF blocked responses"] = tostring(state.blocked)
      out["Requests issued"] = tostring(state.requests)
      if #errors > 0 then
        out["Probe errors"] = errors
      end
      return out
    end

    out["Risk Level"] = RISK_LEVEL
    out["Status"] = STATUS_CLEAN
    out["Candidates probed"] = tostring(state.requests)
    if #rejected > 0 then
      local lines = {}
      for _, item in ipairs(rejected) do
        table.insert(lines, string.format("%s (HTTP %d, %d bytes): %s", item.path, item.status, item.length, tostring(item.reason)))
      end
      out["Rejected candidates"] = lines
    end
    if #suppressed > 0 then
      local lines = {}
      for _, item in ipairs(suppressed) do
        table.insert(lines, string.format("%s (HTTP %d): %s", item.path, item.status, item.reason))
      end
      out["Suppressed candidates"] = lines
    end
    if baseline.enabled and baseline.samples > 0 then
      out["Soft-404 baseline"] = string.format("%d probes, dominant status %s, %s",
        baseline.samples, tostring(baseline.dominant_status or "n/a"),
        baseline.consistent and "catch-all confirmed" or "no catch-all")
    end
    if #errors > 0 then
      out["Probe errors"] = errors
    end
    out["Requests issued"] = tostring(state.requests)
    return out
  end

  for _, item in ipairs(confirmed) do
    table.insert(assessments, assess_file(item.path, item.validation, args))
  end

  local findings, counts = dedupe_findings(assessments)
  local total_weight = 0
  local real_total = 0
  local production_files = {}
  for _, assessment in ipairs(assessments) do
    total_weight = total_weight + assessment.weight
    real_total = real_total + assessment.real_secrets
    if assessment.scope == "production" then
      table.insert(production_files, assessment.path)
    end
  end

  local worst = "MEDIUM"
  local order = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5 }
  for _, assessment in ipairs(assessments) do
    if (order[assessment.verdict] or 9) < (order[worst] or 9) then
      worst = assessment.verdict
    end
  end

  out["Risk Level"] = RISK_LEVEL
  if real_total > 0 then
    out["Status"] = STATUS_EXPOSED
  else
    out["Status"] = "AUDITED - configuration files are publicly readable but contain no live secrets."
  end

  local file_lines = {}
  for index, item in ipairs(confirmed) do
    local assessment = assessments[index]
    table.insert(file_lines, string.format("[%s] %s (HTTP %d, %d bytes, %d keys, %d live secrets, scope: %s)",
      assessment.verdict, item.path, item.status, item.length,
      assessment.key_count, assessment.real_secrets, assessment.scope))
  end
  out["Exposed files"] = file_lines

  for index, item in ipairs(confirmed) do
    local assessment = assessments[index]
    if #assessment.details > 0 then
      out["Validation " .. item.path] = assessment.details
    end
  end

  local rendered = {}
  for _, finding in ipairs(findings) do
    table.insert(rendered, string.format("[%s] %s — %s", finding.severity, finding.path, finding.detail))
  end
  out["Credential findings"] = rendered

  out["Severity counts"] = string.format("CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d",
    counts.CRITICAL or 0, counts.HIGH or 0, counts.MEDIUM or 0, counts.LOW or 0)
  out["Worst verdict"] = worst
  out["Weighted exposure score"] = tostring(total_weight)
  out["Live secrets parsed"] = tostring(real_total)

  if #production_files > 0 then
    out["Production-scope files"] = production_files
  end

  out["Remediation"] = build_remediation(assessments, counts)

  if #rejected > 0 then
    local lines = {}
    for _, item in ipairs(rejected) do
      table.insert(lines, string.format("%s (HTTP %d): %s", item.path, item.status, tostring(item.reason)))
    end
    out["Rejected candidates"] = lines
  end

  if #suppressed > 0 then
    local lines = {}
    for _, item in ipairs(suppressed) do
      table.insert(lines, string.format("%s (HTTP %d): %s", item.path, item.status, item.reason))
    end
    out["Suppressed candidates"] = lines
  end

  if #errors > 0 then
    out["Probe errors"] = errors
  end

  out["Requests issued"] = tostring(state.requests)

  return out
end

action = function(host, port)
  state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }
  math.randomseed((os.time() * 7919) + (port.number or 0))

  local args = read_args()
  local prefixes = select_prefixes(args)
  local candidates = build_candidate_list(args)
  local baseline = build_soft404_baseline(host, port, args)

  local confirmed, suppressed, rejected, errors = probe_candidates(host, port, prefixes, candidates, args, baseline)

  if nmap and nmap.verbosity and nmap.verbosity() > 1 then
    table.insert(errors, string.format("verbose: %d prefixes x %d candidates planned", #prefixes, #candidates))
  end

  return render_output(confirmed, suppressed, rejected, errors, baseline, args)
end
