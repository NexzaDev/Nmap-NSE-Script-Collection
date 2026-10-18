local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

local http = require "http"

description = [[

Audits how strictly a GraphQL endpoint enforces the Content-Type header on
POSTed operations. Spec-conformant servers accept application/json (and,
depending on the spec version, application/x-www-form-urlencoded) and
reject everything else with 415 Unsupported Media Type. Servers that parse
the body regardless of the declared Content-Type give WAFs and CDNs that
key their GraphQL inspection rules on the header a blind spot: an
operation can be delivered with a Content-Type the security stack does not
inspect, while the application still executes it.

Why it matters
- WAF/CDN rule sets commonly trigger GraphQL analysis only for
  application/json (or -form-urlencoded) bodies; text/plain, multipart or
  application/xml bodies may skip the rule entirely and still be executed.
- Inconsistent Content-Type handling also breaks client libraries that
  rely on the 415 contract, and it makes cache and logging pipelines
  misclassify requests.
- A compliant server answers wrong Content-Types with 415 and a clear
  UNSUPPORTED_CONTENT_TYPE-style error; that is the baseline the script
  reports.

What the script does
1. Discovers the GraphQL endpoint (user path first, then candidates).
2. Sends the same cheap query with application/json as the control.
3. Resends it with a ladder of alternative Content-Types:
   application/x-www-form-urlencoded (form-encoded body), text/plain,
   application/xml, multipart/form-data and application/graphql
   (the vendor content type).
4. Records for each Content-Type whether the server executed the query
   (200 + data), rejected it with 415, or answered some other way.
5. Emits MEDIUM when non-standard Content-Types execute the query
   (enforcement bypass surface), LOW when only the form-encoded variant
   deviates from a strict JSON-only policy, and NOT VULNERABLE when every
   non-JSON variant is refused with 415.

The query is a read-only __typename probe; nothing is mutated.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  {80, 443, 3000, 4000, 8000, 8080, 8443, 8888, 9000},
  {"http", "https", "graphql"},
  "tcp"
)

local SCRIPT_NAME = "graphql-content-type-bypass"

local RISK_LEVEL = "🟡 MEDIUM"

local DEFAULT_ARGS = {
  maxrequests = 20,
  timeout = 8,
  retries = 2,
  delay = 0.4,
  useragent = "Mozilla/5.0 (compatible; gql-audit/1.0)",
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
  { key = "retries", minimum = 0, maximum = 5, integer = true },
  { key = "delay", minimum = 0 },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = { "path", "useragent" }

local CVSS_CTBYPASS = "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)"

local GQL_CANDIDATES = { "/graphql", "/api/graphql", "/gql", "/graphql/v1", "/api/v1/graphql" }

local CT_REJECT_CODES = { "UNSUPPORTED_CONTENT_TYPE", "CONTENT_TYPE_NOT_ALLOWED" }

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

local BS = string.char(92)
local function gql_wire_escape(value)
  local s = tostring(value or "")
  local out = {}
  for i = 1, #s do
    local c = s:sub(i, i)
    if c == BS then
      out[#out + 1] = BS .. BS
    elseif c == '"' then
      out[#out + 1] = BS .. '"'
    elseif c == "\n" then
      out[#out + 1] = BS .. "n"
    elseif c == "\r" then
      out[#out + 1] = BS .. "r"
    elseif c == "\t" then
      out[#out + 1] = BS .. "t"
    else
      out[#out + 1] = c
    end
  end
  return table.concat(out)
end

local function gql_json_parse(text)
  if type(text) ~= "string" or #text == 0 then
    return nil, "empty input"
  end
  local pos = 1
  local len = #text

  local function skip_ws(p)
    while p <= len do
      local c = text:sub(p, p)
      if c == " " or c == "\t" or c == "\n" or c == "\r" then
        p = p + 1
      else
        break
      end
    end
    return p
  end

  local parse_value

  local function parse_string(p)
    if text:sub(p, p) ~= '"' then
      return nil, p, "expected string"
    end
    p = p + 1
    local out = {}
    while p <= len do
      local c = text:sub(p, p)
      if c == '"' then
        return table.concat(out), p + 1, nil
      end
      if c == "\\" then
        local esc = text:sub(p + 1, p + 1)
        if esc == '"' then
          out[#out + 1] = '"'
          p = p + 2
        elseif esc == "\\" then
          out[#out + 1] = "\\"
          p = p + 2
        elseif esc == "/" then
          out[#out + 1] = "/"
          p = p + 2
        elseif esc == "n" then
          out[#out + 1] = "\n"
          p = p + 2
        elseif esc == "t" then
          out[#out + 1] = "\t"
          p = p + 2
        elseif esc == "r" then
          out[#out + 1] = "\r"
          p = p + 2
        elseif esc == "b" then
          out[#out + 1] = "\b"
          p = p + 2
        elseif esc == "f" then
          out[#out + 1] = "\f"
          p = p + 2
        elseif esc == "u" then
          local hex = text:sub(p + 2, p + 5)
          if hex:match("^%x%x%x%x$") then
            local code = tonumber(hex, 16)
            if code < 128 then
              out[#out + 1] = string.char(code)
            else
              out[#out + 1] = "?"
            end
            p = p + 6
          else
            return nil, p, "bad unicode escape"
          end
        else
          return nil, p, "bad escape"
        end
      else
        out[#out + 1] = c
        p = p + 1
      end
    end
    return nil, p, "unterminated string"
  end

  local function parse_number(p)
    local num_str = text:match("^[%-]?%d+%.?%d*[eE]?[+-]?%d*", p)
    if not num_str then
      return nil, p, "bad number"
    end
    return tonumber(num_str), p + #num_str, nil
  end

  parse_value = function(p)
    p = skip_ws(p)
    if p > len then
      return nil, p, "unexpected end"
    end
    local c = text:sub(p, p)
    if c == '"' then
      return parse_string(p)
    end
    if c == "{" then
      local obj = {}
      p = p + 1
      p = skip_ws(p)
      if text:sub(p, p) == "}" then
        return obj, p + 1, nil
      end
      while true do
        p = skip_ws(p)
        local key, p2, kerr = parse_string(p)
        if not key then
          return nil, p, kerr or "bad key"
        end
        p = skip_ws(p2)
        if text:sub(p, p) ~= ":" then
          return nil, p, "expected colon"
        end
        p = p + 1
        local value, p3, verr = parse_value(p)
        if p3 == p and verr then
          return nil, p, verr
        end
        obj[key] = value
        p = skip_ws(p3)
        local d = text:sub(p, p)
        if d == "," then
          p = p + 1
        elseif d == "}" then
          return obj, p + 1, nil
        else
          return nil, p, "expected , or }"
        end
      end
    end
    if c == "[" then
      local arr = {}
      p = p + 1
      p = skip_ws(p)
      if text:sub(p, p) == "]" then
        return arr, p + 1, nil
      end
      while true do
        local value, p2, verr = parse_value(p)
        if p2 == p and verr then
          return nil, p, verr
        end
        arr[#arr + 1] = value
        p = skip_ws(p2)
        local d = text:sub(p, p)
        if d == "," then
          p = p + 1
        elseif d == "]" then
          return arr, p + 1, nil
        else
          return nil, p, "expected , or ]"
        end
      end
    end
    if c == "t" then
      if text:sub(p, p + 3) == "true" then
        return true, p + 4, nil
      end
      return nil, p, "bad literal"
    end
    if c == "f" then
      if text:sub(p, p + 4) == "false" then
        return false, p + 5, nil
      end
      return nil, p, "bad literal"
    end
    if c == "n" then
      if text:sub(p, p + 3) == "null" then
        return nil, p + 4, nil
      end
      return nil, p, "bad literal"
    end
    if c:match("[%d%-]") then
      return parse_number(p)
    end
    return nil, p, "unexpected character"
  end

  local value, p, err = parse_value(1)
  if err and err ~= "unexpected end" then
    return nil, err
  end
  return value, nil
end

local function gql_parse_response(body)
  local parsed = {
    data = nil,
    errors = {},
    extensions = nil,
    raw = tostring(body or ""),
    ok = false,
  }
  local value, err = gql_json_parse(tostring(body or ""))
  if type(value) ~= "table" then
    parsed.parse_error = err or "not a JSON object"
    return parsed
  end
  parsed.ok = true
  parsed.data = value.data
  parsed.extensions = value.extensions
  if type(value.errors) == "table" then
    for i, e in ipairs(value.errors) do
      if type(e) == "table" then
        local entry = {
          message = tostring(e.message or ""),
          code = e.extensions and tostring(e.extensions.code or ""),
          path = nil,
          debug = nil,
        }
        if type(e.path) == "table" then
          entry.path = table.concat(e.path, ".")
        end
        if type(e.debug) == "string" then
          entry.debug = e.debug
        end
        table.insert(parsed.errors, entry)
      end
    end
  end
  return parsed
end

local function gql_errors_text(parsed, limit)
  local parts = {}
  for i, e in ipairs(parsed.errors or {}) do
    if i > (limit or 5) then
      break
    end
    local line = e.message
    if e.code and e.code ~= "" then
      line = line .. " (code=" .. e.code .. ")"
    end
    table.insert(parts, line)
  end
  return table.concat(parts, " | ")
end

local SENSITIVE_FIELD_HINTS = {
  { name = "identifier", patterns = { "ssn", "ss_number", "social", "passport", "national_id", "id_card", "tax_id", "vat" } },
  { name = "financial", patterns = { "iban", "bic", "swift", "cvv", "cvc", "card", "billing", "salary", "balance", "transaction", "payment", "invoice", "statement", "bank" } },
  { name = "contact", patterns = { "email", "phone", "mobile", "address", "location", "geolocation" } },
  { name = "biographic", patterns = { "birthdate", "birth_date", "dob", "age", "gender", "marital" } },
  { name = "credential", patterns = { "password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "credential" } },
  { name = "medical", patterns = { "medical", "health", "diagnosis", "prescription", "allerg" } },
}

local function gql_classify_field_name(name)
  local lower_name = lower(name or "")
  for _, class in ipairs(SENSITIVE_FIELD_HINTS) do
    for _, hint in ipairs(class.patterns) do
      if lower_name:find(hint, 1, true) then
        return class.name
      end
    end
  end
  return nil
end

local ADMIN_TYPE_HINTS = { "admin", "staff", "moderator", "superuser", "internal", "system", "root", "operator", "service_account", "serviceaccount" }
local USER_TYPE_HINTS = { "user", "account", "member", "profile", "customer", "employee", "client", "person" }
local MONEY_TYPE_HINTS = { "payment", "order", "transaction", "invoice", "billing", "wallet", "refund", "charge" }
local PII_TYPE_HINTS = { "address", "identity", "document", "passport", "medical", "health" }

local function gql_classify_type_name(name)
  local lower_name = lower(name or "")
  for _, hint in ipairs(ADMIN_TYPE_HINTS) do
    if lower_name:find(hint, 1, true) then
      return "admin"
    end
  end
  for _, hint in ipairs(MONEY_TYPE_HINTS) do
    if lower_name:find(hint, 1, true) then
      return "financial"
    end
  end
  for _, hint in ipairs(USER_TYPE_HINTS) do
    if lower_name:find(hint, 1, true) then
      return "account"
    end
  end
  for _, hint in ipairs(PII_TYPE_HINTS) do
    if lower_name:find(hint, 1, true) then
      return "pii-document"
    end
  end
  return nil
end

local function gql_type_base_name(type_json)
  local s = tostring(type_json or "")
  local inner = s:match("^%[(.*)%]$") or s
  inner = inner:gsub("!", "")
  return inner
end
local function gql_type_name_ref(t)
  local cur = t
  local depth = 0
  while type(cur) == "table" and depth < 4 do
    local kind = tostring(cur.kind or "")
    if kind == "NON_NULL" or kind == "LIST" then
      cur = cur.type
      depth = depth + 1
    else
      break
    end
  end
  if type(cur) ~= "table" then
    return ""
  end
  if cur.name then
    return tostring(cur.name)
  end
  local kind = tostring(cur.kind or "")
  if kind ~= "" and kind ~= "NON_NULL" and kind ~= "LIST" then
    return kind
  end
  return ""
end

local function gql_analyze_schema(schema)
  local analysis = {
    available = false,
    type_count = 0,
    object_count = 0,
    interface_count = 0,
    enum_count = 0,
    scalar_count = 0,
    input_count = 0,
    union_count = 0,
    query_type = nil,
    mutation_type = nil,
    subscription_type = nil,
    directive_count = 0,
    directives = {},
    field_total = 0,
    fields_by_type = {},
    sensitive_fields = {},
    type_classes = {},
    deprecated_fields = 0,
    description_findings = {},
    cycles = {},
  }
  if type(schema) ~= "table" then
    return analysis
  end
  analysis.available = true
  local qt = schema.queryType
  local mt = schema.mutationType
  local st = schema.subscriptionType
  analysis.query_type = type(qt) == "table" and tostring(qt.name or "") or nil
  analysis.mutation_type = type(mt) == "table" and tostring(mt.name or "") or nil
  analysis.subscription_type = type(st) == "table" and tostring(st.name or "") or nil
  local types = schema.types
  if type(types) == "table" then
    for _, t in ipairs(types) do
      if type(t) ~= "table" then
      else
      analysis.type_count = analysis.type_count + 1
      local kind = tostring(t.kind or "")
      local name = tostring(t.name or "")
      if kind == "OBJECT" then
        analysis.object_count = analysis.object_count + 1
        local class = gql_classify_type_name(name)
        if class then
          analysis.type_classes[class] = (analysis.type_classes[class] or 0) + 1
          if not analysis["first_" .. class .. "_type"] then
            analysis["first_" .. class .. "_type"] = name
          end
        end
        if type(t.fields) == "table" then
          for _, f in ipairs(t.fields) do
            if type(f) == "table" then
              analysis.field_total = analysis.field_total + 1
              local fname = tostring(f.name or "")
              local fclass = gql_classify_field_name(fname)
              if fclass then
                local key = name .. "." .. fname
                if not list_contains(analysis.sensitive_fields, key) then
                  table.insert(analysis.sensitive_fields, key)
                end
              end
              if f.isDeprecated == true then
                analysis.deprecated_fields = analysis.deprecated_fields + 1
              end
              if type(f.description) == "string" and #f.description > 0 then
                table.insert(analysis.description_findings, {
                  type = name,
                  field = fname,
                  text = truncate(f.description, 200),
                })
              end
              if type(t.description) == "string" and #t.description > 0 then
                if not analysis["type_desc_" .. name] then
                  analysis["type_desc_" .. name] = truncate(t.description, 200)
                end
              end
              if not analysis.fields_by_type[name] then
                analysis.fields_by_type[name] = {}
              end
              table.insert(analysis.fields_by_type[name], {
                name = fname,
                base = gql_type_name_ref(f.type),
              })
            end
          end
        end
      elseif kind == "INTERFACE" then
        analysis.interface_count = analysis.interface_count + 1
      elseif kind == "ENUM" then
        analysis.enum_count = analysis.enum_count + 1
      elseif kind == "SCALAR" then
        analysis.scalar_count = analysis.scalar_count + 1
      elseif kind == "INPUT_OBJECT" then
        analysis.input_count = analysis.input_count + 1
      elseif kind == "UNION" then
        analysis.union_count = analysis.union_count + 1
      end
      end
    end
  end
  if type(schema.directives) == "table" then
    for _, d in ipairs(schema.directives) do
      if type(d) == "table" then
        analysis.directive_count = analysis.directive_count + 1
        table.insert(analysis.directives, tostring(d.name or ""))
      end
    end
  end
  return analysis
end

local function gql_find_schema_cycles(schema)
  if type(schema) ~= "table" or type(schema.types) ~= "table" then
    return {}
  end
  local edges = {}
  for _, t in ipairs(schema.types) do
    if type(t) == "table" and t.kind == "OBJECT" then
      local tname = tostring(t.name or "")
      if tname ~= "" then
        edges[tname] = edges[tname] or {}
      end
    end
  end
  for _, t in ipairs(schema.types) do
    if type(t) == "table" and t.kind == "OBJECT" and type(t.fields) == "table" then
      for _, f in ipairs(t.fields) do
        if type(f) == "table" and type(f.type) == "table" then
          local target = f.type
          while type(target) == "table" and (target.kind == "NON_NULL" or target.kind == "LIST") do
            target = target.type
          end
          local tname = ""
          if type(target) == "table" then
            if target.name then
              tname = tostring(target.name)
            else
              local kind = tostring(target.kind or "")
              if kind ~= "" and kind ~= "NON_NULL" and kind ~= "LIST" then
                tname = kind
              end
            end
          end
          if tname ~= "" then
            local list = edges[tostring(t.name)] or {}
            if not list_contains(list, tname) then
              table.insert(list, tname)
              edges[tostring(t.name)] = list
            end
          end
        end
      end
    end
  end
  local cycles = {}
  local seen_cycle = {}
  for start_node, targets in pairs(edges) do
    for _, t in ipairs(targets) do
      if edges[t] and list_contains(edges[t], start_node) and start_node < t then
        local key = start_node .. "<->" .. t
        if not seen_cycle[key] then
          seen_cycle[key] = true
          table.insert(cycles, { a = start_node, b = t })
        end
      end
    end
  end
  return cycles
end

local STACK_TRACE_SIGNATURES = { "Traceback (most recent call last)", "at com.", "at io.", "at org.", "at java.", "Stack trace:", "exception.", "Exception:", "panic:", "goroutine " }
local FILE_PATH_SIGNATURES = { "/var/www", "/var/lib", "/var/log", "/home/", "/app/", "/usr/local/lib", "C:%5C", "C:\\", ".venv\\", ".venv/", "site-packages", "node_modules", "vendor/", "/opt/" }
local DB_HINT_SIGNATURES = { "psycopg2", "sqlalchemy", "mysql", "mariadb", "mongodb", "redis", "elasticsearch", "jdbc", "ORM", "relation ", "table ", "query: SELECT", "query: select" }
local ENV_HINT_SIGNATURES = { "NODE_ENV", "DEBUG=true", "debug: true", "FLASK_ENV", "RAILS_ENV", "ASPNETCORE_ENVIRONMENT", "php_version", "PHP/", "gunicorn", "uvicorn", "strawberry", "graphene" }
local LEAK_VALUE_SIGNATURES = { "password", "secret", "token", "api_key", "authorization", "bearer " }

local FRAMEWORK_FINGERPRINTS = {
  { name = "Strawberry GraphQL (Python)", patterns = { "strawberry/schema/schema.py", "strawberry/http", "strawberry-graphql" } },
  { name = "Graphene (Python)", patterns = { "graphene/types", "graphene/graphql", "graphene/" } },
  { name = "GraphQL-java", patterns = { "graphql/execution", "com.coyotegraphql", "graphql.GraphQL", "graphql-java" } },
  { name = "Apollo Server (Node.js)", patterns = { "apollo-server", "graphql/execute", "cjs/execute", "apollo/server" } },
  { name = "GraphQL Yoga", patterns = { "graphql-yoga", "@envelop", "graphql-yoga/execute" } },
  { name = "Lighthouse (Laravel)", patterns = { "nuwave/lighthouse", "webonyx/graphql-php/src/Executor" } },
  { name = "Webonyx GraphQL (PHP)", patterns = { "webonyx/graphql-php", "GraphQL/Executor" } },
  { name = "Hasura", patterns = { "hasura", "x-hasura" } },
  { name = "Prisma", patterns = { "@prisma/client", "prisma-engines" } },
  { name = "graphql-go", patterns = { "graphql-go/graphql", "vektah/gqlparser" } },
  { name = "Relay (Facebook)", patterns = { "relay-runtime", "relay-compiler" } },
  { name = "GraphQL.NET", patterns = { "GraphQL/Execution", "HotChocolate", "graphql-dotnet" } },
  { name = "Nexus.js", patterns = { "@nexus/schema", "nexus/schema" } },
  { name = "Async-GraphQL (Rust)", patterns = { "async-graphql", "async_graphql" } },
  { name = "Juniper (Rust)", patterns = { "juniper", "juniper_graphql" } },
}

local function gql_fingerprint_framework(text)
  local hits = {}
  local lower_text = lower(text or "")
  for _, fp in ipairs(FRAMEWORK_FINGERPRINTS) do
    for _, pat in ipairs(fp.patterns) do
      if lower_text:find(lower(pat), 1, true) then
        if not list_contains(hits, fp.name) then
          table.insert(hits, fp.name)
        end
        break
      end
    end
  end
  return hits
end

local function gql_scan_error_content(text)
  local scan = {
    has_stack_trace = false,
    stack_signatures = {},
    file_paths = {},
    db_hints = {},
    env_hints = {},
    leak_values = {},
    frameworks = {},
    pid = nil,
    addr = nil,
    span = nil,
  }
  if type(text) ~= "string" or #text == 0 then
    return scan
  end
  for _, sig in ipairs(STACK_TRACE_SIGNATURES) do
    if text:find(sig, 1, true) then
      scan.has_stack_trace = true
      if not list_contains(scan.stack_signatures, sig) then
        table.insert(scan.stack_signatures, sig)
      end
    end
  end
  for _, sig in ipairs(FILE_PATH_SIGNATURES) do
    if text:find(sig, 1, true) then
      local start_idx = text:find(sig, 1, true)
      local chunk = text:sub(start_idx)
      local path = chunk:match("^([%w%._/%-%-]+)")
      if path and #path > 3 and not list_contains(scan.file_paths, path) then
        table.insert(scan.file_paths, path)
      end
    end
  end
  for _, sig in ipairs(DB_HINT_SIGNATURES) do
    if text:find(sig, 1, true) and not list_contains(scan.db_hints, sig) then
      table.insert(scan.db_hints, sig)
    end
  end
  for _, sig in ipairs(ENV_HINT_SIGNATURES) do
    if text:find(sig, 1, true) and not list_contains(scan.env_hints, sig) then
      table.insert(scan.env_hints, sig)
    end
  end
  for _, sig in ipairs(LEAK_VALUE_SIGNATURES) do
    if lower(text):find(sig, 1, true) and not list_contains(scan.leak_values, sig) then
      table.insert(scan.leak_values, sig)
    end
  end
  scan.frameworks = gql_fingerprint_framework(text)
  scan.pid = text:match("PID=(%d+)")
  scan.addr = text:match("ADDR=(0x%x+)")
  scan.span = text:match("SPAN=([%w_%-]+)")
  return scan
end

local function gql_extract_suggestion(message)
  if type(message) ~= "string" then
    return nil
  end
  local suggested = message:match('Did you mean "[%s]*([%w_]+)"')
  if not suggested then
    suggested = message:match("Did you mean '([%w_]+)'")
  end
  return suggested
end

local function skip_ws_local(s, p)
  while p <= #s do
    local c = s:sub(p, p)
    if c == " " or c == "\t" or c == "\n" or c == "\r" then
      p = p + 1
    else
      break
    end
  end
  return p
end

local function gql_count_aliases(query)
  local count = 0
  if type(query) ~= "string" then
    return 0
  end
  local in_str = false
  local esc = false
  local i = 1
  local len = #query
  while i <= len do
    local c = query:sub(i, i)
    if in_str then
      if esc then
        esc = false
      elseif c == "\\" then
        esc = true
      elseif c == '"' then
        in_str = false
      end
      i = i + 1
    else
      if c == '"' then
        in_str = true
        i = i + 1
      elseif c:match("[%w_]") then
        local word_end = i
        while word_end <= len and query:sub(word_end, word_end):match("[%w_]") do
          word_end = word_end + 1
        end
        local after = skip_ws_local(query, word_end)
        if query:sub(after, after) == ':' then
          count = count + 1
        end
        i = word_end
      else
        i = i + 1
      end
    end
  end
  return count
end

local function gql_query_depth(query)
  if type(query) ~= "string" then
    return 0
  end
  local depth = 0
  local max = 0
  for i = 1, #query do
    local c = query:sub(i, i)
    if c == "{" then
      depth = depth + 1
      if depth > max then
        max = depth
      end
    elseif c == "}" then
      depth = depth - 1
    end
  end
  return max
end

local function gql_build_alias_query(count, field)
  local parts = {}
  for i = 1, count do
    parts[i] = "f" .. i .. ": " .. field
  end
  return "{ " .. table.concat(parts, " ") .. " }"
end

local function gql_build_depth_query(depth, chain)
  local open = "{ "
  for i = 1, depth do
    local field = chain[((i - 1) % #chain) + 1]
    if i < depth then
      open = open .. field .. " { "
    else
      open = open .. field .. " { id } "
    end
  end
  open = open .. string.rep("} ", depth)
  return open
end

local function gql_build_batch(count)
  local parts = {}
  for i = 1, count do
    parts[i] = '{"query":"{__typename}"}'
  end
  return "[" .. table.concat(parts, ",") .. "]"
end

local SHA256_K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

local function gql_bit_xor(a, b)
  local r = 0
  local p = 1
  for _ = 0, 31 do
    if (a % 2) + (b % 2) == 1 then
      r = r + p
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    p = p * 2
  end
  return r
end

local function gql_bit_and(a, b)
  local r = 0
  local p = 1
  for _ = 0, 31 do
    if a % 2 == 1 and b % 2 == 1 then
      r = r + p
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    p = p * 2
  end
  return r
end

local function gql_shl32(x, n)
  return (x * (2 ^ n)) % 4294967296
end

local function gql_shr32(x, n)
  return math.floor(x / (2 ^ n)) % 4294967296
end

local function gql_rotr32(x, n)
  return (gql_bit_and(gql_shl32(x, 32 - n), 4294967295) + gql_shr32(x, n)) % 4294967296
end

local function gql_sha256_compress(state, block)
  local w = {}
  for i = 1, 16 do
    local base = (i - 1) * 4
    w[i] = (block:byte(base + 1) * 16777216) + (block:byte(base + 2) * 65536) + (block:byte(base + 3) * 256) + block:byte(base + 4)
  end
  for i = 17, 64 do
    local s0 = gql_bit_xor(gql_rotr32(w[i - 15], 7), gql_bit_xor(gql_rotr32(w[i - 15], 18), gql_shr32(w[i - 15], 3)))
    local s1 = gql_bit_xor(gql_rotr32(w[i - 2], 17), gql_bit_xor(gql_rotr32(w[i - 2], 19), gql_shr32(w[i - 2], 10)))
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % 4294967296
  end
  local a, b, c, d = state[1], state[2], state[3], state[4]
  local e, f, g, h = state[5], state[6], state[7], state[8]
  for i = 1, 64 do
    local S1 = (gql_bit_xor(gql_rotr32(e, 6), gql_bit_xor(gql_rotr32(e, 11), gql_rotr32(e, 25)))) % 4294967296
    local ch = (gql_bit_and(e, f) + gql_bit_and(4294967295 - e, g)) % 4294967296
    local S0 = (gql_bit_xor(gql_rotr32(a, 2), gql_bit_xor(gql_rotr32(a, 13), gql_rotr32(a, 22)))) % 4294967296
    local triple = gql_bit_and(gql_bit_and(a, b), c)
    local maj = (gql_bit_and(a, b) + gql_bit_and(a, c) + gql_bit_and(b, c) - 2 * triple) % 4294967296
    local t1 = (h + S1 + ch + SHA256_K[i] + w[i]) % 4294967296
    local t2 = (S0 + maj) % 4294967296
    h = g
    g = f
    f = e
    e = (d + t1) % 4294967296
    d = c
    c = b
    b = a
    a = (t1 + t2) % 4294967296
  end
  state[1] = (state[1] + a) % 4294967296
  state[2] = (state[2] + b) % 4294967296
  state[3] = (state[3] + c) % 4294967296
  state[4] = (state[4] + d) % 4294967296
  state[5] = (state[5] + e) % 4294967296
  state[6] = (state[6] + f) % 4294967296
  state[7] = (state[7] + g) % 4294967296
  state[8] = (state[8] + h) % 4294967296
end

local function gql_sha256_hex(text)
  local msg = tostring(text or "")
  local bit_len = #msg * 8
  local pad = msg .. string.char(128)
  while #pad % 64 ~= 56 do
    pad = pad .. string.char(0)
  end
  local hi = math.floor(bit_len / 4294967296)
  local lo = bit_len % 4294967296
  pad = pad .. string.char(
    math.floor(hi / 16777216) % 256, math.floor(hi / 65536) % 256, math.floor(hi / 256) % 256, hi % 256,
    math.floor(lo / 16777216) % 256, math.floor(lo / 65536) % 256, math.floor(lo / 256) % 256, lo % 256
  )
  local state = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
  for block_start = 1, #pad, 64 do
    gql_sha256_compress(state, pad:sub(block_start, block_start + 63))
  end
  local out = {}
  for i = 1, 8 do
    out[i] = string.format("%08x", state[i])
  end
  return table.concat(out)
end

local function gql_build_pq_extensions(query)
  local hash = gql_sha256_hex(tostring(query or ''))
  return '{"persistedQuery":{"version":1,"sha256Hash":"' .. hash .. '"}}'
end

local function gql_pseudo_sha256(value)
  local h = fnv1a32(tostring(value or ''))
  return h .. fnv1a32('s2' .. h) .. fnv1a32(h .. 's3') .. fnv1a32('s4' .. h .. 'e')
end

local SUBSCRIPTION_CATEGORIES = {
  { name = "financial stream", patterns = { "price", "trade", "ticker", "quote", "fx", "crypto", "wallet", "balance", "order" } },
  { name = "user event", patterns = { "notification", "message", "chat", "comment", "activity", "feed" } },
  { name = "system event", patterns = { "system", "event", "log", "audit", "metric", "status" } },
}

local function gql_classify_subscription(name)
  local lower_name = lower(name or "")
  for _, cat in ipairs(SUBSCRIPTION_CATEGORIES) do
    for _, pat in ipairs(cat.patterns) do
      if lower_name:find(pat, 1, true) then
        return cat.name
      end
    end
  end
  return "generic"
end

local DIRECTIVE_CLASSES = {
  auth = { "auth", "authorize", "authenticated", "permission", "permissions", "role", "roles", "scoped" },
  rate = { "ratelimit", "rate_limit", "throttle", "complexity", "cost" },
  cache = { "cache", "cachecontrol", "cache_control", "caching" },
  deprecation = { "deprecated", "deprecate" },
  internal = { "internal", "admin", "hidden" },
  standard = { "include", "skip", "specifiedby", "oneof" },
}

local function gql_classify_directive(name)
  local lower_name = lower(name or "")
  for class_name, hints in pairs(DIRECTIVE_CLASSES) do
    for _, hint in ipairs(hints) do
      if lower_name:find(hint, 1, true) then
        return class_name
      end
    end
  end
  return "custom"
end

local function gql_urlencode(value)
  local s = tostring(value or "")
  local out = {}
  for i = 1, #s do
    local c = s:sub(i, i)
    if c:match("[%w%-%._~]") then
      out[#out + 1] = c
    else
      out[#out + 1] = string.format("%%%02X", c:byte())
    end
  end
  return table.concat(out)
end

local GQL_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function gql_base64_encode(data)
  local out = {}
  local i = 1
  local n = #data
  while i + 2 <= n do
    local a = data:byte(i)
    local b = data:byte(i + 1)
    local c = data:byte(i + 2)
    local v = a * 65536 + b * 256 + c
    out[#out + 1] = GQL_B64_ALPHABET:sub(math.floor(v / 262144) + 1, math.floor(v / 262144) + 1)
    out[#out + 1] = GQL_B64_ALPHABET:sub(math.floor(v / 4096) % 64 + 1, math.floor(v / 4096) % 64 + 1)
    out[#out + 1] = GQL_B64_ALPHABET:sub(math.floor(v / 64) % 64 + 1, math.floor(v / 64) % 64 + 1)
    out[#out + 1] = GQL_B64_ALPHABET:sub(v % 64 + 1, v % 64 + 1)
    i = i + 3
  end
  local rem = n - i + 1
  if rem == 1 then
    local a = data:byte(i)
    local v = a * 65536
    out[#out + 1] = GQL_B64_ALPHABET:sub(math.floor(v / 262144) + 1, math.floor(v / 262144) + 1)
    out[#out + 1] = GQL_B64_ALPHABET:sub(math.floor(v / 4096) % 64 + 1, math.floor(v / 4096) % 64 + 1)
    out[#out + 1] = "="
    out[#out + 1] = "="
  elseif rem == 2 then
    local a = data:byte(i)
    local b = data:byte(i + 1)
    local v = a * 65536 + b * 256
    out[#out + 1] = GQL_B64_ALPHABET:sub(math.floor(v / 262144) + 1, math.floor(v / 262144) + 1)
    out[#out + 1] = GQL_B64_ALPHABET:sub(math.floor(v / 4096) % 64 + 1, math.floor(v / 4096) % 64 + 1)
    out[#out + 1] = GQL_B64_ALPHABET:sub(math.floor(v / 64) % 64 + 1, math.floor(v / 64) % 64 + 1)
    out[#out + 1] = "="
  end
  return table.concat(out)
end

local function gql_random_key16()
  local bytes = {}
  for i = 1, 16 do
    bytes[i] = string.char(math.random(0, 255))
  end
  return gql_base64_encode(table.concat(bytes))
end

local GQL_QUOTE = string.char(34)
local GQL_BACKSLASH = string.char(92)

local function gql_json_escape_string(value)
  local s = tostring(value or "")
  local out = {}
  for i = 1, #s do
    local c = s:sub(i, i)
    local code = c:byte()
    if c == GQL_QUOTE then
      out[#out + 1] = GQL_BACKSLASH .. GQL_QUOTE
    elseif c == GQL_BACKSLASH then
      out[#out + 1] = GQL_BACKSLASH .. GQL_BACKSLASH
    elseif code < 32 then
      out[#out + 1] = string.format(GQL_BACKSLASH .. "u%04x", code)
    else
      out[#out + 1] = c
    end
  end
  return GQL_QUOTE .. table.concat(out) .. GQL_QUOTE
end

local function gql_build_body(query, operation_name, variables_json, extensions_json)
  local parts = {}
  if query and query ~= "" then
    parts[#parts + 1] = '"query":' .. gql_json_escape_string(query)
  end
  if operation_name and operation_name ~= "" then
    parts[#parts + 1] = '"operationName":' .. gql_json_escape_string(operation_name)
  end
  if variables_json and variables_json ~= "" then
    parts[#parts + 1] = '"variables":' .. variables_json
  end
  if extensions_json and extensions_json ~= "" then
    parts[#parts + 1] = '"extensions":' .. extensions_json
  end
  if #parts == 0 then
    return "{}"
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function gql_request(host, port, path, args, opts)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  local method = (opts and opts.method) or "POST"
  local options = { header = {}, no_cache = true, timeout = args.timeout }
  options.header["User-Agent"] = args.useragent
    or ("Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. "; security audit)")
  options.header["Accept"] = (opts and opts.accept) or "application/json, */*;q=0.8"
  options.header["Accept-Encoding"] = "identity"
  options.header["Connection"] = "close"
  if opts and opts.headers then
    for name, value in pairs(opts.headers) do
      options.header[name] = tostring(value)
    end
  end
  local body = opts and opts.body
  if method == "POST" and not options.header["Content-Type"] and not options.header["content-type"] then
    options.header["Content-Type"] = "application/json"
  end
  local sender
  if method == "GET" then
    sender = function() return http.get(host, port, path, options) end
  elseif method == "HEAD" then
    sender = function() return http.head(host, port, path, options) end
  elseif method == "POST" then
    sender = function() return http.post(host, port, path, options, body or "") end
  elseif method == "PUT" or method == "DELETE" or method == "PATCH" then
    if http.request then
      sender = function() return http.request(host, port, path, options, body, method) end
    end
  else
    sender = function() return nil, "unsupported method" end
  end
  if not sender then
    return nil, "http method unavailable in this Nmap build"
  end
  local attempt = 0
  local last_error = nil
  while attempt <= args.retries do
    attempt = attempt + 1
    local ok, response = pcall(sender)
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

local function gql_is_graphql_response(resp)
  if not resp then
    return false
  end
  local header = nil
  local body
  if type(resp) == "string" then
    body = resp
  else
    body = tostring(resp.body or "")
    header = resp.header
  end
  if body:find('"data"%s*:', 1) then
    return true
  end
  if body:find('"errors"%s*:', 1) then
    return true
  end
  if type(header) == "table" then
    local ct = tostring(header["content-type"] or header["Content-Type"] or "")
    if ct:find("application/graphql-response+json", 1, true) then
      return true
    end
  end
  return false
end

local GQL_PROBE_BODY = '{"query":"{__typename}"}'

local function find_gql_endpoint(host, port, args, candidates)
  local found = {}
  for index = 1, #candidates do
    local path = candidates[index]
    local entry = { path = path }
    if budget_exhausted(args) then
      entry.skipped = true
      table.insert(found, entry)
      break
    end
    local resp, err = gql_request(host, port, path, args, {
      method = "POST",
      body = GQL_PROBE_BODY,
    })
    if resp then
      entry.reachable = true
      entry.status = resp.status
      if gql_is_graphql_response(resp) then
        entry.is_graphql = true
        local tn = tostring(resp.body or ""):match('"__typename"%s*:%s*"([^"]+)"')
        if tn then
          entry.typename = tn
        end
      end
    else
      entry.reachable = false
      entry.detail = err
    end
    table.insert(found, entry)
  end
  return found
end

local function gql_sock_read(sock, max_bytes)
  local a, b = sock:receive(max_bytes or 256)
  if type(b) == "string" and #b > 0 then
    return b
  end
  if type(a) == "string" and #a > 0 then
    return a
  end
  return nil, a
end

local function gql_ws_probe(host, port, path, args, subprotocols)
  local result = { upgraded = false }
  local sock, serr = nmap.new_socket("tcp")
  if not sock then
    result.error = "socket: " .. tostring(serr)
    return result
  end
  local ok, cerr = sock:connect(host.ip or host, port.number or port)
  if not ok then
    result.error = "connect: " .. tostring(cerr)
    sock:close()
    return result
  end
  result.sock = sock
  local key = gql_random_key16()
  local host_header = host.name or host.ip or "target"
  local request = table.concat({
    "GET " .. path .. " HTTP/1.1\r\n",
    "Host: " .. host_header .. "\r\n",
    "Upgrade: websocket\r\n",
    "Connection: Upgrade\r\n",
    "Sec-WebSocket-Version: 13\r\n",
    "Sec-WebSocket-Key: " .. key .. "\r\n",
    "Sec-WebSocket-Protocol: " .. table.concat(subprotocols, ", ") .. "\r\n",
    "User-Agent: " .. (args.useragent or "gql-audit/1.0") .. "\r\n",
    "\r\n",
  })
  local sent, send_err = sock:send(request)
  if not sent then
    result.error = "send: " .. tostring(send_err)
    sock:close()
    return result
  end
  local collected = ""
  local reads = 0
  local has_boundary = false
  while not has_boundary and reads < 40 do
    local chunk, rerr = gql_sock_read(sock, 512)
    if not chunk then
      result.read_error = tostring(rerr)
      break
    end
    collected = collected .. chunk
    reads = reads + 1
    if collected:find("\r\n\r\n", 1, true) then
      has_boundary = true
    end
  end
  result.handshake_raw = collected
  local status = collected:match("^HTTP/1%.1 (%d+)")
  result.status = tonumber(status)
  result.accept = collected:match("Sec%-WebSocket%-Accept:%s*([%w%+/=]+)")
  result.protocol = collected:match("Sec%-WebSocket%-Protocol:%s*(%S+)")
  if result.status == 101 then
    result.upgraded = true
    local expected_accept = gql_base64_encode(gql_sha1_raw(key .. "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
    result.accept_valid = (result.accept == expected_accept)
  end
  return result
end

local function gql_ws_xor_byte(a, b)
  local r = 0
  for i = 0, 7 do
    local ca = math.floor(a / 2 ^ i) % 2
    local cb = math.floor(b / 2 ^ i) % 2
    if ca + cb == 1 then
      r = r + 2 ^ i
    end
  end
  return r
end

local function gql_ws_bit_xor(a, b)
  local r = 0
  local p = 1
  for _ = 0, 31 do
    if (a % 2) + (b % 2) == 1 then
      r = r + p
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    p = p * 2
  end
  return r
end

local function gql_ws_bit_and(a, b)
  local r = 0
  local p = 1
  for _ = 0, 31 do
    if a % 2 == 1 and b % 2 == 1 then
      r = r + p
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    p = p * 2
  end
  return r
end

local function gql_ws_shl32(x, n)
  return (x * (2 ^ n)) % 4294967296
end

local function gql_ws_shr32(x, n)
  return math.floor(x / (2 ^ n)) % 4294967296
end

local function gql_ws_rol32(x, n)
  return (gql_ws_bit_and(gql_ws_shl32(x, n), 4294967295) + gql_ws_shr32(x, 32 - n)) % 4294967296
end

local function gql_sha1_raw(text)
  local msg = tostring(text or "")
  local bit_len = #msg * 8
  local pad = msg .. string.char(0x80)
  while #pad % 64 ~= 56 do
    pad = pad .. string.char(0)
  end
  local hi = math.floor(bit_len / 4294967296)
  local lo = bit_len % 4294967296
  pad = pad .. string.char(
    math.floor(hi / 16777216) % 256, math.floor(hi / 65536) % 256, math.floor(hi / 256) % 256, hi % 256,
    math.floor(lo / 16777216) % 256, math.floor(lo / 65536) % 256, math.floor(lo / 256) % 256, lo % 256
  )
  local h0 = 0x67452301
  local h1 = 0xEFCDAB89
  local h2 = 0x98BADCFE
  local h3 = 0x10325476
  local h4 = 0xC3D2E1F0
  for block_start = 1, #pad, 64 do
    local block = pad:sub(block_start, block_start + 63)
    local w = {}
    for i = 0, 15 do
      local base = i * 4
      w[i] = (block:byte(base + 1) * 16777216) + (block:byte(base + 2) * 65536) + (block:byte(base + 3) * 256) + block:byte(base + 4)
    end
    for i = 16, 79 do
      w[i] = gql_ws_rol32(gql_ws_bit_xor(w[i - 3], gql_ws_bit_xor(w[i - 8], gql_ws_bit_xor(w[i - 14], w[i - 16]))), 1)
    end
    local a, b, c, d, e = h0, h1, h2, h3, h4
    for i = 0, 79 do
      local f
      local k
      if i < 20 then
        f = (gql_ws_bit_and(b, c) + gql_ws_bit_and(4294967295 - b, d)) % 4294967296
        k = 0x5A827999
      elseif i < 40 then
        f = gql_ws_bit_xor(gql_ws_bit_xor(b, c), d)
        k = 0x6ED9EBA1
      elseif i < 60 then
        local triple = gql_ws_bit_and(gql_ws_bit_and(b, c), d)
        f = (gql_ws_bit_and(b, c) + gql_ws_bit_and(b, d) + gql_ws_bit_and(c, d) - 2 * triple) % 4294967296
        k = 0x8F1BBCDC
      else
        f = gql_ws_bit_xor(gql_ws_bit_xor(b, c), d)
        k = 0xCA62C1D6
      end
      local temp = (gql_ws_rol32(a, 5) + f + e + k + w[i]) % 4294967296
      e = d
      d = c
      c = gql_ws_rol32(b, 30)
      b = a
      a = temp
    end
    h0 = (h0 + a) % 4294967296
    h1 = (h1 + b) % 4294967296
    h2 = (h2 + c) % 4294967296
    h3 = (h3 + d) % 4294967296
    h4 = (h4 + e) % 4294967296
  end
  return string.char(
    math.floor(h0 / 16777216) % 256, math.floor(h0 / 65536) % 256, math.floor(h0 / 256) % 256, h0 % 256,
    math.floor(h1 / 16777216) % 256, math.floor(h1 / 65536) % 256, math.floor(h1 / 256) % 256, h1 % 256,
    math.floor(h2 / 16777216) % 256, math.floor(h2 / 65536) % 256, math.floor(h2 / 256) % 256, h2 % 256,
    math.floor(h3 / 16777216) % 256, math.floor(h3 / 65536) % 256, math.floor(h3 / 256) % 256, h3 % 256,
    math.floor(h4 / 16777216) % 256, math.floor(h4 / 65536) % 256, math.floor(h4 / 256) % 256, h4 % 256
  )
end

local function gql_sha1_hex(text)
  local raw = gql_sha1_raw(text)
  local out = {}
  for i = 1, #raw do
    out[i] = string.format("%02x", raw:byte(i))
  end
  return table.concat(out)
end

local function gql_ws_build_frame(opcode, payload)
  local mask = string.char(math.random(0, 255), math.random(0, 255),
    math.random(0, 255), math.random(0, 255))
  local out = {}
  out[#out + 1] = string.char(0x80 + opcode)
  local len = #payload
  if len <= 125 then
    out[#out + 1] = string.char(0x80 + len)
  elseif len < 65536 then
    out[#out + 1] = string.char(0x80 + 126)
    out[#out + 1] = string.char(math.floor(len / 256) % 256, len % 256)
  else
    out[#out + 1] = string.char(0x80 + 127)
    out[#out + 1] = string.char(
      math.floor(len / 72057594037927936) % 256, math.floor(len / 281474976710656) % 256,
      math.floor(len / 1099511627776) % 256, math.floor(len / 4294967296) % 256,
      math.floor(len / 16777216) % 256, math.floor(len / 65536) % 256,
      math.floor(len / 256) % 256, len % 256
    )
  end
  out[#out + 1] = mask
  local xored = {}
  for i = 1, len do
    local code = payload:byte(i)
    xored[i] = string.char(gql_ws_xor_byte(code, mask:byte(((i - 1) % 4) + 1)))
  end
  out[#out + 1] = table.concat(xored)
  return table.concat(out)
end

local function gql_ws_text_frame(payload)
  return gql_ws_build_frame(1, payload)
end

local function gql_ws_close_frame(code, reason)
  local payload = string.char(math.floor((code or 1000) / 256) % 256, (code or 1000) % 256)
  if reason and reason ~= "" then
    payload = payload .. reason
  end
  return gql_ws_build_frame(8, payload)
end

local function gql_ws_read_frame(sock, max_payload)
  local header = ""
  while #header < 2 do
    local chunk, rerr = gql_sock_read(sock, 256)
    if not chunk then
      return nil, "header: " .. tostring(rerr)
    end
    header = header .. chunk
  end
  local first = header:byte(1)
  local second = header:byte(2)
  local opcode = first % 16
  local len = second % 128
  local consumed = 2
  if len == 126 then
    while #header < consumed + 2 do
      local chunk, rerr = gql_sock_read(sock, 256)
      if not chunk then
        return nil, "length: " .. tostring(rerr)
      end
      header = header .. chunk
    end
    len = header:byte(3) * 256 + header:byte(4)
    consumed = 4
  elseif len == 127 then
    while #header < consumed + 8 do
      local chunk, rerr = gql_sock_read(sock, 256)
      if not chunk then
        return nil, "length: " .. tostring(rerr)
      end
      header = header .. chunk
    end
    local hi = 0
    for i = 3, 8 do
      hi = hi * 256 + header:byte(i)
    end
    len = hi
    consumed = 10
  end
  if len > max_payload or len > 262144 then
    return nil, "frame too large: " .. tostring(len)
  end
  local payload = ""
  while #payload < len do
    local chunk, rerr = gql_sock_read(sock, 256)
    if not chunk then
      if #payload == 0 then
        return nil, "payload: " .. tostring(rerr)
      end
      break
    end
    payload = payload .. chunk
  end
  return { opcode = opcode, payload = payload:sub(1, len) }, nil
end

local function gql_ws_close(result)
  if result and result.sock then
    pcall(function()
      result.sock:close()
    end)
    result.sock = nil
  end
end

local function gql_ws_teardown(result)
  if result and result.sock then
    if result.upgraded then
      pcall(function()
        result.sock:send(gql_ws_close_frame(1000, "audit complete"))
      end)
    end
    pcall(function()
      result.sock:close()
    end)
    result.sock = nil
    result.closed = true
  end
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

local function gql_candidate_list(args)
  local list = {}
  if args.path and #args.path > 0 then
    table.insert(list, args.path)
  end
  if type(args.paths) == "table" then
    for _, p in ipairs(args.paths) do
      if not list_contains(list, p) then
        table.insert(list, p)
      end
    end
  end
  if #list == 0 then
    for _, p in ipairs(GQL_CANDIDATES) do
      table.insert(list, p)
    end
  end
  return list
end

local function gql_find_endpoint(host, port, args)
  local candidates = gql_candidate_list(args)
  local results = find_gql_endpoint(host, port, args, candidates)
  for _, entry in ipairs(results) do
    if entry.is_graphql then
      return entry, results
    end
  end
  return nil, results
end

local function gql_post_with_ct(host, port, args, path, content_type, body)
  local resp, err = gql_request(host, port, path, args, {
    method = "POST",
    body = body,
    headers = { ["Content-Type"] = content_type },
  })
  if not resp then
    state.errors = state.errors + 1
    return nil, err
  end
  return resp
end

local function ct_verdict(resp)
  local row = { state = "error", detail = "transport error", reject_code = nil }
  if not resp then
    return row
  end
  local parsed = gql_parse_response(resp.body)
  if resp.status == 200 and parsed.ok and parsed.data ~= nil then
    row.state = "executed"
    row.detail = "HTTP 200 with data"
    return row
  end
  if resp.status == 415 then
    row.state = "rejected-415"
    if parsed.ok then
      for _, e in ipairs(parsed.errors) do
        if e.code and list_contains(CT_REJECT_CODES, e.code) then
          row.reject_code = e.code
        end
      end
    end
    row.detail = "HTTP 415" .. (row.reject_code and (" code=" .. row.reject_code) or "")
    return row
  end
  if parsed.ok and resp.status == 400 then
    row.state = "rejected-400"
    row.detail = "HTTP 400 - " .. truncate(gql_errors_text(parsed, 1), 90)
    return row
  end
  row.state = "other"
  row.detail = "HTTP " .. tostring(resp.status)
  return row
end

local CT_LADDER = {
  {
    name = "application/json (control)",
    header = "application/json",
    body = function() return gql_build_body("{ __typename }", nil, nil, nil) end,
    standard = true,
  },
  {
    name = "application/x-www-form-urlencoded",
    header = "application/x-www-form-urlencoded",
    body = function() return "query=" .. gql_urlencode("{ __typename }") end,
    standard = true,
  },
  {
    name = "text/plain",
    header = "text/plain",
    body = function() return gql_build_body("{ __typename }", nil, nil, nil) end,
    standard = false,
  },
  {
    name = "application/xml",
    header = "application/xml",
    body = function() return gql_build_body("{ __typename }", nil, nil, nil) end,
    standard = false,
  },
  {
    name = "multipart/form-data",
    header = "multipart/form-data; boundary=nseaudit",
    body = function()
      return "--nseaudit\r\nContent-Disposition: form-data; name=\"query\"\r\n\r\n{ __typename }\r\n--nseaudit--\r\n"
    end,
    standard = false,
  },
  {
    name = "application/graphql (vendor)",
    header = "application/graphql",
    body = function() return "{ __typename }" end,
    standard = false,
  },
}

local function remediation_section()
  local remediation = stdnse.output_table()
  remediation["1. Enforce the Content-Type Contract"] = "Accept only application/json (plus form-urlencoded if spec v1.0 form support is intended) and answer every other Content-Type with 415 before parsing the body."
  remediation["2. Align WAF/CDN Rules with the Server"] = "Make the security stack inspect exactly the Content-Types the application accepts - no more, no less - so nothing slips through an uninspected type."
  remediation["3. Reject Early, Log the Header"] = "Fail fast on wrong Content-Types and log the declared header value; repeated attempts with exotic types indicate active probing."
  remediation["4. Pin the Vendor Content Type"] = "If application/graphql is supported deliberately, document it, inspect it in the WAF, and keep the JSON path as the canonical one."
  return { key = "Remediation", value = remediation }
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()

local endpoint, scan_results = gql_find_endpoint(host, port, args)

if not endpoint then
  local status_text = "No GraphQL endpoint found on the probed paths."
  for _, entry in ipairs(scan_results or {}) do
    add_finding("INFO", "Path probe " .. tostring(entry.path) .. " -> " .. (entry.reachable and ("HTTP " .. tostring(entry.status)) or tostring(entry.detail or "unreachable")), {
      path = entry.path,
      evidence = "candidate=" .. tostring(entry.path),
    })
  end
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, {})
end

add_finding("INFO", "GraphQL endpoint confirmed at " .. tostring(endpoint.path), {
  subject = endpoint.path,
  path = endpoint.path,
  evidence = "probe __typename -> " .. (endpoint.typename and ("__typename=" .. tostring(endpoint.typename)) or "HTTP " .. tostring(endpoint.status)),
})

local rows = {}
local executed_nonstandard = {}
local executed_form = false
local rejected_415 = 0
local control_ok = false

for _, step in ipairs(CT_LADDER) do
  if budget_exhausted(args) then
    table.insert(rows, { name = step.name, state = "skipped", detail = "request budget exhausted" })
    break
  end
  local resp = gql_post_with_ct(host, port, args, endpoint.path, step.header, step.body())
  local verdict = ct_verdict(resp)
  table.insert(rows, { name = step.name, standard = step.standard, verdict = verdict })
  if step.standard and step.header == "application/json" then
    control_ok = (verdict.state == "executed")
  end
  if verdict.state == "executed" then
    if not step.standard then
      table.insert(executed_nonstandard, step.name)
    end
    if step.header:find("x-www-form-urlencoded", 1, true) then
      executed_form = true
    end
  elseif verdict.state == "rejected-415" then
    rejected_415 = rejected_415 + 1
  end
end

local status_text
local sections = {}

if not control_ok then
  status_text = "Indeterminate - the JSON control query did not execute; Content-Type analysis is inconclusive"
  add_finding("INFO", "Control query failed; see Content-Type Results", {
    subject = "content-type",
    path = endpoint.path,
  })
elseif #executed_nonstandard > 0 then
  status_text = "VULNERABLE - Non-standard Content-Types execute GraphQL operations"
  add_finding("MEDIUM", "The server executes queries with Content-Types it should not parse: " .. table.concat(executed_nonstandard, ", "), {
    subject = "content-type enforcement",
    path = endpoint.path,
    confidence = "high",
    evidence = "identical query executed under non-JSON Content-Types while the JSON control also executed",
  })
  add_finding("LOW", "WAF/CDN rules keyed on application/json do not inspect these bodies (inspection bypass surface)", {
    subject = "security rule alignment",
    evidence = "declared Content-Type differs from the type security stacks typically inspect",
    confidence = "medium",
  })
elseif executed_form then
  status_text = "NOT VULNERABLE - Content-Type enforcement matches the GraphQL-over-HTTP spec"
  add_finding("INFO", "Form-encoded bodies are accepted (spec-permitted) while all other non-JSON variants were refused with 415", {
    subject = "content-type enforcement",
    evidence = tostring(rejected_415) .. " non-standard variants refused; application/json and application/x-www-form-urlencoded accepted",
  })
else
  status_text = "NOT VULNERABLE - Content-Type is enforced (non-JSON variants refused with 415)"
  add_finding("INFO", "All " .. tostring(rejected_415) .. " non-standard Content-Type variants were refused", {
    subject = "content-type enforcement",
    evidence = "415 responses with UNSUPPORTED_CONTENT_TYPE-style handling",
  })
end

local out = stdnse.output_table()
for i, r in ipairs(rows) do
  local v = r.verdict or { state = r.state, detail = r.detail }
  out[r.name] = v.state .. " - " .. v.detail
end
table.insert(sections, { key = "Content-Type Results", value = out })

table.insert(sections, remediation_section())

local cvss = { key = "CVSS Score", value = CVSS_CTBYPASS }
if #executed_nonstandard == 0 then
  cvss.value = "n/a - content-type enforced"
end
table.insert(sections, cvss)

local unique, counts = dedupe_findings()
local final_out = new_output(RISK_LEVEL, status_text)
return finish_output(final_out, unique, counts, sections)

end
