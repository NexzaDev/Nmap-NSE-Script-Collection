#!/usr/bin/env python3
"""Smoke-test harness for the NSE collection.

Loads an *.nse file inside a Lua sandbox that provides mock versions of the
Nmap Scripting Engine libraries (shortport, http, stdnse, nmap, url, dns, ...)
plus a synthetic target, executes action(), and prints the resulting output
table. Any Lua error is reported with its message so broken scripts can be
found without a live Nmap installation.

Usage:
    python3 tools/smoke_nse.py HTTP/http-security-headers.nse
    python3 tools/smoke_nse.py HTTP                       # whole folder
    python3 tools/smoke_nse.py --scenario=hardened HTTP   # synthetic posture
    python3 tools/smoke_nse.py --quiet HTTP               # failures only
"""

import os
import sys

from lupa import LuaRuntime

SCENARIOS = ("plain", "hardened", "waf", "empty", "error", "redirect", "json", "listing", "methods", "crawler", "policy", "phpinfo", "swagger", "tls", "tls-legacy", "db", "db-secure", "ftp", "ftp-secure", "docker", "docker-secure", "graphql", "graphql-secure", "mqtt", "mqtt-secure", "snmp", "snmp-secure", "ldap", "ldap-secure", "rdp", "rdp-secure", "vnc", "vnc-secure")

MOCK_PRELUDE = r"""
SCENARIO = "plain"
BANNER = nil
PORT_NUMBER = 80
PORT_SERVICE = "http"
PORT_SSL = false

function make_output_table()
  local t = {}
  local mt = { __newindex = function(self, key, value) rawset(self, key, value) end }
  setmetatable(t, mt)
  return t
end

local real_string = string
local real_table = table
local real_math = math
local real_pairs = pairs
local real_ipairs = ipairs

mocklib = {}
mocklib.string = real_string
mocklib.table = real_table
mocklib.math = real_math

mocklib.shortport = {
  http = function(host, port) return true end,
  ssl = function(host, port) return true end,
  port_or_service = function(...) return function(host, port) return true end end,
  portnumber = function(...) return function(host, port) return true end end,
  service = function(...) return function(host, port) return true end end,
  port_state = function(...) return function(host, port) return true end end,
  version = function(...) return function(host, port) return true end end,
}

mocklib.stdnse = {
  output_table = make_output_table,
  get_script_args = function(name) return SCRIPT_ARGS[name] end,
  get_script_argument = function(name) return SCRIPT_ARGS[name] end,
  debug = function(...) end,
  debug1 = function(...) end,
  debug2 = function(...) end,
  debug3 = function(...) end,
  print_debug = function(...) end,
  verbose = function(...) return nil end,
  verbose1 = function(...) return nil end,
  format = function(fmt, ...) return real_string.format(fmt, ...) end,
  strjoin = function(sep, list) return real_table.concat(list, sep) end,
  strsplit = function(sep, value)
    local parts = {}
    for chunk in real_string.gmatch(value or "", "([^" .. sep .. "]+)") do parts[#parts + 1] = chunk end
    return parts
  end,
  sleep = function(seconds) end,
  clock_ms = function() return 0 end,
  timespec = function() return "0.00s" end,
  tohex = function(value) return real_string.rep("ab", 4) end,
  urlencode = function(value) return value end,
  url_encode = function(value) return value end,
  make_buffer = function() return function() return nil end end,
  bin = {},
}

mocklib.nmap = {
  verbosity = function() return 0 end,
  debugging = function() return 0 end,
  have_ssl = function() return true end,
  address_type = function() return "inet" end,
  set_port_state = function() end,
  get_interface_info = function() return true, "127.0.0.1", "255.0.0.0" end,
  registry = {},
  new_socket = function(proto) return new_mock_socket(proto) end,
  new_dnet = function()
    return {
      interface_open = function() return true end,
      interface_close = function() return true end,
      ethernet_send = function() return true end,
    }
  end,
}

mocklib.url = {
  parse = function(value)
    local scheme, host, port, path = real_string.match(value or "", "^(%w+)://([^/:]+):?(%d*)(/.*)$")
    if not scheme then
      local only_path = real_string.match(value or "", "^(/.*)$")
      if only_path then return { path = only_path } end
      return nil
    end
    return { scheme = scheme, host = host, port = tonumber(port), path = path or "/" }
  end,
  build = function(parts)
    return (parts.scheme or "http") .. "://" .. (parts.host or "") .. (parts.path or "/")
  end,
  absolute = function(base, rel) return rel end,
}

mocklib.bin = {
  balign = function() end,
  pack = function(fmt, ...) return real_string.rep("\0", 4) end,
  unpack = function(fmt, data, pos) return 0, 1 end,
}

mocklib.base64 = {
  enc = function(value) return "bW9jaw==" end,
  dec = function(value) return "mock" end,
}

mocklib.json = {
  generate = function(value) return "{}" end,
  parse = function(value) return true, {} end,
}

mocklib.openssl = {
  md5 = function(value) return real_string.rep("a", 16) end,
  sha1 = function(value) return real_string.rep("a", 20) end,
  rand_bytes = function(n) return real_string.rep("z", n or 8) end,
}

mocklib.bit = {}
for _, name in ipairs({"band", "bor", "bxor", "bnot", "lshift", "rshift", "arshift"}) do
  mocklib.bit[name] = function(a, b) return a or 0 end
end

mocklib.unittest = {
  test_suite = function() return true end,
  save_test_data = function() end,
  load_test_data = function() return nil end,
  check_equal = function() return true end,
  check_true = function() return true end,
}

mocklib.target = { fail_if = function() end, FAILED = false }
mocklib.datafiles = {
  parse_file = function() return true, {} end,
  parse_csv = function() return true, {} end,
  parse_sslcert = function() return true, {} end,
}
mocklib.datetime = { get_time = function() return 0 end, format_time = function() return "" end }
mocklib.ipOps = {
  isPrivate = function() return false end,
  compare_ip = function() return 0 end,
  ip_to_str = function() return "" end,
  bin_to_ip = function() return "" end,
}
mocklib.dns = {
  PACKETFLAG = {}, OPCODE = {}, TYPE = {}, CLASS = {},
  new = function(options) return { options = options } end,
  query = function(name, options) return nil, "mock dns" end,
}
mocklib.sasl = { new = function() return {} end }
mocklib.slaxml = { parser = function() return { parse = function() end } end }
mocklib.tab = {
  new = function(size)
    local t = {}
    function t:addrow(...)
      local row = {}
      for i = 1, select("#", ...) do row[i] = tostring(select(i, ...)) end
      t[#t + 1] = row
    end
    function t:addrow_table(r)
      local row = {}
      for i, v in ipairs(r) do row[i] = tostring(v) end
      t[#t + 1] = row
    end
    function t:dump()
      local parts = {}
      for _, row in ipairs(t) do parts[#parts + 1] = real_table.concat(row, " ") end
      return real_table.concat(parts, "\n")
    end
    return t
  end,
  add = function(t, ...) return t end,
  dump = function(t) return "" end,
}
mocklib.unicode = {
  utf8_enc = function(v) return v end,
  utf16_enc = function(v) return v end,
  decode = function() return "" end,
}
mocklib.rand = {
  random_string = function(n) return real_string.rep("x", n or 8) end,
  random_string_upper = function(n) return "ABCDEF" end,
}
mocklib.strbuf = {
  new = function()
    local buf = { parts = {} }
    function buf:append(v) self.parts[#self.parts + 1] = tostring(v) return self end
    function buf:concat(sep) return real_table.concat(self.parts, sep or "") end
    return buf
  end,
}
mocklib.text = {}
mocklib.match = {}
mocklib.packet = {}
mocklib.tls = {}
mocklib.cdp = {}
mocklib.rpc = {}
mocklib.vnc = {}
mocklib.rdp = {}
mocklib.smb = {}
mocklib.smb2 = {}
mocklib.smbauth = {}
mocklib.mssql = {}
mocklib.mysql = {}
mocklib.mysqlserver = {}
mocklib.ldap = {}
mocklib.snmp = { new = function() return {} end }
mocklib.mqtt = {}
mocklib.kerberos = {}
mocklib.httpspider = { new = function(host, port) return { crawl = function() return { pages = {} } end } end }
mocklib.crawl = mocklib.httpspider

function lpath_target(value)
  return real_string.lower(real_string.gsub(tostring(value or ""), "/$", ""))
end

local function gql_urldecode(s)
  s = tostring(s or "")
  s = s:gsub("+", " ")
  s = s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
  return s
end

local function gql_unescape_query(s)
  return (tostring(s or "")
    :gsub('\\"', '"')
    :gsub("\\\\", "\\"))
end

local function gql_extract_json_string(body, key)
  local pos = body:find('"' .. key .. '"', 1, true)
  if not pos then return nil end
  local colon = body:find(':', pos + #key + 2, true)
  if not colon then return nil end
  local i = colon + 1
  while i <= #body do
    local c = body:sub(i, i)
    if c == ' ' or c == string.char(9) then i = i + 1 else break end
  end
  if body:sub(i, i) ~= '"' then return nil end
  i = i + 1
  local out = {}
  while i <= #body do
    local ch = body:sub(i, i)
    if ch == string.char(92) and i + 1 <= #body then
      local nx = body:sub(i + 1, i + 1)
      if nx == '"' then out[#out + 1] = '"'
      elseif nx == string.char(92) then out[#out + 1] = string.char(92)
      elseif nx == 'n' then out[#out + 1] = string.char(10)
      elseif nx == 't' then out[#out + 1] = string.char(9)
      elseif nx == 'r' then out[#out + 1] = string.char(13)
      else out[#out + 1] = nx end
      i = i + 2
    elseif ch == '"' then
      break
    else
      out[#out + 1] = ch
      i = i + 1
    end
  end
  return table.concat(out)
end
local function gql_lev(a, b)
  local la, lb = #a, #b
  if la == 0 then return lb end
  if lb == 0 then return la end
  local prev = {}
  for i = 0, lb do prev[i] = i end
  for i = 1, la do
    local cur = { [0] = i }
    for j = 1, lb do
      local cost = 1
      if a:byte(i) == b:byte(j) then cost = 0 end
      local best = prev[j] + 1
      if cur[j - 1] + 1 < best then best = cur[j - 1] + 1 end
      if prev[j - 1] + cost < best then best = prev[j - 1] + cost end
      cur[j] = best
    end
    prev = cur
  end
  return prev[lb]
end


local function gql_type_json(t)
  local inner = tostring(t)
  local non_null = inner:match("!$") ~= nil
  if non_null then inner = inner:sub(1, -2) end
  if inner:match("^%[.-%]$") then
    local list_inner = inner:sub(2, -2)
    local list_nnull = list_inner:match("!$") ~= nil
    if list_nnull then list_inner = list_inner:sub(1, -2) end
    local leaf = '{"kind":"' .. list_inner .. '"}'
    if list_nnull then leaf = '{"kind":"NON_NULL","type":' .. leaf .. '}' end
    local list = '{"kind":"LIST","type":' .. leaf .. '}'
    if non_null then
      return '{"kind":"NON_NULL","type":' .. list .. '}'
    end
    return list
  end
  local leaf = '{"kind":"' .. inner .. '"}'
  if non_null then
    return '{"kind":"NON_NULL","type":' .. leaf .. '}'
  end
  return leaf
end

local GQL_FIELDS = {
  Query = {
    { name = "me", type = "User", desc = "Currently authenticated user." },
    { name = "user", type = "User", args = { { name = "id", type = "ID!" } } },
    { name = "users", type = "[User!]", args = { { name = "limit", type = "Int" } } },
    { name = "post", type = "Post", args = { { name = "id", type = "ID!" } } },
    { name = "posts", type = "[Post!]", args = { { name = "limit", type = "Int" } } },
    { name = "order", type = "Order", args = { { name = "id", type = "ID!" } } },
    { name = "orders", type = "[Order!]", args = { { name = "limit", type = "Int", default = "20" }, { name = "status", type = "OrderStatus" } } },
    { name = "organization", type = "Organization", args = { { name = "id", type = "ID!" } } },
    { name = "organizations", type = "[Organization!]", args = { { name = "limit", type = "Int" } } },
    { name = "search", type = "[SearchResult!]", args = { { name = "term", type = "String!" } } },
  },
  Mutation = {
    { name = "login", type = "AuthPayload", args = { { name = "email", type = "String!" }, { name = "password", type = "String!" } } },
    { name = "register", type = "AuthPayload", args = { { name = "input", type = "RegisterInput!" } } },
    { name = "resetPassword", type = "Boolean!", args = { { name = "token", type = "String!" } } },
    { name = "changePassword", type = "Boolean!", args = { { name = "current", type = "String!" }, { name = "new", type = "String!" } } },
    { name = "updateProfile", type = "User", args = { { name = "input", type = "ProfileInput!" } } },
    { name = "changeEmail", type = "Boolean!", args = { { name = "token", type = "String!" }, { name = "email", type = "String!" } } },
    { name = "addAddress", type = "Address", args = { { name = "input", type = "AddressInput!" } } },
    { name = "deleteAccount", type = "AccountDeletion", args = { { name = "token", type = "String!" } } },
    { name = "inviteUser", type = "User", args = { { name = "email", type = "String!" }, { name = "role", type = "Role!" } } },
    { name = "updateUser", type = "User", args = { { name = "id", type = "ID!" }, { name = "input", type = "UserInput!" } } },
    { name = "transferFunds", type = "Transaction", args = { { name = "amount", type = "Float!" }, { name = "to", type = "ID!" } } },
    { name = "addPaymentMethod", type = "PaymentMethod", args = { { name = "input", type = "PaymentMethodInput!" } } },
    { name = "sendVerificationEmail", type = "Boolean!", args = { { name = "email", type = "String!" } } },
    { name = "unsubscribe", type = "Boolean!", args = { { name = "token", type = "String!" } } },
    { name = "createOrder", type = "Order", args = { { name = "items", type = "[OrderItemInput!]!" } } },
  },
  Subscription = {
    { name = "orderStatus", type = "OrderEvent", args = { { name = "orderId", type = "ID!" } } },
    { name = "priceUpdates", type = "PriceTick", args = { { name = "symbol", type = "String!" } } },
    { name = "notification", type = "Notification", args = {} },
  },
  User = {
    { name = "id", type = "ID!", desc = "Primary key, bigint serialized as string." },
    { name = "name", type = "String!" },
    { name = "email", type = "String!", desc = "Stored in users.email, encrypted at rest (key ref k8s://secrets/user-pii-key)." },
    { name = "phone", type = "String", deprecate = "Use contact service /internal/contact/v1 (retiring 2026-Q4)." },
    { name = "avatarUrl", type = "String" },
    { name = "friends", type = "[User!]", desc = "Forward friendship graph; self-referential by design." },
    { name = "posts", type = "[Post!]" },
    { name = "organization", type = "Organization" },
    { name = "role", type = "Role!" },
    { name = "isStaff", type = "Boolean!" },
    { name = "lastLogin", type = "DateTime" },
    { name = "createdAt", type = "DateTime!" },
  },
  Post = {
    { name = "id", type = "ID!" },
    { name = "title", type = "String!" },
    { name = "body", type = "String!" },
    { name = "author", type = "User" },
    { name = "comments", type = "[Comment!]" },
    { name = "createdAt", type = "DateTime!" },
  },
  Comment = {
    { name = "id", type = "ID!" },
    { name = "body", type = "String!" },
    { name = "author", type = "User" },
    { name = "createdAt", type = "DateTime!" },
  },
  Order = {
    { name = "id", type = "ID!" },
    { name = "items", type = "[OrderItem!]" },
    { name = "total", type = "Float!" },
    { name = "status", type = "OrderStatus!" },
    { name = "customer", type = "User" },
    { name = "createdAt", type = "DateTime!" },
  },
  OrderItem = {
    { name = "id", type = "ID!" },
    { name = "sku", type = "String!" },
    { name = "quantity", type = "Int!" },
    { name = "unitPrice", type = "Float!" },
  },
  Organization = {
    { name = "id", type = "ID!" },
    { name = "name", type = "String!" },
    { name = "members", type = "[User!]" },
    { name = "owner", type = "User" },
  },
  Admin = {
    { name = "id", type = "ID!" },
    { name = "username", type = "String!" },
    { name = "role", type = "Role!" },
    { name = "users", type = "[User!]", desc = "All users the admin can manage." },
  },
  AuthPayload = {
    { name = "token", type = "String" },
    { name = "user", type = "User" },
  },
  Transaction = {
    { name = "id", type = "ID!" },
    { name = "amount", type = "Float!" },
    { name = "status", type = "String!" },
  },
  OrderEvent = {
    { name = "orderId", type = "ID!" },
    { name = "status", type = "OrderStatus!" },
  },
  PriceTick = {
    { name = "symbol", type = "String!" },
    { name = "price", type = "Float!" },
  },
  Notification = {
    { name = "id", type = "ID!" },
    { name = "message", type = "String!" },
  },
  SearchResult = {
    { name = "type", type = "String!" },
    { name = "id", type = "ID!" },
  },
  Address = {
    { name = "id", type = "ID!" },
    { name = "line1", type = "String!" },
  },
  PaymentMethod = {
    { name = "id", type = "ID!" },
    { name = "brand", type = "String!" },
    { name = "last4", type = "String!" },
  },
  AccountDeletion = {
    { name = "status", type = "String!" },
  },
}

local GQL_ENUMS = {
  Role = {
    desc = "Account permission roles (see rbac-middleware v3).",
    { name = "ADMIN", desc = "Full administrative access." },
    { name = "USER", desc = nil },
    { name = "MODERATOR", desc = nil },
    { name = "SUPPORT", desc = "Support agents: read-only escalation console at /internal/support." },
  },
  OrderStatus = {
    desc = "Order lifecycle states (order-svc v2.3.1).",
    { name = "PENDING", desc = nil },
    { name = "PAID", desc = nil },
    { name = "SHIPPED", desc = nil },
    { name = "DELIVERED", desc = nil },
    { name = "CANCELLED", desc = nil },
    { name = "REFUNDED", desc = nil },
  },
}

local GQL_SCALARS = {
  DateTime = "ISO-8601 timestamp (UTC) stored in pg timestamptz.",
  ID = "Unique identifier (bigint serialized).",
  JSON = "Opaque JSON value (pg jsonb).",
}

local GQL_DIRECTIVES = {
  { name = "include", desc = "Directs the executor to include this field or fragment only when the `if` argument is true.", locations = { "FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT" }, args = { { name = "if", type = "Boolean!" } } },
  { name = "skip", desc = "Directs the executor to skip this field or fragment when the `if` argument is true.", locations = { "FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT" }, args = { { name = "if", type = "Boolean!" } } },
  { name = "deprecated", desc = "Marks an element of a GraphQL schema as no longer supported.", locations = { "FIELD_DEFINITION", "ARGUMENT_DEFINITION", "INPUT_FIELD_DEFINITION", "ENUM_VALUE" }, args = { { name = "reason", type = "String", default = "\"No longer supported\"" } } },
  { name = "auth", desc = "Auth directive: JWT verified at /internal/auth/v1 before resolver execution.", locations = { "FIELD_DEFINITION" }, args = { { name = "required", type = "Boolean", default = "true" } } },
  { name = "role", desc = "Restricts resolver access to the given roles (evaluated by rbac-middleware v3).", locations = { "FIELD_DEFINITION" }, args = { { name = "allowed", type = "[Role!]" } } },
  { name = "rateLimit", desc = "Per-IP rate limit enforced at the gateway (redis key prefix rl:gateway).", locations = { "FIELD_DEFINITION" }, args = { { name = "max", type = "Int" } } },
  { name = "cacheControl", desc = "Edge cache TTL in seconds for CDN purging hooks.", locations = { "FIELD_DEFINITION", "OBJECT" }, args = { { name = "maxAge", type = "Int" } } },
  { name = "internal", desc = "Marks an internal-only field. Gateway strips it from the public schema; reachable on the :9090 admin port.", locations = { "FIELD_DEFINITION" }, args = {} },
}

local function gql_type_entry(kind, name, desc, fields, enums, input_fields)
  local f_json = "null"
  if fields then
    local entries = {}
    for _, f in ipairs(fields) do
      local args_json = "[]"
      if f.args and #f.args > 0 then
        local aentries = {}
        for _, a in ipairs(f.args) do
          local aitem = '{"name":"' .. a.name .. '","description":null,"type":' .. gql_type_json(a.type)
          if a.default then
            aitem = aitem .. ',"defaultValue":' .. a.default
          else
            aitem = aitem .. ',"defaultValue":null'
          end
          aentries[#aentries + 1] = aitem .. "}"
        end
        args_json = "[" .. table.concat(aentries, ",") .. "]"
      end
      local deprecate = "false"
      local reason = "null"
      if f.deprecate then
        deprecate = "true"
        reason = '"' .. f.deprecate .. '"'
      end
      entries[#entries + 1] = '{"name":"' .. f.name .. '","description":' .. (f.desc and ('"' .. f.desc .. '"') or "null") .. ',"args":' .. args_json .. ',"type":' .. gql_type_json(f.type) .. ',"isDeprecated":' .. deprecate .. ',"deprecationReason":' .. reason .. "}"
    end
    f_json = "[" .. table.concat(entries, ",") .. "]"
  end
  local e_json = "null"
  if enums then
    local entries = {}
    for i = 2, #enums do
      local v = enums[i]
      local deprecate = "false"
      local reason = "null"
      if v.deprecate then
        deprecate = "true"
        reason = '"' .. v.deprecate .. '"'
      end
      entries[#entries + 1] = '{"name":"' .. v.name .. '","description":' .. (v.desc and ('"' .. v.desc .. '"') or "null") .. ',"isDeprecated":' .. deprecate .. ',"deprecationReason":' .. reason .. "}"
    end
    e_json = "[" .. table.concat(entries, ",") .. "]"
  end
  return '{"kind":"' .. kind .. '","name":"' .. name .. '","description":' .. (desc and ('"' .. desc .. '"') or "null") .. ',"fields":' .. f_json .. ',"interfaces":[],"enumValues":' .. e_json .. ',"inputFields":' .. (input_fields or "null") .. ',"possibleTypes":null}'
end

local function gql_directive_entry(d)
  local args_json = "[]"
  if d.args and #d.args > 0 then
    local aentries = {}
    for _, a in ipairs(d.args) do
      local aitem = '{"name":"' .. a.name .. '","description":null,"type":' .. gql_type_json(a.type)
      if a.default then
        aitem = aitem .. ',"defaultValue":' .. a.default
      else
        aitem = aitem .. ',"defaultValue":null'
      end
      aentries[#aentries + 1] = aitem .. "}"
    end
    args_json = "[" .. table.concat(aentries, ",") .. "]"
  end
  local locs = {}
  for _, l in ipairs(d.locations) do locs[#locs + 1] = '"' .. l .. '"' end
  return '{"name":"' .. d.name .. '","description":' .. ('"' .. d.desc .. '"') .. ',"locations":[' .. table.concat(locs, ",") .. '],"args":' .. args_json .. ',"repeatable":false}'
end

local function gql_introspection_body()
  local types = {}
  for name, fields in pairs(GQL_FIELDS) do
    types[#types + 1] = gql_type_entry("OBJECT", name, GQL_TYPE_DESC[name], fields)
  end
  for name, e in pairs(GQL_ENUMS) do
    types[#types + 1] = gql_type_entry("ENUM", name, e.desc, nil, e)
  end
  for name, desc in pairs(GQL_SCALARS) do
    types[#types + 1] = gql_type_entry("SCALAR", name, desc)
  end
  table.sort(types, function(a, b) return a < b end)
  local dirs = {}
  for _, d in ipairs(GQL_DIRECTIVES) do
    dirs[#dirs + 1] = gql_directive_entry(d)
  end
  return '{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":{"name":"Subscription"},"types":[' .. table.concat(types, ",") .. '],"directives":[' .. table.concat(dirs, ",") .. ']}}}'
end

GQL_TYPE_DESC = {
  Query = "Top-level query object of the public API.",
  Mutation = "Top-level mutation object. Mutations are journaled to /var/log/app/mutations.log.",
  Subscription = "Realtime channels, served over graphql-transport-ws on the same port.",
  User = "A registered account. Backing table: users (pg 14.2, replica usr-replica-2).",
  Post = "Blog post object.",
  Comment = "Post comment object.",
  Order = "E-commerce order (order-svc v2.3.1, kafka topic orders.v2).",
  OrderItem = "Line item inside an order.",
  Organization = "Company organization (SSO via Okta, app id okta_88231).",
  Admin = "Internal administration type. Do not expose in the public API. Backing table: admin_users.",
  AuthPayload = "JWT issued by the auth service (/internal/auth/v1).",
  Transaction = "Ledger transaction (ledger-svc v1.9.0).",
  OrderEvent = "Order lifecycle event pushed on the orderStatus channel.",
  PriceTick = "Market data tick (provider: feed-agg-2).",
  Notification = "In-app notification.",
  SearchResult = "Unified search hit.",
  Address = "Shipping address (pii encrypted, key ref k8s://secrets/address-key).",
  PaymentMethod = "Stored card token (vaulted with provider tokenization).",
  AccountDeletion = "GDPR deletion ticket (processed by jobs-svc).",
}

local GQL_LEAF_VALUES = {
  id = "u_101",
  name = "Ada Lovelace",
  email = "ada@example.com",
  phone = "+44 20 7946 0001",
  avatarUrl = "https://cdn.example.com/avatars/u_101.png",
  role = "USER",
  isStaff = "false",
  lastLogin = "2026-09-20T14:32:11Z",
  createdAt = "2021-03-14T09:15:00Z",
  title = "Getting started with the API",
  body = "Sample post body.",
  total = "1234.56",
  status = "PAID",
  sku = "SKU-001",
  quantity = "2",
  unitPrice = "42.00",
  amount = "100.00",
  orderId = "o_501",
  symbol = "EURUSD",
  price = "1.0912",
  message = "Welcome aboard",
  type = "User",
  line1 = "1 Analytical Engine Way",
  brand = "VISA",
  last4 = "4242",
  username = "svc-admin",
}

local function gql_target_type(field_type)
  local t = tostring(field_type)
  local inner = t:match("^%[(.*)%]$") or t
  inner = inner:gsub("!", "")
  return inner
end

local function gql_field_lookup(type_name, field_name)
  local fields = GQL_FIELDS[type_name]
  if not fields then return nil end
  for _, f in ipairs(fields) do
    if f.name == field_name then return f end
  end
  return nil
end

local function gql_encode(v)
  local t = type(v)
  if t == "string" then
    local s = v:gsub('[%c\\"%z]', function(c)
      if c == "\"" then return "\\\"" end
      if c == "\\" then return "\\\\" end
      if c == "\n" then return "\\n" end
      if c == "\r" then return "\\r" end
      if c == "\t" then return "\\t" end
      return string.format("\\u%04x", c:byte())
    end)
    return '"' .. s .. '"'
  elseif t == "number" then
    return tostring(v)
  elseif t == "boolean" then
    return v and "true" or "false"
  elseif t == "table" then
    if v.__gql_json then return v.__gql_json end
    if v.__gql_error then
      return '{"__gql_error":' .. gql_encode(v.__gql_error) .. '}'
    end
    local n = 0
    local is_array = true
    for k in pairs(v) do
      n = n + 1
      if type(k) ~= "number" then is_array = false break end
    end
    if n == 0 then return "{}" end
    if is_array then
      local parts = {}
      for i = 1, #v do parts[i] = gql_encode(v[i]) end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local keys = {}
    for k in pairs(v) do keys[#keys + 1] = k end
    table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
    local parts = {}
    for _, k in ipairs(keys) do
      parts[#parts + 1] = '"' .. k .. '":' .. gql_encode(v[k])
    end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return "null"
end

local function gql_parse_selections(text, type_name)
  local out = {}
  local i = 1
  local len = #text
  local function skip_ws(p)
    while p <= len and text:sub(p, p):match("%s") do p = p + 1 end
    return p
  end
  local function read_ident(p)
    local c = p
    while c <= len and text:sub(c, c):match("[%w_]") do c = c + 1 end
    if c > p then
      return text:sub(p, c - 1), c
    end
    return nil, p
  end
  local function find_close(p)
    local depth = 0
    while p <= len do
      local ch = text:sub(p, p)
      if ch == "{" then
        depth = depth + 1
      elseif ch == "}" then
        depth = depth - 1
        if depth == 0 then return p end
      end
      p = p + 1
    end
    return nil
  end
  while true do
    i = skip_ws(i)
    if i > len or text:sub(i, i) == "}" then break end
    if not text:sub(i, i):match("[%w_]") then
      i = i + 1
      if i > len then break end
    end
    local first, ni = read_ident(i)
    if not first then
      i = i + 1
      if i > len then break end
    end
    i = skip_ws(ni)
    local alias = nil
    local fname = first
    local ni2 = ni
    if text:sub(i, i) == ':' then
      alias = first
      i = skip_ws(i + 1)
      if not text:sub(i, i):match('[%w_]') then break end
      fname, ni2 = read_ident(i)
      if not fname then break end
    end
    i = skip_ws(ni2)
    local args = nil
    if text:sub(i, i) == "(" then
      local close = text:find(")", i, true)
      if not close then break end
      args = text:sub(i, close)
      i = skip_ws(close + 1)
    end
    local sub = nil
    if text:sub(i, i) == "{" then
      local close = find_close(i)
      if not close then break end
      sub = text:sub(i + 1, close - 1)
      i = close + 1
    end
    out[#out + 1] = { alias = alias, name = fname, args = args, sub = sub, type = type_name }
  end
  return out
end

local function gql_max_depth(query)
  local depth = 0
  local max = 0
  for i = 1, #query do
    local ch = query:sub(i, i)
    if ch == "{" then
      depth = depth + 1
      if depth > max then max = depth end
    elseif ch == "}" then
      depth = depth - 1
    end
  end
  return max
end

local function gql_build_value(sel, type_name, depth)
  if depth > 160 then
    return { __typename = type_name }, nil
  end
  if sel.name == "__typename" then
    return type_name, nil
  end
  local field = gql_field_lookup(type_name, sel.name)
  if not field then
    return nil, 'Field "' .. sel.name .. '" does not exist on type "' .. type_name .. '".'
  end
  local target = gql_target_type(field.type)
  local is_list = field.type:match("^%[") ~= nil
  local is_object = GQL_FIELDS[target] ~= nil
  if sel.sub then
    local children = gql_parse_selections(sel.sub, target)
    local function build_one()
      local obj = {}
      for _, c in ipairs(children) do
        local v, e = gql_build_value(c, target, depth + 1)
        if e then
          return nil, e
        end
        if v ~= nil then
          obj[c.alias or c.name] = v
        end
      end
      return obj, nil
    end
    if is_list then
      local a, e1 = build_one()
      if e1 then return nil, e1 end
      local b, e2 = build_one()
      if e2 then return nil, e2 end
      return { a, b }, nil
    end
    return build_one()
  end
  if is_object then
    return nil, 'Field "' .. sel.name .. '" must have a selection of subfields. Did you mean "' .. sel.name .. ' { ... }"?'
  end
  local raw = GQL_LEAF_VALUES[sel.name] or sel.name
  if is_list then
    if raw == "USER" then return { "USER", "USER" }, nil end
    return { raw, raw }, nil
  end
  if raw == "false" then return false, nil end
  if raw == "2" then return 2, nil end
  local num = tonumber(raw)
  if num then return num, nil end
  return raw, nil
end

local GQL_DEBUG_TRACES = {
  field = "Traceback (most recent call last):\n  File \"/var/www/api/.venv/lib/python3.11/site-packages/graphql/execution/executor.py\", line 481, in execute\n    result = self.execute_field(execution_context, parent_type, field_nodes, source_name, result)\n  File \"/var/www/api/app/queries.py\", line 412, in resolve_user\n    user = db.session.query(User).filter(User.id == args[\"id\"]).first()\n  File \"/var/www/api/.venv/lib/python3.11/site-packages/sqlalchemy/orm/query.py\", line 2742, in _iter\n    result.context._execute_and_make_cursor()\n  File \"/var/www/api/.venv/lib/python3.11/site-packages/psycopg2/__init__.py\", line 122, in connect\n    conn = _connect(dsn, connection_factory=connection_factory, **kwasync)\npsycopg2.OperationalError: connection to server \"10.10.4.17:5432\" failed: FATAL:  password authentication failed for user \"app_rw\"\n  PID=48211 ADDR=0x7f3a2c1b4e90 SPAN=spn_9f2a",
  validation = "Traceback (most recent call last):\n  File \"/var/www/api/.venv/lib/python3.11/site-packages/graphql/validation/validate.py\", line 76, in validate\n    doc_errors = list(doc_errors)\n  File \"/var/www/api/app/input.py\", line 128, in validate_args\n    coerced = coerce_scalar(arg_type, arg_value)\n  File \"/var/www/api/app/input.py\", line 54, in coerce_scalar\n    raise ValidationError(f\"expected {arg_type}, got {type(arg_value).__name__}\")\napp.errors.ValidationError: expected ID!, got NoneType\n  PID=48211 ADDR=0x7f3a2c1b4f10 SPAN=spn_9f2a",
  generic = "Traceback (most recent call last):\n  File \"/var/www/api/.venv/lib/python3.11/site-packages/strawberry/http/async_http.py\", line 84, in process\n    result = await schema.execute(self.payload, context_value=context_value)\n  File \"/var/www/api/.venv/lib/python3.11/site-packages/strawberry/schema/schema.py\", line 480, in execute\n    return await execution.execute()\n  File \"/var/www/api/app/schema.py\", line 341, in <lambda>\n    raise ExecutionError(\"query depth or complexity budget exceeded\")\napp.errors.ExecutionError: query depth or complexity budget exceeded\n  PID=48211 ADDR=0x7f3a2c1b5020 SPAN=spn_9f2a",
}

local function gql_response_body(status, result)
  if type(result) == "table" and result.raw then
    return result.raw
  end
  return gql_encode(result)
end

local function gql_best_suggestion(name, type_name)
  local fields = GQL_FIELDS[type_name]
  if not fields then return nil end
  local best = nil
  local best_dist = 3
  for _, f in ipairs(fields) do
    local d = gql_lev(name, f.name)
    if d <= 2 and d < best_dist then
      best_dist = d
      best = f.name
    end
  end
  return best
end

local function gql_graphiql_html()
  return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\"/>\n  <title>GraphiQL</title>\n  <link rel=\"stylesheet\" href=\"/static/css/graphiql.min.css\">\n  <link rel=\"stylesheet\" href=\"/static/css/prism.css\">\n  <script src=\"/static/js/graphiql.min.js\"></script>\n</head>\n<body class=\"theme-light\">\n  <div id=\"graphiql\">Loading...</div>\n  <script>\n    function graphQLFetcher(graphQLParams) {\n      return fetch(\"/graphql\", {\n        method: \"post\",\n        headers: {\"Content-Type\": \"application/json\"},\n        body: JSON.stringify(graphQLParams),\n        credentials: \"same-origin\",\n      }).then(function(response) { return response.json(); });\n    }\n    GraphiQL.createFetcher({ url: \"/graphql\" });\n  </script>\n</body>\n</html>"
end

local function gql_play_html()
  return "<!DOCTYPE html>\n<html>\n<head>\n  <title>GraphQL Play</title>\n  <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/graphql-playground-react/build/assets/css/index.css\"/>\n  <script type=\"text/javascript\" src=\"https://cdn.jsdelivr.net/npm/graphql-playground-react/build/browser/index.js\"></script>\n</head>\n<body>\n  <script>window.onload = function () { GraphQLPlayground.init({ endpoint: '/graphql' }) }</script>\n</body>\n</html>"
end

local function gql_split_top_level_array(body)
  local elements = {}
  local depth = 0
  local start_pos = nil
  local in_str = false
  local esc = false
  for i = 1, #body do
    local ch = body:sub(i, i)
    if in_str then
      if esc then esc = false
      elseif ch == string.char(92) then esc = true
      elseif ch == '"' then in_str = false end
    else
      if ch == '"' then in_str = true
      elseif ch == '[' then depth = depth + 1
      elseif ch == ']' then
        depth = depth - 1
        if depth == 0 then break end
      elseif ch == '{' and depth == 1 then start_pos = i
      elseif ch == '}' and depth == 1 and start_pos then
        elements[#elements + 1] = body:sub(start_pos, i)
        start_pos = nil
      end
    end
  end
  return elements
end

local function gql_top_level_set(query)
  local lower = real_string.lower(query)
  local p = 1
  local op_kind = 'query'
  local kw = nil
  if lower:match('^%s*query%s') then kw = 'query'
  elseif lower:match('^%s*mutation%s') then kw = 'mutation'
  elseif lower:match('^%s*subscription%s') then kw = 'subscription' end
  if not kw and lower:match('^%s*%{') then
    op_kind = 'query'
  end
  if kw then
    op_kind = kw
    local _, op_end = lower:find(kw .. '%s', 1)
    p = op_end + 1
    local name = query:match('^[%a_][%w_]*', p)
    if name then p = p + #name end
    local sp1 = query:match('^%s*', p)
    p = p + #sp1
    if query:sub(p, p) == '(' then
      local close = query:find(')', p, true)
      if close then p = close + 1 end
    end
    local sp2 = query:match('^%s*', p)
    p = p + #sp2
  end
  if query:sub(p, p) ~= '{' then
    return nil, op_kind
  end
  local depth = 0
  for i = p, #query do
    local ch = query:sub(i, i)
    if ch == '{' then
      depth = depth + 1
    elseif ch == '}' then
      depth = depth - 1
      if depth == 0 then
        return query:sub(p + 1, i - 1), op_kind
      end
    end
  end
  return nil, op_kind
end


local function gql_execute_single(secure, query, has_variables, operation)
  if query:find("__schema", 1, true) or query:find("__type(", 1, true) then
    if secure then
      return 200, { errors = { { message = "Introspection is not allowed on this server.", extensions = { code = "INTROSPECTION_DISABLED" } } } }
    end
    return 200, { raw = gql_introspection_body() }
  end
  local set_text, op_kind = gql_top_level_set(query)
  local lower_query = real_string.lower(query)
  local is_mutation = op_kind == 'mutation'
  local is_subscription = op_kind == 'subscription'
  local root_type = 'Query'
  if is_mutation then root_type = 'Mutation' end
  if is_subscription then root_type = 'Subscription' end
  local selections = set_text and gql_parse_selections(set_text, root_type) or {}
  local depth = gql_max_depth(query)
  local alias_count = 0
  for _, s in ipairs(selections) do
    if s.alias then alias_count = alias_count + 1 end
  end
  if secure and depth > 20 then
    return 400, { errors = { { message = string.format("Query depth %d exceeds maximum allowed depth of 20", depth), extensions = { code = "DEPTH_LIMIT_EXCEEDED" } } } }
  end
  if secure and alias_count > 100 then
    return 400, { errors = { { message = string.format("Query alias count %d exceeds maximum allowed aliases of 100", alias_count), extensions = { code = "COMPLEXITY_LIMIT_EXCEEDED" } } } }
  end
  if is_mutation and operation == "GET" and secure then
    return 405, { errors = { { message = "Mutations are not allowed via GET requests.", extensions = { code = "MUTATION_VIA_GET_BLOCKED" } } } }
  end
  if is_mutation then
    if secure then
      return 400, { errors = { { message = "You must be authenticated to perform this operation.", extensions = { code = "UNAUTHENTICATED" } } } }
    end
  end
  if query:find("$", 1, true) and not has_variables then
    local vname = query:match("%$([%w_]+)") or "x"
    return 400, { errors = { { message = 'Variable "' .. vname .. '" of type "ID!" was not provided.', extensions = { code = "MISSING_VARIABLE" } } } }
  end
  if lower_query:find("@nope", 1) then
    return 400, { errors = { { message = 'Unknown directive "nope".', extensions = { code = "GRAPHQL_VALIDATION_FAILED" } } } }
  end
  if query:find("status: BOGUS", 1, true) then
    return 400, { errors = { { message = 'Expected value of type "OrderStatus", found "BOGUS".', extensions = { code = "GRAPHQL_VALIDATION_FAILED" } } } }
  end
  local data = {}
  for _, sel in ipairs(selections) do
    local field = gql_field_lookup(sel.type, sel.name)
    if sel.name ~= "__typename" and not field then
      local suggestion = nil
      if not secure then
        suggestion = gql_best_suggestion(sel.name, sel.type)
      end
      local msg = 'Cannot query field "' .. sel.name .. '" on type "' .. sel.type .. '".'
      if suggestion then
        msg = msg .. ' Did you mean "' .. suggestion .. '"?'
      end
      return 400, { errors = { { message = msg, extensions = { code = "GRAPHQL_VALIDATION_FAILED" } } } }
    end
    local key = sel.alias or sel.name
    if is_mutation then
      if sel.name == "login" then
        data[key] = { __typename = "AuthPayload", token = nil, user = nil }
        return 200, {
          data = data,
          errors = { { message = "Invalid credentials.", extensions = { code = "AUTHENTICATION_ERROR" } } },
        }
      end
      if sel.name == "register" or sel.name == "updateProfile" or sel.name == "updateUser"
        or sel.name == "addAddress" or sel.name == "addPaymentMethod" or sel.name == "createOrder"
        or sel.name == "changePassword" then
        local argname = "input"
        if sel.name == "changePassword" then argname = "current" end
        if sel.name == "createOrder" then argname = "items" end
        return 400, { errors = { { message = string.format('Argument "%s" of type "Input!" is required for field "Mutation.%s".', argname, sel.name), extensions = { code = "MISSING_ARGUMENT" } } } }
      end
      if sel.name == "resetPassword" or sel.name == "changeEmail"
        or sel.name == "sendVerificationEmail" or sel.name == "unsubscribe" then
        data[key] = true
        return 200, { data = data }
      end
      if sel.name == "deleteAccount" then
        data[key] = { __typename = "AccountDeletion", status = "requested" }
        return 200, { data = data }
      end
      if sel.name == "inviteUser" then
        data[key] = { __typename = "User", id = "u_1001", name = "Invited User" }
        return 200, { data = data }
      end
      if sel.name == "transferFunds" then
        data[key] = { __typename = "Transaction", id = "txn_77", amount = 100.0, status = "pending" }
        return 200, { data = data }
      end
    end
    local v, e = gql_build_value(sel, sel.type, 1)
    if e then
      return 400, { errors = { { message = e, extensions = { code = "GRAPHQL_VALIDATION_FAILED" } } } }
    end
    if v ~= nil then
      data[key] = v
    end
  end
  return 200, { data = data }
end

local GQL_ENDPOINTS = {
  ["/graphql"] = true,
  ["/api/graphql"] = true,
  ["/gql"] = true,
  ["/graphql/v1"] = true,
  ["/api/v1/graphql"] = true,
}

local GQL_IDE_PATHS = {
  ["/graphiql"] = "graphiql",
  ["/graphiql/"] = "graphiql",
  ["/api/graphiql"] = "graphiql",
  ["/graphql/graphiql"] = "graphiql",
  ["/graphql-console"] = "play",
  ["/playground"] = "play",
  ["/playground/"] = "play",
  ["/api/playground"] = "play",
  ["/graphql/playground"] = "play",
}

"""



def build_lua():
    from smoke_mocks import MOCK_PRELUDE_EXTRA
    from smoke_mocks2 import MOCK_PRELUDE_EXTRA2
    lua = LuaRuntime(unpack_returned_tuples=False)
    lua.execute(MOCK_PRELUDE + "\n" + MOCK_PRELUDE_EXTRA + "\n" + MOCK_PRELUDE_EXTRA2)

    import hashlib as _hashlib
    import base64 as _b64

    def _mock_ws_accept(key):
        return _b64.b64encode(_hashlib.sha1(key.encode("latin1")).digest()).decode("ascii")

    lua.globals()["mock_sha1_b64"] = _mock_ws_accept
    testdata = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")
    tls_assets = (
        ("TLS_CERT_MODERN_B64", "modern.b64"),
        ("TLS_CERT_LEGACY_B64", "legacy.b64"),
        ("TLS_DH_2048_HEX", "dh2048.hex"),
        ("TLS_DH_1024_HEX", "dh1024.hex"),
    )
    for var, filename in tls_assets:
        path = os.path.join(testdata, filename)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                value = fh.read().strip()
            lua.globals()[var] = value
    return lua


def smoke(path, lua, scenario="plain", banner=None, port_number=80,
          port_service="http", port_ssl=False, script_args=None):
    with open(path, encoding="utf-8") as fh:
        code = fh.read()
    out, err, socklog = lua.eval("run_script")(
        code, "@" + os.path.basename(path), scenario, banner,
        port_number, port_service, port_ssl, script_args or {})
    return out, err, socklog


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scenario = "plain"
    banner = "220 (vsFTPd 3.0.3)\r\n"
    port_number, port_service, port_ssl = 80, "http", False
    quiet = False
    targets = []

    for arg in argv:
        if arg.startswith("--scenario="):
            scenario = arg.split("=", 1)[1]
        elif arg.startswith("--banner="):
            banner = arg.split("=", 1)[1].replace("\\r", "\r").replace("\\n", "\n")
        elif arg.startswith("--port="):
            spec = arg.split("=", 1)[1]
            number, _, rest = spec.partition("/")
            port_number = int(number)
            port_service = rest or "unknown"
            port_ssl = scenario in ("tls", "tls-legacy") or port_service in ("https", "ssl")
        elif arg == "--quiet":
            quiet = True
        else:
            targets.append(arg)

    lua = build_lua()
    failures = 0
    checked = 0

    for target in targets:
        candidate = target if os.path.isabs(target) else os.path.join(root, target)
        files = []
        if os.path.isdir(candidate):
            for name in sorted(os.listdir(candidate)):
                if name.endswith(".nse"):
                    files.append(os.path.join(candidate, name))
        elif os.path.isfile(candidate):
            files.append(candidate)
        else:
            print("SKIP %s (not found)" % target)
            continue

        for path in files:
            checked += 1
            out, err, socklog = smoke(path, lua, scenario, banner,
                                      port_number, port_service, port_ssl)
            rel = os.path.relpath(path, root)
            if err:
                failures += 1
                print("FAIL %-46s %s" % (rel, err))
            elif not quiet:
                print("OK   %-46s%s" % (rel, out or ""))

    print(f"smoke: {checked} scripts, {faulries} failures (scenario={scenario})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
