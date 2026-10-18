local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Audits the TLS profile negotiated after STARTTLS: a modern AEAD
baseline, a TLS 1.3 attempt and a legacy RC4 rejection check, each as
an independent connection + STARTTLS + ClientHello exchange.

Why it matters
- Mail TLS is often the oldest certificate and protocol stack on the
  network; RC4/CBC/export suites still linger on legacy gateways.
- The negotiated profile is what actually protects the credentials and
  envelopes.

What the script does
1. Baseline handshake with AEAD-only suites.
2. TLS 1.3 offer via supported_versions.
3. Legacy RC4-only offer (should be rejected).

Safe operation: three handshakes total; no mail flows inside the
tunnels.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"defensive", "safe"}

portrule = shortport.port_or_service(
  25,
  "smtp",
  "tcp"
)

local SCRIPT_NAME = "smtp-tls-ciphers-audit"

local RISK_LEVEL = "🟡 MEDIUM"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 48,
  recv_window = 6,
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {}

local NUMERIC_ARGS = {
  { key = "timeout", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "recv_window", minimum = 1, maximum = 30, integer = true },
}

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

SMTP_T = {
  AUDIT_HOST = "nse-audit.invalid",
  CODES = {
    [220] = "Service ready", [221] = "Service closing transmission channel",
    [235] = "Authentication successful", [250] = "Requested action completed",
    [251] = "User not local; will forward", [252] = "Cannot VRFY user, but will accept",
    [253] = "OK, pending messages for node started", [334] = "Auth continuation",
    [354] = "Start mail input", [421] = "Service not available",
    [450] = "Mailbox unavailable (temporary)", [451] = "Local error (temporary)",
    [452] = "Insufficient storage", [454] = "TLS not available due to temporary reason",
    [500] = "Syntax error", [501] = "Syntax error in parameters",
    [502] = "Command not implemented", [503] = "Bad sequence of commands",
    [504] = "Command parameter not implemented", [530] = "Authentication required",
    [534] = "Authentication mechanism too weak", [535] = "Authentication credentials invalid",
    [538] = "Encryption required for requested auth mechanism",
    [550] = "Mailbox unavailable", [551] = "User not local",
    [552] = "Exceeded storage allocation", [553] = "Mailbox name not allowed",
    [554] = "Transaction failed",
  },
  EHLO_KEYWORDS = { "SIZE", "8BITMIME", "PIPELINING", "STARTTLS", "AUTH", "ENHANCEDSTATUSCODES", "DSN", "SMTPUTF8", "HELP", "ETRN", "CHUNKING", "BINARYMIME", "VRFY", "ETRN", "XFORWARD", "X-EXPS" },
  AUTH_MECHS = { "PLAIN", "LOGIN", "CRAM-MD5", "DIGEST-MD5", "GSSAPI", "XOAUTH2", "NTLM", "ANONYMOUS", "EXTERNAL", "X-EXPS" },
  MTAS = {
    { mta = "Postfix", patterns = { "Postfix" } },
    { mta = "Exim", patterns = { "Exim", "exim" } },
    { mta = "Sendmail", patterns = { "Sendmail" } },
    { mta = "Microsoft Exchange", patterns = { "Microsoft ESMTP", "Microsoft SMTP" } },
    { mta = "Zimbra", patterns = { "Zimbra" } },
    { mta = "OpenSMTPD", patterns = { "OpenSMTPD", "opensmtpd" } },
    { mta = "Haraka", patterns = { "Haraka" } },
    { mta = "PowerMTA", patterns = { "PowerMTA" } },
    { mta = "MailEnable", patterns = { "MailEnable" } },
    { mta = "Proofpoint", patterns = { "Proofpoint", "pps Filter" } },
    { mta = "Mimecast", patterns = { "Mimecast" } },
    { mta = "Cisco IronPort", patterns = { "IronPort", " Cisco " } },
    { mta = "Qmail", patterns = { "qmail" } },
    { mta = "DMARC gateway", patterns = { "dmarc" } },
  },
  B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
}

local function b64_encode(data)
  local out = {}
  local alphabet = SMTP_T.B64_ALPHABET
  for i = 1, #data, 3 do
    local a, b, c = string.byte(data, i, i + 2)
    local pack = a * 65536 + (b or 0) * 256 + (c or 0)
    out[#out + 1] = string.sub(alphabet, math.floor(pack / 262144) % 64 + 1, math.floor(pack / 262144) % 64 + 1)
    out[#out + 1] = string.sub(alphabet, math.floor(pack / 4096) % 64 + 1, math.floor(pack / 4096) % 64 + 1)
    if b ~= nil then
      out[#out + 1] = string.sub(alphabet, math.floor(pack / 64) % 64 + 1, math.floor(pack / 64) % 64 + 1)
    else
      out[#out + 1] = "="
    end
    if c ~= nil then
      out[#out + 1] = string.sub(alphabet, pack % 64 + 1, pack % 64 + 1)
    else
      out[#out + 1] = "="
    end
  end
  return table.concat(out)
end

local function b64_decode(data)
  local lookup = {}
  for i = 1, #SMTP_T.B64_ALPHABET do
    lookup[string.sub(SMTP_T.B64_ALPHABET, i, i)] = i - 1
  end
  local clean = string.gsub(data, "[^%w%+%/]", "")
  local out = {}
  for i = 1, #clean - 3, 4 do
    local n = lookup[string.sub(clean, i, i)] * 262144 + lookup[string.sub(clean, i + 1, i + 1)] * 4096
      + lookup[string.sub(clean, i + 2, i + 2)] * 64 + lookup[string.sub(clean, i + 3, i + 3)]
    out[#out + 1] = string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
  end
  local rem = #clean % 4
  if rem == 2 then
    local i = #clean - 1
    local n = lookup[string.sub(clean, i, i)] * 262144 + lookup[string.sub(clean, i + 1, i + 1)] * 4096
    out[#out + 1] = string.char(math.floor(n / 65536) % 256)
  elseif rem == 3 then
    local i = #clean - 2
    local n = lookup[string.sub(clean, i, i)] * 262144 + lookup[string.sub(clean, i + 1, i + 1)] * 4096
      + lookup[string.sub(clean, i + 2, i + 2)] * 64
    out[#out + 1] = string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256)
  end
  return table.concat(out)
end

SMTP_B = {}

function SMTP_B.cmd(text)
  return text .. "\r\n"
end

function SMTP_B.helo(name)
  return "HELO " .. (name or SMTP_T.AUDIT_HOST) .. "\r\n"
end

function SMTP_B.ehlo(name)
  return "EHLO " .. (name or SMTP_T.AUDIT_HOST) .. "\r\n"
end

function SMTP_B.mail_from(addr, opts)
  opts = opts or {}
  local line = "MAIL FROM:<" .. addr .. ">"
  if opts.size then
    line = line .. " SIZE=" .. tostring(opts.size)
  end
  if opts.body_8bit then
    line = line .. " BODY=8BITMIME"
  end
  return line .. "\r\n"
end

function SMTP_B.rcpt_to(addr)
  return "RCPT TO:<" .. addr .. ">\r\n"
end

function SMTP_B.data()
  return "DATA\r\n"
end

function SMTP_B.mail_body(lines)
  local body = {}
  for _, l in ipairs(lines) do
    if string.sub(l, 1, 1) == "." then
      l = "." .. l
    end
    body[#body + 1] = l
  end
  return table.concat(body, "\r\n") .. "\r\n.\r\n"
end

function SMTP_B.rset()
  return "RSET\r\n"
end

function SMTP_B.vrfy(user)
  return "VRFY " .. user .. "\r\n"
end

function SMTP_B.expn(list)
  return "EXPN " .. list .. "\r\n"
end

function SMTP_B.help(topic)
  if topic then
    return "HELP " .. topic .. "\r\n"
  end
  return "HELP\r\n"
end

function SMTP_B.noop()
  return "NOOP\r\n"
end

function SMTP_B.quit()
  return "QUIT\r\n"
end

function SMTP_B.starttls()
  return "STARTTLS\r\n"
end

function SMTP_B.auth_plain_initial(user, pass)
  local blob = "\0" .. user .. "\0" .. pass
  return "AUTH PLAIN " .. b64_encode(blob) .. "\r\n"
end

function SMTP_B.auth_plain_line(user, pass)
  return b64_encode("\0" .. user .. "\0" .. pass) .. "\r\n"
end

function SMTP_B.auth_login_user(user)
  return "AUTH LOGIN\r\n"
end

function SMTP_B.auth_login_user_b64(user)
  return b64_encode(user) .. "\r\n"
end

function SMTP_B.auth_login_pass_b64(pass)
  return b64_encode(pass) .. "\r\n"
end

function SMTP_B.auth_cram_response(user, digest)
  return user .. " " .. digest .. "\r\n"
end

SMTP_X = {}

function SMTP_X.parse_reply(buf)
  local reply = { lines = {}, raw = buf or "" }
  local pos = 1
  local code = nil
  while pos <= #reply.raw do
    local nl = string.find(reply.raw, "\r\n", pos, true)
    if nl == nil then
      break
    end
    local line = string.sub(reply.raw, pos, nl - 1)
    pos = nl + 2
    if #line >= 3 then
      local prefix = string.sub(line, 1, 3)
      local n = tonumber(prefix)
      if n ~= nil then
        local sep = string.sub(line, 4, 4)
        code = n
        local text = string.sub(line, 5)
        reply.lines[#reply.lines + 1] = text
        if sep == " " then
          reply.code = n
          reply.text = table.concat(reply.lines, " | ")
          reply.enhanced = string.match(reply.lines[#reply.lines], "^(%d%.%d%.%d)")
          reply.complete = true
          reply.consumed = pos
          return reply
        end
      end
    end
  end
  reply.code = code
  reply.complete = false
  return reply
end

function SMTP_X.parse_ehlo(reply)
  local out = { keywords = {}, raw = {} }
  if reply == nil or reply.code ~= 250 then
    out.code = reply and reply.code
    return out
  end
  out.code = 250
  out.hostname = reply.lines[1]
  for i = 2, #reply.lines do
    local line = reply.lines[i]
    out.raw[#out.raw + 1] = line
    local kw, params = string.match(line, "^([%w%-]+)%s*(.*)$")
    if kw then
      out.keywords[string.upper(kw)] = params
      if string.upper(kw) == "SIZE" then
        out.size_limit = tonumber(params)
      elseif string.upper(kw) == "AUTH" or string.upper(kw) == "X-EXPS" then
        out.auth_mechs = {}
        for mech in string.gmatch(params, "[^%s]+") do
          out.auth_mechs[#out.auth_mechs + 1] = mech
        end
      end
    end
  end
  out.starttls = out.keywords["STARTTLS"] ~= nil
  out.pipelining = out.keywords["PIPELINING"] ~= nil
  out.eightbit = out.keywords["8BITMIME"] ~= nil
  out.enhanced = out.keywords["ENHANCEDSTATUSCODES"] ~= nil
  out.smtputf8 = out.keywords["SMTPUTF8"] ~= nil
  out.dsn = out.keywords["DSN"] ~= nil
  out.help_kw = out.keywords["HELP"] ~= nil
  out.chunking = out.keywords["CHUNKING"] ~= nil
  return out
end

function SMTP_X.classify_banner(text)
  local out = { mta = "Unknown", version = nil, raw = text or "" }
  if text == nil or text == "" then
    return out
  end
  for _, sig in ipairs(SMTP_T.MTAS) do
    for _, pat in ipairs(sig.patterns) do
      local s, e = string.find(text, pat)
      if s then
        out.mta = sig.mta
        local after = string.sub(text, e + 1)
        out.version = string.match(after, "%s*[vV]?([0-9]+%.[0-9]+[0-9a-zA-Z%.%-%_]*)")
          or string.match(text, "([0-9]+%.[0-9]+[0-9a-zA-Z%.%-%_]*)")
        return out
      end
    end
  end
  out.version = string.match(text, "([0-9]+%.[0-9]+[0-9a-zA-Z%.%-%_]*)")
  return out
end

function SMTP_X.reply_class(code)
  if code == nil then
    return "no-answer"
  end
  if code >= 500 then
    return "permanent-error"
  elseif code >= 400 then
    return "temporary-error"
  elseif code >= 300 then
    return "intermediate"
  elseif code >= 200 then
    return "success"
  end
  return "other"
end

function SMTP_X.addr_class(code)
  local cls = SMTP_X.reply_class(code)
  if cls == "success" or cls == "intermediate" then
    return "accepted"
  elseif code == 550 or code == 551 or code == 553 then
    return "unknown-or-refused"
  elseif cls == "temporary-error" then
    return "greylist-or-temp"
  else
    return "refused"
  end
end

function SMTP_X.relay_envelope(mail_code, rcpt_code)
  local mail_ok = mail_code ~= nil and mail_code < 300
  local rcpt_ok = rcpt_code ~= nil and rcpt_code < 300
  if mail_ok and rcpt_ok then
    return "relayed"
  elseif rcpt_code == 554 or rcpt_code == 550 then
    return "denied"
  elseif mail_ok == false then
    return "sender-refused"
  end
  return "unclear"
end

function SMTP_X.vrfy_classify(code)
  if code == 250 or code == 251 then
    return "disclosure"
  elseif code == 252 then
    return "weak"
  elseif code == 502 or code == 500 or code == 501 then
    return "disabled"
  elseif code == 550 then
    return "denied"
  end
  return "unclear"
end

function SMTP_X.enhanced_class(enhanced)
  if enhanced == nil then
    return nil
  end
  local cls, subj = string.match(enhanced, "^(%d)%.(%d)%.%d+$")
  if cls == nil then
    return nil
  end
  local subjects = {
    ["0"] = "other", ["1"] = "addressing", ["2"] = "mailbox", ["3"] = "mail-system",
    ["4"] = "network/routing", ["5"] = "delivery", ["6"] = "message-content", ["7"] = "security/policy",
  }
  return { cls = cls, subject = subj, subject_name = subjects[subj] or "other" }
end

SMTP_A = {}

function SMTP_A.selftest()
  if b64_encode("Man") ~= "TWFu" then
    return false, "base64 encode failed"
  end
  if b64_encode("\0admin\0admin") ~= "AGFkbWluAGFkbWlu" then
    return false, "base64 auth blob failed: " .. b64_encode("\0admin\0admin")
  end
  if b64_decode("TWFu") ~= "Man" then
    return false, "base64 decode failed"
  end
  local r = SMTP_X.parse_reply("250-mail.corp.example.com\r\n250-PIPELINING\r\n250-SIZE 20480000\r\n250 AUTH PLAIN LOGIN\r\n")
  if r.code ~= 250 or not r.complete or #r.lines ~= 4 then
    return false, "multiline reply parse failed"
  end
  local ehlo = SMTP_X.parse_ehlo(r)
  if ehlo.starttls or ehlo.auth_mechs == nil or #ehlo.auth_mechs ~= 2 or ehlo.size_limit ~= 20480000 then
    return false, "ehlo parse failed"
  end
  if not ehlo.pipelining then
    return false, "ehlo pipelining flag failed"
  end
  local single = SMTP_X.parse_reply("550 5.1.1 <nosuch@corp.example.com>: Recipient address rejected\r\n")
  if single.code ~= 550 or single.enhanced ~= "5.1.1" then
    return false, "single reply parse failed"
  end
  local ec = SMTP_X.enhanced_class(single.enhanced)
  if ec == nil or ec.subject_name ~= "addressing" then
    return false, "enhanced code classify failed"
  end
  local banner = SMTP_X.classify_banner("220 mail.corp.example.com ESMTP Postfix (Ubuntu)")
  if banner.mta ~= "Postfix" then
    return false, "banner classify failed: " .. tostring(banner.mta)
  end
  if SMTP_X.vrfy_classify(250) ~= "disclosure" or SMTP_X.vrfy_classify(502) ~= "disabled" or SMTP_X.vrfy_classify(252) ~= "weak" then
    return false, "vrfy classify failed"
  end
  if SMTP_X.relay_envelope(250, 250) ~= "relayed" or SMTP_X.relay_envelope(250, 554) ~= "denied" then
    return false, "relay classify failed"
  end
  local auth = SMTP_B.auth_plain_initial("admin", "admin")
  if not string.find(auth, "AUTH PLAIN AGFkbWluAGFkbWlu", 1, true) then
    return false, "auth plain build failed"
  end
  return true, "SMTP codec and parsers verified"
end

local function tl_u16(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

local function tl_u24(n)
  return string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

local function tl_u32(n)
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256, n % 256)
end

local function tl_b16(b)
  return b:byte(1) * 256 + b:byte(2)
end

local function tl_b24(b)
  return b:byte(1) * 65536 + b:byte(2) * 256 + b:byte(3)
end

local function tl_b32(b)
  return b:byte(1) * 16777216 + b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
end

local function tl_record(type_byte, version, payload)
  return string.char(type_byte) .. tl_u16(version or 0x0303) .. tl_u16(#payload) .. payload
end

local function tl_handshake(type_byte, body)
  return string.char(type_byte) .. tl_u24(#body) .. body
end

local function tl_client_hello(opts)
  opts = opts or {}
  local version = opts.version or 0x0303
  local random = opts.random or string.char(
    0xa1, 0x4f, 0x02, 0x9c, 0x77, 0x1b, 0xd3, 0x40,
    0x55, 0x90, 0xe8, 0x2f, 0x66, 0xab, 0x17, 0xc3,
    0x09, 0xd4, 0x2a, 0x58, 0xb1, 0x3e, 0x88, 0x72,
    0xe6, 0x04, 0xc9, 0xd5, 0x11, 0xfa, 0x6b, 0x20)
  local session_id = opts.session_id or ""
  local ciphers = opts.ciphers or { 0xc02f, 0xc030, 0x009c, 0x009d, 0x1301, 0x1302 }
  local comps = opts.comps or { 0 }
  local list = ""
  for _, c in ipairs(ciphers) do
    list = list .. tl_u16(c)
  end
  local comp_list = ""
  for _, c in ipairs(comps) do
    comp_list = comp_list .. string.char(c)
  end
  local exts = ""
  local function add_ext(id, data)
    exts = exts .. tl_u16(id) .. tl_u16(#data) .. data
  end
  if opts.sni then
    local entry = string.char(0) .. tl_u16(#opts.sni) .. opts.sni
    local inner = tl_u16(#entry) .. entry
    add_ext(0, inner)
  end
  if opts.ems ~= false then
    add_ext(0x0017, string.char(0))
  end
  if opts.alpn then
    local al = ""
    for _, p in ipairs(opts.alpn) do
      al = al .. string.char(#p) .. p
    end
    add_ext(16, tl_u16(#al) .. al)
  end
  if opts.status_request then
    add_ext(5, string.char(1, 0))
  end
  if opts.sig_algs then
    local sa = ""
    for _, s in ipairs(opts.sig_algs) do
      sa = sa .. tl_u16(s)
    end
    add_ext(13, tl_u16(#sa) .. sa)
  end
  if opts.supported_versions then
    local sv = ""
    for _, v in ipairs(opts.supported_versions) do
      sv = sv .. tl_u16(v)
    end
    add_ext(43, string.char(#sv) .. sv)
  end
  if opts.heartbeat then
    add_ext(15, tl_u16(1))
  end
  if opts.renegotiation_info then
    add_ext(0xff01, string.char(1, 0))
  end
  if opts.raw_exts then
    for _, re in ipairs(opts.raw_exts) do
      exts = exts .. tl_u16(re.id) .. tl_u16(#re.data) .. re.data
    end
  end
  local body = tl_u16(opts.record_version or version)
    .. random
    .. string.char(#session_id) .. session_id
    .. tl_u16(#list) .. list
    .. string.char(#comps) .. comp_list
    .. tl_u16(#exts) .. exts
  return tl_record(0x16, version, tl_handshake(0x01, body))
end

local function tl_parse_records(buf)
  local records = {}
  local i = 1
  while i + 4 <= #buf do
    local t = buf:byte(i)
    local v = tl_b16(buf:sub(i + 1, i + 2))
    local l = tl_b16(buf:sub(i + 3, i + 4))
    if i + 4 + l > #buf then
      break
    end
    records[#records + 1] = { type = t, version = v, payload = buf:sub(i + 5, i + 4 + l) }
    i = i + 5 + l
  end
  return records
end

local function tl_parse_handshake_messages(payload)
  local msgs = {}
  local i = 1
  while i + 3 <= #payload do
    local t = payload:byte(i)
    local l = tl_b24(payload:sub(i + 1, i + 3))
    if i + 3 + l > #payload then
      break
    end
    msgs[#msgs + 1] = { type = t, body = payload:sub(i + 4, i + 3 + l) }
    i = i + 4 + l
  end
  return msgs
end

local function tl_parse_extensions(body, off)
  local exts = {}
  if off == nil or off + 2 > #body then
    return exts, off
  end
  local total = tl_b16(body:sub(off, off + 1))
  local end_at = off + 2 + total
  local i = off + 2
  while i + 4 <= end_at and i + 3 <= #body do
    local id = tl_b16(body:sub(i, i + 1))
    local len = tl_b16(body:sub(i + 2, i + 3))
    exts[id] = body:sub(i + 4, i + 3 + len)
    i = i + 4 + len
  end
  return exts, i
end

local function tl_parse_server_hello(body)
  local out = {}
  if #body < 2 then
    return out
  end
  out.version = tl_b16(body:sub(1, 2))
  out.random = #body >= 34 and body:sub(3, 34) or nil
  if #body < 35 then
    return out
  end
  local sid_len = body:byte(35)
  if 35 + sid_len + 3 > #body then
    return out
  end
  out.session_id = body:sub(36, 35 + sid_len)
  local ci = 36 + sid_len
  out.cipher = tl_b16(body:sub(ci, ci + 1))
  out.compression = body:byte(ci + 2) or 0
  local ext_off = ci + 3
  if ext_off + 1 <= #body then
    out.extensions = tl_parse_extensions(body, ext_off)
  end
  return out
end

local function tl_parse_certificate(body)
  local out = { certs = {} }
  local total = tl_b24(body:sub(1, 3))
  local i = 4
  local end_at = 4 + total
  while i + 3 <= end_at and i + 3 <= #body do
    local l = tl_b24(body:sub(i, i + 2))
    out.certs[#out.certs + 1] = body:sub(i + 3, i + 2 + l)
    i = i + 3 + l
  end
  return out
end

local function tl_parse_server_key_exchange(body)
  local out = {}
  local i = 1
  if i + 1 > #body then
    return out
  end
  local p_len = tl_b16(body:sub(i, i + 1))
  if i + 1 + p_len > #body then
    return out
  end
  out.dh_prime = body:sub(i + 2, i + 1 + p_len)
  out.prime_bits = #out.dh_prime * 8
  i = i + 2 + p_len
  if i > #body then
    return out
  end
  local g_len = body:byte(i)
  if i + g_len > #body then
    return out
  end
  out.dh_gen = body:sub(i + 1, i + g_len)
  i = i + 1 + g_len
  if i + 1 <= #body then
    out.sig_len = tl_b16(body:sub(i, i + 1))
    i = i + 2
    if i <= #body then
      out.hash_len = body:byte(i)
    end
  end
  return out
end

local function tl_parse_alert(body)
  return { level = body:byte(1), code = body:byte(2) }
end

local function tl_parse_certificate_status(body)
  local out = { status_type = body:byte(1) }
  if out.status_type == 1 then
    local l = tl_b24(body:sub(2, 4))
    out.ocsp_len = l
    out.ocsp = body:sub(5, 4 + l)
  end
  return out
end

local function tl_parse_heartbeat(body)
  local out = {
    type = body:byte(1),
    payload_len = tl_b16(body:sub(2, 3)),
    random = body:sub(4, 19),
  }
  local data_end = math.min(19 + out.payload_len, #body)
  out.data = body:sub(20, data_end)
  out.trailer = #body - data_end
  return out
end

local function tl_alpn_selected(body)
  if body == nil or #body < 3 then
    return nil
  end
  local l = tl_b16(body:sub(1, 2))
  if l < 1 or 2 + l > #body then
    return nil
  end
  return body:sub(3, 2 + l)
end

local function tl_dh_prime_bits(prime)
  if prime == nil or #prime == 0 then
    return nil
  end
  local i = 1
  while i < #prime and prime:byte(i) == 0 do
    i = i + 1
  end
  if i > #prime then
    return 0
  end
  local top = prime:byte(i)
  local bits = 0
  while top > 0 do
    bits = bits + 1
    top = math.floor(top / 2)
  end
  return (#prime - i) * 8 + bits
end

local TL_ALERT_NAMES = {
  [0] = "close_notify", [10] = "unexpected_message", [20] = "bad_record_mac",
  [30] = "handshake_failure", [40] = "bad_certificate",
  [45] = "unsupported_certificate", [46] = "certificate_unknown",
  [50] = "decrypt_error", [70] = "protocol_version",
  [71] = "insufficient_security", [80] = "internal_error",
  [86] = "inappropriate_fallback", [90] = "user_canceled",
  [100] = "no_renegotiation", [109] = "missing_extension",
  [110] = "unsupported_extension", [112] = "unrecognized_name",
  [113] = "bad_certificate_status_response", [115] = "unknown_psk_identity",
  [116] = "certificate_required", [120] = "no_application_protocol",
}

local function tl_alert_name(level, code)
  if level == 2 then
    return "fatal:" .. (TL_ALERT_NAMES[code] or ("0x%02x"):format(code))
  end
  return "warning:" .. (TL_ALERT_NAMES[code] or ("0x%02x"):format(code))
end

local function tl_alert_record(code, version)
  return tl_record(0x15, version or 0x0303, string.char(2, code))
end

local TL_VERSION_NAMES = {
  [0x0300] = "SSL 3.0",
  [0x0301] = "TLS 1.0",
  [0x0302] = "TLS 1.1",
  [0x0303] = "TLS 1.2",
  [0x0304] = "TLS 1.3",
}

local function tl_version_name(v)
  return TL_VERSION_NAMES[v] or string.format("0x%04x", v or 0)
end

local function tl_der_tlv(data, off)
  local tag = data:byte(off)
  local len = data:byte(off + 1)
  local hdr = 2
  if len >= 0x80 then
    local n = len - 0x80
    if off + 1 + n > #data then
      return nil
    end
    len = 0
    for i = 1, n do
      len = len * 256 + data:byte(off + 1 + i)
    end
    hdr = 2 + n
  end
  if off + hdr + len - 1 > #data then
    return nil
  end
  return {
    tag = tag,
    len = len,
    hdr = hdr,
    content = data:sub(off + hdr, off + hdr + len - 1),
    next = off + hdr + len,
  }
end

local function tl_der_walk(data)
  local nodes = {}
  local function walk(off, depth)
    local t = tl_der_tlv(data, off)
    if t == nil then
      return nil
    end
    local idx = #nodes + 1
    nodes[idx] = {
      tag = t.tag, len = t.len, content = t.content,
      start = off, end_at = t.next, depth = depth, index = idx,
    }
    if t.tag == 0x30 or t.tag == 0x31 or (t.tag >= 0xa0 and t.tag <= 0xbf) then
      local i = off + t.hdr
      while i < t.next do
        i = walk(i, depth + 1)
        if i == nil then
          break
        end
      end
    end
    return t.next
  end
  walk(1, 0)
  return nodes
end

local function tl_child_list(nodes, parent)
  local list = {}
  local i = parent.index + 1
  while i <= #nodes do
    local n = nodes[i]
    if n == nil or n.start >= parent.end_at then
      break
    end
    if n.depth == parent.depth + 1 then
      list[#list + 1] = n
    end
    i = i + 1
  end
  return list
end

local TL_OID_NAMES = {
  ["1.2.840.113549.1.1.1"] = "rsaEncryption",
  ["1.2.840.113549.1.1.2"] = "md2WithRSAEncryption",
  ["1.2.840.113549.1.1.4"] = "md5WithRSAEncryption",
  ["1.2.840.113549.1.1.5"] = "sha1WithRSAEncryption",
  ["1.2.840.113549.1.1.11"] = "sha256WithRSAEncryption",
  ["1.2.840.113549.1.1.12"] = "sha384WithRSAEncryption",
  ["1.2.840.113549.1.1.13"] = "sha512WithRSAEncryption",
  ["1.2.840.113549.1.1.14"] = "sha224WithRSAEncryption",
  ["1.2.840.113549.1.1.15"] = "sha512-224WithRSAEncryption",
  ["1.2.840.113549.1.1.16"] = "sha512-256WithRSAEncryption",
  ["1.2.840.10045.2.1"] = "ecPublicKey",
  ["2.5.29.14"] = "keyUsage",
  ["2.5.29.15"] = "extendedKeyUsage",
  ["2.5.29.17"] = "subjectAltName",
  ["2.5.29.19"] = "basicConstraints",
  ["2.5.29.31"] = "crlDistributionPoints",
  ["1.3.6.1.5.5.7.1.1"] = "authorityInfoAccess",
  ["1.3.6.1.5.5.7.48.1"] = "ocsp",
  ["1.3.6.1.5.5.7.48.5"] = "caIssuers",
}

local TL_NAME_OIDS = {
  ["2.5.4.3"] = "CN",
  ["2.5.4.4"] = "SN",
  ["2.5.4.5"] = "serialNumber",
  ["2.5.4.6"] = "C",
  ["2.5.4.7"] = "L",
  ["2.5.4.8"] = "ST",
  ["2.5.4.9"] = "street",
  ["2.5.4.10"] = "O",
  ["2.5.4.11"] = "OU",
  ["0.9.2342.19200300.100.1.25"] = "DC",
  ["1.3.6.1.4.1.311.60.2.1.3"] = "jurisdictionC",
}

local function tl_der_oid_str(data)
  if data == nil or #data == 0 then
    return nil
  end
  local parts = {}
  local i = 1
  local function read_arc()
    local v = 0
    while i <= #data do
      local b = data:byte(i)
      i = i + 1
      v = v * 128 + (b & 0x7f)
      if (b & 0x80) == 0 then
        break
      end
    end
    return v
  end
  local first = data:byte(1)
  i = 2
  if first < 40 then
    parts[1] = "0." .. first
  elseif first < 80 then
    parts[1] = "1." .. (first - 40)
  else
    parts[1] = "2.5"
  end
  local rest = read_arc()
  parts[#parts + 1] = tostring(rest)
  while i <= #data do
    parts[#parts + 1] = tostring(read_arc())
  end
  return table.concat(parts, ".")
end

local function tl_der_name_str(nodes, parent)
  local parts = {}
  for _, rdn in ipairs(tl_child_list(nodes, parent)) do
    if rdn.tag == 0x31 then
      local attrs = {}
      for _, attr in ipairs(tl_child_list(nodes, rdn)) do
        if attr.tag == 0x30 then
          local ac = tl_child_list(nodes, attr)
          local oid_n = ac[1]
          local val_n = ac[2]
          if oid_n ~= nil and oid_n.tag == 0x06 and val_n ~= nil then
            local oid = tl_der_oid_str(oid_n.content)
            local label = TL_NAME_OIDS[oid] or oid
            attrs[#attrs + 1] = label .. "=" .. val_n.content
          end
        end
      end
      if #attrs > 0 then
        parts[#parts + 1] = table.concat(attrs, ", ")
      end
    end
  end
  return table.concat(parts, " / ")
end

local function tl_der_name_key(nodes, parent)
  local parts = {}
  for _, rdn in ipairs(tl_child_list(nodes, parent)) do
    if rdn.tag == 0x31 then
      local attrs = {}
      for _, attr in ipairs(tl_child_list(nodes, rdn)) do
        if attr.tag == 0x30 then
          local ac = tl_child_list(nodes, attr)
          local oid_n = ac[1]
          local val_n = ac[2]
          if oid_n ~= nil and oid_n.tag == 0x06 and val_n ~= nil then
            local oid = tl_der_oid_str(oid_n.content)
            local label = TL_NAME_OIDS[oid] or oid
            attrs[#attrs + 1] = label .. "=" .. val_n.content
          end
        end
      end
      if #attrs > 0 then
        table.sort(attrs)
        parts[#parts + 1] = table.concat(attrs, ",")
      end
    end
  end
  table.sort(parts)
  return table.concat(parts, "/")
end

local function tl_der_int_value(data)
  if data == nil or #data == 0 then
    return nil
  end
  local v = 0
  for i = 1, #data do
    v = v * 256 + data:byte(i)
  end
  return v
end

local function tl_utctime_to_epoch(s)
  if s == nil or #s < 12 then
    return nil
  end
  local yy = tonumber(s:sub(1, 2))
  local mm = tonumber(s:sub(3, 4))
  local dd = tonumber(s:sub(5, 6))
  local hh = tonumber(s:sub(7, 8))
  local mi = tonumber(s:sub(9, 10))
  local ss = tonumber(s:sub(11, 12))
  if yy == nil or mm == nil or dd == nil then
    return nil
  end
  hh = hh or 0
  mi = mi or 0
  ss = ss or 0
  if yy < 50 then
    yy = yy + 2000
  else
    yy = yy + 1900
  end
  local days = 0
  for y = 1970, yy - 1 do
    days = days + 365
    if (y % 4 == 0 and y % 100 ~= 0) or y % 400 == 0 then
      days = days + 1
    end
  end
  local mdays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
  if (yy % 4 == 0 and yy % 100 ~= 0) or yy % 400 == 0 then
    mdays[2] = 29
  end
  for m = 1, mm - 1 do
    days = days + mdays[m]
  end
  days = days + dd - 1
  return days * 86400 + hh * 3600 + mi * 60 + ss
end

local function tl_gentime_to_epoch(s)
  if s == nil or #s < 14 then
    return nil
  end
  local yyyy = tonumber(s:sub(1, 4))
  local mm = tonumber(s:sub(5, 6))
  local dd = tonumber(s:sub(7, 8))
  local hh = tonumber(s:sub(9, 10))
  local mi = tonumber(s:sub(11, 12))
  local ss = tonumber(s:sub(13, 14))
  if yyyy == nil or mm == nil or dd == nil then
    return nil
  end
  hh = hh or 0
  mi = mi or 0
  ss = ss or 0
  local days = 0
  for y = 1970, yyyy - 1 do
    days = days + 365
    if (y % 4 == 0 and y % 100 ~= 0) or y % 400 == 0 then
      days = days + 1
    end
  end
  local mdays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
  if (yyyy % 4 == 0 and yyyy % 100 ~= 0) or yyyy % 400 == 0 then
    mdays[2] = 29
  end
  for m = 1, mm - 1 do
    days = days + mdays[m]
  end
  days = days + dd - 1
  return days * 86400 + hh * 3600 + mi * 60 + ss
end

local function tl_parse_time(tag, content)
  if tag == 0x17 then
    return tl_utctime_to_epoch(content)
  end
  if tag == 0x18 then
    return tl_gentime_to_epoch(content)
  end
  return nil
end

local function tl_x509_parse(der)
  local cert = { raw_len = #der }
  local nodes = tl_der_walk(der)
  local root = nodes[1]
  if root == nil or root.tag ~= 0x30 or #nodes < 5 then
    return cert
  end
  local tbs = tl_child_list(nodes, root)[1]
  if tbs == nil or tbs.tag ~= 0x30 then
    return cert
  end
  local fields = tl_child_list(nodes, tbs)
  local pos = 1
  local function next_field()
    local n = fields[pos]
    if n == nil then
      return nil
    end
    pos = pos + 1
    return n
  end
  local n = next_field()
  if n ~= nil and n.tag == 0xa0 then
    cert.version = 2
  else
    cert.version = 1
    pos = pos - 1
  end
  n = next_field()
  if n ~= nil and n.tag == 0x02 then
    cert.serial = tl_der_int_value(n.content)
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    local alg = tl_child_list(nodes, n)
    local oid = alg[1]
    if oid ~= nil and oid.tag == 0x06 then
      cert.sig_oid = tl_der_oid_str(oid.content)
      cert.sig_algorithm = TL_OID_NAMES[cert.sig_oid] or cert.sig_oid
    end
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    cert.issuer = tl_der_name_str(nodes, n)
    cert.issuer_key = tl_der_name_key(nodes, n)
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    local times = {}
    for _, c in ipairs(tl_child_list(nodes, n)) do
      if c.tag == 0x17 or c.tag == 0x18 then
        times[#times + 1] = c
      end
    end
    if #times >= 1 then
      cert.not_before = tl_parse_time(times[1].tag, times[1].content)
      cert.not_before_raw = times[1].content
    end
    if #times >= 2 then
      cert.not_after = tl_parse_time(times[#times].tag, times[#times].content)
      cert.not_after_raw = times[#times].content
    end
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    cert.subject = tl_der_name_str(nodes, n)
    cert.subject_key = tl_der_name_key(nodes, n)
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    cert.spki = {}
    local children = tl_child_list(nodes, n)
    local alg = children[1]
    if alg ~= nil and alg.tag == 0x30 then
      local oid = tl_child_list(nodes, alg)[1]
      if oid ~= nil and oid.tag == 0x06 then
        cert.spki.oid = tl_der_oid_str(oid.content)
        cert.spki.algorithm = TL_OID_NAMES[cert.spki.oid] or cert.spki.oid
      end
    end
    for _, c in ipairs(children) do
      if c.tag == 0x03 then
        local key_bytes = c.content:sub(2)
        local inner = tl_der_walk(key_bytes)
        local ints = {}
        for _, ic in ipairs(inner) do
          if ic.tag == 0x02 then
            ints[#ints + 1] = ic
          end
        end
        if cert.spki.algorithm == "rsaEncryption" and #ints >= 1 then
          local modulus = ints[1].content
          if #modulus > 0 and modulus:byte(1) == 0 then
            modulus = modulus:sub(2)
          end
          local rsa_bits = 0
          if #modulus > 0 then
            local first = modulus:byte(1)
            local top = 0
            while first > 0 do
              top = top + 1
              first = math.floor(first / 2)
            end
            rsa_bits = (#modulus - 1) * 8 + top
          end
          cert.spki.bits = rsa_bits
          cert.spki.type = "RSA"
        end
        if cert.spki.algorithm == "ecPublicKey" then
          cert.spki.type = "EC"
        end
        break
      end
    end
  end
  for _, c in ipairs(fields) do
    if c.tag == 0xa3 then
      cert.extensions = {}
      local list = tl_child_list(nodes, c)[1]
      if list ~= nil and list.tag == 0x30 then
        for _, e in ipairs(tl_child_list(nodes, list)) do
          if e.tag == 0x30 then
            local ec = tl_child_list(nodes, e)
            local oid_n = ec[1]
            local val_n = ec[2]
            if oid_n ~= nil and oid_n.tag == 0x06 and val_n ~= nil and val_n.tag == 0x04 then
              local oid = tl_der_oid_str(oid_n.content)
              local entry = { oid = oid, name = TL_OID_NAMES[oid] or oid, value = val_n.content }
              if oid == "2.5.29.17" then
                entry.sans = {}
                local san_nodes = tl_der_walk(val_n.content)
                for _, sn in ipairs(san_nodes) do
                  if sn.tag == 0x82 then
                    entry.sans[#entry.sans + 1] = { type = "DNS", value = sn.content }
                  elseif sn.tag == 0x87 then
                    entry.sans[#entry.sans + 1] = { type = "IP", value = sn.content }
                  elseif sn.tag == 0x84 then
                    entry.sans[#entry.sans + 1] = { type = "URI", value = sn.content }
                  elseif sn.tag == 0x88 then
                    entry.sans[#entry.sans + 1] = { type = "email", value = sn.content }
                  end
                end
              end
              cert.extensions[#cert.extensions + 1] = entry
            end
          end
        end
      end
      break
    end
  end
  cert.self_signed = (cert.issuer_key ~= nil and cert.subject_key ~= nil and cert.issuer_key == cert.subject_key)
  return cert
end

local function tl_hex(data)
  if data == nil then
    return ""
  end
  local out = {}
  for i = 1, #data do
    out[#out + 1] = string.format("%02x", data:byte(i))
  end
  return table.concat(out)
end

local function tl_days_between(a, b)
  if a == nil or b == nil then
    return nil
  end
  return math.floor(math.abs(b - a) / 86400)
end

local TL_VERSIONS = {
  [0x0300] = "SSLv3",
  [0x0301] = "TLS 1.0",
  [0x0302] = "TLS 1.1",
  [0x0303] = "TLS 1.2",
  [0x0304] = "TLS 1.3",
}

local TL_CIPHER_INFO = {
  [0x0001] = { name = "TLS_RSA_WITH_NULL_MD5", kx = "RSA", cipher = "NULL", mac = "MD5" },
  [0x0002] = { name = "TLS_RSA_WITH_NULL_SHA", kx = "RSA", cipher = "NULL", mac = "SHA1" },
  [0x0003] = { name = "TLS_RSA_WITH_RC4_128_MD5", kx = "RSA", cipher = "RC4", mac = "MD5" },
  [0x0005] = { name = "TLS_RSA_WITH_RC4_128_SHA", kx = "RSA", cipher = "RC4", mac = "SHA1" },
  [0x0006] = { name = "TLS_RSA_WITH_DES_CBC_SHA", kx = "RSA", cipher = "DES", mac = "SHA1" },
  [0x0004] = { name = "TLS_RSA_WITH_RC4_40_MD5", kx = "RSA", cipher = "RC4", mac = "MD5" },
  [0x0007] = { name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA", kx = "RSA", cipher = "3DES", mac = "SHA1" },
  [0x000a] = { name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA", kx = "RSA", cipher = "3DES", mac = "SHA1" },
  [0x0008] = { name = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", kx = "DH_d", cipher = "3DES", mac = "SHA1" },
  [0x0009] = { name = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", kx = "DH_s", cipher = "3DES", mac = "SHA1" },
  [0x000c] = { name = "TLS_EDH_RSA_WITH_3DES_EDE_CBC_SHA", kx = "DHE", cipher = "3DES", mac = "SHA1" },
  [0x000d] = { name = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", kx = "DHE", cipher = "3DES", mac = "SHA1" },
  [0x0013] = { name = "TLS_RSA_WITH_IDEA_CBC_SHA", kx = "RSA", cipher = "IDEA", mac = "SHA1" },
  [0x0016] = { name = "TLS_KRB5_WITH_RC4_128_SHA", kx = "KRB5", cipher = "RC4", mac = "SHA1" },
  [0x0019] = { name = "TLS_KRB5_WITH_DES_CBC_SHA", kx = "KRB5", cipher = "DES", mac = "SHA1" },
  [0x001c] = { name = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", kx = "KRB5", cipher = "3DES", mac = "SHA1" },
  [0x002f] = { name = "TLS_RSA_WITH_AES_128_CBC_SHA", kx = "RSA", cipher = "AES128", mac = "SHA1" },
  [0x0033] = { name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", kx = "DHE", cipher = "AES128", mac = "SHA1" },
  [0x0035] = { name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", kx = "DHE", cipher = "AES256", mac = "SHA1" },
  [0x0039] = { name = "TLS_RSA_WITH_AES_128_GCM_SHA256", kx = "RSA", cipher = "AES128-GCM", mac = "SHA256" },
  [0x003c] = { name = "TLS_RSA_WITH_AES_256_CBC_SHA", kx = "RSA", cipher = "AES256", mac = "SHA1" },
  [0x0067] = { name = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", kx = "DHE", cipher = "AES128-GCM", mac = "SHA256" },
  [0x006b] = { name = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", kx = "DHE", cipher = "AES256-GCM", mac = "SHA384" },
  [0x009c] = { name = "TLS_RSA_WITH_AES_256_GCM_SHA384", kx = "RSA", cipher = "AES256-GCM", mac = "SHA384" },
  [0x009d] = { name = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", kx = "DHE", cipher = "AES128-GCM", mac = "SHA256" },
  [0xc008] = { name = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", kx = "ECDHE", cipher = "3DES", mac = "SHA1" },
  [0xc009] = { name = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", kx = "ECDHE", cipher = "AES128", mac = "SHA1" },
  [0xc00a] = { name = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", kx = "ECDHE", cipher = "AES256", mac = "SHA1" },
  [0xc012] = { name = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", kx = "ECDHE", cipher = "3DES", mac = "SHA1" },
  [0xc023] = { name = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", kx = "ECDHE", cipher = "AES128", mac = "SHA1" },
  [0xc027] = { name = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", kx = "ECDHE", cipher = "AES256", mac = "SHA1" },
  [0xc02b] = { name = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", kx = "ECDHE", cipher = "3DES", mac = "SHA1" },
  [0xc02f] = { name = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", kx = "ECDHE", cipher = "AES128-GCM", mac = "SHA256" },
  [0xc030] = { name = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", kx = "ECDHE", cipher = "AES256-GCM", mac = "SHA384" },
  [0xcc0a] = { name = "TLS_PSK_WITH_3DES_EDE_CBC_SHA", kx = "PSK", cipher = "3DES", mac = "SHA1" },
  [0x1301] = { name = "TLS_AES_128_GCM_SHA256", kx = "(1.3)", cipher = "AES128-GCM", mac = "SHA256" },
  [0x1302] = { name = "TLS_AES_256_GCM_SHA384", kx = "(1.3)", cipher = "AES256-GCM", mac = "SHA384" },
  [0x1303] = { name = "TLS_CHACHA20_POLY1305_SHA256", kx = "(1.3)", cipher = "CHACHA20", mac = "SHA256" },
}

local function tl_cipher_name(id)
  local info = TL_CIPHER_INFO[id]
  if info ~= nil then
    return info.name
  end
  return string.format("0x%04x", id or 0)
end

local function tl_cipher_class(id)
  local info = TL_CIPHER_INFO[id]
  if info == nil then
    return "unknown"
  end
  if info.cipher == "NULL" then
    return "null"
  end
  if info.cipher == "RC4" then
    return "rc4"
  end
  if info.cipher == "DES" then
    return "export-des"
  end
  if info.cipher == "3DES" then
    return "3des"
  end
  if info.mac == "MD5" then
    return "md5"
  end
  if info.kx == "KRB5" and (info.cipher == "RC4" or info.cipher == "DES" or info.cipher == "3DES") then
    return "krb5-legacy"
  end
  return "acceptable"
end

local function tl_connect(host, port)
  local sock = nmap.new_socket("tcp")
  local ok, err = sock:connect(host.ip, port)
  if not ok then
    return nil, err
  end
  sock:set_timeout(10)
  return sock, nil
end

local function tl_read_record(sock)
  local ok, hdr, rerr = sock:receive_bytes(5)
  if not ok or hdr == nil or #hdr < 5 then
    return nil, rerr or "TIMEOUT"
  end
  local rtype = hdr:byte(1)
  local rlen = hdr:byte(4) * 256 + hdr:byte(5)
  local ok2, payload, rerr2 = sock:receive_bytes(rlen)
  if not ok2 or payload == nil then
    return nil, rerr2 or "TIMEOUT"
  end
  return { type = rtype, version = hdr:byte(2) * 256 + hdr:byte(3), payload = payload }, nil
end

local function tl_collect_server_flight(sock, limit)
  local msgs = {}
  local alert = nil
  for _ = 1, limit or 12 do
    local rec, err = tl_read_record(sock)
    if rec == nil then
      return msgs, alert, err
    end
    if rec.type == 21 then
      local parsed = tl_parse_alert(rec.payload)
      alert = {
        level = parsed.level,
        code = parsed.code,
        name = tl_alert_name(parsed.level, parsed.code),
      }
      return msgs, alert, nil
    elseif rec.type == 22 then
      local hs = tl_parse_handshake_messages(rec.payload)
      for _, m in ipairs(hs) do
        msgs[#msgs + 1] = m
        if m.type == 14 then
          return msgs, alert, nil
        end
      end
    end
  end
  return msgs, alert, nil
end

local function tl_summarize_flight(msgs)
  local info = {}
  for _, m in ipairs(msgs) do
    if m.type == 2 then
      local sh = tl_parse_server_hello(m.body)
      info.version = sh.version
      info.cipher = sh.cipher
      info.cipher_name = tl_cipher_name(sh.cipher)
      info.compression = sh.compression
      local exts = sh.extensions or {}
      info.exts = exts
      local sv = exts[43]
      if sv ~= nil and #sv >= 2 then
        info.negotiated_version = sv:byte(1) * 256 + sv:byte(2)
      else
        info.negotiated_version = sh.version
      end
      info.version_name = TL_VERSIONS[info.negotiated_version]
        or tl_version_name(info.negotiated_version)
      local alpn = exts[16]
      if alpn ~= nil then
        info.alpn = tl_alpn_selected(alpn)
      end
      if exts[5] ~= nil then
        info.status_request_echo = true
      end
      if exts[0xff01] ~= nil then
        info.renegotiation_info = true
      end
    elseif m.type == 11 then
      local parsed = tl_parse_certificate(m.body)
      info.cert_count = #parsed.certs
      if parsed.certs[1] ~= nil then
        info.cert_der = parsed.certs[1]
        info.cert = tl_x509_parse(parsed.certs[1])
      end
    elseif m.type == 12 then
      info.ske = tl_parse_server_key_exchange(m.body)
      if info.ske.dh_prime ~= nil then
        info.dh_bits = info.ske.prime_bits or tl_dh_prime_bits(info.ske.dh_prime)
      end
    elseif m.type == 5 then
      info.ocsp = tl_parse_certificate_status(m.body)
    elseif m.type == 4 then
      info.session_ticket = true
    end
  end
  return info
end

local function tl_read_records_until(sock, wanted, limit)
  for _ = 1, limit or 8 do
    local rec, err = tl_read_record(sock)
    if rec == nil then
      return false, err
    end
    if rec.type == 21 then
      local parsed = tl_parse_alert(rec.payload)
      return false, "alert:" .. tl_alert_name(parsed.level, parsed.code)
    end
    if rec.type == 22 then
      local hs = tl_parse_handshake_messages(rec.payload)
      for _, m in ipairs(hs) do
        if m.type == wanted then
          return true, nil
        end
      end
    end
  end
  return false, "NO_MESSAGE"
end

local function tl_finish_client_flight(sock)
  local pre = string.rep("k", 32)
  local cke = tl_record(0x16, 0x0303, tl_handshake(0x10, tl_u16(#pre) .. pre))
  local ccs = tl_record(0x14, 0x0303, "")
  local fin = tl_record(0x16, 0x0303, tl_handshake(0x14, string.rep("f", 12)))
  sock:send(cke)
  sock:send(ccs)
  sock:send(fin)
  return tl_read_records_until(sock, 20)
end

local function tl_perform_handshake(host, port, opts)
  opts = opts or {}
  local sock, cerr = tl_connect(host, port)
  if sock == nil then
    return { status = "connect_error", error = cerr }
  end
  local hello_opts = {
    version = opts.version or 0x0303,
    ciphers = opts.ciphers or { 0xc02f, 0xc030, 0x009c, 0x0039 },
    comps = opts.comps or { 0 },
    sni = opts.sni,
    alpn = opts.alpn,
    status_request = opts.status_request,
    supported_versions = opts.supported_versions,
    heartbeat = opts.heartbeat,
    renegotiation_info = opts.renegotiation_info,
    ems = opts.ems ~= nil and opts.ems or false,
  }
  if opts.scsv then
    hello_opts.ciphers = { 0x0035, 0xc02f, 0x5600 }
    hello_opts.version = opts.version or 0x0302
  end
  local hello = tl_client_hello(hello_opts)
  local ok, serr = pcall(sock.send, sock, hello)
  if not ok then
    sock:close()
    return { status = "send_error", error = serr }
  end
  local msgs, alert = tl_collect_server_flight(sock)
  local server = tl_summarize_flight(msgs)
  local result = { status = "handshake", server = server, sock = sock }
  if alert ~= nil then
    result.status = "alert"
    result.alert = alert
    return result
  end
  if server.version == nil then
    sock:close()
    result.status = "no_server_hello"
    return result
  end
  local done, dterr = tl_finish_client_flight(sock)
  result.completed = done
  if not done then
    result.completion_error = dterr
  end
  return result
end

local function tl_close(result)
  if result ~= nil and result.sock ~= nil then
    local ok = pcall(result.sock.close, result.sock)
    if ok then
      result.sock = nil
    end
  end
  return result
end

local function tl_probe_version(host, port, version, supported, ciphers)
  local opts = { version = version, ciphers = ciphers }
  if supported ~= nil then
    opts.supported_versions = supported
  end
  return tl_close(tl_perform_handshake(host, port, opts))
end

local function tl_supported_versions(result)
  local server = result.server or {}
  local neg = server.negotiated_version
  local accepted = neg ~= nil and result.status == "handshake"
  return accepted, neg
end

local function tl_probe_cipher_set(host, port, ciphers, version)
  return tl_close(tl_perform_handshake(host, port, {
    version = version or 0x0303,
    ciphers = ciphers,
  }))
end

local function tl_cipher_accepted(result)
  if result.status ~= "handshake" then
    return false, nil
  end
  local server = result.server or {}
  return true, server.cipher
end

local function tl_renegotiation_probe(host, port, with_info)
  local first = tl_perform_handshake(host, port, {
    version = 0x0303,
    ciphers = { 0x0035, 0xc02f },
  })
  if first.status ~= "handshake" then
    return tl_close(first)
  end
  local hello = tl_client_hello({
    version = 0x0303,
    ciphers = { 0x0035, 0xc02f },
    renegotiation_info = with_info,
  })
  local ok, serr = pcall(first.sock.send, first.sock, hello)
  if not ok then
    first.status = "send_error"
    first.error = serr
    return tl_close(first)
  end
  local msgs, alert = tl_collect_server_flight(first.sock)
  local server = tl_summarize_flight(msgs)
  local result = {
    status = "renegotiated",
    server = server,
    base_version = first.server.negotiated_version,
  }
  if alert ~= nil then
    result.status = "alert"
    result.alert = alert
  elseif server.version == nil then
    result.status = "no_server_hello"
  end
  return tl_close(result)
end

local function tl_heartbeat_probe(host, port, payload)
  local first = tl_perform_handshake(host, port, {
    version = 0x0303,
    ciphers = { 0x0035, 0xc02f },
    heartbeat = true,
  })
  if first.status ~= "handshake" then
    return tl_close(first)
  end
  local p = payload or "tl-heartbeat-probe"
  local body = string.char(0) .. tl_u16(#p) .. string.rep("h", 16) .. p
    .. string.rep("\0", 16)
  local ok, serr = pcall(first.sock.send, first.sock, tl_record(0x18, 0x0303, body))
  if not ok then
    first.status = "send_error"
    first.error = serr
    return tl_close(first)
  end
  local rec, rerr = tl_read_record(first.sock)
  local result = { status = "no_response", error = rerr }
  if rec ~= nil then
    if rec.type == 21 then
      local parsed = tl_parse_alert(rec.payload)
      result.status = "alert"
      result.alert = {
        level = parsed.level,
        code = parsed.code,
        name = tl_alert_name(parsed.level, parsed.code),
      }
    elseif rec.type == 24 then
      local hb = tl_parse_heartbeat(rec.payload)
      result.status = "response"
      result.heartbeat = hb
      result.overread = hb.trailer > 0
    else
      result.status = "unexpected"
      result.record_type = rec.type
    end
  end
  return tl_close(result)
end

local function tl_read_all(sock)
  local parts = {}
  while true do
    local ok, chunk, err = sock:receive_bytes(65536)
    if not ok or chunk == nil or #chunk == 0 then
      return table.concat(parts), err
    end
    parts[#parts + 1] = chunk
    if #chunk < 65536 then
      break
    end
  end
  return table.concat(parts), nil
end

local function tl_parse_http_response(raw)
  local parsed = { raw = raw }
  local status = raw:match("^HTTP/1%.%d (%d%d%d)")
  parsed.status = tonumber(status)
  local headers_end = raw:find("\r\n\r\n", 1, true)
  if headers_end == nil then
    return parsed
  end
  parsed.headers = {}
  for line in raw:sub(1, headers_end - 1):gmatch("([^\r\n]+)") do
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k ~= nil then
      parsed.headers[k:lower()] = v
    end
  end
  parsed.body = raw:sub(headers_end + 4)
  return parsed
end

local function tl_http_over_tls(result, path)
  if result == nil or result.sock == nil or result.status ~= "handshake" then
    return nil, "no_open_session"
  end
  local req = "GET " .. (path or "/") .. " HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
  local ok, serr = pcall(result.sock.send, result.sock, req)
  if not ok then
    return nil, serr
  end
  local raw, rerr = tl_read_all(result.sock)
  if raw == nil or #raw == 0 then
    return nil, rerr or "EMPTY_RESPONSE"
  end
  return tl_parse_http_response(raw), nil
end

local function tl_classify_cert_window(cert, now, warndays)
  if cert == nil or cert.not_before == nil or cert.not_after == nil then
    return "unknown"
  end
  if now < cert.not_before then
    return "not_yet_valid"
  end
  if now > cert.not_after then
    return "expired"
  end
  local days = tl_days_between(now, cert.not_after)
  if days <= (warndays or 30) then
    return "expiring_soon"
  end
  return "valid"
end

local function tl_cert_days_to_expiry(cert, now)
  if cert == nil or cert.not_after == nil then
    return nil
  end
  return tl_days_between(now, cert.not_after)
end

local function tl_hostname_matches_pattern(pattern, hostname)
  if pattern == nil or hostname == nil then
    return false
  end
  pattern = pattern:lower()
  hostname = hostname:lower()
  if pattern == hostname then
    return true
  end
  if pattern:sub(1, 2) ~= "*." then
    return false
  end
  local suffix = pattern:sub(3)
  if #hostname <= #suffix then
    return false
  end
  if hostname:sub(-#suffix) ~= suffix then
    return false
  end
  local label = hostname:sub(1, #hostname - #suffix - 1)
  if label:find(".", 1, true) then
    return false
  end
  if #label == 0 then
    return false
  end
  return true
end

local function tl_extract_cn(subject)
  if subject == nil then
    return nil
  end
  for part in subject:gmatch("[^/]+") do
    local key, val = part:match("^%s*(%w+)%s*=%s*(.-)%s*$")
    if key ~= nil and key:upper() == "CN" then
      return val
    end
  end
  return nil
end

local function tl_hostname_check(cert, hostname)
  local result = { match = false, sources = {}, wildcards = 0 }
  if cert == nil then
    return result
  end
  local sans = {}
  for _, e in ipairs(cert.extensions or {}) do
    if e.name == "subjectAltName" then
      for _, s in ipairs(e.sans or {}) do
        if s.type == "DNS" then
          sans[#sans + 1] = s.value
        end
      end
    end
  end
  if #sans > 0 then
    for _, s in ipairs(sans) do
      if tl_hostname_matches_pattern(s, hostname) then
        result.match = true
        result.sources[#result.sources + 1] = "SAN:" .. s
        if s:find("^%*%.") then
          result.wildcards = result.wildcards + 1
        end
      end
    end
    result.uses_san = true
  end
  local cn = tl_extract_cn(cert.subject)
  if cn ~= nil and not result.match then
    if tl_hostname_matches_pattern(cn, hostname) then
      result.match = true
      result.sources[#result.sources + 1] = "CN:" .. cn
    end
  end
  return result
end

local TL_WEAK_SIG_ALGS = {
  ["md5WithRSAEncryption"] = "MD5",
  ["sha1WithRSAEncryption"] = "SHA-1",
  ["shaWithRSAEncryption"] = "SHA-0",
  ["md5WithRSA"] = "MD5",
  ["sha1WithRSA"] = "SHA-1",
}

local function tl_sig_algorithm_class(cert)
  if cert == nil or cert.sig_algorithm == nil then
    return "unknown", nil
  end
  local weak = TL_WEAK_SIG_ALGS[cert.sig_algorithm]
  if weak ~= nil then
    return "weak", weak
  end
  if cert.sig_oid ~= nil then
    local rsa_sig_weak = { "2", "4", "5" }
    for _, suffix in ipairs(rsa_sig_weak) do
      if cert.sig_oid == ("1.2.840.113549.1.1." .. suffix) then
        return "weak", cert.sig_algorithm
      end
    end
  end
  return "strong", nil
end

local function tl_known_dh_group(prime)
  if prime == nil or #prime < 16 then
    return nil
  end
  local head = ""
  for i = 1, 21 do
    if i > #prime then
      return nil
    end
    head = head .. string.format("%02x", prime:byte(i))
  end
  if #prime == 128 and head:sub(1, 40) == "ffffffffffffffffc90fdaa22168c234c4c6628b" then
    return "RFC 3526 group 14 (1024-bit MODP)"
  end
  if #prime == 256 and head == "04ffffffffffffffffc90fdaa22168c234c4c6628b" then
    return "RFC 7919 ffdhe2048"
  end
  return nil
end

local function tl_dh_strength(bits)
  if bits == nil then
    return "unknown"
  end
  if bits < 1024 then
    return "critically_weak"
  end
  if bits < 2048 then
    return "weak"
  end
  return "acceptable"
end

local function tl_scsv_probe(host, port)
  return tl_close(tl_perform_handshake(host, port, {
    scsv = true,
    version = 0x0302,
  }))
end

local function tl_weak_cipher_groups()
  return {
    null = { 0x0001, 0x0002 },
    rc4 = { 0x0005, 0x0004, 0x0016, 0x0013 },
    export_des = { 0x0006, 0x0007 },
    md5 = { 0x0003 },
    three_des = { 0x000a, 0x0008, 0x0009, 0x000c, 0x000d, 0xc008, 0xc012, 0xc02b },
  }
end

local function tl_probe_each_group(host, port, groups)
  local results = {}
  for group, ciphers in pairs(groups) do
    local result = tl_probe_cipher_set(host, port, ciphers)
    local accepted, cipher = tl_cipher_accepted(result)
    results[group] = {
      accepted = accepted,
      cipher = cipher,
      cipher_name = accepted and tl_cipher_name(cipher) or nil,
      status = result.status,
      alert = result.alert,
    }
  end
  return results
end

local function tl_version_probe_battery(host, port)
  local probes = {
    { label = "SSLv3", version = 0x0300, supported = nil },
    { label = "TLS 1.0", version = 0x0301, supported = nil },
    { label = "TLS 1.1", version = 0x0302, supported = nil },
    { label = "TLS 1.2", version = 0x0303, supported = nil },
    { label = "TLS 1.3", version = 0x0303, supported = { 0x0304 }, ciphers = { 0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0x009c, 0x0039 } },
  }
  local out = {}
  for _, p in ipairs(probes) do
    local result = tl_probe_version(host, port, p.version, p.supported, p.ciphers)
    local ok, neg = tl_supported_versions(result)
    out[#out + 1] = {
      label = p.label,
      accepted = ok,
      negotiated = neg,
      status = result.status,
      alert = result.alert,
    }
  end
  return out
end

local function smtp_session_new(host, port, args)
  local hname = host
  if type(host) == "table" then
    hname = host.ip or host.name or host.targetname or "192.0.2.10"
  end
  local pnum = port
  if type(port) == "table" then
    pnum = port.number or 25
  end
  return {
    host = hname or "192.0.2.10",
    host_table = host,
    port = pnum or 25,
    args = args or {},
    sock = nil,
    connected = false,
    closed = false,
    greeting = nil,
    ehlo = nil,
    tls_active = false,
    connects = 0,
    sends = 0,
    recvs = 0,
    timeouts = 0,
    errors = 0,
    transactions = 0,
    audit = {},
  }
end

local function smtp_audit(sess, kind, detail)
  sess.audit[#sess.audit + 1] = kind .. ":" .. tostring(detail)
end

local function smtp_connect(sess)
  if sess.connected then
    return 1
  end
  local sock = nmap.new_socket("tcp")
  if not sock then
    return nil, "socket allocation failed"
  end
  sock:set_timeout(math.floor((sess.args.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, "tcp")
  if not ok then
    sock:close()
    return nil, "TCP connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  sess.connects = sess.connects + 1
  smtp_audit(sess, "connect", sess.port)
  return 1
end

local function smtp_close(sess)
  if sess and sess.sock and not sess.closed then
    pcall(sess.sock.close, sess.sock)
  end
  if sess then
    sess.closed = true
    sess.connected = false
  end
end

local function smtp_send_raw(sess, data)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  if budget_exhausted(sess.args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  sess.sends = sess.sends + 1
  smtp_audit(sess, "send", #data)
  local ok, err = sess.sock:send(data)
  if not ok then
    sess.errors = sess.errors + 1
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  return 1
end

local function smtp_recv_chunk(sess, wait_seconds)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  local remaining = math.max(1, wait_seconds or 2)
  sess.sock:set_timeout(remaining * 1000)
  local ok, dat = sess.sock:receive(65535)
  if ok then
    sess.recvs = sess.recvs + 1
    smtp_audit(sess, "recv", #dat)
    return dat
  end
  local err = dat
  if err == "TIMEOUT" or err == "EOF" then
    sess.timeouts = sess.timeouts + 1
    return nil, "timeout"
  end
  sess.errors = sess.errors + 1
  return nil, "receive failed: " .. tostring(err or "unknown")
end

local function smtp_recv_reply(sess, deadline_seconds)
  local deadline = os.time() + math.max(1, deadline_seconds or 6)
  local buf = ""
  while os.time() < deadline do
    if budget_exhausted(sess.args) then
      break
    end
    local chunk, err = smtp_recv_chunk(sess, 1)
    if chunk then
      buf = buf .. chunk
      local reply = SMTP_X.parse_reply(buf)
      if reply.complete then
        return reply
      end
    end
    if err == "timeout" and #buf > 0 then
      break
    end
    if err ~= nil and err ~= "timeout" then
      break
    end
  end
  if buf ~= "" then
    local reply = SMTP_X.parse_reply(buf)
    return reply
  end
  return nil, "no reply before deadline"
end

local function smtp_drain_replies(sess, count, deadline_seconds)
  local deadline = os.time() + math.max(1, deadline_seconds or 6)
  local buf = ""
  local replies = {}
  while os.time() < deadline and #replies < count do
    if budget_exhausted(sess.args) then
      break
    end
    local chunk, err = smtp_recv_chunk(sess, 1)
    if chunk then
      buf = buf .. chunk
      while true do
        local reply = SMTP_X.parse_reply(buf)
        if not reply.complete then
          break
        end
        replies[#replies + 1] = reply
        buf = string.sub(buf, reply.consumed or (#buf + 1))
        if #replies >= count then
          break
        end
      end
    end
    if err == "timeout" and #replies == 0 then
    end
  end
  return replies
end

local function smtp_transaction(sess, cmd_text)
  local ok, err = smtp_send_raw(sess, cmd_text)
  if not ok then
    return nil, err
  end
  local reply, rerr = smtp_recv_reply(sess, sess.args.recv_window or 6)
  if reply == nil then
    return nil, rerr
  end
  sess.transactions = sess.transactions + 1
  return reply
end

local function smtp_open_session(host, port, args)
  local sess = smtp_session_new(host, port, args)
  local ok, err = smtp_connect(sess)
  if not ok then
    smtp_close(sess)
    return nil, err
  end
  local greeting, gerr = smtp_recv_reply(sess, args and args.recv_window or 6)
  if greeting == nil then
    smtp_close(sess)
    return nil, gerr
  end
  sess.greeting = greeting
  return sess, greeting
end

local function smtp_ehlo(sess, name, args)
  local reply, err = smtp_transaction(sess, SMTP_B.ehlo(name or SMTP_T.AUDIT_HOST))
  if reply == nil then
    return nil, err
  end
  local ehlo = SMTP_X.parse_ehlo(reply)
  sess.ehlo = ehlo
  return ehlo
end

local function smtp_starttls(sess, args)
  local reply, err = smtp_transaction(sess, SMTP_B.starttls())
  if reply == nil then
    return nil, err
  end
  return reply
end

local function smtp_tls_upgrade(sess, hello_opts)
  local sock = sess.sock
  local opts = hello_opts or {}
  local hello = tl_client_hello({
    version = opts.version or 0x0303,
    ciphers = opts.ciphers or { 0xc02f, 0xc030, 0x009c, 0x0039 },
    comps = opts.comps or { 0 },
    sni = opts.sni,
    supported_versions = opts.supported_versions,
    ems = (opts.ems ~= nil) and opts.ems or false,
    renegotiation_info = opts.renegotiation_info,
  })
  local ok, err = sock:send(hello)
  if not ok then
    return nil, err
  end
  local msgs, alert = tl_collect_server_flight(sock, 12)
  local server = tl_summarize_flight(msgs)
  local result = { status = "handshake", server = server, msgs = msgs }
  if alert ~= nil then
    result.status = "alert"
    result.alert = alert
    return result
  end
  if server.version == nil then
    result.status = "no_server_hello"
    return result
  end
  sess.tls_active = true
  return result
end

local function smtp_tls_probe(host, port, args, hello_opts)
  local sess, greeting = smtp_open_session(host, port, args)
  if sess == nil then
    return { status = "connect_error", error = greeting }
  end
  local ehlo = smtp_ehlo(sess, nil, args)
  local starttls = smtp_starttls(sess, args)
  if starttls == nil or starttls.code ~= 220 then
    smtp_close(sess)
    return { status = "starttls-rejected", code = starttls and starttls.code, ehlo = ehlo }
  end
  local result = smtp_tls_upgrade(sess, hello_opts)
  smtp_close(sess)
  return result
end

local function smtp_auth_plain(sess, user, pass, args)
  local reply, err = smtp_transaction(sess, SMTP_B.auth_plain_initial(user, pass))
  if reply == nil then
    return nil, err
  end
  return reply
end

local function smtp_auth_login(sess, user, pass, args)
  local reply, err = smtp_transaction(sess, SMTP_B.auth_login_user(user))
  if reply == nil or reply.code ~= 334 then
    return reply, err
  end
  local u2 = smtp_transaction(sess, SMTP_B.auth_login_user_b64(user))
  if u2 == nil or u2.code ~= 334 then
    return u2, err
  end
  local p2 = smtp_transaction(sess, SMTP_B.auth_login_pass_b64(pass))
  return p2, err
end

local function smtp_envelope_probe(sess, from_addr, to_addr, args, opts)
  opts = opts or {}
  smtp_transaction(sess, SMTP_B.rset())
  local mail = smtp_transaction(sess, SMTP_B.mail_from(from_addr, opts))
  if mail == nil then
    return nil, "no answer to MAIL FROM"
  end
  local rcpt = nil
  if mail.code ~= nil and mail.code < 400 then
    rcpt = smtp_transaction(sess, SMTP_B.rcpt_to(to_addr))
    if rcpt == nil then
      return { mail_code = mail.code, rcpt_code = nil }, "no answer to RCPT TO"
    end
  end
  local out = {
    mail_code = mail.code,
    rcpt_code = rcpt and rcpt.code or nil,
    mail_enhanced = mail.enhanced,
    rcpt_enhanced = rcpt and rcpt.enhanced or nil,
    relayed = nil,
    queued = nil,
  }
  if rcpt ~= nil and rcpt.code ~= nil and rcpt.code < 300 then
    out.relayed = true
    if opts.with_data then
      local d = smtp_transaction(sess, SMTP_B.data())
      if d ~= nil and d.code == 354 then
        local body = smtp_transaction(sess, SMTP_B.mail_body({ "Subject: nse audit", "", "bounded audit message", "" }))
        out.queued = body ~= nil and body.code or nil
      end
    end
  else
    out.relayed = false
  end
  return out
end

local function smtp_vrfy_probe(sess, user)
  return smtp_transaction(sess, SMTP_B.vrfy(user))
end

local function smtp_expn_probe(sess, list)
  return smtp_transaction(sess, SMTP_B.expn(list))
end

local function smtp_help_probe(sess, topic)
  return smtp_transaction(sess, SMTP_B.help(topic))
end

local function smtp_pipeline_probe(sess, cmds)
  local batch = {}
  for _, c in ipairs(cmds) do
    batch[#batch + 1] = c
  end
  local ok, err = smtp_send_raw(sess, table.concat(batch, ""))
  if not ok then
    return nil, err
  end
  local replies = smtp_drain_replies(sess, #cmds, sess.args.recv_window or 6)
  sess.transactions = sess.transactions + 1
  return replies
end

local function smtp_quit(sess)
  if sess ~= nil and sess.sock ~= nil and not sess.closed then
    pcall(function() sess.sock:send("QUIT\r\n") end)
  end
  smtp_close(sess)
end

SMTP_TP = {
  session_new = smtp_session_new,
  audit = smtp_audit,
  connect = smtp_connect,
  close = smtp_close,
  send_raw = smtp_send_raw,
  recv_chunk = smtp_recv_chunk,
  recv_reply = smtp_recv_reply,
  drain_replies = smtp_drain_replies,
  transaction = smtp_transaction,
  open_session = smtp_open_session,
  ehlo = smtp_ehlo,
  starttls = smtp_starttls,
  tls_upgrade = smtp_tls_upgrade,
  tls_probe = smtp_tls_probe,
  auth_plain = smtp_auth_plain,
  auth_login = smtp_auth_login,
  envelope_probe = smtp_envelope_probe,
  vrfy_probe = smtp_vrfy_probe,
  expn_probe = smtp_expn_probe,
  help_probe = smtp_help_probe,
  pipeline_probe = smtp_pipeline_probe,
  quit = smtp_quit,
}

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

local function smtp_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - SMTP audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The SMTP audit did not complete against this target", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function smtp_probe_args(args)
  return {
    timeout = args.timeout or 8,
    maxrequests = args.maxrequests or 48,
    recv_window = args.recv_window or 6,
  }
end

local function smtp_open_ehlo(host, port, args)
  local sess, greeting = SMTP_TP.open_session(host, port, smtp_probe_args(args))
  if sess == nil then
    return nil, nil, tostring(greeting)
  end
  local ehlo = SMTP_TP.ehlo(sess, nil, smtp_probe_args(args))
  if ehlo == nil then
    SMTP_TP.quit(sess)
    return nil, nil, "EHLO failed"
  end
  return sess, ehlo, nil
end

local function smtp_domain_of(hostname)
  local domain = string.match(hostname or "", "[^%.]+%.(.+)$")
  return domain or hostname
end

local DEFAULT_CIPHERS = { 0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009e, 0x009f }

local function run_probe(host, port, args, label, hello_opts, sections)
  local r = SMTP_TP.tls_probe(host, port, smtp_probe_args(args), hello_opts)
  local row = { profile = label, outcome = r.status }
  if r.status == "handshake" and r.server ~= nil then
    row.negotiated = r.server.version_name or tostring(r.server.negotiated_version or r.server.version)
    row.cipher = r.server.cipher_name or tostring(r.server.cipher)
  end
  sections[#sections + 1] = row
  return r
end

local function run_audit(host, port, args)
  local sections = {}
  local sess, ehlo, err = smtp_open_ehlo(host, port, args)
  if sess == nil then
    return smtp_incomplete("EHLO failed: " .. tostring(err), sections, "session", err)
  end
  SMTP_TP.quit(sess)
  if not ehlo.starttls then
    return smtp_incomplete("STARTTLS not advertised; no TLS profile to audit (see smtp-starttls-support)", sections, "starttls", "not advertised")
  end

  local baseline = run_probe(host, port, args, "baseline_aead", { version = 0x0303, ciphers = DEFAULT_CIPHERS }, sections)
  local tls13 = run_probe(host, port, args, "tls13_offer", { version = 0x0303, ciphers = { 0x1301, 0x1302, 0x1303 }, supported_versions = { 0x0304 } }, sections)
  local legacy = run_probe(host, port, args, "legacy_rc4", { version = 0x0303, ciphers = { 0x0005, 0x0004, 0x000a } }, sections)

  local remediation = {}
  local status_text
  if baseline.status ~= "handshake" then
    status_text = "VULNERABLE - STARTTLS is advertised but no modern TLS handshake succeeded (" .. baseline.status .. ")"
    add_finding("MEDIUM", "No usable TLS profile on the STARTTLS channel", {
      subject = "tls-ciphers",
      evidence = "baseline AEAD handshake ended with " .. baseline.status,
      confidence = "high",
      cvss = 5.0,
    })
    remediation["1. Fix TLS"] = "Repair the MTA certificate and protocol configuration."
  else
    local note13 = tls13.status == "handshake" and "offered" or "not offered"
    local rc4 = legacy.status == "handshake" and "ACCEPTED (must fix)" or "rejected"
    if legacy.status == "handshake" then
      status_text = "VULNERABLE - legacy RC4 suites negotiable on the STARTTLS channel (" .. tostring(legacy.server and legacy.server.cipher_name or "RC4") .. ")"
      add_finding("MEDIUM", "Deprecated cipher suites accepted", {
        subject = "tls-ciphers",
        evidence = "RC4-only offer negotiated " .. tostring(legacy.server and legacy.server.cipher_name or "?") .. "; TLS1.3 " .. note13,
        confidence = "high",
        cvss = 5.0,
      })
      remediation["1. Disable legacy"] = "Remove RC4/CBC/export suites from the MTA cipher policy."
    else
      status_text = "SECURE - modern TLS baseline negotiates (" .. tostring(baseline.server and baseline.server.version_name or "TLS") .. " / " .. tostring(baseline.server and baseline.server.cipher_name or "AEAD") .. "); RC4 rejected; TLS1.3 " .. note13
      add_finding("INFO", "STARTTLS cipher profile is modern", {
        subject = "tls-ciphers",
        evidence = "baseline " .. tostring(baseline.server and baseline.server.cipher_name or "?") .. "; TLS1.3 " .. note13 .. "; RC4 rejected",
        confidence = "high",
      })
      remediation["1. Maintain"] = "Track protocol policy after TLS library upgrades."
    end
  end
  sections[#sections + 1] = { key = "Remediation", value = remediation }

  local out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(out, unique, counts, sections)
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()
seed_random(port)

return run_audit(host, port, args)

end
