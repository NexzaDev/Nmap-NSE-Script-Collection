local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Checks whether the root account is reachable through the telnet login
prompt: sends the root username once and records whether the service
proceeds to a password prompt or rejects the name outright.

Why it matters
- Direct root telnet couples the highest-privilege account with a
  cleartext transport and an online guessing surface.
- Many hardened stacks refuse root before the password stage; that
  distinction is exactly what this audit measures.

What the script does
1. Opens the login flow and sends "root" (or a configured user) once.
2. Records the next stage: password prompt (surface exists), immediate
   denial, or lockout.
3. Never sends a password - the probe stops at the first stage.

Safe operation: one username submission, zero passwords, connection
closed right after the observed stage.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  23,
  "telnet",
  "tcp"
)

local SCRIPT_NAME = "telnet-root-login-allowed"

local RISK_LEVEL = "🟠 HIGH"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 32,
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {}

local NUMERIC_ARGS = {
  { key = "timeout", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 1, integer = true },
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

TEL_T = {}

TEL_T.IAC_SE = 240
TEL_T.IAC_NOP = 241
TEL_T.IAC_DM = 242
TEL_T.IAC_BRK = 243
TEL_T.IAC_IP = 244
TEL_T.IAC_AO = 245
TEL_T.IAC_AYT = 246
TEL_T.IAC_EC = 247
TEL_T.IAC_EL = 248
TEL_T.IAC_GA = 249
TEL_T.IAC_SB = 250
TEL_T.IAC_WILL = 251
TEL_T.IAC_WONT = 252
TEL_T.IAC_DO = 253
TEL_T.IAC_DONT = 254
TEL_T.IAC = 255

TEL_T.OPT_BINARY = 0
TEL_T.OPT_ECHO = 1
TEL_T.OPT_SGA = 3
TEL_T.OPT_STATUS = 5
TEL_T.OPT_TM = 6
TEL_T.OPT_TTYPE = 24
TEL_T.OPT_EOR = 25
TEL_T.OPT_NAWS = 31
TEL_T.OPT_TSPEED = 32
TEL_T.OPT_LFLOW = 33
TEL_T.OPT_LINEMODE = 34
TEL_T.OPT_XDISPLOC = 35
TEL_T.OPT_OLD_ENVIRON = 36
TEL_T.OPT_AUTH = 37
TEL_T.OPT_ENCRYPT = 38
TEL_T.OPT_NEW_ENVIRON = 39
TEL_T.OPT_TN3270E = 40
TEL_T.OPT_CHARSET = 42
TEL_T.OPT_RSP = 43
TEL_T.OPT_COMPORT = 44
TEL_T.OPT_SLE = 45
TEL_T.OPT_STARTTLS = 46
TEL_T.OPT_KERMIT = 47
TEL_T.OPT_PRAGMA_LOGON = 138
TEL_T.OPT_SSPI_LOGON = 139

TEL_T.OPTION_NAMES = {
  [0] = "BINARY (RFC 856)",
  [1] = "ECHO (RFC 857)",
  [2] = "RECONNECTION",
  [3] = "SGA (RFC 858)",
  [4] = "APPROX-MESSAGE-SIZE",
  [5] = "STATUS (RFC 859)",
  [6] = "TIMING-MARK (RFC 860)",
  [7] = "RCTE",
  [24] = "TTYPE (RFC 1091)",
  [25] = "END-OF-RECORD (RFC 885)",
  [31] = "NAWS (RFC 1073)",
  [32] = "TSPEED (RFC 1079)",
  [33] = "LFLOW (RFC 1372)",
  [34] = "LINEMODE (RFC 1184)",
  [35] = "XDISPLOC (RFC 1096)",
  [36] = "OLD-ENVIRON (RFC 1408)",
  [37] = "AUTHENTICATION (RFC 2941)",
  [38] = "ENCRYPT (RFC 2946)",
  [39] = "NEW-ENVIRON (RFC 1572)",
  [40] = "TN3270E (RFC 2355)",
  [41] = "XAUTH",
  [42] = "CHARSET (RFC 2066)",
  [43] = "RSP",
  [44] = "COM-PORT (RFC 2217)",
  [45] = "SUPPRESS-LOCAL-ECHO",
  [46] = "START-TLS",
  [47] = "KERMIT",
  [48] = "SEND-URL",
  [138] = "PRAGMA-LOGON (Microsoft)",
  [139] = "SSPI-LOGON (Microsoft NTLM/Kerberos)",
}

TEL_T.AUTH_TYPES = {
  [0] = "NULL (no authentication)",
  [1] = "KERBEROS_V4",
  [2] = "KERBEROS_V5",
  [3] = "SPX",
  [4] = "MINK",
  [5] = "SRP",
  [6] = "RSA",
  [7] = "SSL",
  [8] = "KERBEROS_V5 extended",
  [9] = "NTLM",
  [10] = "SRA (Secure RPC)",
  [11] = "BUILTIN-PK",
  [12] = "KEA_SJ",
  [13] = "KEA_SJ_INTEG",
  [14] = "DSS",
}

TEL_T.AUTH_WEAK = {
  [0] = "NULL accepts unauthenticated sessions",
  [9] = "NTLM legacy credential format",
  [10] = "SRA secure-RPC (DES-era, deprecated)",
}

TEL_T.ENV_CMDS = {
  [0] = "IS",
  [1] = "SEND",
  [2] = "INFO",
}

TEL_T.ENV_TYPES = {
  [3] = "VAR",
  [4] = "VALUE",
  [5] = "ESC",
  [6] = "USERVAR",
}

TEL_T.ENCRYPT_TYPES = {
  [1] = "DES_CFB64",
  [2] = "DES_OFB64",
  [3] = "DES3_CFB64",
  [4] = "DES3_OFB64",
  [8] = "CAST5_40_CFB64",
  [9] = "CAST5_40_OFB64",
  [10] = "CAST128_CFB64",
  [11] = "CAST128_OFB64",
}

TEL_T.ENCRYPT_CMDS = {
  [0] = "ENC_IS",
  [1] = "ENC_SUPPORT",
  [2] = "ENC_REPLY",
  [3] = "ENC_START",
  [4] = "ENC_END",
  [5] = "ENC_REQUESTSTART",
  [6] = "ENC_REQUESTEND",
  [7] = "ENC_ENCRYPT",
  [8] = "ENC_DECRYPT",
}

TEL_T.PROMPT_PATTERNS = {
  { kind = "login", re = "[Ll]ogin:%s*$" },
  { kind = "login", re = "[Uu]ser(?:name|[iI]d)?:%s*$" },
  { kind = "password", re = "[Pp]assword:%s*$" },
  { kind = "password", re = "passphrase:%s*$" },
  { kind = "error", re = "[Ll]ogin incorrect" },
  { kind = "error", re = "[Aa]uthentication failed" },
  { kind = "error", re = "[Dd]enied" },
  { kind = "error", re = "too many[^%r]*" },
  { kind = "lockout", re = "locked[^%r]*" },
  { kind = "denied-root", re = "root[^%r]*(not allowed|refused|denied)[^%r]*" },
  { kind = "shell", re = "[#%$>]%s*$" },
  { kind = "menu", re = "[Mm]enu|%[[0-9]%]" },
}

TEL_T.DEVICE_SIGNATURES = {
  { vendor = "Moxa", patterns = { "NPort", "MOXA", "Moxa" }, family = "serial/device server (ICS edge)" },
  { vendor = "Schneider", patterns = { "Schneider", "TSX", "BMEX", "Quantum", "Premium", "M340" }, family = "industrial PLC (Modbus/TCP stack)" },
  { vendor = "Siemens", patterns = { "Siemens", "SIMATIC", "S7%-", "S7-200", "S7-300", "S7-1200" }, family = "industrial PLC (PROFINET stack)" },
  { vendor = "Allen-Bradley", patterns = { "Allen%-Bradley", "Rockwell", "SLC 5/" }, family = "industrial PLC (EtherNet/IP stack)" },
  { vendor = "Wago", patterns = { "WAGO", "Wago", "750%-8", "750-8" }, family = "industrial controller" },
  { vendor = "Hirschmann", patterns = { "Hirschmann", "RS2-", "EAGLE" }, family = "industrial network switch" },
  { vendor = "Digi", patterns = { "Digi One", "PortServer", "ConnectPort" }, family = "device/serial server" },
  { vendor = "Lantronix", patterns = { "Lantronix", "UDS1100", "MSS100" }, family = "device/serial server" },
  { vendor = "Cisco", patterns = { "Cisco", "IOS %(tm%)", "User Access Verification" }, family = "network equipment" },
  { vendor = "HP", patterns = { "HP JetDirect", "JetDirect" }, family = "printer" },
  { vendor = "BusyBox", patterns = { "BusyBox" }, family = "embedded busybox shell" },
  { vendor = "Microsoft", patterns = { "Microsoft Telnet", "Windows NT" }, family = "Windows telnet server" },
}

TEL_T.BUSYBOX_CVES = "BusyBox telnetd < 1.30-era IAC handling issues; CVE-2020-10188 (netkit telnetd utility format string) shares the code lineage on embedded builds"

TEL_T.CVE_FLAGS = {
  {
    matches = { "BusyBox v1%.[0-2]%d", "BusyBox v1%.[0-2]%d%." },
    label = "BusyBox pre-1.30 embedded telnetd",
    note = TEL_T.BUSYBOX_CVES,
  },
  {
    matches = { "netkit telnetd", "netkit%-telnetd" },
    label = "netkit telnetd",
    note = "CVE-2020-10188: utility format-string overflow in telnetd (remote root potential on affected builds)",
  },
  {
    matches = { "NPort", "MOXA", "Moxa" },
    label = "Moxa NPort family",
    note = "Moxa NPort firmware advisories include cleartext management protocols (telnet/console) and pre-auth issues - migrate to SSH-based management",
  },
  {
    matches = { "Microsoft Telnet" },
    label = "Microsoft Telnet Server",
    note = "Windows telnet service transmits credentials in cleartext unless NTLM SSPI (option 139) is enforced; the role is deprecated",
  },
}

TEL_T.DEFAULT_USERS = { "admin", "root", "cisco", "user", "support", "manager", "telnet" }

TEL_B = {}

TEL_B.iac = function(cmd_byte)
  return string.char(255, cmd_byte % 256)
end

TEL_B.iac2 = function(cmd_byte, opt)
  return string.char(255, cmd_byte % 256, opt % 256)
end

TEL_B.will = function(opt)
  return TEL_B.iac2(TEL_T.IAC_WILL, opt)
end

TEL_B.wont = function(opt)
  return TEL_B.iac2(TEL_T.IAC_WONT, opt)
end

TEL_B.do_opt = function(opt)
  return TEL_B.iac2(TEL_T.IAC_DO, opt)
end

TEL_B.dont = function(opt)
  return TEL_B.iac2(TEL_T.IAC_DONT, opt)
end

TEL_B.sb = function(option, payload)
  return string.char(255, TEL_T.IAC_SB, option % 256) .. payload .. string.char(255, TEL_T.IAC_SE)
end

TEL_B.ttype_is = function(name)
  return TEL_B.sb(TEL_T.OPT_TTYPE, "\x00" .. tostring(name or "XTERM"))
end

TEL_B.ttype_send = function()
  return TEL_B.sb(TEL_T.OPT_TTYPE, "\x01")
end

TEL_B.naws = function(cols, rows)
  return TEL_B.sb(TEL_T.OPT_NAWS, string.char(
    math.floor((cols or 80) / 256) % 256, (cols or 80) % 256,
    math.floor((rows or 24) / 256) % 256, (rows or 24) % 256))
end

TEL_B.environ_send = function(pairs)
  local payload = "\x00"
  for _, kv in ipairs(pairs) do
    payload = payload .. "\x03" .. kv[1] .. "\x04" .. kv[2]
  end
  return TEL_B.sb(TEL_T.OPT_NEW_ENVIRON, payload)
end

TEL_B.environ_request = function(varnames)
  local payload = "\x01"
  local names = varnames or { "USER", "HOME", "PATH", "SHELL", "HOSTNAME" }
  for _, name in ipairs(names) do
    payload = payload .. "\x03" .. name
  end
  return TEL_B.sb(TEL_T.OPT_NEW_ENVIRON, payload)
end

TEL_B.auth_send = function(ctype, modifier)
  return TEL_B.sb(TEL_T.OPT_AUTH, string.char(1, ctype % 256, modifier or 0))
end

TEL_B.auth_reply = function(ctype, modifier)
  return TEL_B.sb(TEL_T.OPT_AUTH, string.char(2, ctype % 256, modifier or 0))
end

TEL_B.encrypt_support = function(types)
  local payload = string.char(1)
  for _, t in ipairs(types or { 3 }) do
    payload = payload .. string.char(t % 256)
  end
  return TEL_B.sb(TEL_T.OPT_ENCRYPT, payload)
end

TEL_B.ayt = function()
  return TEL_B.iac(TEL_T.IAC_AYT)
end

TEL_B.escape_byte = function(data)
  return (data:gsub("\255", "\255\255"))
end

TEL_X = {}

TEL_X.parse_stream = function(data)
  local out = { text = {}, commands = {}, raw_commands = {} }
  local pos = 1
  local n = #data
  while pos <= n do
    local b = data:byte(pos)
    if b ~= 255 then
      out.text[#out.text + 1] = data:sub(pos, pos)
      pos = pos + 1
    else
      local cmd = data:byte(pos + 1)
      if cmd == nil then
        out.truncated_iac = true
        break
      end
      if cmd == 255 then
        out.text[#out.text + 1] = "\255"
        pos = pos + 2
      elseif cmd == 250 then
        local option = data:byte(pos + 2)
        local inner = pos + 3
        local payload = {}
        local done = false
        while inner <= n do
          local ib = data:byte(inner)
          if ib == 255 then
            local next_b = data:byte(inner + 1)
            if next_b == 240 then
              done = true
              inner = inner + 1
              break
            elseif next_b == 255 then
              payload[#payload + 1] = "\255"
              inner = inner + 2
            else
              payload[#payload + 1] = "\255"
              inner = inner + 1
            end
          else
            payload[#payload + 1] = data:sub(inner, inner)
            inner = inner + 1
          end
        end
        out.commands[#out.commands + 1] = { kind = "SB", opt = option, payload = table.concat(payload, "") }
        out.raw_commands[#out.raw_commands + 1] = data:sub(pos, inner)
        pos = inner + 1
        if not done then
          out.truncated_sb = true
        end
      elseif cmd >= 251 and cmd <= 254 then
        local option = data:byte(pos + 2)
        local kinds = { [251] = "WILL", [252] = "WONT", [253] = "DO", [254] = "DONT" }
        out.commands[#out.commands + 1] = { kind = kinds[cmd], opt = option }
        out.raw_commands[#out.raw_commands + 1] = data:sub(pos, pos + 2)
        pos = pos + 3
      else
        local names = {
          [240] = "SE", [241] = "NOP", [242] = "DM", [243] = "BRK", [244] = "IP",
          [245] = "AO", [246] = "AYT", [247] = "EC", [248] = "EL", [249] = "GA",
        }
        out.commands[#out.commands + 1] = { kind = names[cmd] or ("CMD-" .. tostring(cmd)) }
        out.raw_commands[#out.raw_commands + 1] = data:sub(pos, pos + 1)
        pos = pos + 2
      end
    end
  end
  out.text = table.concat(out.text, "")
  return out
end

TEL_X.option_name = function(opt)
  return TEL_T.OPTION_NAMES[opt] or ("option " .. tostring(opt))
end

TEL_X.parse_sb = function(cmd)
  local out = { opt = cmd.opt, payload = cmd.payload or "" }
  if cmd.opt == TEL_T.OPT_TTYPE then
    out.kind = "ttype"
    if #cmd.payload >= 1 then
      out.tcmd = cmd.payload:byte(1)
      out.tcmd_name = (out.tcmd == 0 and "IS" or (out.tcmd == 1 and "SEND" or tostring(out.tcmd)))
      out.terminal = cmd.payload:sub(2)
    end
  elseif cmd.opt == TEL_T.OPT_AUTH then
    out.kind = "auth"
    if #cmd.payload >= 3 then
      out.acmd = cmd.payload:byte(1)
      out.acmd_name = (out.acmd == 1 and "SEND" or (out.acmd == 2 and "REPLY" or tostring(out.acmd)))
      out.atype = cmd.payload:byte(2)
      out.modifier = cmd.payload:byte(3)
      out.type_name = TEL_T.AUTH_TYPES[out.atype] or ("type " .. tostring(out.atype))
      out.type_weak = TEL_T.AUTH_WEAK[out.atype]
    end
  elseif cmd.opt == TEL_T.OPT_NEW_ENVIRON or cmd.opt == TEL_T.OPT_OLD_ENVIRON then
    out.kind = "environ"
    out.environ_variant = (cmd.opt == TEL_T.OPT_NEW_ENVIRON) and "NEW-ENVIRON" or "OLD-ENVIRON"
    local vars = {}
    local pos = 2
    local current_var = nil
    while pos <= #cmd.payload do
      local b = cmd.payload:byte(pos)
      local ch = cmd.payload:sub(pos, pos)
      if TEL_T.ENV_TYPES[b] then
        current_var = TEL_T.ENV_TYPES[b]
      else
        local nxt = cmd.payload:find("[\003\004\005\006]", pos + 1)
        local stop = nxt or (#cmd.payload + 1)
        if current_var ~= nil then
          vars[#vars + 1] = { type = current_var, name = cmd.payload:sub(pos, stop - 1) }
        end
        pos = stop - 1
      end
      pos = pos + 1
    end
    out.items = vars
  elseif cmd.opt == TEL_T.OPT_ENCRYPT then
    out.kind = "encrypt"
    if #cmd.payload >= 1 then
      out.ecmd = cmd.payload:byte(1)
      out.ecmd_name = TEL_T.ENCRYPT_CMDS[out.ecmd] or tostring(out.ecmd)
      out.types = {}
      for i = 2, #cmd.payload do
        local t = cmd.payload:byte(i)
        out.types[#out.types + 1] = { id = t, name = TEL_T.ENCRYPT_TYPES[t] or ("type " .. tostring(t)) }
      end
    end
  else
    out.kind = "generic"
  end
  return out
end

TEL_X.negotiation_summary = function(stream)
  local out = { will = {}, wont = {}, do_ = {}, dont = {}, sbs = {}, others = {} }
  for _, cmd in ipairs(stream.commands or {}) do
    if cmd.kind == "WILL" then
      out.will[cmd.opt] = true
    elseif cmd.kind == "WONT" then
      out.wont[cmd.opt] = true
    elseif cmd.kind == "DO" then
      out.do_[cmd.opt] = true
    elseif cmd.kind == "DONT" then
      out.dont[cmd.opt] = true
    elseif cmd.kind == "SB" then
      out.sbs[#out.sbs + 1] = TEL_X.parse_sb(cmd)
    else
      out.others[#out.others + 1] = cmd.kind
    end
  end
  return out
end

TEL_X.offers_option = function(summary, opt)
  return summary.will[opt] == true or summary.do_[opt] == true
end

TEL_X.classify_banner = function(text)
  local out = { raw_first_line = (text:match("^%s*(.-)[\r\n]") or text:sub(1, 60)), vendors = {}, version = nil }
  for _, sig in ipairs(TEL_T.DEVICE_SIGNATURES) do
    local hit = false
    for _, alt in ipairs(sig.patterns) do
      if text:find(alt) then
        hit = true
        break
      end
    end
    if hit then
      out.vendors[#out.vendors + 1] = { vendor = sig.vendor, family = sig.family }
      if sig.vendor == "BusyBox" then
        out.busybox = text:match("BusyBox v(%d+%.%d+%.%d+)")
      end
      if sig.vendor == "Moxa" then
        out.device = text:match("(NPort[%w%-]*)") or out.device
        out.firmware = text:match("Firmware (F?[%d%.]+)")
      end
      if sig.vendor == "Microsoft" then
        out.windows = true
      end
    end
  end
  out.version = text:match("[Vv]ersion%s+([%d%.]+)") or text:match("Firmware (F?[%d%.]+)")
    or text:match("Release ([%d%.%-A-Za-z]+)") or out.firmware
  out.os_hint = text:match("%(([^%)]*Linux[^%)]*)%)")
    or text:match("(LeapOS[^%r]*)")
    or text:match("%(([^%)]*BSD[^%)]*)%)")
  local cves = {}
  for _, flag in ipairs(TEL_T.CVE_FLAGS) do
    local hit = false
    for _, alt in ipairs(flag.matches) do
      if text:find(alt) then
        hit = true
        break
      end
    end
    if hit then
      cves[#cves + 1] = { family = flag.label, note = flag.note }
    end
  end
  out.cve_flags = cves
  return out
end

TEL_X.prompt_classify = function(text)
  for _, pattern in ipairs(TEL_T.PROMPT_PATTERNS) do
    local start_pos, end_pos = text:find(pattern.re)
    if start_pos then
      local matched = text:sub(start_pos, end_pos)
      return pattern.kind, matched
    end
  end
  return "none", nil
end

TEL_X.login_outcome = function(text)
  if text:find("locked", 1, true) then
    return "lockout", "lockout"
  end
  if text:find("[Dd]enied") or text:find("Disconnecting")
    or text:find("[Dd]isallowed") then
    return "denied", "error"
  end
  if text:find("[Ll]ogin incorrect") or text:find("[Aa]uthentication failed") then
    local kind = TEL_X.prompt_classify(text)
    if kind == "login" then
      return "failed-retry", kind
    end
    return "failed", kind
  end
  local kind = TEL_X.prompt_classify(text)
  if kind == "shell" or kind == "menu" then
    return "success", kind
  end
  if kind == "password" then
    return "need-password", kind
  end
  if kind == "login" then
    return "retry-login", kind
  end
  return "unclear", kind
end

TEL_X.is_cisco_prompt = function(text)
  return text:find("User Access Verification", 1, true) ~= nil
    or (text:find("Password:", 1, true) ~= nil and text:find("^[^\r\n]*>", 1) ~= nil)
end

TEL_X.is_windows_telnet = function(text)
  return text:find("Microsoft Telnet", 1, true) ~= nil or text:find("Welcome to Microsoft", 1, true) ~= nil
end

TEL_X.windows_options_seen = function(summary)
  return TEL_X.offers_option(summary, TEL_T.OPT_PRAGMA_LOGON)
    or TEL_X.offers_option(summary, TEL_T.OPT_SSPI_LOGON)
end

TEL_A = {}

TEL_A.selftest = function()
  local stream = TEL_X.parse_stream("hello\r\n" .. TEL_B.will(TEL_T.OPT_SGA) .. TEL_B.do_opt(TEL_T.OPT_TTYPE)
    .. "data\255\255more" .. TEL_B.sb(TEL_T.OPT_TTYPE, "\x01"))
  if stream.text ~= "hello\r\ndata\255more" then
    return false, "stream text mismatch: " .. (stream.text:gsub("\r", "<CR>"):gsub("\n", "<LF>"))
  end
  if #stream.commands ~= 3 then
    return false, "command count mismatch: " .. tostring(#stream.commands)
  end
  local summary = TEL_X.negotiation_summary(stream)
  if not summary.will[TEL_T.OPT_SGA] or not summary.do_[TEL_T.OPT_TTYPE] then
    return false, "negotiation summary failed"
  end
  if summary.sbs[1] == nil or summary.sbs[1].kind ~= "ttype" or summary.sbs[1].tcmd_name ~= "SEND" then
    return false, "subnegotiation parse failed"
  end
  local probe = TEL_B.environ_request({ "USER", "HOME" })
  local parsed = TEL_X.parse_stream(probe)
  if parsed.raw_commands[1] == nil or #parsed.commands ~= 1 then
    return false, "environ request roundtrip failed"
  end
  local env = TEL_X.parse_sb(parsed.commands[1])
  if env.environ_variant ~= "NEW-ENVIRON" or #env.items ~= 2 or env.items[1].name ~= "USER" then
    return false, "environ items parse failed"
  end
  local kind = TEL_X.prompt_classify("Welcome\r\n\r\nlogin: ")
  if kind ~= "login" then
    return false, "login prompt classify failed"
  end
  if TEL_X.login_outcome("Access denied\r\n\r\nlogin: ") ~= "denied" then
    return false, "outcome classify (denied) failed"
  end
  if TEL_X.login_outcome("Login incorrect\r\n\r\nlogin: ") ~= "failed-retry" then
    return false, "outcome classify (failed-retry) failed"
  end
  if TEL_X.login_outcome("\r\nNPort admin shell ready\r\nNPort> ") ~= "success" then
    return false, "outcome classify (success) failed"
  end
  local banner = TEL_X.classify_banner("\r\nNPort 5650-8\r\nFirmware F3.2\r\nBusyBox v1.20.2 built-in shell\r\n\r\nlogin: ")
  if banner.busybox ~= "1.20.2" or banner.firmware ~= "F3.2" or #banner.cve_flags == 0 then
    return false, "banner classify failed"
  end
  return true, "IAC codec and classifiers verified"
end

local function tel_session_new(host, port, args)
  return {
    host = host,
    port = port or 23,
    args = args,
    sock = nil,
    connected = false,
    closed = false,
    peer_will = {},
    peer_wont = {},
    peer_do = {},
    peer_dont = {},
    our_will = {},
    our_wont = {},
    our_do = {},
    our_dont = {},
    connects = 0,
    sends = 0,
    recvs = 0,
    timeouts = 0,
    errors = 0,
    audit = {},
  }
end

local function tel_audit(sess, kind, detail)
  sess.audit[#sess.audit + 1] = kind .. ":" .. tostring(detail)
end

local function tel_connect(sess)
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
  tel_audit(sess, "connect", sess.port)
  return 1
end

local function tel_close(sess)
  if sess and sess.sock and not sess.closed then
    sess.sock:close()
  end
  if sess then
    sess.closed = true
    sess.connected = false
  end
end

local function tel_send_raw(sess, data)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  if budget_exhausted(sess.args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  sess.sends = sess.sends + 1
  tel_audit(sess, "send", #data)
  local ok, err = sess.sock:send(data)
  if not ok then
    sess.errors = sess.errors + 1
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  return 1
end

local function tel_recv_chunk(sess, wait_seconds)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  local remaining = math.max(1, wait_seconds or 2)
  sess.sock:set_timeout(remaining * 1000)
  local ok, chunk = sess.sock:receive(65536)
  if ok then
    sess.recvs = sess.recvs + 1
    tel_audit(sess, "recv", #chunk)
    return chunk
  end
  local err = chunk
  if err == "TIMEOUT" or err == "EOF" then
    sess.timeouts = sess.timeouts + 1
    return nil, "timeout"
  end
  sess.errors = sess.errors + 1
  return nil, "receive failed: " .. tostring(err or "unknown")
end

local function tel_recv_until(sess, deadline_seconds, stop_kinds)
  local deadline = os.time() + math.max(1, deadline_seconds or 4)
  local buf = ""
  while os.time() < deadline do
    if budget_exhausted(sess.args) then
      break
    end
    local chunk, err = tel_recv_chunk(sess, 1)
    if chunk then
      buf = buf .. chunk
      local stream = TEL_X.parse_stream(buf)
      local kind = TEL_X.prompt_classify(stream.text)
      for _, k in ipairs(stop_kinds or {}) do
        if kind == k then
          return stream, kind, buf
        end
      end
    else
      if err == "timeout" and #buf > 0 then
        local stream = TEL_X.parse_stream(buf)
        return stream, TEL_X.prompt_classify(stream.text), buf
      end
      if err ~= "timeout" then
        break
      end
    end
  end
  local stream = TEL_X.parse_stream(buf)
  return stream, TEL_X.prompt_classify(stream.text), buf
end

local function tel_apply_policy(sess, stream)
  local replies = {}
  for _, cmd in ipairs(stream.commands or {}) do
    if cmd.kind == "DO" then
      sess.peer_do[cmd.opt] = true
      if cmd.opt == TEL_T.OPT_SGA or cmd.opt == TEL_T.OPT_BINARY then
        sess.our_will[cmd.opt] = true
        replies[#replies + 1] = TEL_B.will(cmd.opt)
      else
        sess.our_wont[cmd.opt] = true
        replies[#replies + 1] = TEL_B.wont(cmd.opt)
      end
    elseif cmd.kind == "WILL" then
      sess.peer_will[cmd.opt] = true
      if cmd.opt == TEL_T.OPT_SGA then
        sess.our_do[cmd.opt] = true
        replies[#replies + 1] = TEL_B.do_opt(cmd.opt)
      else
        sess.our_dont[cmd.opt] = true
        replies[#replies + 1] = TEL_B.dont(cmd.opt)
      end
    elseif cmd.kind == "WONT" then
      sess.peer_wont[cmd.opt] = true
    elseif cmd.kind == "DONT" then
      sess.peer_dont[cmd.opt] = true
      if sess.our_will[cmd.opt] then
        sess.our_will[cmd.opt] = nil
        sess.our_wont[cmd.opt] = true
      end
    end
  end
  if #replies > 0 then
    tel_send_raw(sess, table.concat(replies, ""))
  end
  return TEL_X.negotiation_summary(stream)
end

local function tel_open_session(host, port, args, opts)
  opts = opts or {}
  local sess = tel_session_new(host, port, args)
  local ok, err = tel_connect(sess)
  if not ok then
    return nil, err
  end
  local stream, kind = tel_recv_until(sess, opts.banner_wait or 3, { "login", "password", "shell", "menu", "error" })
  if opts.negotate ~= false then
    tel_apply_policy(sess, stream)
  end
  return sess, stream, kind
end

local function tel_login_probe(host, port, username, password, args)
  local sess, stream, kind = tel_open_session(host, port, args, {})
  if sess == nil then
    return nil, stream, nil
  end
  local stages = {}
  local outcome = "unclear"
  if kind == "password" then
    stages[#stages + 1] = "password-first prompt"
  elseif kind ~= "login" then
    stages[#stages + 1] = "no login prompt (state: " .. tostring(kind) .. ")"
  else
    stages[#stages + 1] = "login prompt"
  end
  if kind == "login" then
    local ok, err = tel_send_raw(sess, TEL_B.escape_byte(username) .. "\r\n")
    if not ok then
      tel_close(sess)
      return sess, { stages = stages, outcome = "send failed: " .. tostring(err) }, nil
    end
    stream, kind = tel_recv_until(sess, args.timeout or 4, { "password", "error", "shell", "menu", "denied-root", "lockout" })
    tel_apply_policy(sess, stream)
    stages[#stages + 1] = "after user: " .. tostring(kind)
  end
  if kind == "password" and password ~= nil then
    local ok, err = tel_send_raw(sess, TEL_B.escape_byte(password) .. "\r\n")
    if not ok then
      tel_close(sess)
      return sess, { stages = stages, outcome = "send failed: " .. tostring(err) }, nil
    end
    stream, kind = tel_recv_until(sess, args.timeout or 4, { "shell", "menu", "error", "login", "lockout", "denied-root" })
    tel_apply_policy(sess, stream)
    stages[#stages + 1] = "after password: " .. tostring(kind)
  elseif kind == "password" and password == nil then
    stages[#stages + 1] = "password prompt shown; no credentials sent"
  end
  outcome = TEL_X.login_outcome(stream.text)
  tel_close(sess)
  return sess, { stages = stages, outcome = outcome, kind = kind, text = stream.text, summary = TEL_X.negotiation_summary(stream) }, nil
end

local function tel_env_probe(host, port, args)
  local sess, stream = tel_open_session(host, port, args, { banner_wait = 2 })
  if sess == nil then
    return nil, stream
  end
  local ok, err = tel_send_raw(sess, TEL_B.environ_request({ "USER", "HOME", "PATH", "SHELL", "HOSTNAME" }))
  if not ok then
    tel_close(sess)
    return nil, err
  end
  local reply, kind, buf = tel_recv_until(sess, 3, { "login", "password", "shell" })
  local parsed = TEL_X.parse_stream(buf)
  local envs = {}
  for _, cmd in ipairs(parsed.commands) do
    if cmd.kind == "SB" then
      local sb = TEL_X.parse_sb(cmd)
      if sb.kind == "environ" then
        envs[#envs + 1] = sb
      end
    end
  end
  tel_close(sess)
  return envs, nil, parsed
end

local function tel_ttype_probe(host, port, args, ttype_name)
  local sess, stream = tel_open_session(host, port, args, { banner_wait = 2 })
  if sess == nil then
    return nil, stream
  end
  local ok, err = tel_send_raw(sess, TEL_B.ttype_is(ttype_name or "XTERM"))
  if not ok then
    tel_close(sess)
    return nil, err
  end
  local reply, kind, buf = tel_recv_until(sess, 3, { "login", "password", "shell" })
  local parsed = TEL_X.parse_stream(buf)
  tel_close(sess)
  return parsed, nil, kind
end

local function tel_option_scan(host, port, args)
  local sess, stream = tel_open_session(host, port, args, { banner_wait = 2 })
  if sess == nil then
    return nil, stream
  end
  local probe_opts = { TEL_T.OPT_AUTH, TEL_T.OPT_ENCRYPT, TEL_T.OPT_NEW_ENVIRON, TEL_T.OPT_TTYPE,
    TEL_T.OPT_NAWS, TEL_T.OPT_CHARSET, TEL_T.OPT_COMPORT, TEL_T.OPT_STARTTLS,
    TEL_T.OPT_PRAGMA_LOGON, TEL_T.OPT_SSPI_LOGON }
  local outgoing = {}
  for _, opt in ipairs(probe_opts) do
    outgoing[#outgoing + 1] = TEL_B.do_opt(opt)
  end
  local ok, err = tel_send_raw(sess, table.concat(outgoing, ""))
  if not ok then
    tel_close(sess)
    return nil, err, sess
  end
  local reply, kind, buf = tel_recv_until(sess, 3, { "login", "password", "shell" })
  local parsed = TEL_X.parse_stream(buf)
  local responses = { do_ = {}, wont = {}, will = {}, dont = {}, other = {} }
  for _, cmd in ipairs(parsed.commands) do
    if cmd.kind == "DO" then
      responses.do_[cmd.opt] = true
    elseif cmd.kind == "WONT" then
      responses.wont[cmd.opt] = true
    elseif cmd.kind == "WILL" then
      responses.will[cmd.opt] = true
    elseif cmd.kind == "DONT" then
      responses.dont[cmd.opt] = true
    elseif cmd.kind == "SB" then
      local sb = TEL_X.parse_sb(cmd)
      responses.other[#responses.other + 1] = sb
    end
  end
  tel_close(sess)
  return responses, nil, sess
end

local function tel_iac_probe(host, port, args)
  local sess, banner_stream = tel_open_session(host, port, args, { banner_wait = 2 })
  if sess == nil then
    return nil, banner_stream
  end
  local probes = {}
  local ok, err = tel_send_raw(sess, "ping" .. string.char(255, 255) .. "data\r\n")
  probes[#probes + 1] = { name = "escaped data byte (IAC IAC)", bytes = 12 }
  if ok then
    tel_send_raw(sess, TEL_B.sb(TEL_T.OPT_TTYPE, "\x00" .. string.rep("A", 60)))
    probes[#probes + 1] = { name = "legal 60-byte TTYPE subnegotiation", bytes = 66 }
    ok = nil
  end
  local reply, kind, buf = tel_recv_until(sess, 2, { "login", "password", "shell", "none" })
  local stream = TEL_X.parse_stream(buf)
  tel_close(sess)
  local alive = false
  local health_sess = tel_session_new(host, port, args)
  if tel_connect(health_sess) then
    local hstream = tel_recv_until(health_sess, 2, { "login", "password", "shell" })
    alive = hstream ~= nil and hstream.text ~= nil and #hstream.text > 0
    tel_close(health_sess)
  end
  return {
    probes = probes,
    echoed = #stream.text,
    service_alive = tostring(alive),
    banner_before = banner_stream.text,
  }
end

local function tel_capacity_probe(host, port, args, max_extra)
  local accepted = 0
  local attempts = {}
  local limit = math.min(max_extra or 5, 8)
  for i = 1, limit do
    if budget_exhausted(args) then
      break
    end
    local sess = tel_session_new(host, port, args)
    local ok, err = tel_connect(sess)
    if ok then
      local stream = tel_recv_until(sess, 2, { "login", "password", "shell" })
      if stream.text and #stream.text > 0 then
        accepted = accepted + 1
        attempts[#attempts + 1] = { connection = tostring(i), outcome = "banner served, closed" }
      else
        attempts[#attempts + 1] = { connection = tostring(i), outcome = "connected but silent" }
      end
    else
      attempts[#attempts + 1] = { connection = tostring(i), outcome = "refused: " .. tostring(err) }
    end
    tel_close(sess)
  end
  return { accepted = accepted, attempts = attempts, bound = limit }
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

local function tel_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - TELNET audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The TELNET audit did not complete against this target", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function tel_open(host, port, args)
  local sess, stream, kind = tel_open_session(host, port, args, {})
  if sess == nil then
    return nil, tostring(stream)
  end
  return sess, stream, kind
end

local function tel_options(host, port, args)
  local responses, err, sess = tel_option_scan(host, port, args)
  return responses, err, sess
end

local function run_audit(host, port, args)
  local sections = {}
  local psess, probe = tel_login_probe(host, port, "root", nil, args)
  if psess == nil and probe == nil then
    return tel_incomplete("login probe failed", sections, "session", "no response")
  end
  if psess ~= nil then
    tel_close(psess)
  end
  local outcome = probe ~= nil and probe.outcome or "unknown"
  local flow = probe ~= nil and table.concat(probe.stages or {}, " -> ") or "n/a"
  sections[#sections + 1] = { key = "Root Login Probe", value = {
    submitted_user = "root",
    next_stage = outcome,
    flow = flow,
    password_sent = "no",
  } }
  sections[#sections + 1] = { key = "Privilege Path Context", value = {
    root_over_cleartext = "root credentials and session keystrokes ride the network unencrypted",
    post_compromise = "interactive root shell enables audit-log tampering, sniffer placement and lateral movement",
    policy_reference = "hardening baselines (CIS, DISA STIG) require root logins restricted to a named console or refused entirely",
    observed_stage = outcome,
  } }
  sections[#sections + 1] = { key = "Root Policy Matrix", value = {
    ["denied before password"] = "protected: the account name is rejected without credential exchange",
    ["password prompt shown"] = "exposed surface: root participates in online guessing over an unauthenticated transport",
    ["lockout triggered"] = "protected with throttling: repeated root attempts are rate limited",
    ["direct shell"] = "critical misconfiguration: root without any credential stage",
  } }
  sections[#sections + 1] = { key = "Attempt Trace", value = {
    stage_1 = "connect and read the greeting until the first prompt",
    stage_2 = "submit the root username once (no password generated)",
    stage_3 = "classify the next server stage and close the session",
    observed = flow,
  } }
  sections[#sections + 1] = { key = "Alias Note", value = "root-equivalent names vary per stack (root, admin, superuser, system, operator); this probe submits 'root' only - alias behaviour must be covered by the default-credential audit" }
  sections[#sections + 1] = { key = "Related Controls", value = {
    "SSH with PermitRootLogin no / prohibit-password as the replacement path",
    "console-only root access (physical or BMC managed)",
    "named-sudo accounts for audited privilege elevation",
  } }

  local remediation = {}
  local status_text
  if outcome == "need-password" then
    status_text = "VULNERABLE - root accepted at the login stage over telnet (password prompt shown)"
    add_finding("HIGH", "Direct root login surface on the telnet service", {
      subject = "root-login",
      evidence = "root username accepted; password prompt displayed without any transport protection guarantee",
      confidence = "high",
      cvss = 8.1,
    })
    remediation["1. Block root"] = "Configure the daemon/hosts.equiv policy so root is refused before the password stage."
    remediation["2. Replace"] = "Move administration to SSH with PermitRootLogin disabled."
  elseif outcome == "denied" or outcome == "lockout" then
    status_text = "SECURE - root rejected before any credential exchange (" .. outcome .. ")"
    add_finding("INFO", "Root name refused at the login stage", {
      subject = "root-login",
      evidence = "flow: " .. flow,
      confidence = "high",
    })
    remediation["1. Maintain"] = "Keep the root restriction and audit the policy after upgrades."
  else
    status_text = "INFORMATIONAL - root login posture inconclusive (stage " .. outcome .. ")"
    add_finding("INFO", "Root probe did not reach a decisive stage", {
      subject = "root-login",
      evidence = "flow: " .. flow,
      confidence = "medium",
    })
    remediation["1. Re-run"] = "Re-run the audit to classify the root policy."
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
