local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Reads holding registers (function code 3) anonymously - setpoints,
counters and configuration values of the process.

Why it matters
- Holding registers carry the process brain: setpoints, alarm limits,
  recipe values. Anonymous reads enable precise, targeted manipulation
  later.
- Regulatory frameworks (IEC 62443) require zone segmentation exactly
  against this class of exposure.

What the script does
1. Sends Read Holding Registers (FC 3) for addresses 0-3.
2. Decodes register values or the exception answer.
3. Grades the disclosure.

Safe operation: one read request; no writes are issued.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  502,
  "modbus",
  {"tcp", "udp"}
)

local SCRIPT_NAME = "modbus-unauth-read-holding"

local RISK_LEVEL = "🔴 CRITICAL"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 48,
  recv_window = 3,
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

ICS_T = {}

ICS_T.MODBUS_PORT = 502
ICS_T.MODBUS_FC_READ_COILS = 1
ICS_T.MODBUS_FC_READ_DISCRETE = 2
ICS_T.MODBUS_FC_READ_HOLDING = 3
ICS_T.MODBUS_FC_READ_INPUT = 4
ICS_T.MODBUS_FC_WRITE_COIL = 5
ICS_T.MODBUS_FC_READ_DEVICE_ID = 43
ICS_T.MODBUS_MEI_DEVICE_ID = 14
ICS_T.MODBUS_EXC_BIT = 128

ICS_T.MODBUS_EXCEPTIONS = {
  [1] = "ILLEGAL_FUNCTION",
  [2] = "ILLEGAL_DATA_ADDRESS",
  [3] = "ILLEGAL_DATA_VALUE",
  [4] = "SERVER_DEVICE_FAILURE",
  [6] = "SERVER_DEVICE_BUSY",
  [10] = "GATEWAY_PATH_UNAVAILABLE",
  [11] = "GATEWAY_TARGET_FAILED",
}

ICS_T.MODBUS_SENTINEL_ADDR = 65535

ICS_T.DEVICE_ID_OBJECTS = {
  [0] = "VendorName",
  [1] = "ProductCode",
  [2] = "MajorMinorRevision",
}

ICS_T.BACNET_PORT = 47808
ICS_T.BACNET_TYPE_UNICAST_NPDU = 0x81
ICS_T.BACNET_BVLC_ORIGINAL_UNICAST = 0x0A
ICS_T.BACNET_BVLC_ORIGINAL_BROADCAST = 0x0B
ICS_T.BACNET_NPDU = "\x01\x20\xff\xff\x00\xff"
ICS_T.BACNET_APDU_UNCONFIRMED = 0x10
ICS_T.BACNET_PDU_WHOIS = 0x08
ICS_T.BACNET_PDU_IAM = 0x00
ICS_T.BACNET_PDU_CONFIRMED_REQ = 0x00
ICS_T.BACNET_PDU_COMPLEX_ACK = 0x30
ICS_T.BACNET_PDU_ERROR = 0x50
ICS_T.BACNET_SVC_READ_PROP = 0x0C
ICS_T.BACNET_OBJ_DEVICE = 8
ICS_T.BACNET_PROP_OBJECT_NAME = 77
ICS_T.BACNET_PROP_DESCRIPTION = 28
ICS_T.BACNET_TAGS = {
  [0] = "NULL",
  [1] = "BOOLEAN",
  [2] = "UINT",
  [3] = "INT",
  [4] = "REAL",
  [5] = "DOUBLE",
  [6] = "OCTET",
  [7] = "STRING",
}

ICS_T.DNP3_PORT = 20000
ICS_T.DNP3_START_BYTES = "\x05\x64"
ICS_T.DNP3_CTRL_REQUEST_LINK_STATUS = 0x49
ICS_T.DNP3_CTRL_RESET_LINK = 0x40
ICS_T.DNP3_CTRL_ACK = 0x00
ICS_T.DNP3_CTRL_NACK = 0x01
ICS_T.DNP3_CTRL_LINK_STATUS = 0x0B
ICS_T.DNP3_CTRL_NAMES = {
  [0] = "ACK",
  [1] = "NACK",
  [3] = "STATUS_OF_LINK",
  [4] = "NOT_SUPPORTED",
  [9] = "REQUEST_LINK_STATUS",
  [11] = "LINK_STATUS",
  [12] = "RESET_LINK",
}

ICS_T.EIP_PORT = 44818
ICS_T.EIP_CMD_LIST_IDENTITY = 0x63
ICS_T.EIP_CMD_LIST_INTERFACES = 0x64
ICS_T.EIP_CMD_REGISTER_SESSION = 0x65
ICS_T.EIP_CMD_NAMES = {
  [0x63] = "ListIdentity",
  [0x64] = "ListInterfaces",
  [0x65] = "RegisterSession",
  [0x66] = "UnRegisterSession",
  [0x6E] = "SendRRData",
}

ICS_T.EIP_STATUS_NAMES = {
  [0] = "success",
  [1] = "invalid_cmd",
  [103] = "insufficient_memory",
}

ICS_T.FINS_PORT = 9600
ICS_T.FINS_MAGIC = "FINS"
ICS_T.FINS_CMD_NODE_SEARCH = "\x00\x00\x00\x03"
ICS_T.FINS_CMD_NODE_ADD = "\x00\x00\x00\x14"
ICS_T.FINS_TCP_CMD_SEND = 2
ICS_T.FINS_ICF_RESPONSE = 0xC0
ICS_T.FINS_MRC_MEM_READ = 0x01
ICS_T.FINS_SRC_MEM_WORD = 0x01
ICS_T.FINS_AREA_DM_WORD = 0x82
ICS_T.FINS_AREA_CIO_WORD = 0xB0

ICS_T.FOX_PORT = 1911
ICS_T.FOX_HELLO = "fox a 0 -1 hello {\nfox.version=35\nid=1\n}\n\0"
ICS_T.FOX_FRAME_END = "\0"

ICS_T.HART_PORT = 5094
ICS_T.HART_VERSION = 1
ICS_T.HART_MSG_REQUEST = 1
ICS_T.HART_MSG_RESPONSE = 2
ICS_T.HART_DELIM_MASTER_TO_SLAVE = 0x82
ICS_T.HART_CMD_READ_UNIQUE_ID = 0
ICS_T.HART_CMD_READ_DEVICE_VARS = 3

ICS_T.IEC104_PORT = 2404
ICS_T.IEC104_START_BYTE = 0x68
ICS_T.IEC104_U_FORMAT = 3
ICS_T.IEC104_TESTFR_ACT = 0x43
ICS_T.IEC104_TESTFR_CON = 0x83
ICS_T.IEC104_STARTDT_ACT = 0x07
ICS_T.IEC104_STARTDT_CON = 0x0B
ICS_T.IEC104_STOPDT_ACT = 0x13
ICS_T.IEC104_I_FORMAT = 0

ICS_T.MELSEC_PORT = 5007
ICS_T.MELSEC_SUBHEADER_3E = 0x5000
ICS_T.MELSEC_CPU_TIMER = 0x0010
ICS_T.MELSEC_CMD_READ_WORD = 0x0401
ICS_T.MELSEC_CMD_READ_CPU_TYPE = 0x0101
ICS_T.MELSEC_DEVICE_D = 0x0044
ICS_T.MELSEC_ERRORS = {
  [0xC04D] = "invalid_subheader",
  [0xC059] = "command_par_length_error",
  [0xC05B] = "ascii_decode_error",
  [0xC05D] = "access_forbidden",
  [0xC05F] = "cpu_busy",
  [0xC0C0] = "ok_prefix",
}

ICS_T.PROFINET_PORT = 34964
ICS_T.PROFINET_DCP_SERVICE_ID = 0x05
ICS_T.PROFINET_DCP_SERVICE_ID_GET = 0x04
ICS_T.PROFINET_DCP_OPTION_IP = 0x01
ICS_T.PROFINET_DCP_SUB_IP_PARAM = 0x02
ICS_T.PROFINET_DCP_OPTION_NAME = 0x02
ICS_T.PROFINET_DCP_SUB_NAME_DEV = 0x02
ICS_T.PROFINET_DCP_OPTION_CONTROL = 0x05
ICS_T.PROFINET_DCP_BLOCK_QUALIFIER = 0x0001

ICS_T.S7_PORT = 102
ICS_T.S7_ROSCTR_JOB = 1
ICS_T.S7_ROSCTR_ACK = 3
ICS_T.S7_FUNC_SETUP = 0xF0
ICS_T.S7_FUNC_READ_VAR = 0x04
ICS_T.S7_FUNC_READ_SZL = 0xB4
ICS_T.S7_SUBFUNCTION_SZL = 0x01
ICS_T.S7_SZL_MODULE_IDENT = 0x0111
ICS_T.S7_SZL_COMPONENT_ID = 0x001C
ICS_T.S7_ITEM_SYNTAX_SZL = 0x12
ICS_T.S7_TRANSPORTS = {
  [4] = "basic",
  [15] = "PK_optimized",
}
ICS_T.S7_ERROR_CLASSES = {
  [0] = "no_error",
  [129] = "application_relationship_error",
  [130] = "object_definition_error",
  [135] = "resource_error",
  [137] = "service_not_supported",
}

ICS_T.SESSION_BUDGET_DEFAULT = 48

ICS_MB = {}

function ICS_MB.mbap(tid, unit, pdu)
  return string.char(math.floor(tid / 256) % 256, tid % 256) .. "\0\0" ..
    string.char(math.floor((#pdu + 1) / 256) % 256, (#pdu + 1) % 256) ..
    string.char(unit % 256) .. pdu
end

function ICS_MB.parse_mbap(data)
  if #data < 8 then
    return nil, "short MBAP frame"
  end
  local a, b, c, d = string.byte(data, 1, 4)
  local tid = a * 256 + b
  local pid = c * 256 + d
  local len_hi, len_lo, unit = string.byte(data, 5, 7)
  local plen = len_hi * 256 + len_lo
  if pid ~= 0 or plen < 2 then
    return nil, "bad MBAP fields"
  end
  return { tid = tid, proto = pid, length = plen, unit = unit, pdu = string.sub(data, 8, 7 + plen - 1) }
end

function ICS_MB.read_coils(tid, unit, addr, qty)
  return ICS_MB.mbap(tid, unit,
    string.char(ICS_T.MODBUS_FC_READ_COILS) ..
    string.char(math.floor(addr / 256) % 256, addr % 256) ..
    string.char(math.floor(qty / 256) % 256, qty % 256))
end

function ICS_MB.read_holding(tid, unit, addr, qty)
  return ICS_MB.mbap(tid, unit,
    string.char(ICS_T.MODBUS_FC_READ_HOLDING) ..
    string.char(math.floor(addr / 256) % 256, addr % 256) ..
    string.char(math.floor(qty / 256) % 256, qty % 256))
end

function ICS_MB.write_coil(tid, unit, addr, value)
  local val = value and 0xFF00 or 0
  return ICS_MB.mbap(tid, unit,
    string.char(ICS_T.MODBUS_FC_WRITE_COIL) ..
    string.char(math.floor(addr / 256) % 256, addr % 256) ..
    string.char(math.floor(val / 256) % 256, val % 256))
end

function ICS_MB.read_device_id(tid, unit, code, obj)
  return ICS_MB.mbap(tid, unit,
    string.char(ICS_T.MODBUS_FC_READ_DEVICE_ID, ICS_T.MODBUS_MEI_DEVICE_ID) ..
    string.char(code or 1, obj or 0))
end

function ICS_MB.decode_device_id(pdu)
  if pdu == nil or #pdu < 7 then
    return nil
  end
  local fc, mei = string.byte(pdu, 1, 2)
  if fc ~= ICS_T.MODBUS_FC_READ_DEVICE_ID or mei ~= ICS_T.MODBUS_MEI_DEVICE_ID then
    return nil
  end
  local out = { conformity = string.byte(pdu, 4), follow = string.byte(pdu, 5), next_object = string.byte(pdu, 6), count = string.byte(pdu, 7), objects = {} }
  local off = 8
  for _ = 1, out.count do
    if off + 2 > #pdu then
      break
    end
    local obj_id = string.byte(pdu, off)
    local olen = string.byte(pdu, off + 1)
    local val = string.sub(pdu, off + 2, off + 2 + olen - 1)
    out.objects[#out.objects + 1] = { id = obj_id, name = ICS_T.DEVICE_ID_OBJECTS[obj_id] or tostring(obj_id), value = val }
    off = off + 2 + olen
  end
  return out
end

function ICS_MB.decode_exception(pdu)
  if pdu == nil or #pdu < 2 then
    return nil
  end
  local fc = string.byte(pdu, 1)
  if fc >= ICS_T.MODBUS_EXC_BIT then
    return { original_fc = fc - ICS_T.MODBUS_EXC_BIT, code = string.byte(pdu, 2),
      name = ICS_T.MODBUS_EXCEPTIONS[string.byte(pdu, 2)] or tostring(string.byte(pdu, 2)) }
  end
  return nil
end

function ICS_MB.decode_coils(pdu, qty)
  if pdu == nil or #pdu < 3 then
    return nil
  end
  local fc = string.byte(pdu, 1)
  local n = string.byte(pdu, 2)
  if fc ~= ICS_T.MODBUS_FC_READ_COILS or n < 1 then
    return nil
  end
  local out = {}
  for i = 1, math.min(qty or (n * 8), 64) do
    local byte = string.byte(pdu, 3 + math.floor((i - 1) / 8))
    if byte == nil then
      break
    end
    out[i] = (math.floor(byte / 2 ^ ((i - 1) % 8)) % 2) == 1
  end
  return out
end

function ICS_MB.decode_registers(pdu, qty)
  if pdu == nil or #pdu < 3 then
    return nil
  end
  local fc = string.byte(pdu, 1)
  local n = string.byte(pdu, 2)
  if fc ~= ICS_T.MODBUS_FC_READ_HOLDING then
    return nil
  end
  local out = {}
  for i = 1, math.min(math.floor(n / 2), qty or 16) do
    local hi, lo = string.byte(pdu, 3 + (i - 1) * 2, 4 + (i - 1) * 2)
    if hi == nil then
      break
    end
    out[i] = hi * 256 + lo
  end
  return out
end

ICS_BA = {}

function ICS_BA.apdu_whois(low, high)
  local body = ""
  if low ~= nil then
    body = string.char(0x08) .. ICS_BA.context_int(low) .. ICS_BA.context_int(high or low)
  end
  return "\x10\x08" .. body
end

function ICS_BA.frame(bvlc_func, npdu_apdu)
  return "\x81" .. string.char(bvlc_func) .. string.char(math.floor(#npdu_apdu / 256) % 256, #npdu_apdu % 256) .. npdu_apdu
end

function ICS_BA.context_int(v)
  if v < 256 then
    return "\x21" .. string.char(v)
  elseif v < 65536 then
    return "\x22" .. string.char(math.floor(v / 256) % 256, v % 256)
  end
  return "\x23" .. string.char(0, 0, math.floor(v / 256) % 256, v % 256)
end

function ICS_BA.whois_frame(low, high)
  return ICS_BA.frame(ICS_T.BACNET_BVLC_ORIGINAL_BROADCAST, ICS_T.BACNET_NPDU .. ICS_BA.apdu_whois(low, high))
end

function ICS_BA.read_property_frame(instance, prop)
  local invoke = string.char(1, 1)
  local obj = ICS_BA.context_int(instance)
  local apdu = "\x00\x0c" .. invoke ..
    ICS_BA.context_tag(12, "\x0a") .. "\x08" .. obj ..
    ICS_BA.context_tag(9, "\x19" .. string.char(prop or ICS_T.BACNET_PROP_OBJECT_NAME))
  return ICS_BA.frame(ICS_T.BACNET_BVLC_ORIGINAL_UNICAST, ICS_T.BACNET_NPDU .. apdu)
end

function ICS_BA.context_tag(num, content)
  return string.char(0x08 + num * 8, #content) .. content
end

function ICS_BA.decode_i_am(data)
  if #data < 4 + #ICS_T.BACNET_NPDU then
    return nil
  end
  local apdu_off = 4 + #ICS_T.BACNET_NPDU + 1
  if string.byte(data, apdu_off) ~= ICS_T.BACNET_APDU_UNCONFIRMED then
    return nil
  end
  if string.byte(data, apdu_off + 1) ~= ICS_T.BACNET_PDU_IAM then
    return nil
  end
  local off = apdu_off + 2
  local obj_hi, obj_lo = string.byte(data, off, off + 1)
  if obj_hi ~= 0xC4 then
    return nil
  end
  local instance = string.byte(data, off + 1) % 64 * 65536 + string.byte(data, off + 2) * 256 + string.byte(data, off + 3)
  local max_apdu = string.byte(data, off + 4)
  local vendor_hi, vendor_lo = string.byte(data, off + 6, off + 7)
  return { instance = instance, max_apdu = max_apdu, vendor_id = vendor_hi * 256 + vendor_lo }
end

function ICS_BA.decode_read_prop_ack(data)
  local apdu_off = 4 + #ICS_T.BACNET_NPDU + 1
  if #data < apdu_off + 2 then
    return nil
  end
  local fc = string.byte(data, apdu_off)
  if fc == ICS_T.BACNET_PDU_ERROR then
    return { error = true, class = string.byte(data, apdu_off + 4), code = string.byte(data, apdu_off + 6) }
  end
  if math.floor(fc / 16) ~= 3 then
    return nil
  end
  local off = apdu_off + 11
  local tag = string.byte(data, off)
  if tag == nil then
    return nil
  end
  local tagnum = math.floor(tag / 8) % 8
  if tagnum == 7 then
    local len = string.byte(data, off + 1)
    local val = string.sub(data, off + 2, off + 2 + len - 1)
    return { error = false, value = val, tag = "STRING" }
  elseif tagnum == 2 then
    local len = string.byte(data, off + 1)
    local v = 0
    for i = 1, len do
      v = v * 256 + string.byte(data, off + 1 + i)
    end
    return { error = false, value = tostring(v), tag = "UINT" }
  end
  return nil
end

ICS_D3 = {}

function ICS_D3.crc_dnp(data)
  local tbl = ICS_D3.crc_table()
  local lo, hi = 0, 0
  for i = 1, #data do
    local idx = (lo % 256) ~ string.byte(data, i)
    lo = tbl[idx + 1] ~ hi
    hi = math.floor(idx / 256)
  end
  return string.char(lo % 256, hi % 256)
end

function ICS_D3.crc_table()
  if ICS_D3._crc ~= nil then
    return ICS_D3._crc
  end
  local tbl = {}
  for i = 0, 255 do
    local v = i
    for _ = 1, 8 do
      if v % 2 == 1 then
        v = (math.floor(v / 2)) ~ 0xA001
      else
        v = math.floor(v / 2)
      end
    end
    tbl[i + 1] = v
  end
  ICS_D3._crc = tbl
  return tbl
end

function ICS_D3.frame(ctrl, dst, src, payload)
  payload = payload or ""
  local hdr = ICS_T.DNP3_START_BYTES .. string.char(5 + #payload) ..
    string.char(ctrl) .. string.char(dst % 256, math.floor(dst / 256) % 256) ..
    string.char(src % 256, math.floor(src / 256) % 256)
  local out = hdr .. ICS_D3.crc_dnp(string.sub(hdr, 3))
  if #payload > 0 then
    out = out .. payload .. ICS_D3.crc_dnp(payload)
  end
  return out
end

function ICS_D3.request_link_status(dst, src)
  return ICS_D3.frame(ICS_T.DNP3_CTRL_REQUEST_LINK_STATUS, dst, src, "")
end

function ICS_D3.decode_frame(data)
  if data == nil or #data < 10 then
    return nil, "short frame"
  end
  if string.sub(data, 1, 2) ~= ICS_T.DNP3_START_BYTES then
    return nil, "missing start bytes"
  end
  local len = string.byte(data, 3)
  if len < 5 or #data < len + 5 - 2 then
    return nil, "truncated frame"
  end
  local ctrl = string.byte(data, 4)
  local dst = string.byte(data, 5) + string.byte(data, 6) * 256
  local src = string.byte(data, 7) + string.byte(data, 8) * 256
  local fc = ctrl % 16
  return { len = len, ctrl = ctrl, primary = math.floor(ctrl / 64) % 2 == 1, dst = dst, src = src,
    func = fc, func_name = ICS_T.DNP3_CTRL_NAMES[fc] or tostring(fc) }
end

ICS_EI = {}

function ICS_EI.header(cmd, session, payload)
  local len = payload and #payload or 0
  return string.char(cmd % 256, 0) .. string.char(len % 256, math.floor(len / 256) % 256) ..
    string.char(session % 256, 0, 0, 0) .. "\0\0\0\0" .. "\0\0\0\0\0\0\0\0" .. "\0\0\0\0"
end

function ICS_EI.list_identity()
  return ICS_EI.header(ICS_T.EIP_CMD_LIST_IDENTITY, 0, "")
end

function ICS_EI.decode_response(data)
  if data == nil or #data < 24 then
    return nil, "short encapsulation header"
  end
  local cmd = string.byte(data, 1) + string.byte(data, 2) * 256
  local len = string.byte(data, 3) + string.byte(data, 4) * 256
  local status = string.byte(data, 9)
  local out = { cmd = cmd, cmd_name = ICS_T.EIP_CMD_NAMES[cmd] or tostring(cmd), len = len, status = status }
  if status == 0 and cmd == ICS_T.EIP_CMD_LIST_IDENTITY and len > 4 then
    local item_count = string.byte(data, 25) + string.byte(data, 26) * 256
    out.item_count = item_count
    if item_count > 0 and #data >= 32 then
      local item_len = string.byte(data, 27) + string.byte(data, 28) * 256
      local body = string.sub(data, 31, 29 + item_len - 1)
      out.item_len = item_len
      if #body >= 16 then
        out.version = string.byte(body, 1) + string.byte(body, 2) * 256
        out.sin_port = string.byte(body, 3) + string.byte(body, 4) * 256
        local ip = {}
        for i = 5, 8 do
          ip[#ip + 1] = tostring(string.byte(body, i))
        end
        out.ip = table.concat(ip, ".")
        out.vendor_id = string.byte(body, 11) + string.byte(body, 12) * 256
        out.device_type = string.byte(body, 13) + string.byte(body, 14) * 256
        out.product_code = string.byte(body, 15) + string.byte(body, 16) * 256
        if #body >= 22 then
          local rev = string.byte(body, 18) + string.byte(body, 19) * 256
          out.revision = string.format("%d.%02d", math.floor(rev / 100), rev % 100)
        end
        if #body >= 26 then
          local nlen = string.byte(body, 21) + string.byte(body, 22) * 256
          out.product_name = string.sub(body, 23, 23 + nlen - 1)
        end
      end
    end
  end
  return out
end

ICS_FN = {}

function ICS_FN.tcp_header(cmd, payload)
  return ICS_T.FINS_MAGIC .. string.char(math.floor(#payload / 16777216) % 256, math.floor(#payload / 65536) % 256,
    math.floor(#payload / 256) % 256, #payload % 256) ..
    (cmd or "\0\0") .. "\0\0" .. payload
end

function ICS_FN.node_search()
  return ICS_FN.tcp_header("\0\0", ICS_T.FINS_CMD_NODE_SEARCH)
end

function ICS_FN.fins_frame(dst_net, dst_node, dst_unit, mrc, src, data)
  return string.char(0x80, 0x00, 0x02, dst_net or 0, dst_node or 1, dst_unit or 0, 0, 0, 0, 1) ..
    string.char(mrc or 0, src or 0) .. (data or "")
end

function ICS_FN.memory_read_word(area, addr, count)
  return ICS_FN.fins_frame(0, 1, 0, ICS_T.FINS_MRC_MEM_READ, ICS_T.FINS_SRC_MEM_WORD,
    string.char(area, math.floor(addr / 16777216) % 256, math.floor(addr / 65536) % 256,
      math.floor(addr / 256) % 256, addr % 256, 0, 0, count % 256))
end

function ICS_FN.tcp_read_dm(addr, count)
  return ICS_FN.tcp_header("\0\0", ICS_FN.memory_read_word(ICS_T.FINS_AREA_DM_WORD, addr or 0, count or 2))
end

function ICS_FN.decode_response(data)
  if data == nil or #data < 30 then
    return nil, "short FINS/TCP frame"
  end
  if string.sub(data, 1, 4) ~= ICS_T.FINS_MAGIC then
    return nil, "missing FINS magic"
  end
  local out = { tcp_cmd = string.byte(data, 10) }
  local body = string.sub(data, 13)
  if #body >= 12 then
    out.icf = string.byte(body, 1)
    out.mrc = string.byte(body, 11)
    out.src = string.byte(body, 12)
    out.end_code = string.byte(body, 13, 14) and (string.byte(body, 13) * 256 + string.byte(body, 14)) or nil
    out.data = string.sub(body, 15)
    if out.mrc == ICS_T.FINS_MRC_MEM_READ and out.data ~= nil and #out.data >= 2 then
      out.words = {}
      for i = 1, math.min(math.floor(#out.data / 2), 16) do
        out.words[i] = string.byte(out.data, (i - 1) * 2 + 1) * 256 + string.byte(out.data, (i - 1) * 2 + 2)
      end
    end
  end
  return out
end

ICS_FX = {}

function ICS_FX.hello_frame()
  return ICS_T.FOX_HELLO
end

function ICS_FX.decode_hello(data)
  if data == nil or #data < 10 then
    return nil, "no fox answer"
  end
  local out = {}
  out.accepted = string.find(data, "hello", 1, true) ~= nil
  local ver = string.match(data, "fox%.version=(%d+)")
  out.version = ver and tonumber(ver) or nil
  local host = string.match(data, "host=([%w%-%.%_]+)")
  out.host = host
  local sys = string.match(data, "sys=([%w%-%.%_]+)")
  out.sys = sys
  local brand = string.match(data, "brand=([%w%-%.%_]+)")
  out.brand = brand
  local err = string.match(data, "err=(%w+)")
  out.err = err
  return out
end

ICS_HP = {}

function ICS_HP.header(msg_type, seq, body_len)
  return string.char(ICS_T.HART_VERSION, msg_type, 0) ..
    string.char(math.floor(seq / 256) % 256, seq % 256) ..
    string.char(math.floor((body_len + 8) / 256) % 256, (body_len + 8) % 256)
end

function ICS_HP.hart_frame(cmd, data)
  local body = string.char(ICS_T.HART_DELIM_MASTER_TO_SLAVE, 0, cmd, #data) .. (data or "")
  return body
end

function ICS_HP.read_unique_id(seq)
  return ICS_HP.header(ICS_T.HART_MSG_REQUEST, seq, 9) .. ICS_HP.hart_frame(ICS_T.HART_CMD_READ_UNIQUE_ID, "\0")
end

function ICS_HP.decode_response(data)
  if data == nil or #data < 18 then
    return nil, "short HART-IP frame"
  end
  local out = { version = string.byte(data, 1), msg_type = string.byte(data, 2),
    status = string.byte(data, 3) * 256 + string.byte(data, 4) }
  local seq = string.byte(data, 5) * 256 + string.byte(data, 6)
  out.seq = seq
  local delim = string.byte(data, 9)
  if delim == nil then
    return out
  end
  out.addr_type = math.floor(delim / 32) % 2
  out.cmd = string.byte(data, 11)
  out.rc = string.byte(data, 12)
  out.body_len = string.byte(data, 12)
  if out.cmd == ICS_T.HART_CMD_READ_UNIQUE_ID and #data >= 20 then
    out.expansion = string.byte(data, 13)
    out.device_type = string.byte(data, 14) * 256 + string.byte(data, 15)
    local uid = {}
    for i = 1, 5 do
      uid[#uid + 1] = string.format("%02x", string.byte(data, 15 + i) or 0)
    end
    out.unique_id = table.concat(uid, ":")
  end
  return out
end

ICS_104 = {}

function ICS_104.apci(ctrl1, ctrl2, ctrl3, ctrl4)
  return "\x68\x04" .. string.char(ctrl1, ctrl2, ctrl3, ctrl4)
end

function ICS_104.testfr_act()
  return ICS_104.apci(ICS_T.IEC104_TESTFR_ACT, 0, 0, 0)
end

function ICS_104.startdt_act()
  return ICS_104.apci(ICS_T.IEC104_STARTDT_ACT, 0, 0, 0)
end

function ICS_104.decode_apci(data)
  if data == nil or #data < 6 or string.byte(data, 1) ~= ICS_T.IEC104_START_BYTE then
    return nil, "missing start byte"
  end
  local len = string.byte(data, 2)
  local c1, c2, c3, c4 = string.byte(data, 3, 6)
  local ctrl1 = c1 % 4
  local out = { length = len, ctrl1 = ctrl1 }
  if ctrl1 == ICS_T.IEC104_U_FORMAT then
    out.format = "U"
    out.UTYPE = c1
    out.testfr_con = c1 == ICS_T.IEC104_TESTFR_CON
    out.startdt_con = c1 == ICS_T.IEC104_STARTDT_CON
    out.stopdt_con = c1 == ICS_T.IEC104_STOPDT_ACT
  elseif ctrl1 == 1 then
    out.format = "S"
  else
    out.format = "I"
    out.seq_tx = c1 + c2 * 256
    out.seq_rx = c3 + c4 * 256
  end
  return out
end

ICS_MS = {}

function ICS_MS.header(net, pc, module, req_len)
  return string.char(ICS_T.MELSEC_SUBHEADER_3E % 256, math.floor(ICS_T.MELSEC_SUBHEADER_3E / 256) % 256,
    net or 0, pc or 0, math.floor((module or 0xff40) / 256) % 256, (module or 0xff40) % 256) ..
    string.char(math.floor((req_len + 6) / 256) % 256, (req_len + 6) % 256) ..
    string.char(0, ICS_T.MELSEC_CPU_TIMER)
end

function ICS_MS.read_word(device, addr, points)
  local data = string.char(ICS_T.MELSEC_CMD_READ_WORD % 256, math.floor(ICS_T.MELSEC_CMD_READ_WORD / 256) % 256) ..
    "\0\0" ..
    string.char(device % 256, math.floor(device / 256) % 256) ..
    string.char(math.floor(addr / 16777216) % 256, math.floor(addr / 65536) % 256,
      math.floor(addr / 256) % 256, addr % 256) ..
    string.char(points % 256, math.floor(points / 256) % 256)
  return ICS_MS.header(0, 0, 0xff40, #data) .. data
end

function ICS_MS.read_cpu_type()
  local data = string.char(0x01, 0x01) .. "\0\0"
  return ICS_MS.header(0, 0, 0xff40, #data) .. data
end

function ICS_MS.decode_response(data)
  if data == nil or #data < 9 then
    return nil, "short MELSEC frame"
  end
  local sub = string.byte(data, 1) + string.byte(data, 2) * 256
  local out = { subheader = sub, is_3e = sub == ICS_T.MELSEC_SUBHEADER_3E }
  if not out.is_3e then
    return nil, "not a 3E frame"
  end
  local end_code = string.byte(data, 11) + string.byte(data, 12) * 256
  out.end_code = end_code
  out.ok = end_code == 0
  out.body = string.sub(data, 13)
  if out.ok and #out.body >= 2 then
    out.words = {}
    for i = 1, math.min(math.floor(#out.body / 2), 16) do
      out.words[i] = string.byte(out.body, (i - 1) * 2 + 1) * 256 + string.byte(out.body, (i - 1) * 2 + 2)
    end
  end
  return out
end

ICS_PN = {}

function ICS_PN.dcp_identify(xid)
  xid = xid or 1
  local block = string.char(ICS_T.PROFINET_DCP_SERVICE_ID, ICS_T.PROFINET_DCP_SUB_IP_PARAM, 0, 0)
  return string.char(0xFE, 0xFE) .. string.char(math.floor(xid / 16777216) % 256, math.floor(xid / 65536) % 256,
    math.floor(xid / 256) % 256, xid % 256) .. "\0\0" .. block
end

function ICS_PN.decode_identify(data)
  if data == nil or #data < 10 then
    return nil, "short DCP frame"
  end
  local service_id = string.byte(data, 9)
  if service_id ~= ICS_T.PROFINET_DCP_SERVICE_ID then
    return nil, "not an identify response"
  end
  local out = { service_id = service_id }
  local off = 11
  out.blocks = {}
  while off + 4 <= #data and #out.blocks < 16 do
    local opt = string.byte(data, off)
    local sub = string.byte(data, off + 1)
    local len = string.byte(data, off + 2) * 256 + string.byte(data, off + 3)
    if len < 2 or off + 4 + len - 2 > #data then
      break
    end
    local val = string.sub(data, off + 4, off + 4 + len - 1)
    if opt == ICS_T.PROFINET_DCP_OPTION_NAME and sub == ICS_T.PROFINET_DCP_SUB_NAME_DEV then
      out.device_name = string.sub(val, 3)
    elseif opt == ICS_T.PROFINET_DCP_OPTION_IP and sub == ICS_T.PROFINET_DCP_SUB_IP_PARAM then
      local ip = {}
      for i = 3, 6 do
        ip[#ip + 1] = tostring(string.byte(val, i) or 0)
      end
      out.ip = table.concat(ip, ".")
    end
    out.blocks[#out.blocks + 1] = { option = opt, suboption = sub, len = len }
    off = off + 2 + len
  end
  return out
end

ICS_S7 = {}

function ICS_S7.tpkt(payload)
  return "\x03\x00" .. string.char(math.floor((#payload + 4) / 256) % 256, (#payload + 4) % 256) .. payload
end

function ICS_S7.cotp_cr(dst_ref, src_ref)
  return ICS_S7.tpkt(string.char(3, 0, 0, math.floor((dst_ref or 1) / 256) % 256, (dst_ref or 1) % 256,
    math.floor((src_ref or 16) / 256) % 256, (src_ref or 16) % 256, 0, 0xC0, 1, 9, 8, 1, 0xC1, 2, 6, 0, 1,
    0xC2, 2, 2, 1))
end

function ICS_S7.setup_comm(pdu_ref)
  return ICS_S7.tpkt("\x02\xf0\x80" ..
    "\x03\x00\x00" ..
    string.char(math.floor(pdu_ref / 256) % 256, pdu_ref % 256) ..
    "\x00\x08\x00\x00\x00\x00" ..
    "\xF0\x00\x00\x01\x00\x01\x01\xE0")
end

function ICS_S7.read_szl(pdu_ref, szl_id, index)
  local param = "\x04\x01\x01\x12\x08\x12\x84" ..
    string.char(math.floor(szl_id / 256) % 256, szl_id % 256, index or 1) .. "\x00\x0a\x00\x00\x00\x00"
  local payload = "\x02\xf0\x80" ..
    "\x03\x00\x00" ..
    string.char(math.floor(pdu_ref / 256) % 256, pdu_ref % 256) ..
    string.char(0, #param, 0, 0, 0, 0) .. param
  return ICS_S7.tpkt(payload)
end

function ICS_S7.decode_response(data)
  if data == nil or #data < 8 then
    return nil, "short S7 frame"
  end
  if string.byte(data, 1) ~= 0x03 or string.byte(data, 2) ~= 0x00 then
    return nil, "missing TPKT"
  end
  local off = 8
  local rosctr = string.byte(data, off)
  if rosctr == nil then
    return nil, "truncated S7 header"
  end
  local out = { rosctr = rosctr }
  if rosctr == ICS_T.S7_ROSCTR_ACK then
    local plen_hi = string.byte(data, off + 5)
    local plen_lo = string.byte(data, off + 6)
    if plen_hi ~= nil and plen_lo ~= nil then
      local plen = plen_hi * 256 + plen_lo
      out.param_len = plen
      local pfunc = string.byte(data, off + 11)
      out.pfunc = pfunc
      out.error_class = string.byte(data, off + 9)
      if pfunc == ICS_T.S7_FUNC_SETUP then
        local pdu_hi = string.byte(data, off + 11 + plen - 2)
        local pdu_lo = string.byte(data, off + 11 + plen - 1)
        out.negotiated_pdu = pdu_hi * 256 + pdu_lo
        out.setup_ok = true
      end
      out.data_off = off + 11 + plen
      local dlen_hi = string.byte(data, off + 7)
      local dlen_lo = string.byte(data, off + 8)
      out.data_len = dlen_hi * 256 + dlen_lo
      if out.data_len ~= nil and out.data_len > 0 and #data >= out.data_off + 4 then
        out.item_result = string.byte(data, out.data_off)
        out.payload = string.sub(data, out.data_off + 4)
      end
    end
  elseif rosctr == ICS_T.S7_ROSCTR_JOB then
    out.is_job = true
  end
  return out
end

ICS_A = {}

function ICS_A.selftest()
  local failures = {}
  local function expect_eq(got, want, what)
    if got ~= want then
      failures[#failures + 1] = what .. ": got " .. tostring(got) .. " want " .. tostring(want)
    end
  end
  local mb = ICS_MB.mbap(7, 1, "\x01\x00\x00\x00\x08")
  expect_eq(#mb, 12, "mbap length")
  local pm = ICS_MB.parse_mbap(mb)
  expect_eq(pm and pm.tid, 7, "mbap tid roundtrip")
  expect_eq(pm and pm.unit, 1, "mbap unit roundtrip")
  expect_eq(pm and pm.pdu, "\x01\x00\x00\x00\x08", "mbap pdu roundtrip")
  local did = ICS_MB.decode_device_id("\x2b\x0e\x01\x81\x00\x00\x03\x00\x06Vendor\x01\x04M221\x02\x031.5")
  expect_eq(did and did.objects[1] and did.objects[1].value, "Vendor", "device id vendor")
  expect_eq(did and did.objects[3] and did.objects[3].value, "1.5", "device id revision")
  local exc = ICS_MB.decode_exception("\x85\x01")
  expect_eq(exc and exc.name, "ILLEGAL_FUNCTION", "modbus exception decode")
  local coils = ICS_MB.decode_coils("\x01\x01\xa5", 8)
  expect_eq(coils and coils[1], true, "coil bit 0")
  expect_eq(coils and coils[2], false, "coil bit 1")
  expect_eq(coils and coils[3], true, "coil bit 2")
  local wf = ICS_BA.whois_frame()
  expect_eq(string.sub(wf, 1, 2), "\x81\x0b", "bacnet bvlc header")
  expect_eq(wf and string.sub(wf, 5, 6), "\x01\x20", "bacnet npdu version")
  local rp = ICS_BA.read_property_frame(56832, 77)
  expect_eq(rp and string.byte(rp, 2), 0x0a, "bacnet readprop unicast func")
  local dnp = ICS_D3.request_link_status(3, 4)
  expect_eq(string.sub(dnp, 1, 2), "\x05\x64", "dnp3 start bytes")
  local dd = ICS_D3.decode_frame(dnp)
  expect_eq(dd and dd.dst, 3, "dnp3 dst roundtrip")
  expect_eq(dd and dd.func, 9, "dnp3 func link-status request")
  local eip = ICS_EI.list_identity()
  expect_eq(eip and string.byte(eip, 1), 0x63, "eip list-identity cmd")
  local fins = ICS_FN.tcp_read_dm(0, 2)
  expect_eq(string.sub(fins, 1, 4), "FINS", "fins magic")
  local fox = ICS_FX.decode_hello("fox hello ack {\nfox.version=35\nhost=niagara\nsys=tridium\n}\n\0")
  expect_eq(fox and fox.accepted, true, "fox hello accepted")
  expect_eq(fox and fox.host, "niagara", "fox host parse")
  local hart = ICS_HP.read_unique_id(1)
  expect_eq(hart and string.byte(hart, 2), ICS_T.HART_MSG_REQUEST, "hart msg type")
  expect_eq(#hart, 12, "hart read-unique-id length")
  local t104 = ICS_104.testfr_act()
  expect_eq(t104 and string.byte(t104, 3), 0x43, "iec104 testfr act")
  local d104 = ICS_104.decode_apci("\x68\x04\x83\x00\x00\x00")
  expect_eq(d104 and d104.testfr_con, true, "iec104 testfr con decode")
  local mel = ICS_MS.read_word(ICS_T.MELSEC_DEVICE_D, 0, 2)
  expect_eq(mel and string.byte(mel, 1), 0x00, "melsec subheader lo")
  local mresp = ICS_MS.decode_response("\x00\x50\x00\x00\xff\x40\x00\x08\x00\x10\x00\x00\x00\x12\x34\x56\x78")
  expect_eq(mresp and mresp.ok, true, "melsec response ok")
  expect_eq(mresp and mresp.words[1], 18, "melsec word decode")
  expect_eq(mresp and mresp.words[2], 13398, "melsec word decode 2")
  local s7 = ICS_S7.read_szl(1, 0x0111, 1)
  expect_eq(string.sub(s7, 1, 2), "\x03\x00", "s7 tpkt magic")
  local tbl = ICS_D3.crc_table()
  expect_eq(tbl and tbl[1], 0, "dnp3 crc table seed")
  if #failures > 0 then
    return false, table.concat(failures, "; ")
  end
  return true, "ICS/SCADA protocol codecs verified (11 protocol stacks)"
end

ICS_TP = {}

local budget_of = function(args)
  return {
    timeout = args.timeout or 8,
    maxrequests = args.maxrequests or 48,
    recv_window = args.recv_window or 3,
  }
end

local new_session = function(host, port, args, proto)
  return {
    host = host,
    port = port,
    proto = proto or "tcp",
    budget = budget_of(args),
    sock = nil,
    connected = false,
    closed = false,
    requests = 0,
    audit = {},
  }
end

ICS_TP.session_new = new_session
ICS_TP.budget_of = budget_of

function ICS_TP.audit(sess, event, detail)
  sess.audit[#sess.audit + 1] = tostring(event) .. ":" .. tostring(detail)
end

function ICS_TP.connect(sess)
  if sess.connected then
    return 1
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  local sock = nmap.new_socket()
  sock:set_timeout(math.floor((sess.budget.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, sess.proto)
  if not ok then
    sock:close()
    return nil, string.upper(sess.proto) .. " connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  local port_value = sess.port
  if type(port_value) == "table" then
    port_value = port_value.number or 0
  end
  ICS_TP.audit(sess, "connect", tostring(port_value) .. "/" .. tostring(sess.proto))
  return 1
end

function ICS_TP.close(sess)
  if sess and sess.sock and not sess.closed then
    pcall(sess.sock.close, sess.sock)
    sess.closed = true
    sess.connected = false
  end
end

function ICS_TP.send(sess, data)
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local ok, err = sess.sock:send(data)
  if not ok then
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  ICS_TP.audit(sess, "send", #data .. "B")
  return 1
end

function ICS_TP.recv(sess, wait)
  sess.sock:set_timeout(math.floor((wait or sess.budget.timeout or 8) * 1000))
  local ok, dat = sess.sock:receive(65535)
  if ok then
    ICS_TP.audit(sess, "recv", #dat .. "B")
    return dat
  end
  if dat == "TIMEOUT" or dat == "EOF" then
    return nil, "timeout"
  end
  return nil, "receive failed: " .. tostring(dat or "unknown")
end

function ICS_TP.exchange(sess, request)
  local ok, err = ICS_TP.connect(sess)
  if not ok then
    return nil, err
  end
  local sok, serr = ICS_TP.send(sess, request)
  if not sok then
    return nil, serr
  end
  return ICS_TP.recv(sess)
end

local function wrap_tcp(host, port, args, fn)
  local sess = new_session(host, port, args, "tcp")
  local out, err = fn(sess)
  ICS_TP.close(sess)
  return out, err
end

local function wrap_udp(host, port, args, fn)
  local sess = new_session(host, port, args, "udp")
  local out, err = fn(sess)
  ICS_TP.close(sess)
  return out, err
end

ICS_TP.wrap_tcp = wrap_tcp
ICS_TP.wrap_udp = wrap_udp

ICS_TP.modbus_read = function(host, port, args, unit, tid, pdu_builder)
  return wrap_tcp(host, port or ICS_T.MODBUS_PORT, args, function(sess)
    ICS_TP.xid = ICS_TP.xid or (tid or 1)
    local raw, err = ICS_TP.exchange(sess, pdu_builder(tid))
    if raw == nil then
      return nil, err
    end
    local frame, perr = ICS_MB.parse_mbap(raw)
    if frame == nil then
      return nil, perr or "MBAP parse failed"
    end
    return frame
  end)
end

ICS_TP.modbus_read_coils = function(host, port, args, unit, addr, qty)
  local tid = (addr or 0) * 31 + 7
  return ICS_TP.modbus_read(host, port, args, unit, tid, function(t)
    return ICS_MB.read_coils(t, unit, addr or 0, qty or 8)
  end)
end

ICS_TP.modbus_read_holding = function(host, port, args, unit, addr, qty)
  local tid = (addr or 0) * 31 + 11
  return ICS_TP.modbus_read(host, port, args, unit, tid, function(t)
    return ICS_MB.read_holding(t, unit, addr or 0, qty or 4)
  end)
end

ICS_TP.modbus_write_coil = function(host, port, args, unit, addr, value)
  local tid = 23 + (addr % 100)
  return ICS_TP.modbus_read(host, port, args, unit, tid, function(t)
    return ICS_MB.write_coil(t, unit, addr, value)
  end)
end

ICS_TP.modbus_device_id = function(host, port, args, unit)
  return ICS_TP.modbus_read(host, port, args, unit, 41, function(t)
    return ICS_MB.read_device_id(t, unit, 1, 0)
  end)
end

ICS_TP.bacnet_whois = function(host, port, args, low, high)
  return wrap_udp(host, port or ICS_T.BACNET_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_BA.whois_frame(low, high))
    if raw == nil then
      return nil, err
    end
    return raw
  end)
end

ICS_TP.bacnet_read_property = function(host, port, args, instance, prop)
  return wrap_udp(host, port or ICS_T.BACNET_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_BA.read_property_frame(instance or 56832, prop))
    if raw == nil then
      return nil, err
    end
    return raw
  end)
end

ICS_TP.dnp3_link_status = function(host, port, args, dst, src)
  return wrap_tcp(host, port or ICS_T.DNP3_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_D3.request_link_status(dst or 3, src or 4))
    if raw == nil then
      return nil, err
    end
    return ICS_D3.decode_frame(raw)
  end)
end

ICS_TP.eip_list_identity = function(host, port, args)
  return wrap_tcp(host, port or ICS_T.EIP_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_EI.list_identity())
    if raw == nil then
      return nil, err
    end
    return ICS_EI.decode_response(raw)
  end)
end

ICS_TP.fins_read_dm = function(host, port, args, addr, count)
  return wrap_tcp(host, port or ICS_T.FINS_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_FN.tcp_read_dm(addr, count))
    if raw == nil then
      return nil, err
    end
    return ICS_FN.decode_response(raw)
  end)
end

ICS_TP.fins_node_search = function(host, port, args)
  return wrap_tcp(host, port or ICS_T.FINS_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_FN.node_search())
    if raw == nil then
      return nil, err
    end
    return { answered = true, len = #raw, body = raw }
  end)
end

ICS_TP.fox_hello = function(host, port, args)
  return wrap_tcp(host, port or ICS_T.FOX_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_FX.hello_frame())
    if raw == nil then
      return nil, err
    end
    return ICS_FX.decode_hello(raw)
  end)
end

ICS_TP.hart_unique_id = function(host, port, args)
  return wrap_udp(host, port or ICS_T.HART_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_HP.read_unique_id(1))
    if raw == nil then
      return nil, err
    end
    return ICS_HP.decode_response(raw)
  end)
end

ICS_TP.iec104_handshake = function(host, port, args)
  return wrap_tcp(host, port or ICS_T.IEC104_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_104.testfr_act())
    if raw == nil then
      return nil, err
    end
    local testfr = ICS_104.decode_apci(raw)
    if testfr == nil then
      return nil, "TESTFR answer unparseable"
    end
    local raw2, err2 = ICS_TP.exchange(sess, ICS_104.startdt_act())
    if raw2 == nil then
      return testfr, nil
    end
    testfr.startdt = ICS_104.decode_apci(raw2)
    return testfr
  end)
end

ICS_TP.melsec_read = function(host, port, args, device, addr, points)
  return wrap_tcp(host, port or ICS_T.MELSEC_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_MS.read_word(device or ICS_T.MELSEC_DEVICE_D, addr or 0, points or 2))
    if raw == nil then
      return nil, err
    end
    return ICS_MS.decode_response(raw)
  end)
end

ICS_TP.profinet_identify = function(host, port, args)
  return wrap_udp(host, port or ICS_T.PROFINET_PORT, args, function(sess)
    local raw, err = ICS_TP.exchange(sess, ICS_PN.dcp_identify(1))
    if raw == nil then
      return nil, err
    end
    return ICS_PN.decode_identify(raw)
  end)
end

ICS_TP.s7_setup = function(host, port, args)
  return wrap_tcp(host, port or ICS_T.S7_PORT, args, function(sess)
    ICS_TP.exchange(sess, ICS_S7.cotp_cr())
    local raw2, err2 = ICS_TP.exchange(sess, ICS_S7.setup_comm(1))
    if raw2 == nil then
      return nil, "S7 setup failed: " .. tostring(err2)
    end
    return ICS_S7.decode_response(raw2)
  end)
end

ICS_TP.s7_read_szl = function(host, port, args, szl_id, index)
  return wrap_tcp(host, port or ICS_T.S7_PORT, args, function(sess)
    ICS_TP.exchange(sess, ICS_S7.cotp_cr())
    ICS_TP.exchange(sess, ICS_S7.setup_comm(1))
    local raw3, err3 = ICS_TP.exchange(sess, ICS_S7.read_szl(2, szl_id, index))
    if raw3 == nil then
      return nil, "SZL read failed: " .. tostring(err3)
    end
    return ICS_S7.decode_response(raw3)
  end)
end

ICS_TP.modbus_unit_scan = function(host, port, args, units)
  local results = {}
  for _, unit in ipairs(units or {}) do
    local frame, err = ICS_TP.modbus_device_id(host, port, args, unit)
    results[#results + 1] = { unit = unit, answered = frame ~= nil,
      detail = frame ~= nil and ("tid " .. tostring(frame.tid)) or tostring(err) }
  end
  return results
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

local function ics_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - ICS audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The ICS/SCADA audit did not complete against this endpoint", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local ics_summary = function(result)
  if result == nil then
    return "no answer"
  end
  return "answered"
end

local function run_audit(host, port, args)
  local sections = {}
  local frame = ICS_TP.modbus_read_holding(host, port, args, 1, 0, 4)
  if frame == nil then
    return ics_incomplete("read holding request failed", sections, "read-holding", "no MBAP answer")
  end
  local exc = ICS_MB.decode_exception(frame.pdu)
  local regs = exc == nil and ICS_MB.decode_registers(frame.pdu, 4) or nil
  local rows = {}
  if regs ~= nil then
    for i, v in ipairs(regs) do
      rows[#rows + 1] = { register = i - 1, value = v }
    end
  end
  sections[#sections + 1] = { key = "Holding Registers (FC3 addr 0-3)", value = #rows > 0 and rows
    or { answer = exc and exc.name or "unparseable" } }

  local remediation = {}
  local status_text
  if regs ~= nil then
    status_text = "VULNERABLE - holding registers readable without authentication (" .. #regs .. " registers)"
    add_finding("CRITICAL", "Anonymous Modbus setpoint reads", {
      subject = "read-holding",
      evidence = "FC3 answered " .. tostring(#regs) .. " register values (first: " .. tostring(regs[1]) .. ") to an unauthenticated client",
      confidence = "high",
      cvss = 8.2,
    })
    remediation["1. Segment"] = "Restrict port 502 to the control network and deploy read-only proxies for historians."
  elseif exc ~= nil then
    status_text = "SECURE - register reads refused (" .. exc.name .. ")"
    add_finding("INFO", "Setpoint reads rejected", {
      subject = "read-holding",
      evidence = "FC3 answered exception " .. tostring(exc.code) .. " (" .. exc.name .. ")",
      confidence = "high",
    })
    remediation["1. Maintain"] = "Re-verify the policy after gateway upgrades."
  else
    status_text = "INFORMATIONAL - register answer unparseable"
    add_finding("INFO", "Unexpected register answer", {
      subject = "read-holding",
      evidence = "FC3 answered without a decodable body",
      confidence = "low",
    })
    remediation["1. Re-run"] = "Re-run the probe."
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
