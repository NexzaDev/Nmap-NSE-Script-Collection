---------------------------------------------------------------------------
-- netlogon.lua - MS-NRPC (Netlogon) exposure assessment engine
--
-- This library implements the client half of the protocol stack that a
-- Netlogon secure channel probe needs, from the transport up:
--
--   SMB2 (MS-SMB2)                        negotiate / anonymous session /
--                                         IPC$ tree connect / named pipe I/O
--   DCE/RPC connection oriented PDUs      bind / request / response / fault
--     (MS-RPCE)
--   NDR transfer syntax (MS-RPCE 2.2.6)   referents, unique strings, fixed and
--                                         conformant arrays
--   MS-NRPC (Netlogon)                    NetrServerReqChallenge,
--                                         NetrServerAuthenticate3,
--                                         NetrServerGetInfo
--
-- Why a dedicated library: several scripts in this collection need to reach
-- the Netlogon pipe (CVE-2020-1472 assessment, machine account password policy
-- inventory, secure channel hardening checks), and none of Nmap's bundled
-- libraries expose Netlogon. The stock smb library only covers SMB1, which
-- modern domain controllers frequently disable, so the SMB2 client below is
-- implemented from the specification instead.
--
-- Design rules followed throughout:
--
--   * Every encoder has a matching decoder in the same file, and both are
--     exercised by the integration scenarios in tools/tests/.
--   * Numbers wider than 31 bits are handled with arithmetic, never with
--     hexadecimal literals or bitwise operators on values above 0x7FFFFFFF:
--     a Lua VM with 32-bit integers (and this repository's test VM) folds such
--     literals into negative values. Use u32() to normalise and hex32() to
--     print. Small masks use bits.test()/bits.set() so a 32-bit or 64-bit
--     integer width gives identical results.
--   * The socket contract is Nmap's: send() returns true|false,err,
--     receive_bytes() returns everything buffered (more or fewer bytes than
--     requested), and timeouts surface as false,"TIMEOUT". Reads therefore
--     accumulate into an explicit buffer and extract whole transport frames
--     instead of assuming one read equals one message.
--   * Nothing here changes server state. The highest opnum this library will
--     marshal is NetrServerAuthenticate3; the password writing opnum
--     (NetrServerPasswordSet2) is deliberately absent, so a script cannot
--     reach it by mistake.
--
-- References:
--   [MS-SMB2]  2.2.1 SMB2 header, 2.2.3 NEGOTIATE, 2.2.5 SESSION_SETUP,
--              2.2.9 TREE_CONNECT, 2.2.13 CREATE, 2.2.19 WRITE, 2.2.21 READ
--   [MS-SPNG]  2.2.1 NEGOTIATE_MESSAGE, 2.2.2 CHALLENGE_MESSAGE,
--              2.2.3 AUTHENTICATE_MESSAGE (NTLM)
--   [MS-RPCE]  2.2.2.x connection oriented PDU types, 2.2.6.1 referents,
--              12.6.2 UUID encodings, 14.3 string/array layout rules
--   [MS-NRPC]  2.2.1.1.x structures, 2.2.1.3.13 secure channel types,
--              3.1.4.2 negotiable options, 3.5.4.4.2 NetrServerReqChallenge,
--              3.5.4.4.4 NetrServerAuthenticate3, 3.5.4.5.2 NetrServerGetInfo
--   CVE-2020-1472 (ZeroLogon) - Secura/SecureAuth analysis and Microsoft's
--              August 2020 and February 2021 remediation guidance
--
-- @author  collection maintainers
-- @license Same as Nmap -- See https://nmap.org/book/man-legal.html
---------------------------------------------------------------------------

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"
local os = require "os"

local M = {}

M.VERSION = "1.0.0"
M.SCRIPT_BANNER = "netlogon.lua"

-- ---------------------------------------------------------------------------
-- 1. Numeric and byte utilities
-- ---------------------------------------------------------------------------

-- Normalise a value into the unsigned 32-bit domain as a Lua number.
-- Accepts the negative result a 32-bit integer VM produces for a hexadecimal
-- literal above 0x7FFFFFFF, and is the identity on 64-bit integer builds.
local function u32(value)
  if value < 0 then
    return value + 4294967296.0
  end
  return value % 4294967296.0
end

M.u32 = u32

-- Eight hexadecimal digits of an unsigned 32-bit value, without ever handing a
-- value above 0x7FFFFFFF to string.format.
local function hex32(value)
  value = u32(value)
  return string.format("%04X%04X", math.floor(value / 65536.0), value % 65536.0)
end

M.hex32 = hex32

-- Lower case hexadecimal of a byte string.
local function hex(data, separator)
  local parts = {}
  for i = 1, #data do
    parts[i] = string.format("%02x", string.byte(data, i))
  end
  return table.concat(parts, separator or "")
end

M.hex = hex

-- Annotated hex dump, used by the transcript section of the reports.
function M.hexdump(data, width)
  width = width or 16
  local lines = {}
  for offset = 0, #data - 1, width do
    local chunk = string.sub(data, offset + 1, offset + width)
    local bytes, ascii = {}, {}
    for i = 1, width do
      local b = string.byte(chunk, i)
      if b then
        bytes[#bytes + 1] = string.format("%02x", b)
        ascii[#ascii + 1] = (b >= 32 and b <= 126) and string.char(b) or "."
      else
        bytes[#bytes + 1] = "  "
        ascii[#ascii + 1] = " "
      end
    end
    lines[#lines + 1] = string.format("%04x  %s  %s", offset, table.concat(bytes, " "), table.concat(ascii))
  end
  return table.concat(lines, "\n")
end

-- Bit helpers that never depend on the width of Lua's integer type. Flags are
-- powers of two, so they are always representable, and division plus modulo
-- performs the test without a bitwise operator.
local bits = {}

function bits.test(value, flag)
  if not flag or flag <= 0 then
    return false
  end
  return math.floor(u32(value) / flag) % 2 == 1
end

function bits.set(value, flag)
  value = u32(value)
  if bits.test(value, flag) then
    return value
  end
  return u32(value + flag)
end

function bits.clear(value, flag)
  value = u32(value)
  if not bits.test(value, flag) then
    return value
  end
  return u32(value - flag)
end

-- Names of the flags present in a value, given a catalogue of
-- { flag = <power of two>, name = "...", meaning = "..." } records.
function bits.describe(value, catalogue)
  local names = {}
  for _, entry in ipairs(catalogue) do
    if bits.test(value, entry.flag) then
      names[#names + 1] = entry.name
    end
  end
  return names
end

M.bits = bits

-- Little endian readers. All of them return Lua numbers, so a 32-bit read is a
-- float between 0 and 4294967295 rather than a negative integer.
local function rd_u8(data, pos)
  local b = string.byte(data, pos)
  if not b then
    return nil, string.format("truncated: byte at offset %d missing", pos - 1)
  end
  return b
end

local function rd_u16le(data, pos)
  local a, b = string.byte(data, pos, pos + 1)
  if not a or not b then
    return nil, string.format("truncated: 16-bit field at offset %d", pos - 1)
  end
  return a + b * 256
end

local function rd_u32le(data, pos)
  local a, b, c, d = string.byte(data, pos, pos + 3)
  if not a or not b or not c or not d then
    return nil, string.format("truncated: 32-bit field at offset %d", pos - 1)
  end
  return a + b * 256 + c * 65536 + d * 16777216.0
end

local function rd_u64le(data, pos)
  local low, err = rd_u32le(data, pos)
  if not low then
    return nil, err
  end
  local high, err2 = rd_u32le(data, pos + 4)
  if not high then
    return nil, err2
  end
  return high * 4294967296.0 + low
end

local function wr_u16le(value)
  value = value % 65536
  return string.char(math.floor(value % 256), math.floor(value / 256))
end

local function wr_u32le(value)
  value = u32(value)
  local b1 = math.floor(value % 256)
  local b2 = math.floor((value / 256) % 256)
  local b3 = math.floor((value / 65536) % 256)
  local b4 = math.floor((value / 16777216) % 256)
  return string.char(b1, b2, b3, b4)
end

local function wr_u64le(value)
  local low = value % 4294967296.0
  local high = math.floor(value / 4294967296.0)
  return wr_u32le(low) .. wr_u32le(high)
end

M.num = {
  rd_u8 = rd_u8,
  rd_u16le = rd_u16le,
  rd_u32le = rd_u32le,
  rd_u64le = rd_u64le,
  wr_u16le = wr_u16le,
  wr_u32le = wr_u32le,
  wr_u64le = wr_u64le,
}

-- Windows FILETIME (100 ns ticks since 1601-01-01) to Unix seconds. The
-- conversion stays in floating point because the tick count exceeds 2^53 only
-- for dates far outside the protocol's useful range.
local FILETIME_EPOCH_DELTA = 11644473600.0

local function filetime_to_unix(ticks)
  if ticks == nil or ticks == 0 then
    return nil
  end
  return ticks / 10000000.0 - FILETIME_EPOCH_DELTA
end

M.filetime_to_unix = filetime_to_unix

-- UTF-16LE text to ASCII, with non-ASCII and unpaired surrogates replaced so a
-- malformed server string cannot break a report.
local function utf16le_to_string(data)
  local out = {}
  for i = 1, #data - 1, 2 do
    local code = string.byte(data, i) + string.byte(data, i + 1) * 256
    if code == 0 then
      break
    elseif code < 128 then
      out[#out + 1] = string.char(code)
    else
      out[#out + 1] = "?"
    end
  end
  return table.concat(out)
end

local function string_to_utf16le(text)
  local out = {}
  for i = 1, #text do
    out[#out + 1] = string.char(string.byte(text, i), 0)
  end
  return table.concat(out)
end

M.utf16le_to_string = utf16le_to_string
M.string_to_utf16le = string_to_utf16le

-- Transports are named so a report can say how a frame travelled.
local TRANSPORT = { TCP_445 = "tcp/445 direct host", PIPE = "named pipe" }

-- ---------------------------------------------------------------------------
-- 2. SMB2 status codes
-- ---------------------------------------------------------------------------

local SMB2_STATUS = {}

-- Entries are { code = <unsigned>, name = "...", meaning = "..." }. The table
-- is ordered by relevance to the secure channel probe rather than by number.
local SMB2_STATUS_LIST = {
  { code = u32(0x00000000), name = "STATUS_SUCCESS", meaning = "the request completed" },
  { code = u32(0x00000103), name = "STATUS_PENDING", meaning = "the server accepted the request for asynchronous completion" },
  { code = u32(0x80000005), name = "STATUS_BUFFER_OVERFLOW", meaning = "the response carries fewer bytes than requested; read again with the remaining length" },
  { code = u32(0x80000006), name = "STATUS_NO_MORE_FILES", meaning = "the pipe closed after the last message" },
  { code = u32(0xC0000002), name = "STATUS_NOT_IMPLEMENTED", meaning = "the operation is not implemented for this object" },
  { code = u32(0xC0000008), name = "STATUS_INVALID_HANDLE", meaning = "the file id is not open (the pipe was closed under us)" },
  { code = u32(0xC000000D), name = "STATUS_INVALID_PARAMETER", meaning = "a request field was rejected; the server is not vulnerable to this particular shape" },
  { code = u32(0xC0000011), name = "STATUS_END_OF_FILE", meaning = "no more data on the pipe" },
  { code = u32(0xC0000016), name = "STATUS_MORE_PROCESSING_REQUIRED", meaning = "another SESSION_SETUP round is needed" },
  { code = u32(0xC0000022), name = "STATUS_ACCESS_DENIED", meaning = "the server refused access (null session disabled, pipe ACL, or an enforced Netlogon channel)" },
  { code = u32(0xC0000023), name = "STATUS_BUFFER_TOO_SMALL", meaning = "the requested read length is below the message size" },
  { code = u32(0xC0000034), name = "STATUS_OBJECT_NAME_NOT_FOUND", meaning = "the named pipe or share does not exist" },
  { code = u32(0xC00000AC), name = "STATUS_PIPE_NOT_AVAILABLE", meaning = "Netlogon is not listening on the pipe (the service is stopped)" },
  { code = u32(0xC00000BB), name = "STATUS_NOT_SUPPORTED", meaning = "the dialect or command is not supported" },
  { code = u32(0xC00000CC), name = "STATUS_BAD_NETWORK_NAME", meaning = "the share name is wrong or hidden from this session" },
  { code = u32(0xC00000C9), name = "STATUS_NETWORK_NAME_DELETED", meaning = "the share was removed during the session" },
  { code = u32(0xC000006D), name = "STATUS_LOGON_FAILURE", meaning = "the credentials offered were rejected" },
  { code = u32(0xC0000120), name = "STATUS_CANCELLED", meaning = "the operation was cancelled" },
  { code = u32(0xC0000128), name = "STATUS_FILE_CLOSED", meaning = "the file id is closed" },
  { code = u32(0xC0000203), name = "STATUS_USER_SESSION_DELETED", meaning = "the session id is no longer valid" },
  { code = u32(0xC0000205), name = "STATUS_INSUFF_SERVER_RESOURCES", meaning = "the server is out of resources; back off and retry" },
  { code = u32(0xC000035C), name = "STATUS_NETWORK_SESSION_EXPIRED", meaning = "the SMB session expired" },
}

for _, entry in ipairs(SMB2_STATUS_LIST) do
  SMB2_STATUS[entry.name] = entry.code
end

SMB2_STATUS.BY_CODE = SMB2_STATUS_LIST

-- Human readable name plus meaning for a status code, never nil.
function M.smb2_status_text(code)
  if code == nil then
    return "no status recorded"
  end
  code = u32(code)
  for _, entry in ipairs(SMB2_STATUS_LIST) do
    if entry.code == code then
      return string.format("%s (0x%s): %s", entry.name, hex32(code), entry.meaning)
    end
  end
  return string.format("unlisted status 0x%s", hex32(code))
end

function M.smb2_status_name(code)
  if code == nil then
    return nil
  end
  code = u32(code)
  for _, entry in ipairs(SMB2_STATUS_LIST) do
    if entry.code == code then
      return entry.name
    end
  end
  return "0x" .. hex32(code)
end

-- ---------------------------------------------------------------------------
-- 3. SMB2 wire format
-- ---------------------------------------------------------------------------

local smb2 = {}

smb2.PROTOCOL_ID = string.char(0xFE, 0x53, 0x4D, 0x42)
smb2.HEADER_SIZE = 64
smb2.STATUS = SMB2_STATUS

smb2.CMD = {
  NEGOTIATE = 0,
  SESSION_SETUP = 1,
  LOGOFF = 2,
  TREE_CONNECT = 3,
  TREE_DISCONNECT = 4,
  CREATE = 5,
  CLOSE = 6,
  FLUSH = 7,
  READ = 8,
  WRITE = 9,
  LOCK = 10,
  IOCTL = 11,
  CANCEL = 12,
  ECHO = 13,
  QUERY_DIRECTORY = 14,
}

smb2.CMD_NAMES = {}
for name, number in pairs(smb2.CMD) do
  smb2.CMD_NAMES[number] = name
end

smb2.FLAG = {
  SERVER_TO_REDIR = 0x00000001,
  ASYNC_COMMAND = 0x00000002,
  RELATED_OPERATIONS = 0x00000004,
  SIGNED = 0x00000008,
  DFS_OPERATIONS = 0x10000000,
  REPARSE = 0x20000000,
}

-- Dialect revisions the client offers, newest first, with the family they
-- belong to (3.1.1 carries negotiate contexts, which this client does not
-- need for a pipe probe and therefore advertises but does not use).
smb2.DIALECTS = {
  { code = 0x0311, label = "3.1.1" },
  { code = 0x0302, label = "3.0.2" },
  { code = 0x0300, label = "3.0" },
  { code = 0x0210, label = "2.1" },
  { code = 0x0202, label = "2.0.2" },
}

smb2.DIALECT_LABELS = {}
for _, entry in ipairs(smb2.DIALECTS) do
  smb2.DIALECT_LABELS[entry.code] = entry.label
end

smb2.SECURITY_MODE = {
  SIGNING_ENABLED = 0x0001,
  SIGNING_REQUIRED = 0x0002,
}

smb2.CAPABILITIES = {
  DFS = 0x00000001,
  LEASING = 0x00000002,
  LARGE_MTU = 0x00000004,
  MULTI_CHANNEL = 0x00000008,
  PERSISTENT_HANDLES = 0x00000010,
  DIRECTORY_LEASING = 0x00000020,
  ENCRYPTION = 0x00000040,
}

smb2.SHARE_TYPE = { DISK = 1, PIPE = 2, PRINT = 3 }

smb2.CREATE_DISPOSITION = {
  SUPERSEDE = 0,
  OPEN = 1,
  CREATE = 2,
  OPEN_IF = 3,
  OVERWRITE = 4,
  OVERWRITE_IF = 5,
}

smb2.CREATE_OPTIONS = {
  DIRECTORY_FILE = 0x00000001,
  WRITE_THROUGH = 0x00000002,
  SEQUENTIAL_ONLY = 0x00000004,
  NO_INTERMEDIATE_BUFFERING = 0x00000008,
  NON_DIRECTORY_FILE = 0x00000040,
}

smb2.ACCESS = {
  FILE_READ_DATA = 0x00000001,
  FILE_WRITE_DATA = 0x00000002,
  FILE_APPEND_DATA = 0x00000004,
  FILE_READ_EA = 0x00000008,
  FILE_WRITE_EA = 0x00000010,
  FILE_READ_ATTRIBUTES = 0x00000080,
  FILE_WRITE_ATTRIBUTES = 0x00000100,
  DELETE = 0x00010000,
  READ_CONTROL = 0x00020000,
  SYNCHRONIZE = 0x00100000,
  GENERIC_READ = u32(0x80000000),
  GENERIC_WRITE = 0x40000000,
  GENERIC_ALL = 0x10000000,
  MAXIMUM_ALLOWED = 0x02000000,
}

-- A single SMB2 frame, as exchanged on TCP/445: a four byte length prefix
-- (zero, then a 24-bit big-endian length) followed by the message.
function smb2.frame(message)
  local length = #message
  local b1 = math.floor(length / 65536) % 256
  local b2 = math.floor(length / 256) % 256
  local b3 = length % 256
  return string.char(0, b1, b2, b3) .. message
end

-- Extract every complete frame from a buffer. Returns a list of messages and
-- the unconsumed remainder, which is what makes the reader resilient to TCP
-- coalescing (several responses in one read) and to split responses.
function smb2.parse_frames(buffer)
  local messages = {}
  local pos = 1
  while #buffer - pos + 1 >= 4 do
    local b1, b2, b3 = string.byte(buffer, pos + 1, pos + 3)
    local length = b1 * 65536 + b2 * 256 + b3
    if length == 0 then
      -- Keepalive frame: consume it and continue.
      pos = pos + 4
    elseif #buffer - pos - 3 >= length then
      messages[#messages + 1] = string.sub(buffer, pos + 4, pos + 3 + length)
      pos = pos + 4 + length
    else
      break
    end
  end
  return messages, string.sub(buffer, pos)
end

function smb2.new_header(opts)
  local command = opts.command
  local flags = opts.flags or 0
  return table.concat({
    smb2.PROTOCOL_ID,
    wr_u16le(64),                       -- StructureSize
    wr_u16le(opts.credit_charge or 0),  -- CreditCharge
    wr_u32le(opts.status or 0),         -- Status / channel sequence
    wr_u16le(command),
    wr_u16le(opts.credits or 1),        -- CreditRequest / CreditResponse
    wr_u32le(flags),
    wr_u32le(opts.next_command or 0),
    wr_u64le(opts.message_id or 0),
    wr_u32le(opts.async_id or (opts.reserved or 0)),
    wr_u32le(opts.tree_id or 0),
    wr_u64le(opts.session_id or 0),
    string.rep("\0", 16),               -- Signature (not used: no signing)
  })
end

function smb2.parse_header(message)
  if #message < smb2.HEADER_SIZE then
    return nil, string.format("SMB2 message shorter than the 64 byte header (%d bytes)", #message)
  end
  if string.sub(message, 1, 4) ~= smb2.PROTOCOL_ID then
    return nil, "not an SMB2 message: protocol id mismatch"
  end
  local structure_size, err = rd_u16le(message, 5)
  if not structure_size then
    return nil, err
  end
  local header = {
    structure_size = structure_size,
    credit_charge = rd_u16le(message, 7),
    status = rd_u32le(message, 9),
    command = rd_u16le(message, 13),
    credits = rd_u16le(message, 15),
    flags = rd_u32le(message, 17),
    next_command = rd_u32le(message, 21),
    message_id = rd_u64le(message, 25),
    async_id = rd_u32le(message, 33),
    tree_id = rd_u32le(message, 37),
    session_id = rd_u64le(message, 42),
  }
  header.command_name = smb2.CMD_NAMES[header.command] or ("opcode " .. tostring(header.command))
  header.server_to_redirector = bits.test(header.flags, smb2.FLAG.SERVER_TO_REDIR)
  header.signed = bits.test(header.flags, smb2.FLAG.SIGNED)
  header.status_name = M.smb2_status_name(header.status)
  header.body = string.sub(message, smb2.HEADER_SIZE + 1)
  return header
end

function smb2.negotiate_request(opts)
  opts = opts or {}
  local dialects = {}
  for _, entry in ipairs(smb2.DIALECTS) do
    dialects[#dialects + 1] = wr_u16le(entry.code)
  end
  -- StructureSize 36 accounts for the eight byte ClientStartTime field that
  -- precedes the dialect list whenever 3.1.1 is offered, which it always is
  -- here. Servers read the dialect list at offset 36, so omitting the field
  -- makes them scan past the end of the request.
  local body = table.concat({
    wr_u16le(36),                                       -- StructureSize
    wr_u16le(#smb2.DIALECTS),                           -- DialectCount
    wr_u16le(opts.security_mode or smb2.SECURITY_MODE.SIGNING_ENABLED),
    wr_u16le(0),                                        -- Reserved
    wr_u32le(smb2.CAPABILITIES.LARGE_MTU),              -- Capabilities
    opts.client_guid or string.rep("\0", 16),           -- ClientGuid
    wr_u64le(0),                                        -- ClientStartTime (3.1.1)
    table.concat(dialects),
  })
  return smb2.new_header({ command = smb2.CMD.NEGOTIATE, message_id = opts.message_id or 0 }) .. body
end

function smb2.parse_negotiate(body)
  local structure_size, err = rd_u16le(body, 1)
  if not structure_size then
    return nil, err
  end
  if structure_size < 65 then
    return nil, string.format("NEGOTIATE response structure size %d is below the 65 byte minimum", structure_size)
  end
  local out = {
    structure_size = structure_size,
    security_mode = rd_u16le(body, 3),
    dialect = rd_u16le(body, 5),
    server_guid = hex(string.sub(body, 9, 24)),
    capabilities = rd_u32le(body, 25),
    max_transact_size = rd_u32le(body, 29),
    max_read_size = rd_u32le(body, 33),
    max_write_size = rd_u32le(body, 37),
    system_time = filetime_to_unix(rd_u64le(body, 41)),
    server_start_time = filetime_to_unix(rd_u64le(body, 49)),
    security_buffer_offset = rd_u16le(body, 57),
    security_buffer_length = rd_u16le(body, 59),
  }
  out.dialect_label = smb2.DIALECT_LABELS[out.dialect] or string.format("unknown revision 0x%04X", out.dialect)
  out.signing_enabled = bits.test(out.security_mode, smb2.SECURITY_MODE.SIGNING_ENABLED)
  out.signing_required = bits.test(out.security_mode, smb2.SECURITY_MODE.SIGNING_REQUIRED)
  out.encryption_offered = bits.test(out.capabilities, smb2.CAPABILITIES.ENCRYPTION)
  if out.security_buffer_length and out.security_buffer_length > 0 then
    local from = out.security_buffer_offset - smb2.HEADER_SIZE + 1
    out.security_blob = string.sub(body, from, from + out.security_buffer_length - 1)
  end
  return out
end

function smb2.session_setup_request(security_blob, opts)
  opts = opts or {}
  local header_size = smb2.HEADER_SIZE
  local offset = header_size + 24
  local body = table.concat({
    wr_u16le(25),                                   -- StructureSize
    string.char(opts.flags or 0),                   -- Flags (0 = full handshake)
    string.char(opts.security_mode or smb2.SECURITY_MODE.SIGNING_ENABLED),
    wr_u32le(smb2.CAPABILITIES.LARGE_MTU),          -- Capabilities
    wr_u32le(0),                                    -- Channel
    wr_u16le(offset),                               -- SecurityBufferOffset
    wr_u16le(#security_blob),                       -- SecurityBufferLength
    wr_u64le(opts.previous_session_id or 0),        -- PreviousSessionId
    security_blob,
  })
  return smb2.new_header({
    command = smb2.CMD.SESSION_SETUP,
    message_id = opts.message_id or 0,
    session_id = opts.session_id or 0,
  }) .. body
end

function smb2.parse_session_setup(body)
  local structure_size, err = rd_u16le(body, 1)
  if not structure_size then
    return nil, err
  end
  local out = {
    structure_size = structure_size,
    session_flags = rd_u16le(body, 3),
    security_buffer_offset = rd_u16le(body, 5),
    security_buffer_length = rd_u16le(body, 7),
  }
  out.guest_session = bits.test(out.session_flags, 0x0001)
  out.null_session = bits.test(out.session_flags, 0x0002)
  out.encrypt_data = bits.test(out.session_flags, 0x0004)
  if out.security_buffer_length and out.security_buffer_length > 0 then
    local from = out.security_buffer_offset - smb2.HEADER_SIZE + 1
    out.security_blob = string.sub(body, from, from + out.security_buffer_length - 1)
  end
  return out
end

function smb2.tree_connect_request(path, opts)
  opts = opts or {}
  local encoded = string_to_utf16le(path)
  local offset = smb2.HEADER_SIZE + 8
  local body = table.concat({
    wr_u16le(9),                       -- StructureSize
    wr_u16le(0),                       -- Reserved
    wr_u16le(offset),                  -- PathOffset
    wr_u16le(#encoded),                -- PathLength
    encoded,
  })
  return smb2.new_header({
    command = smb2.CMD.TREE_CONNECT,
    message_id = opts.message_id or 0,
    session_id = opts.session_id or 0,
  }) .. body
end

function smb2.parse_tree_connect(body)
  local structure_size, err = rd_u16le(body, 1)
  if not structure_size then
    return nil, err
  end
  local out = {
    structure_size = structure_size,
    share_type = string.byte(body, 3),
    share_flags = rd_u32le(body, 5),
    capabilities = rd_u32le(body, 9),
    maximal_access = rd_u32le(body, 13),
  }
  local labels = { [1] = "disk", [2] = "named pipe (IPC)", [3] = "print" }
  out.share_type_label = labels[out.share_type] or ("type " .. tostring(out.share_type))
  return out
end

function smb2.create_request(name, opts)
  opts = opts or {}
  local encoded = string_to_utf16le(name)
  local offset = smb2.HEADER_SIZE + 56
  local body = table.concat({
    wr_u16le(57),                                  -- StructureSize
    string.char(0),                                -- SecurityFlags
    string.char(opts.oplock_level or 0),           -- RequestedOplockLevel (none)
    wr_u32le(opts.impersonation_level or 2),       -- ImpersonationLevel (impersonation)
    wr_u64le(0),                                   -- SmbCreateFlags
    wr_u64le(0),                                   -- Reserved
    wr_u32le(opts.desired_access or (smb2.ACCESS.FILE_READ_DATA + smb2.ACCESS.FILE_WRITE_DATA)),
    wr_u32le(0),                                   -- FileAttributes
    wr_u32le(opts.share_access or 3),              -- ShareAccess: read + write
    wr_u32le(opts.disposition or smb2.CREATE_DISPOSITION.OPEN),
    wr_u32le(smb2.CREATE_OPTIONS.NON_DIRECTORY_FILE),
    wr_u16le(offset),                              -- NameOffset
    wr_u16le(#encoded),                            -- NameLength
    wr_u32le(0),                                   -- CreateContextsOffset
    wr_u32le(0),                                   -- CreateContextsLength
    encoded,
  })
  return smb2.new_header({
    command = smb2.CMD.CREATE,
    message_id = opts.message_id or 0,
    tree_id = opts.tree_id or 0,
    session_id = opts.session_id or 0,
  }) .. body
end

function smb2.parse_create(body)
  local structure_size, err = rd_u16le(body, 1)
  if not structure_size then
    return nil, err
  end
  -- CREATE Response (MS-SMB2 2.2.14): after the 4 byte header come
  -- CreationTime, LastAccessTime, LastWriteTime, ChangeTime, AllocationSize
  -- and EndOfFile (eight bytes each), then FileAttributes and the file id.
  local out = {
    structure_size = structure_size,
    oplock_level = string.byte(body, 3),
    create_action = rd_u32le(body, 5),
    creation_time = filetime_to_unix(rd_u64le(body, 9)),
    last_write_time = filetime_to_unix(rd_u64le(body, 25)),
    end_of_file = rd_u64le(body, 49),
    file_attributes = rd_u32le(body, 57),
  }
  local persistent, e1 = rd_u64le(body, 65)
  local volatile, e2 = rd_u64le(body, 73)
  if not persistent then
    return nil, e1
  end
  if not volatile then
    return nil, e2
  end
  out.file_id = { persistent = persistent, volatile = volatile }
  out.create_action_label = ({ [0] = "superseded", [1] = "opened", [2] = "created", [3] = "overwritten" })[out.create_action]
  return out
end

function smb2.write_request(file_id, data, opts)
  opts = opts or {}
  local offset = smb2.HEADER_SIZE + 48
  local body = table.concat({
    wr_u16le(49),                   -- StructureSize
    wr_u16le(offset),               -- DataOffset
    wr_u32le(#data),                -- Length
    wr_u64le(opts.offset or 0),     -- Offset (ignored for pipes)
    wr_u64le(file_id.persistent),   -- FileId.Persistent
    wr_u64le(file_id.volatile),     -- FileId.Volatile
    wr_u32le(0),                    -- Channel
    wr_u32le(0),                    -- RemainingBytes
    wr_u16le(0),                    -- WriteChannelInfoOffset
    wr_u16le(0),                    -- WriteChannelInfoLength
    wr_u32le(0),                    -- Flags
    data,
  })
  return smb2.new_header({
    command = smb2.CMD.WRITE,
    message_id = opts.message_id or 0,
    tree_id = opts.tree_id or 0,
    session_id = opts.session_id or 0,
    credit_charge = math.floor((#data + 65535) / 65536),
  }) .. body
end

function smb2.parse_write(body)
  local structure_size, err = rd_u16le(body, 1)
  if not structure_size then
    return nil, err
  end
  return {
    structure_size = structure_size,
    count = rd_u32le(body, 5),
    remaining = rd_u32le(body, 9),
  }
end

function smb2.read_request(file_id, length, opts)
  opts = opts or {}
  local body = table.concat({
    wr_u16le(49),                   -- StructureSize
    string.char(opts.padding or 0), -- Padding
    string.char(opts.flags or 0),   -- Flags
    wr_u32le(length),               -- Length
    wr_u64le(opts.offset or 0),     -- Offset (ignored for pipes)
    wr_u64le(file_id.persistent),   -- FileId.Persistent
    wr_u64le(file_id.volatile),     -- FileId.Volatile
    wr_u32le(opts.minimum_count or 0),
    wr_u32le(0),                    -- Channel
    wr_u32le(0),                    -- RemainingBytes
    wr_u16le(0),                    -- ReadChannelInfoOffset
    wr_u16le(0),                    -- ReadChannelInfoLength
    string.char(0),                 -- Buffer
  })
  return smb2.new_header({
    command = smb2.CMD.READ,
    message_id = opts.message_id or 0,
    tree_id = opts.tree_id or 0,
    session_id = opts.session_id or 0,
    credit_charge = math.floor((length + 65535) / 65536),
  }) .. body
end

function smb2.parse_read(body)
  local structure_size, err = rd_u8(body, 1)
  if not structure_size then
    return nil, err
  end
  local out = {
    structure_size = structure_size,
    data_offset = string.byte(body, 2),
    data_length = rd_u32le(body, 3),
    data_remaining = rd_u32le(body, 7),
  }
  if out.data_length and out.data_length > 0 then
    local from = (out.data_offset or 0) - smb2.HEADER_SIZE + 1
    out.data = string.sub(body, from, from + out.data_length - 1)
  else
    out.data = ""
  end
  return out
end

function smb2.close_request(file_id, opts)
  opts = opts or {}
  local body = table.concat({
    wr_u16le(24),                   -- StructureSize
    wr_u16le(0),                    -- Flags
    wr_u32le(0),                    -- Reserved
    wr_u64le(file_id.persistent),   -- FileId.Persistent
    wr_u64le(file_id.volatile),     -- FileId.Volatile
  })
  return smb2.new_header({
    command = smb2.CMD.CLOSE,
    message_id = opts.message_id or 0,
    tree_id = opts.tree_id or 0,
    session_id = opts.session_id or 0,
  }) .. body
end

function smb2.parse_close(body)
  local structure_size, err = rd_u16le(body, 1)
  if not structure_size then
    return nil, err
  end
  return { structure_size = structure_size }
end

function smb2.tree_disconnect_request(opts)
  opts = opts or {}
  local body = wr_u16le(4) .. wr_u16le(0)
  return smb2.new_header({
    command = smb2.CMD.TREE_DISCONNECT,
    message_id = opts.message_id or 0,
    tree_id = opts.tree_id or 0,
    session_id = opts.session_id or 0,
  }) .. body
end

function smb2.logoff_request(opts)
  opts = opts or {}
  local body = wr_u16le(4) .. wr_u16le(0)
  return smb2.new_header({
    command = smb2.CMD.LOGOFF,
    message_id = opts.message_id or 0,
    session_id = opts.session_id or 0,
  }) .. body
end

function smb2.echo_request(opts)
  opts = opts or {}
  local body = wr_u16le(4) .. wr_u16le(0)
  return smb2.new_header({
    command = smb2.CMD.ECHO,
    message_id = opts.message_id or 0,
    session_id = opts.session_id or 0,
  }) .. body
end

M.smb2 = smb2

-- ---------------------------------------------------------------------------
-- 4. NTLMSSP (MS-SPNG 2.2.1 / 2.2.2 / 2.2.3)
-- ---------------------------------------------------------------------------

-- SMB2 TREE_CONNECT to IPC$ reaches the named pipe file system but is not
-- authenticated on its own; the session must be established first. A null
-- session is what the published Netlogon testers use, and it is expressible
-- simply: an NTLMSSP NEGOTIATE message, then an AUTHENTICATE message with
-- zero length LM and NT responses and an empty user name. No credential is
-- guessed, hashed or replayed.

local ntlmssp = {}

ntlmssp.SIGNATURE = "NTLMSSP\0"
ntlmssp.TYPE = { NEGOTIATE = 1, CHALLENGE = 2, AUTHENTICATE = 3 }

-- NTLM negotiate flags, as powers of two so the bit helpers work on any
-- integer width. Values follow MS-NRPC 3.1.4.2 / MS-SPNG 2.2.1.
ntlmssp.FLAGS = {
  { flag = 0x00000001, name = "NEGOTIATE_UNICODE", meaning = "strings are UTF-16" },
  { flag = 0x00000002, name = "NEGOTIATE_OEM", meaning = "OEM strings are acceptable" },
  { flag = 0x00000004, name = "REQUEST_TARGET", meaning = "the server should send its target name" },
  { flag = 0x00000010, name = "NEGOTIATE_SIGN", meaning = "message signing supported" },
  { flag = 0x00000020, name = "NEGOTIATE_SEAL", meaning = "message sealing supported" },
  { flag = 0x00000200, name = "NEGOTIATE_NTLM", meaning = "NTLM authentication supported" },
  { flag = 0x00008000, name = "NEGOTIATE_ALWAYS_SIGN", meaning = "sign even when not requested" },
  { flag = 0x00080000, name = "NEGOTIATE_EXTENDED_SESSIONSECURITY", meaning = "NTLM2 session security" },
  { flag = 0x00800000, name = "NEGOTIATE_TARGET_INFO", meaning = "the server sends AV pairs" },
  { flag = 0x02000000, name = "NEGOTIATE_VERSION", meaning = "a version field is present" },
  { flag = 0x20000000, name = "NEGOTIATE_128", meaning = "128 bit session keys" },
  { flag = 0x40000000, name = "NEGOTIATE_KEY_EXCH", meaning = "session key exchange" },
  { flag = u32(0x80000000), name = "NEGOTIATE_56", meaning = "56 bit session keys" },
}

-- NTLMSSP_AV_ID values that matter for reporting; the rest are kept verbatim.
ntlmssp.AV_ID = {
  [0] = "EOL",
  [1] = "NbComputerName",
  [2] = "NbDomainName",
  [3] = "DnsComputerName",
  [4] = "DnsDomainName",
  [5] = "DnsTreeName",
  [6] = "Flags",
  [7] = "Timestamp",
  [8] = "SingleHost",
  [9] = "TargetName",
  [10] = "ChannelBindings",
}

function ntlmssp.describe_flags(mask)
  local names = {}
  for _, entry in ipairs(ntlmssp.FLAGS) do
    if bits.test(mask, entry.flag) then
      names[#names + 1] = entry.name
    end
  end
  return names
end

-- Default client flag set: Unicode, request target, NTLM, extended session
-- security, target info, 128 bit keys. Signing and sealing are advertised
-- because the transport negotiation is independent of the secure channel
-- negotiation that follows.
function ntlmssp.default_flags()
  return 0x00000001 + 0x00000004 + 0x00000200 + 0x00008000 + 0x00080000
       + 0x00800000 + 0x20000000
end

-- Payload offset for a security buffer with zero length: the position where
-- the payload would start (the message header plus the optional version).
local function ntlm_payload_offset(has_version)
  return has_version and 40 or 32
end

function ntlmssp.build_negotiate(opts)
  opts = opts or {}
  local flags = opts.flags or ntlmssp.default_flags()
  local domain = opts.domain or ""
  local workstation = opts.workstation or ""
  local header_size = ntlm_payload_offset(false)
  local domain_raw = string_to_utf16le(domain)
  local workstation_raw = string_to_utf16le(workstation)
  local domain_offset = header_size
  local workstation_offset = domain_offset + #domain_raw
  local parts = {
    ntlmssp.SIGNATURE,
    wr_u32le(ntlmssp.TYPE.NEGOTIATE),
    wr_u32le(flags),
    -- DomainNameFields
    wr_u16le(#domain_raw), wr_u16le(#domain_raw), wr_u32le(domain_offset),
    -- WorkstationFields
    wr_u16le(#workstation_raw), wr_u16le(#workstation_raw), wr_u32le(workstation_offset),
    domain_raw,
    workstation_raw,
  }
  return table.concat(parts)
end

-- Parse the server's CHALLENGE message, including its target info AV pairs
-- (a computer name and domain name leak that is useful for the report even
-- when the secure channel probe itself fails).
function ntlmssp.parse_challenge(blob)
  if type(blob) ~= "string" or #blob < 32 then
    return nil, "CHALLENGE message shorter than 32 bytes"
  end
  if string.sub(blob, 1, 8) ~= ntlmssp.SIGNATURE then
    return nil, "CHALLENGE message signature mismatch"
  end
  local msg_type, err = rd_u32le(blob, 9)
  if not msg_type then
    return nil, err
  end
  if msg_type ~= ntlmssp.TYPE.CHALLENGE then
    return nil, string.format("expected NTLMSSP type 2, got type %s", tostring(msg_type))
  end
  local target_len = rd_u16le(blob, 13)
  local target_off = rd_u32le(blob, 17)
  local flags = rd_u32le(blob, 21)
  local challenge = string.sub(blob, 25, 32)
  local info_len = rd_u16le(blob, 41)
  local info_off = rd_u32le(blob, 45)
  local out = {
    target_name = "",
    flags = flags,
    flag_names = ntlmssp.describe_flags(flags),
    server_challenge = challenge,
    server_challenge_hex = hex(challenge),
    target_info = {},
    version_present = bits.test(flags, 0x02000000),
  }
  if target_len and target_len > 0 and target_off and target_off > 0 then
    out.target_name = utf16le_to_string(string.sub(blob, target_off + 1, target_off + target_len))
  end
  if info_len and info_len > 0 and info_off and info_off > 0 then
    local info = string.sub(blob, info_off + 1, info_off + info_len)
    local pos = 1
    while pos + 3 <= #info do
      local av_id = rd_u16le(info, pos)
      local av_len = rd_u16le(info, pos + 2)
      local value = string.sub(info, pos + 4, pos + 3 + av_len)
      out.target_info[#out.target_info + 1] = {
        id = av_id,
        name = ntlmssp.AV_ID[av_id] or string.format("AV_ID %d", av_id),
        raw = value,
        value = utf16le_to_string(value),
      }
      pos = pos + 4 + av_len
      if av_id == 0 then
        break
      end
    end
    for _, av in ipairs(out.target_info) do
      if av.name == "NbDomainName" or av.name == "DnsDomainName" then
        out.domain_name = out.domain_name or av.value
      elseif av.name == "NbComputerName" or av.name == "DnsComputerName" then
        out.computer_name = out.computer_name or av.value
      end
    end
  end
  return out
end

-- Anonymous AUTHENTICATE message: every security buffer is empty. The offsets
-- still have to point at the payload start, because servers validate them.
function ntlmssp.build_anonymous_authenticate(opts)
  opts = opts or {}
  local flags = opts.flags or ntlmssp.default_flags()
  local payload = ntlm_payload_offset(false)
  local parts = {
    ntlmssp.SIGNATURE,
    wr_u32le(ntlmssp.TYPE.AUTHENTICATE),
    -- LmChallengeResponseFields
    wr_u16le(0), wr_u16le(0), wr_u32le(payload),
    -- NtChallengeResponseFields
    wr_u16le(0), wr_u16le(0), wr_u32le(payload),
    -- DomainNameFields
    wr_u16le(0), wr_u16le(0), wr_u32le(payload),
    -- UserNameFields
    wr_u16le(0), wr_u16le(0), wr_u32le(payload),
    -- WorkstationFields
    wr_u16le(0), wr_u16le(0), wr_u32le(payload),
    -- EncryptedRandomSessionKeyFields
    wr_u16le(0), wr_u16le(0), wr_u32le(payload),
    wr_u32le(flags),
  }
  return table.concat(parts)
end

M.ntlmssp = ntlmssp

-- ---------------------------------------------------------------------------
-- 5. SMB2 client
-- ---------------------------------------------------------------------------

-- The client owns one TCP connection, an accumulator for partial reads and a
-- transcript that the calling script can render. Every exchange returns
-- (header, body) on success or (nil, reason, detail) on failure, so callers
-- never have to interpret raw socket errors.
function smb2.new_client(host, port, opts)
  opts = opts or {}
  -- Accept either an NSE port table or a plain port number: the socket layer
  -- and the mock transports both need the numeric form.
  local port_number = type(port) == "table" and port.number or port
  local client = {
    host = host,
    port = port_number,
    port_table = type(port) == "table" and port or nil,
    opts = opts,
    timeout_ms = opts.timeout_ms or 3000,
    transcript = {},
    stats = { round_trips = 0, bytes_sent = 0, bytes_received = 0, reads = 0, frames = 0 },
    buffer = "",
    message_id = 0,
    session_id = 0,
    tree_id = 0,
    dialected = false,
  }

  function client:log(kind, text)
    self.transcript[#self.transcript + 1] = {
      step = #self.transcript + 1,
      kind = kind,
      text = text,
    }
    stdnse.debug(3, "smb2 %s: %s", kind, text)
  end

  function client:next_message_id()
    self.message_id = self.message_id + 1
    return self.message_id
  end

  function client:connect()
    local sock = nmap.new_socket("tcp")
    sock:set_timeout(self.timeout_ms)
    local host_arg = type(self.host) == "table" and (self.host.ip or self.host.name or self.host.targetname) or self.host
    local ok, err = sock:connect(self.host, self.port)
    if not ok then
      -- Older Nmap builds only accept the address string; retry the explicit
      -- form before giving up.
      ok, err = sock:connect(host_arg, self.port)
    end
    if not ok then
      return nil, "connect", string.format("cannot open TCP session to %s:%s (%s)",
        tostring(host_arg), tostring(self.port), tostring(err))
    end
    self.sock = sock
    self:log("transport", string.format("TCP connection to %s:%s established", tostring(host_arg), tostring(self.port)))
    return true
  end

  -- Read one complete frame. Returns the message string, or nil plus reason.
  -- Reads continue until a whole frame is present, which is what makes the
  -- client work against servers that split a response across segments.
  function client:read_frame()
    if not self.sock then
      return nil, "state", "the SMB2 socket is closed"
    end
    -- A single TCP segment can carry several SMB2 messages. Those that arrived
    -- ahead of the response we asked for were stashed here, and they must be
    -- served before the socket is read again or they are lost.
    if self.extra_frames and #self.extra_frames > 0 then
      local stashed = table.remove(self.extra_frames, 1)
      self.stats.frames = self.stats.frames + 1
      self.stats.bytes_received = self.stats.bytes_received + #stashed + 4
      self:log("frame", "served a previously coalesced frame from the buffer")
      return stashed
    end
    local deadline = nmap.clock_ms() + self.timeout_ms
    while true do
      local messages, remainder = smb2.parse_frames(self.buffer)
      if #messages > 0 then
        self.buffer = remainder
        self.stats.frames = self.stats.frames + #messages
        local first = messages[1]
        for i = 2, #messages do
          -- A frame arriving ahead of a response we did not ask for (an
          -- opcode-lock break notification, for example) is put back.
          self.extra_frames = self.extra_frames or {}
          self.extra_frames[#self.extra_frames + 1] = messages[i]
        end
        self.stats.bytes_received = self.stats.bytes_received + #first + 4
        return first
      end
      if nmap.clock_ms() >= deadline then
        return nil, "timeout", string.format("no complete SMB2 frame within %d ms", self.timeout_ms)
      end
      self.sock:set_timeout(math.max(200, deadline - nmap.clock_ms()))
      local status, data = self.sock:receive_bytes(65536)
      self.stats.reads = self.stats.reads + 1
      if status and type(data) == "string" and #data > 0 then
        self.buffer = self.buffer .. data
      elseif status == false or status == nil then
        local reason = tostring(data or "TIMEOUT")
        if string.upper(reason) == "TIMEOUT" then
          return nil, "timeout", string.format("no SMB2 response within %d ms", self.timeout_ms)
        end
        return nil, "transport", string.format("socket error while reading: %s", reason)
      end
    end
  end

  -- Send a request and return the response whose command matches, ignoring
  -- unrelated notifications. Returns (header, body, nil) or (nil, nil, detail).
  function client:exchange(message, expect_command, detail)
    if not self.sock then
      return nil, nil, { reason = "state", text = "the SMB2 socket is closed; no further exchange is possible" }
    end
    self.stats.round_trips = self.stats.round_trips + 1
    self.stats.bytes_sent = self.stats.bytes_sent + #message + 4
    local started = nmap.clock_ms()
    local ok, err = self.sock:send(smb2.frame(message))
    if not ok then
      return nil, nil, { reason = "send", text = string.format("send failed: %s", tostring(err)) }
    end
    local elapsed
    -- Servers may interleave notifications (oplock breaks) with the response,
    -- so frames that do not carry the expected command are logged and skipped
    -- instead of being mistaken for the answer.
    for attempt = 1, 4 do
      local response, reason, text = self:read_frame()
      elapsed = nmap.clock_ms() - started
      if not response then
        self:log("failure", string.format("%s: %s (%s)", detail or "exchange", tostring(text), tostring(reason)))
        return nil, nil, { reason = reason, text = text, elapsed_ms = elapsed }
      end
      local header, herr = smb2.parse_header(response)
      if not header then
        self:log("failure", string.format("%s: %s", detail or "exchange", tostring(herr)))
        return nil, nil, { reason = "decode", text = herr, elapsed_ms = elapsed }
      end
      if expect_command and header.command ~= expect_command then
        self:log("skip", string.format("ignoring %s frame while waiting for %s",
          header.command_name, smb2.CMD_NAMES[expect_command] or "the response"))
        if attempt == 4 then
          return nil, nil, {
            reason = "unexpected-command",
            text = string.format("expected %s response, received %s", smb2.CMD_NAMES[expect_command], header.command_name),
            header = header,
            elapsed_ms = elapsed,
          }
        end
      else
        self:log("exchange", string.format("%s -> %s status=%s (%d ms, %d bytes)",
          detail or header.command_name, header.command_name, header.status_name, elapsed, #response))
        if header.tree_id and header.tree_id ~= 0 then
          self.tree_id = header.tree_id
        end
        if header.session_id and header.session_id ~= 0 then
          self.session_id = header.session_id
        end
        return header, header.body, nil, elapsed
      end
    end
    return nil, nil, { reason = "unexpected-command", text = "no matching response frame", elapsed_ms = elapsed }
  end

  function client:negotiate()
    local request = smb2.negotiate_request({
      message_id = self:next_message_id(),
      client_guid = self.opts.client_guid or string.rep("\0", 16),
      security_mode = smb2.SECURITY_MODE.SIGNING_ENABLED,
    })
    local header, body, failure, elapsed = self:exchange(request, smb2.CMD.NEGOTIATE, "SMB2 NEGOTIATE")
    if not header then
      return nil, failure
    end
    if header.status ~= SMB2_STATUS.STATUS_SUCCESS then
      return nil, { reason = "status", text = M.smb2_status_text(header.status), status = header.status }
    end
    local parsed, err = smb2.parse_negotiate(body)
    if not parsed then
      return nil, { reason = "decode", text = err }
    end
    parsed.rtt_ms = elapsed
    self.dialected = true
    return parsed
  end

  -- Null session: NTLMSSP NEGOTIATE, then NTLMSSP AUTHENTICATE with empty
  -- responses. A server that has anonymous access disabled answers with
  -- STATUS_ACCESS_DENIED or STATUS_LOGON_FAILURE; both are reported to the
  -- caller as an explicit, named condition rather than a generic failure.
  function client:session_setup_anonymous()
    local negotiate_blob = ntlmssp.build_negotiate({})
    local request = smb2.session_setup_request(negotiate_blob, { message_id = self:next_message_id() })
    local header, body, failure, elapsed = self:exchange(request, smb2.CMD.SESSION_SETUP, "SESSION_SETUP (NTLMSSP NEGOTIATE)")
    if not header then
      return nil, failure
    end
    if header.status ~= SMB2_STATUS.STATUS_MORE_PROCESSING_REQUIRED
      and header.status ~= SMB2_STATUS.STATUS_SUCCESS then
      return nil, {
        reason = "status",
        text = M.smb2_status_text(header.status),
        status = header.status,
        stage = "negotiate",
      }
    end
    local stage1, err = smb2.parse_session_setup(body)
    if not stage1 then
      return nil, { reason = "decode", text = err }
    end
    local challenge
    if stage1.security_blob then
      challenge, err = ntlmssp.parse_challenge(stage1.security_blob)
      if not challenge then
        return nil, { reason = "decode", text = string.format("NTLMSSP challenge not usable: %s", tostring(err)) }
      end
    end

    local authenticate_blob = ntlmssp.build_anonymous_authenticate({ flags = challenge and challenge.flags })
    local request2 = smb2.session_setup_request(authenticate_blob, {
      message_id = self:next_message_id(),
      session_id = header.session_id,
    })
    local header2, body2, failure2, elapsed2 = self:exchange(request2, smb2.CMD.SESSION_SETUP, "SESSION_SETUP (anonymous AUTHENTICATE)")
    if not header2 then
      return nil, failure2
    end
    if header2.status ~= SMB2_STATUS.STATUS_SUCCESS then
      return nil, {
        reason = "status",
        text = M.smb2_status_text(header2.status),
        status = header2.status,
        stage = "authenticate",
      }
    end
    local stage2, err2 = smb2.parse_session_setup(body2)
    if not stage2 then
      return nil, { reason = "decode", text = err2 }
    end
    self.session_id = header2.session_id
    return {
      challenge = challenge,
      session_flags = stage2.session_flags,
      null_session = stage2.null_session,
      guest_session = stage2.guest_session,
      encrypt_data = stage2.encrypt_data,
      session_id = header2.session_id,
      first_stage_status = header.status,
      rtt_ms = (elapsed or 0) + (elapsed2 or 0),
    }
  end

  function client:tree_connect(path)
    local request = smb2.tree_connect_request(path, {
      message_id = self:next_message_id(),
      session_id = self.session_id,
    })
    local header, body, failure, elapsed = self:exchange(request, smb2.CMD.TREE_CONNECT,
      string.format("TREE_CONNECT %s", path))
    if not header then
      return nil, failure
    end
    if header.status ~= SMB2_STATUS.STATUS_SUCCESS then
      return nil, { reason = "status", text = M.smb2_status_text(header.status), status = header.status }
    end
    local parsed, err = smb2.parse_tree_connect(body)
    if not parsed then
      return nil, { reason = "decode", text = err }
    end
    parsed.tree_id = header.tree_id
    parsed.rtt_ms = elapsed
    self.tree_id = header.tree_id
    return parsed
  end

  function client:open_pipe(name)
    local request = smb2.create_request(name, {
      message_id = self:next_message_id(),
      session_id = self.session_id,
      tree_id = self.tree_id,
      desired_access = smb2.ACCESS.FILE_READ_DATA + smb2.ACCESS.FILE_WRITE_DATA
        + smb2.ACCESS.SYNCHRONIZE,
      share_access = 3,
      disposition = smb2.CREATE_DISPOSITION.OPEN,
    })
    local header, body, failure, elapsed = self:exchange(request, smb2.CMD.CREATE,
      string.format("CREATE %s", name))
    if not header then
      return nil, failure
    end
    if header.status ~= SMB2_STATUS.STATUS_SUCCESS then
      return nil, {
        reason = "status",
        text = M.smb2_status_text(header.status),
        status = header.status,
        pipe = name,
      }
    end
    local parsed, err = smb2.parse_create(body)
    if not parsed then
      return nil, { reason = "decode", text = err }
    end
    parsed.rtt_ms = elapsed
    parsed.pipe = name
    self.pipe = parsed
    return parsed
  end

  -- Write a PDU to the pipe and read the answer back. The read loop keeps
  -- asking while the server reports STATUS_BUFFER_OVERFLOW, which is how a
  -- response larger than one read window is transferred.
  function client:pipe_write(data)
    local header, body, failure = self:exchange(
      smb2.write_request(self.pipe.file_id, data, {
        message_id = self:next_message_id(),
        session_id = self.session_id,
        tree_id = self.tree_id,
      }), smb2.CMD.WRITE, string.format("WRITE %d bytes to %s", #data, self.pipe.pipe))
    if not header then
      return nil, failure
    end
    if header.status ~= SMB2_STATUS.STATUS_SUCCESS then
      return nil, { reason = "status", text = M.smb2_status_text(header.status), status = header.status }
    end
    local parsed, err = smb2.parse_write(body)
    if not parsed then
      return nil, { reason = "decode", text = err }
    end
    return parsed
  end

  function client:pipe_read(length, opts)
    opts = opts or {}
    length = length or 4280
    local collected = {}
    local rounds = 0
    local max_rounds = opts.max_rounds or 8
    local last_status
    while rounds < max_rounds do
      rounds = rounds + 1
      local want = length
      if #collected > 0 then
        want = math.max(1024, length)
      end
      local header, body, failure = self:exchange(
        smb2.read_request(self.pipe.file_id, want, {
          message_id = self:next_message_id(),
          session_id = self.session_id,
          tree_id = self.tree_id,
        }), smb2.CMD.READ, string.format("READ up to %d bytes from %s", want, self.pipe.pipe))
      if not header then
        if #collected > 0 then
          return table.concat(collected), last_status, { rounds = rounds, partial = true }
        end
        return nil, nil, failure
      end
      last_status = header.status
      if header.status ~= SMB2_STATUS.STATUS_SUCCESS
        and header.status ~= SMB2_STATUS.STATUS_BUFFER_OVERFLOW then
        if #collected > 0 then
          return table.concat(collected), header.status, { rounds = rounds, terminated = true }
        end
        return nil, header.status, { reason = "status", text = M.smb2_status_text(header.status) }
      end
      local parsed, err = smb2.parse_read(body)
      if not parsed then
        return nil, nil, { reason = "decode", text = err }
      end
      if parsed.data and #parsed.data > 0 then
        collected[#collected + 1] = parsed.data
      end
      if header.status == SMB2_STATUS.STATUS_SUCCESS and #collected > 0 then
        break
      end
      if not parsed.data_remaining or parsed.data_remaining == 0 then
        break
      end
    end
    if #collected == 0 then
      return nil, last_status, { reason = "empty", text = "server returned no pipe data" }
    end
    return table.concat(collected), last_status, { rounds = rounds }
  end

  function client:close_pipe()
    if not self.pipe then
      return nil, { reason = "state", text = "no pipe is open" }
    end
    local header, _, failure = self:exchange(
      smb2.close_request(self.pipe.file_id, {
        message_id = self:next_message_id(),
        session_id = self.session_id,
        tree_id = self.tree_id,
      }), smb2.CMD.CLOSE, string.format("CLOSE %s", self.pipe.pipe))
    if not header then
      return nil, failure
    end
    self.pipe = nil
    return true
  end

  function client:logoff()
    if self.session_id == 0 then
      return true
    end
    local header, _, failure = self:exchange(
      smb2.logoff_request({ message_id = self:next_message_id(), session_id = self.session_id }),
      smb2.CMD.LOGOFF, "LOGOFF")
    if not header then
      return nil, failure
    end
    self.session_id = 0
    return true
  end

  function client:close()
    if self.sock then
      self.sock:close()
      self.sock = nil
      self:log("transport", "socket closed")
    end
    return true
  end

  function client:summary()
    return string.format("%d round trip(s), %d byte(s) sent, %d byte(s) received, %d read(s)",
      self.stats.round_trips, self.stats.bytes_sent, self.stats.bytes_received, self.stats.reads)
  end

  return client
end

-- ---------------------------------------------------------------------------
-- 6. DCE/RPC over the named pipe (MS-RPCE connection oriented PDUs)
-- ---------------------------------------------------------------------------

local dcerpc = {}

dcerpc.VERSION_MAJOR = 5
dcerpc.VERSION_MINOR = 0

dcerpc.PDU = {
  REQUEST = 0,
  RESPONSE = 2,
  FAULT = 3,
  BIND = 11,
  BIND_ACK = 12,
  BIND_NAK = 13,
  ALTER_CONTEXT = 14,
  ALTER_CONTEXT_RESP = 15,
  AUTH3 = 16,
  SHUTDOWN = 17,
  ORPHANED = 19,
}

dcerpc.PDU_NAMES = {}
for name, number in pairs(dcerpc.PDU) do
  dcerpc.PDU_NAMES[number] = name
end

dcerpc.PFC = {
  FIRST_FRAG = 0x01,
  LAST_FRAG = 0x02,
  PENDING_CANCEL = 0x04,
  CONC_MPX = 0x10,
  DID_NOT_EXECUTE = 0x20,
  MAYBE = 0x40,
  OBJECT_UUID = 0x80,
}

-- Data representation: little endian integers, ASCII characters, IEEE floats.
dcerpc.DREP = string.char(0x10, 0x00, 0x00, 0x00)

dcerpc.MAX_FRAG = 4280

-- UUIDs used by the Netlogon probe. The Netlogon interface identifier is
-- MSRPC_UUID_NRPC from [MS-NRPC] 1.9; the transfer syntax is the NDR syntax
-- defined in [MS-RPCE] 12.6.2.
dcerpc.UUID = {
  NETLOGON = "12345678-1234-ABCD-EF00-01234567CFFB",
  NDR32 = "8a885d04-1ceb-11c9-9fe8-08002b104860",
  ENDPOINT_MAPPER = "e1af8308-5d1f-11c9-91a4-08002b14a0fa",
}

-- Interface version for Netlogon, from [MS-NRPC] 1.9.
dcerpc.NETLOGON_VERSION = { major = 1, minor = 0 }

dcerpc.BIND_RESULT = {
  [0] = { name = "acceptance", text = "the abstract syntax is supported" },
  [1] = { name = "user_rejection", text = "the server rejected the context for an application defined reason" },
  [2] = { name = "provider_rejection", text = "the requested transfer syntax is not supported" },
  [3] = { name = "negotiate_ack", text = "the server asked for further negotiation" },
}

function dcerpc.uuid_to_bytes(text)
  local compact = string.gsub(string.lower(text), "[-{}]", "")
  if #compact ~= 32 or string.find(compact, "[^0-9a-f]") then
    return nil, string.format("not a UUID: %q", tostring(text))
  end
  -- A UUID is transmitted with the first three fields little endian and the
  -- last two big endian ([MS-RPCE] 12.6.2 / RFC 4122 wire form).
  local bytes = {}
  local function push(hexpair)
    bytes[#bytes + 1] = string.char(tonumber(hexpair, 16))
  end
  push(string.sub(compact, 7, 8))
  push(string.sub(compact, 5, 6))
  push(string.sub(compact, 3, 4))
  push(string.sub(compact, 1, 2))
  push(string.sub(compact, 11, 12))
  push(string.sub(compact, 9, 10))
  push(string.sub(compact, 15, 16))
  push(string.sub(compact, 13, 14))
  for i = 17, 32, 2 do
    push(string.sub(compact, i, i + 1))
  end
  return table.concat(bytes)
end

function dcerpc.bytes_to_uuid(data)
  if #data < 16 then
    return nil, "UUID needs 16 bytes"
  end
  local function pair(i)
    return string.format("%02x", string.byte(data, i))
  end
  return table.concat({
    pair(4), pair(3), pair(2), pair(1), "-",
    pair(6), pair(5), "-",
    pair(8), pair(7), "-",
    pair(9), pair(10), "-",
    pair(11), pair(12), pair(13), pair(14), pair(15), pair(16),
  })
end

local function pdu_header(ptype, flags, frag_length, auth_length, call_id)
  return string.char(dcerpc.VERSION_MAJOR, dcerpc.VERSION_MINOR, ptype, flags)
    .. dcerpc.DREP
    .. wr_u16le(frag_length)
    .. wr_u16le(auth_length)
    .. wr_u32le(call_id)
end

function dcerpc.parse_pdu(data)
  if #data < 16 then
    return nil, string.format("PDU shorter than the 16 byte header (%d bytes)", #data)
  end
  local major, minor, ptype = string.byte(data, 1, 3)
  local flags = string.byte(data, 4)
  local frag_length = rd_u16le(data, 9)
  local auth_length = rd_u16le(data, 11)
  local call_id = rd_u32le(data, 13)
  local out = {
    version_major = major,
    version_minor = minor,
    ptype = ptype,
    ptype_name = dcerpc.PDU_NAMES[ptype] or ("type " .. tostring(ptype)),
    flags = flags,
    frag_length = frag_length,
    auth_length = auth_length,
    call_id = call_id,
    body = string.sub(data, 17),
    raw_length = #data,
  }
  out.first_frag = bits.test(flags, dcerpc.PFC.FIRST_FRAG)
  out.last_frag = bits.test(flags, dcerpc.PFC.LAST_FRAG)
  if frag_length and frag_length ~= #data then
    out.frag_length_mismatch = true
  end
  return out
end

-- Assemble complete PDUs from the pipe byte stream. A PDU is complete when
-- frag_length bytes have arrived; anything shorter stays in the buffer.
function dcerpc.reassemble(buffer)
  local pdus = {}
  local pos = 1
  while #buffer - pos + 1 >= 16 do
    local frag_length = rd_u16le(buffer, pos + 8)
    if not frag_length or frag_length < 16 then
      -- Unparsable header: drop one byte and resynchronise rather than
      -- spinning on the same offset forever.
      pos = pos + 1
    elseif #buffer - pos + 1 >= frag_length then
      local pdu, err = dcerpc.parse_pdu(string.sub(buffer, pos, pos + frag_length - 1))
      if not pdu then
        return pdus, string.sub(buffer, pos), err
      end
      pdus[#pdus + 1] = pdu
      pos = pos + frag_length
    else
      break
    end
  end
  return pdus, string.sub(buffer, pos)
end

function dcerpc.bind_pdu(opts)
  opts = opts or {}
  local abstract = dcerpc.uuid_to_bytes(opts.abstract_syntax or dcerpc.UUID.NETLOGON)
  if not abstract then
    return nil, "abstract syntax UUID is malformed"
  end
  local transfer = dcerpc.uuid_to_bytes(opts.transfer_syntax or dcerpc.UUID.NDR32)
  local major = opts.major or dcerpc.NETLOGON_VERSION.major
  local minor = opts.minor or dcerpc.NETLOGON_VERSION.minor
  local context = wr_u16le(opts.context_id or 0)
    .. string.char(1, 0)                         -- one transfer syntax
    .. abstract
    .. wr_u16le(major) .. wr_u16le(minor)
    .. transfer
    .. wr_u16le(2) .. wr_u16le(0)                -- NDR32 version 2.0
  local body = wr_u16le(opts.max_xmit_frag or dcerpc.MAX_FRAG)
    .. wr_u16le(opts.max_recv_frag or dcerpc.MAX_FRAG)
    .. wr_u32le(opts.assoc_group or 0)
    -- p_cont_list_t: one presentation context, then the two reserved fields
    -- that MS-RPCE 2.2.2.2 keeps between the count and the first context.
    .. string.char(1, 0)
    .. wr_u16le(0)
    .. context
  return pdu_header(dcerpc.PDU.BIND, dcerpc.PFC.FIRST_FRAG + dcerpc.PFC.LAST_FRAG, 16 + #body, 0, opts.call_id or 1)
    .. body
end

function dcerpc.parse_bind_ack(pdu)
  local body = pdu.body
  local out = {
    max_xmit_frag = rd_u16le(body, 1),
    max_recv_frag = rd_u16le(body, 3),
    assoc_group = rd_u32le(body, 5),
    sec_addr_length = rd_u16le(body, 9),
  }
  local sec_addr_offset = 11
  out.secondary_address = string.sub(body, sec_addr_offset, sec_addr_offset + out.sec_addr_length - 1)
  -- The result list starts after the secondary address and its padding to a
  -- four byte boundary.
  local results_offset = sec_addr_offset + out.sec_addr_length
  results_offset = results_offset + ((4 - (results_offset - 1) % 4) % 4)
  out.n_results = string.byte(body, results_offset) or 0
  out.results = {}
  local pos = results_offset + 4
  for i = 1, out.n_results do
    local result = rd_u16le(body, pos)
    local reason = rd_u16le(body, pos + 2)
    local syntax = string.sub(body, pos + 4, pos + 19)
    local version = { rd_u16le(body, pos + 20), rd_u16le(body, pos + 22) }
    local entry = {
      result = result,
      reason = reason,
      transfer_syntax = dcerpc.bytes_to_uuid(syntax),
      version_major = version[1],
      version_minor = version[2],
      context_id = i - 1,
    }
    local label = dcerpc.BIND_RESULT[result]
    entry.result_name = label and label.name or ("result " .. tostring(result))
    entry.result_text = label and label.text or "unlisted bind result"
    out.results[i] = entry
    pos = pos + 24
  end
  out.accepted = false
  for _, entry in ipairs(out.results) do
    if entry.result == 0 then
      out.accepted = true
      out.accepted_context_id = entry.context_id
    end
  end
  return out
end

function dcerpc.request_pdu(opnum, payload, opts)
  opts = opts or {}
  local body = wr_u32le(#payload)                     -- alloc_hint
    .. wr_u16le(opts.context_id or 0)
    .. wr_u16le(opnum)
    .. payload
  return pdu_header(dcerpc.PDU.REQUEST, dcerpc.PFC.FIRST_FRAG + dcerpc.PFC.LAST_FRAG,
    16 + #body, 0, opts.call_id or 2) .. body
end

function dcerpc.parse_response(pdu)
  local body = pdu.body
  local alloc_hint, err = rd_u32le(body, 1)
  if not alloc_hint then
    return nil, err
  end
  local out = {
    alloc_hint = alloc_hint,
    context_id = rd_u16le(body, 5),
    cancel_count = string.byte(body, 7),
    payload = string.sub(body, 9),
  }
  return out
end

function dcerpc.parse_fault(pdu)
  local body = pdu.body
  local status = rd_u32le(body, 9)
  local out = {
    alloc_hint = rd_u32le(body, 1),
    context_id = rd_u16le(body, 5),
    cancel_count = string.byte(body, 7),
    status = status,
    status_name = M.smb2_status_name(status),
    payload = string.sub(body, 25),
  }
  return out
end

-- A channel binds one interface on an already opened named pipe and then
-- performs calls. It owns the SMB2 write/read cycle plus the DCE/RPC
-- reassembly state, so a caller only sees (payload, status) pairs.
function dcerpc.new_channel(client, opts)
  opts = opts or {}
  local channel = {
    client = client,
    buffer = "",
    call_id = opts.call_id or 1,
    context_id = 0,
    transcript = {},
    stats = { calls = 0, faults = 0, reads = 0, bytes = 0 },
  }

  function channel:log(text)
    self.transcript[#self.transcript + 1] = text
  end

  -- Send one PDU and collect the first complete PDU of the answer.
  function channel:round_trip(pdu, expect_type, label)
    self.stats.calls = self.stats.calls + 1
    self.stats.bytes = self.stats.bytes + #pdu
    local ok, failure = self.client:pipe_write(pdu)
    if not ok then
      return nil, failure
    end
    local attempts = 0
    local deadline = nmap.clock_ms() + (self.client.timeout_ms or 3000)
    while attempts < 6 do
      attempts = attempts + 1
      local pdus, remainder = dcerpc.reassemble(self.buffer)
      self.buffer = remainder
      for _, pdu in ipairs(pdus) do
        if not expect_type or pdu.ptype == expect_type then
          self:log(string.format("%s -> %s (%d bytes)", label or "PDU", pdu.ptype_name, pdu.raw_length))
          return pdu
        end
        self:log(string.format("%s -> %s ignored while waiting for %s", label or "PDU", pdu.ptype_name,
          dcerpc.PDU_NAMES[expect_type]))
      end
      if nmap.clock_ms() >= deadline then
        break
      end
      local data, status, detail = self.client:pipe_read(dcerpc.MAX_FRAG, { max_rounds = 2 })
      self.stats.reads = self.stats.reads + 1
      if not data then
        if detail and detail.reason == "empty" then
          return nil, { reason = "empty", text = "the pipe returned no further data" }
        end
        return nil, { reason = detail and detail.reason or "read", text = detail and detail.text or tostring(status) }
      end
      self.buffer = self.buffer .. data
    end
    return nil, { reason = "timeout", text = string.format("no %s PDU within the deadline",
      dcerpc.PDU_NAMES[expect_type] or "expected") }
  end

  function channel:bind(opts2)
    opts2 = opts2 or {}
    self.call_id = self.call_id + 1
    local pdu, err = dcerpc.bind_pdu({
      abstract_syntax = opts2.abstract_syntax or dcerpc.UUID.NETLOGON,
      major = opts2.major or dcerpc.NETLOGON_VERSION.major,
      minor = opts2.minor or dcerpc.NETLOGON_VERSION.minor,
      call_id = self.call_id,
      max_xmit_frag = opts2.max_xmit_frag or dcerpc.MAX_FRAG,
      max_recv_frag = opts2.max_recv_frag or dcerpc.MAX_FRAG,
      context_id = opts2.context_id or 0,
    })
    if not pdu then
      return nil, { reason = "encode", text = err }
    end
    local response, failure = self:round_trip(pdu, nil, "BIND")
    if not response then
      return nil, failure
    end
    if response.ptype == dcerpc.PDU.BIND_NAK then
      local reason = rd_u16le(response.body, 3)
      return nil, {
        reason = "bind-nak",
        text = string.format("the server refused the bind (reason %s)", tostring(reason)),
        bind_nak_reason = reason,
      }
    end
    if response.ptype == dcerpc.PDU.FAULT then
      local fault = dcerpc.parse_fault(response)
      return nil, { reason = "fault", text = "the server faulted the bind", fault = fault }
    end
    if response.ptype ~= dcerpc.PDU.BIND_ACK then
      return nil, { reason = "unexpected", text = string.format("expected BIND_ACK, received %s", response.ptype_name) }
    end
    local ack, err2 = dcerpc.parse_bind_ack(response)
    if not ack then
      return nil, { reason = "decode", text = err2 }
    end
    self.context_id = ack.accepted_context_id or 0
    self.ack = ack
    self:log(string.format("BIND accepted=%s assoc_group=0x%04X max_fragment=%d secondary_address=%q",
      tostring(ack.accepted), ack.assoc_group, ack.max_xmit_frag or 0, ack.secondary_address or ""))
    return ack
  end

  -- Perform one call and return the raw payload answer plus the NTSTATUS carried
  -- either by the response or by a fault PDU.
  function channel:call(opnum, payload, label)
    self.call_id = self.call_id + 1
    local pdu = dcerpc.request_pdu(opnum, payload, {
      call_id = self.call_id,
      context_id = self.context_id,
    })
    local response, failure = self:round_trip(pdu, nil, label or ("call opnum " .. tostring(opnum)))
    if not response then
      return nil, nil, failure
    end
    if response.ptype == dcerpc.PDU.FAULT then
      self.stats.faults = self.stats.faults + 1
      local fault = dcerpc.parse_fault(response)
      return nil, fault.status, {
        reason = "fault",
        text = string.format("DCE/RPC fault %s", M.smb2_status_name(fault.status)),
        fault = fault,
      }
    end
    if response.ptype ~= dcerpc.PDU.RESPONSE then
      return nil, nil, { reason = "unexpected", text = string.format("expected RESPONSE, received %s", response.ptype_name) }
    end
    local parsed, err = dcerpc.parse_response(response)
    if not parsed then
      return nil, nil, { reason = "decode", text = err }
    end
    return parsed.payload, nil, nil, parsed
  end

  function channel:close()
    if self.client.pipe then
      return self.client:close_pipe()
    end
    return true
  end

  return channel
end

M.dcerpc = dcerpc

-- ---------------------------------------------------------------------------
-- 7. NDR transfer syntax (MS-RPCE 2.2.6 / 14.3)
-- ---------------------------------------------------------------------------

-- Only the pieces the Netlogon secure channel calls need are implemented:
-- fixed size scalars, unique pointers to strings, and the referent ordering
-- NDR imposes (the fixed part first, then deferred data in referent order).
--
-- Two rules from the specification shape the code below:
--
--   * Unique pointer referent identifiers start at 0x00020000 and increase by
--     four for every pointer in the fixed part (MS-RPCE 2.2.6.1).
--   * A "[string, unique] wchar_t*" is marshalled as a referent in the fixed
--     part and, at the referent, a conformant string: a four byte maximum
--     count followed by the UTF-16 characters including the terminator.
--     Every referent starts on a four byte boundary, which means a string of
--     odd character count is followed by two bytes of padding.

local ndr = {}

ndr.REFERENT_BASE = 0x00020000
ndr.REFERENT_STEP = 4
ndr.NULL_REFERENT = 0

local function wrap4(value)
  local remainder = value % 4
  if remainder == 0 then
    return 0
  end
  return 4 - remainder
end

function ndr.new_encoder()
  local encoder = {
    fixed = {},
    deferred = {},
    referents = 0,
  }

  function encoder:raw(bytes)
    self.fixed[#self.fixed + 1] = bytes
    return self
  end

  function encoder:u8(value)
    self.fixed[#self.fixed + 1] = string.char(math.floor(value) % 256)
    return self
  end

  function encoder:u16(value)
    self.fixed[#self.fixed + 1] = wr_u16le(value)
    return self
  end

  function encoder:u32(value)
    self.fixed[#self.fixed + 1] = wr_u32le(value)
    return self
  end

  function encoder:align4()
    local size = 0
    for _, chunk in ipairs(self.fixed) do
      size = size + #chunk
    end
    local padding = wrap4(size)
    if padding > 0 then
      self.fixed[#self.fixed + 1] = string.rep("\0", padding)
    end
    return self
  end

  function encoder:fixed_bytes(bytes, width)
    width = width or #bytes
    if #bytes > width then
      bytes = string.sub(bytes, 1, width)
    end
    self.fixed[#self.fixed + 1] = bytes .. string.rep("\0", width - #bytes)
    return self
  end

  function encoder:null_pointer()
    self.fixed[#self.fixed + 1] = wr_u32le(ndr.NULL_REFERENT)
    return self
  end

  -- Allocate the next referent. A referent is not an arbitrary identifier:
  -- its value is 0x00020000 plus the offset at which its deferred data starts
  -- in the finished payload, so it can only be written once the size of the fixed
  -- part is known. The slot is therefore marked here and stamped in finish().
  function encoder:defer(writer)
    self.deferred[#self.deferred + 1] = { writer = writer }
    self.fixed[#self.fixed + 1] = { referent = #self.deferred }
    self.referents = self.referents + 1
    return #self.deferred
  end

  -- "[string, unique] wchar_t*": RPC_UNICODE_STRING header plus deferred text.
  -- At the referent sits a conformant string: the maximum character count,
  -- then the UTF-16 characters including the terminator.
  function encoder:unique_wstring(text)
    local raw = string_to_utf16le(text)
    self.fixed[#self.fixed + 1] = wr_u16le(#raw)
    self.fixed[#self.fixed + 1] = wr_u16le(#raw + 2)
    self:defer(function()
      return wr_u32le(#text + 1) .. raw .. string.char(0, 0)
    end)
    return self
  end

  -- "[in, out] ULONG *": referent in the fixed part, value deferred. The
  -- request carries the offered value; the response carries the negotiated
  -- one, which is why both directions marshal it the same way.
  function encoder:inout_u32(value)
    self:defer(function()
      return wr_u32le(value)
    end)
    return self
  end

  function encoder:finish()
    -- Pass one: the size of the fixed part fixes the offset of the first
    -- referent; each deferred block then pushes the next one along.
    local fixed_size = 0
    for _, entry in ipairs(self.fixed) do
      fixed_size = fixed_size + (type(entry) == "string" and #entry or 4)
    end
    local payloads, sizes, offsets = {}, {}, {}
    local offset = fixed_size
    for index, entry in ipairs(self.deferred) do
      local data = entry.writer()
      payloads[index] = data
      sizes[index] = #data + wrap4(#data)
      offsets[index] = offset
      offset = offset + sizes[index]
    end
    -- Pass two: emit the fixed part with the referents stamped, then the
    -- deferred blocks in referent order with their alignment padding.
    local parts = {}
    local slot = 0
    for _, entry in ipairs(self.fixed) do
      if type(entry) == "string" then
        parts[#parts + 1] = entry
      else
        slot = slot + 1
        parts[#parts + 1] = wr_u32le(ndr.REFERENT_BASE + offsets[slot])
      end
    end
    for index = 1, #payloads do
      parts[#parts + 1] = payloads[index]
      local padding = sizes[index] - #payloads[index]
      if padding > 0 then
        parts[#parts + 1] = string.rep("\0", padding)
      end
    end
    return table.concat(parts)
  end

  return encoder
end

-- Reader for NDR buffers, used by the response parsers. It is deliberately
-- tolerant: every read returns nil plus a reason instead of raising, because
-- a malformed response must degrade into an explicit "unparsable" finding.
function ndr.new_reader(data)
  local reader = { data = data, pos = 1 }

  function reader:remaining()
    return #self.data - self.pos + 1
  end

  function reader:u8()
    local value, err = rd_u8(self.data, self.pos)
    if not value then
      return nil, err
    end
    self.pos = self.pos + 1
    return value
  end

  function reader:u16()
    local value, err = rd_u16le(self.data, self.pos)
    if not value then
      return nil, err
    end
    self.pos = self.pos + 2
    return value
  end

  function reader:u32()
    local value, err = rd_u32le(self.data, self.pos)
    if not value then
      return nil, err
    end
    self.pos = self.pos + 4
    return value
  end

  function reader:bytes(count)
    if self:remaining() < count then
      return nil, string.format("truncated: wanted %d bytes at offset %d, %d remain",
        count, self.pos - 1, self:remaining())
    end
    local out = string.sub(self.data, self.pos, self.pos + count - 1)
    self.pos = self.pos + count
    return out
  end

  function reader:align4()
    local padding = wrap4(self.pos - 1)
    if self:remaining() < padding then
      return nil, "truncated: alignment padding missing"
    end
    self.pos = self.pos + padding
    return true
  end

  -- Read a unique wchar string: header, then follow the referent.
  function reader:wstring()
    local length, err = self:u16()
    if not length then
      return nil, err
    end
    local maximum, err2 = self:u16()
    if not maximum then
      return nil, err2
    end
    local referent, err3 = self:u32()
    if not referent then
      return nil, err3
    end
    local return_pos = self.pos
    if referent == ndr.NULL_REFERENT then
      return "", length, maximum
    end
    self.pos = referent - ndr.REFERENT_BASE + 1
    local chars, err4 = self:bytes(length)
    if not chars then
      self.pos = return_pos
      return nil, err4
    end
    self.pos = return_pos
    return utf16le_to_string(chars), length, maximum
  end

  return reader
end

M.ndr = ndr

-- ---------------------------------------------------------------------------
-- 8. MS-NRPC call marshalling
-- ---------------------------------------------------------------------------

local netlogon = {}

-- Opnums actually marshalled by this library. NetrServerPasswordSet2 (30) and
-- every other state changing call are intentionally not implemented; the
-- highest opnum below is NetrServerAuthenticate3.
netlogon.OPNUM = {
  NETR_SERVER_REQ_CHALLENGE = 4,
  NETR_SERVER_AUTHENTICATE = 8,
  NETR_SERVER_AUTHENTICATE2 = 15,
  NETR_LOGON_CONTROL2_EX = 18,
  NETR_SERVER_GET_INFO = 21,
  NETR_SERVER_AUTHENTICATE3 = 26,
  NETR_SERVER_PASSWORD_SET2 = 30,
}

-- [MS-NRPC] 2.2.1.3.13 NETLOGON_SECURE_CHANNEL_TYPE. ServerSecureChannel (6)
-- is the channel a backup DC uses towards a PDC; it is also the value the
-- published secure channel testers send, because it is accepted by every
-- Windows DC version that implements the handshake.
netlogon.SECURE_CHANNEL = {
  { value = 0, name = "NullSecureChannel", usable = false, note = "rejected with STATUS_INVALID_PARAMETER" },
  { value = 1, name = "MsvApSecureChannel", usable = false, note = "local only" },
  { value = 2, name = "WorkstationSecureChannel", usable = true, note = "domain member to DC" },
  { value = 3, name = "TrustedDnsDomainSecureChannel", usable = true, note = "DC to DC through a DNS trust" },
  { value = 4, name = "TrustedDomainSecureChannel", usable = true, note = "DC to DC through a NetBIOS trust" },
  { value = 5, name = "UasServerSecureChannel", usable = false, note = "removed from the protocol" },
  { value = 6, name = "ServerSecureChannel", usable = true, note = "backup DC to PDC, the value testers use" },
  { value = 7, name = "CdcServerSecureChannel", usable = true, note = "RODC to DC" },
}

netlogon.SECURE_CHANNEL_TYPES = {}
for _, entry in ipairs(netlogon.SECURE_CHANNEL) do
  netlogon.SECURE_CHANNEL_TYPES[entry.name] = entry.value
end

-- [MS-NRPC] 3.1.4.2 Netlogon Negotiable Options. The letter in the comment is
-- the bit identifier used by the specification's table, so a reader can check
-- any entry against the document without translating names first.
netlogon.NEG = {
  { flag = 0x00000001, bit = "A", name = "RESERVED_A", meaning = "not used; ignored on receipt" },
  { flag = 0x00000002, bit = "B", name = "PERSISTENT_SAMREPL", meaning = "BDC keeps retrying SAM replication" },
  { flag = 0x00000004, bit = "C", name = "ARCFOUR", meaning = "RC4 encryption supported" },
  { flag = 0x00000008, bit = "D", name = "RESERVED_D", meaning = "not used; ignored on receipt" },
  { flag = 0x00000010, bit = "E", name = "CHANGELOG_BDC", meaning = "BDC handles changelogs" },
  { flag = 0x00000020, bit = "F", name = "FULL_SYNC_REPL", meaning = "restartable full sync" },
  { flag = 0x00000040, bit = "G", name = "NO_VALIDATION_LEVEL2", meaning = "no validation level 2 for non-generic passthrough" },
  { flag = 0x00000080, bit = "H", name = "DATABASE_REDO", meaning = "NetrDatabaseRedo supported" },
  { flag = 0x00000100, bit = "I", name = "PASSWORD_CHANGE_REFUSAL", meaning = "password changes can be refused" },
  { flag = 0x00000200, bit = "J", name = "LOGON_SEND_TO_SAM", meaning = "NetrLogonSendToSam supported" },
  { flag = 0x00000400, bit = "K", name = "GENERIC_PASSTHROUGH", meaning = "generic pass-through authentication" },
  { flag = 0x00000800, bit = "L", name = "CONCURRENT_RPC", meaning = "concurrent RPC calls" },
  { flag = 0x00001000, bit = "M", name = "AVOID_USER_DB_REPL", meaning = "server-to-server only" },
  { flag = 0x00002000, bit = "N", name = "AVOID_SA_DB_REPL", meaning = "server-to-server only" },
  { flag = 0x00004000, bit = "O", name = "STRONG_KEYS", meaning = "strong keys supported" },
  { flag = 0x00008000, bit = "P", name = "TRANSITIVE_TRUSTS", meaning = "transitive trusts supported" },
  { flag = 0x00010000, bit = "Q", name = "RESERVED_Q", meaning = "not used; ignored on receipt" },
  { flag = 0x00020000, bit = "R", name = "PASSWORD_SET2", meaning = "NetrServerPasswordSet2 supported" },
  { flag = 0x00040000, bit = "S", name = "LOGON_GET_DOMAIN_INFO", meaning = "NetrLogonGetDomainInfo supported" },
  { flag = 0x00080000, bit = "T", name = "CROSS_FOREST_TRUSTS", meaning = "cross forest trusts supported" },
  { flag = 0x00100000, bit = "U", name = "IGNORE_NT4_EMULATOR", meaning = "server ignores the NT4Emulator behaviour" },
  { flag = 0x00200000, bit = "V", name = "RODC_PASSTHROUGH", meaning = "RODC pass-through to other domains" },
  { flag = 0x01000000, bit = "W", name = "AES_SHA2", meaning = "AES-128-CFB8 and SHA2 are available (the Zerologon cipher)" },
  { flag = 0x20000000, bit = "X", name = "RESERVED_X", meaning = "not used; ignored on receipt" },
  { flag = 0x40000000, bit = "Y", name = "SECURE_RPC", meaning = "secure RPC (signing and sealing) is supported" },
  { flag = u32(0x80000000), bit = "Z", name = "KERBEROS_SSP", meaning = "Kerberos is the SSP for secure channel setup" },
}

-- The flag set the published ZeroLogon testers send: every low option up to
-- bit T, plus RODC passthrough and AES, with secure RPC (Y) deliberately
-- absent. It is not a magic value: the AES bit is what makes the server choose
-- the AES-CFB8 credential computation, and the missing Y bit is what keeps the
-- channel unsealed.
netlogon.NEG_PROBE_LEGACY = 0x000FFFFF + 0x00200000 + 0x01000000 + 0x20000000
-- The same probe with secure RPC requested, used to separate "patched" from
-- "patched and enforcing": before the August 2020 update the Y bit changed
-- nothing, after it the server can refuse a channel that does not qualify.
netlogon.NEG_PROBE_SECURE_RPC = netlogon.NEG_PROBE_LEGACY + 0x40000000

function netlogon.describe_neg(mask)
  local names = {}
  for _, entry in ipairs(netlogon.NEG) do
    if bits.test(mask, entry.flag) then
      names[#names + 1] = string.format("%s (%s)", entry.name, entry.bit)
    end
  end
  return names
end

-- NTSTATUS values a secure channel probe can meet, with the interpretation
-- that makes the result actionable. STATUS_SUCCESS is the only code that
-- proves the all-zero credential was accepted.
netlogon.NTSTATUS = {
  { code = u32(0x00000000), name = "STATUS_SUCCESS", class = "accepted",
    meaning = "the server accepted the credential (the all-zero credential in a probe) and completed the handshake" },
  { code = u32(0xC0000022), name = "STATUS_ACCESS_DENIED", class = "refused",
    meaning = "the server refused the secure channel: unpatched servers do this when the account is missing, patched servers also do it for a vulnerable connection that enforcement is not blocking" },
  { code = u32(0xC0000388), name = "STATUS_DOWNGRADE_DETECTED", class = "refused-strong",
    meaning = "the server requires a stronger secure channel than the one offered; a domain controller in enforcement mode answers this way" },
  { code = u32(0xC000000D), name = "STATUS_INVALID_PARAMETER", class = "malformed",
    meaning = "a parameter was rejected: wrong channel type, empty account name, or a credential the server could not use" },
  { code = u32(0xC00000BB), name = "STATUS_NOT_SUPPORTED", class = "unsupported",
    meaning = "the server does not implement this call; retry with the older NetrServerAuthenticate2 form" },
  { code = u32(0xC0000073), name = "STATUS_NONE_MAPPED", class = "no-account",
    meaning = "the named account does not exist in the domain" },
  { code = u32(0xC0000034), name = "STATUS_OBJECT_NAME_NOT_FOUND", class = "no-account",
    meaning = "the named account does not exist in the domain" },
  { code = u32(0xC000006D), name = "STATUS_LOGON_FAILURE", class = "refused",
    meaning = "the credential did not match what the server computed" },
  { code = u32(0xC000006E), name = "STATUS_ACCOUNT_RESTRICTION", class = "refused",
    meaning = "policy blocks the account on this channel" },
  { code = u32(0xC0000072), name = "STATUS_ACCOUNT_DISABLED", class = "refused",
    meaning = "the machine account is disabled" },
  { code = u32(0xC0000234), name = "STATUS_ACCOUNT_LOCKED_OUT", class = "refused",
    meaning = "the machine account is locked out: stop probing and let the lockout expire" },
  { code = u32(0xC000018B), name = "STATUS_NO_TRUST_SAM_ACCOUNT", class = "no-account",
    meaning = "no trust account for the requested principal" },
  { code = u32(0xC000015B), name = "STATUS_LOGON_TYPE_NOT_GRANTED", class = "refused",
    meaning = "the account may not log on this way" },
  { code = u32(0xC000005E), name = "STATUS_NO_LOGON_SERVERS", class = "server-side",
    meaning = "the server cannot reach a logon server for the requested domain" },
  { code = u32(0xC00000A5), name = "STATUS_BAD_IMPERSONATION_LEVEL", class = "refused",
    meaning = "the impersonation level of the caller is insufficient" },
  { code = u32(0xC000009A), name = "STATUS_INSUFFICIENT_RESOURCES", class = "server-side",
    meaning = "the server ran out of resources" },
}

netlogon.NTSTATUS_BY_NAME = {}
for _, entry in ipairs(netlogon.NTSTATUS) do
  netlogon.NTSTATUS_BY_NAME[entry.name] = entry.code
end

function netlogon.status_entry(code)
  if code == nil then
    return nil
  end
  code = u32(code)
  for _, entry in ipairs(netlogon.NTSTATUS) do
    if entry.code == code then
      return entry
    end
  end
  return nil
end

function netlogon.status_text(code)
  local entry = netlogon.status_entry(code)
  if not entry then
    return string.format("NTSTATUS 0x%s (unlisted)", hex32(code))
  end
  return string.format("%s (0x%s): %s", entry.name, hex32(code), entry.meaning)
end

function netlogon.status_name(code)
  local entry = netlogon.status_entry(code)
  if entry then
    return entry.name
  end
  return "0x" .. hex32(code or 0)
end

-- NetrServerReqChallenge (opnum 4), [MS-NRPC] 3.5.4.4.2:
--   NTSTATUS NetrServerReqChallenge(
--     [in] LOGONSRV_HANDLE PrimaryName, [in] PNETLOGON_CREDENTIAL ComputerName,
--     [in] PNETLOGON_CREDENTIAL ClientChallenge,
--     [out] PNETLOGON_CREDENTIAL ServerChallenge)
function netlogon.server_req_challenge(primary_name, computer_name, client_challenge)
  local encoder, err = ndr.new_encoder()
  if not encoder then
    return nil, err
  end
  encoder:unique_wstring(primary_name)
  encoder:unique_wstring(computer_name)
  encoder:fixed_bytes(client_challenge, 8)
  encoder:align4()
  return encoder:finish()
end

function netlogon.parse_server_req_challenge(payload)
  local reader = ndr.new_reader(payload)
  local challenge, err = reader:bytes(8)
  if not challenge then
    return nil, string.format("ServerChallenge not present: %s", tostring(err))
  end
  return { server_challenge = challenge, server_challenge_hex = hex(challenge) }
end

-- NetrServerAuthenticate3 (opnum 26), [MS-NRPC] 3.5.4.4.4. The trailing
-- AccountRid is an [out] pointer and is sent as a null referent.
function netlogon.server_authenticate3(opts)
  local encoder = ndr.new_encoder()
  encoder:unique_wstring(opts.primary_name or "")
  encoder:unique_wstring(opts.account_name or "")
  encoder:u16(opts.secure_channel_type or netlogon.SECURE_CHANNEL_TYPES.ServerSecureChannel)
  encoder:align4()
  encoder:unique_wstring(opts.computer_name or "")
  encoder:fixed_bytes(opts.client_credential or string.rep("\0", 8), 8)
  encoder:u32(opts.negotiate_flags or 0)
  encoder:null_pointer()
  encoder:align4()
  return encoder:finish()
end

-- NetrServerAuthenticate2 (opnum 15) has the same layout minus AccountRid.
function netlogon.server_authenticate2(opts)
  local encoder = ndr.new_encoder()
  encoder:unique_wstring(opts.primary_name or "")
  encoder:unique_wstring(opts.account_name or "")
  encoder:u16(opts.secure_channel_type or netlogon.SECURE_CHANNEL_TYPES.ServerSecureChannel)
  encoder:align4()
  encoder:unique_wstring(opts.computer_name or "")
  encoder:fixed_bytes(opts.client_credential or string.rep("\0", 8), 8)
  encoder:u32(opts.negotiate_flags or 0)
  encoder:align4()
  return encoder:finish()
end

-- Response: ServerCredential (8 bytes), NegotiatedFlags (DWORD), and for the
-- Authenticate3 form the AccountRid (DWORD) plus the trailing NTSTATUS that
-- the IDL declares as the return value.
local function parse_authenticate_response(payload, with_rid)
  local reader = ndr.new_reader(payload)
  local credential, err = reader:bytes(8)
  if not credential then
    return nil, string.format("ServerCredential not present: %s", tostring(err))
  end
  local flags, err2 = reader:u32()
  if not flags then
    return nil, string.format("NegotiatedFlags not present: %s", tostring(err2))
  end
  local out = {
    server_credential = credential,
    server_credential_hex = hex(credential),
    negotiated_flags = flags,
    negotiated_flag_names = netlogon.describe_neg(flags),
  }
  if with_rid then
    local rid, err3 = reader:u32()
    if not rid then
      return nil, string.format("AccountRid not present: %s", tostring(err3))
    end
    out.account_rid = rid
  end
  local status = reader:u32()
  if status then
    out.error_code = status
    out.error_name = netlogon.status_name(status)
    out.error_text = netlogon.status_text(status)
    out.error_class = (netlogon.status_entry(status) or {}).class or "unlisted"
  end
  return out
end

function netlogon.parse_server_authenticate3(payload)
  return parse_authenticate_response(payload, true)
end

function netlogon.parse_server_authenticate2(payload)
  return parse_authenticate_response(payload, false)
end

-- The NP_* codes a bind or call can fail with, kept next to the status table
-- because a script reports both in one findings list.
netlogon.RPC_FAULT = {
  { code = 0x00000000, name = "rpc_s_ok" },
  { code = 0x00000005, name = "rpc_s_access_denied" },
  { code = 0x0000000E, name = "rpc_s_out_of_memory" },
  { code = 0x00000016, name = "rpc_s_protseq_not_supported" },
  { code = 0x0000001F, name = "rpc_s_interface_not_found" },
  { code = 0x000006B5, name = "rpc_s_invalid_binding" },
  { code = 0x000006BA, name = "rpc_s_server_unavailable" },
  { code = 0x000006BE, name = "rpc_s_unknown_if" },
  { code = 0x000006F7, name = "rpc_s_call_failed_dne" },
}

function netlogon.fault_name(code)
  for _, entry in ipairs(netlogon.RPC_FAULT) do
    if entry.code == code then
      return entry.name
    end
  end
  return "rpc_s_unknown"
end

M.netlogon = netlogon

-- ---------------------------------------------------------------------------
-- 9. Convenience: the whole pipe sequence in one call
-- ---------------------------------------------------------------------------

-- Connect, negotiate, establish a null session, open \netlogon and bind the
-- Netlogon interface. Returns a session record with the channel, the collected
-- evidence and an explicit failure reason, so a script can report the exact
-- stage that stopped it. Nothing is called through the channel here.
function M.open_netlogon_pipe(host, port, opts)
  opts = opts or {}
  local port_number = type(port) == "table" and port.number or port
  local record = {
    host = host,
    port = port_number,
    port_table = type(port) == "table" and port or nil,
    stages = {},
    failure = nil,
  }

  local function stage(name, ok, detail)
    record.stages[#record.stages + 1] = {
      name = name,
      ok = ok and true or false,
      detail = detail,
    }
    return ok
  end

  local client = smb2.new_client(host, port, opts)
  record.client = client

  local ok, err = client:connect()
  if not ok then
    record.failure = { stage = "tcp", reason = err and err[1] or "connect", text = err and err[2] or "connection failed" }
    stage("TCP connect to port " .. tostring(port_number or 445), false, record.failure.text)
    return record
  end
  stage("TCP connect to port " .. tostring(port_number or 445), true, "socket open")

  client.opts.client_guid = opts.client_guid or string.rep("\0", 16)
  local negotiate, nerr = client:negotiate()
  if not negotiate then
    record.failure = { stage = "negotiate", reason = nerr and nerr.reason, text = nerr and nerr.text }
    stage("SMB2 NEGOTIATE", false, nerr and nerr.text)
    client:close()
    return record
  end
  record.negotiate = negotiate
  stage("SMB2 NEGOTIATE", true, string.format("dialect %s, signing %s, max read %d",
    negotiate.dialect_label,
    negotiate.signing_required and "required" or (negotiate.signing_enabled and "enabled" or "off"),
    negotiate.max_read_size or 0))

  local session, serr = client:session_setup_anonymous()
  if not session then
    record.failure = {
      stage = "session-setup",
      reason = serr and serr.reason,
      text = serr and serr.text,
      status = serr and serr.status,
    }
    stage("SMB2 anonymous SESSION_SETUP", false, serr and serr.text)
    client:close()
    return record
  end
  record.session = session
  stage("SMB2 anonymous SESSION_SETUP", true,
    session.null_session and "the server granted a null session" or "the server granted a session")
  record.smb_session_key_absent = true

  local share = opts.share or "IPC$"
  -- The share path names the server, and a server only answers to the names it
  -- owns. The client therefore starts with the name the caller supplied (or
  -- the target as addressed) and, when the server answers BAD_NETWORK_NAME and
  -- has just told us its computer name in the NTLMSSP challenge, retries with
  -- that name. Without this, a probe that reaches the session stage would
  -- report a share error for what is really a naming mismatch.
  local host_table = type(host) == "table" and host or nil
  local initial_name = opts.server_name
    or (host_table and (host_table.name or host_table.targetname))
    or (host_table and host_table.ip)
    or tostring(host)
  local function tree_attempt(name)
    local path = string.format("\\\\%s\\%s", name, share)
    local tree, terr = client:tree_connect(path)
    return tree, terr, path
  end

  local tree, terr, share_path = tree_attempt(initial_name)
  if not tree and record.session and record.session.challenge
    and record.session.challenge.computer_name and #record.session.challenge.computer_name > 0 then
    local learned = string.upper(record.session.challenge.computer_name)
    if learned ~= string.upper(tostring(initial_name)) then
      stage("TREE_CONNECT retry", true,
        string.format("the first attempt addressed %s; the server disclosed its name as %s, retrying", tostring(initial_name), learned))
      tree, terr, share_path = tree_attempt(learned)
      if tree then
        record.server_name = learned
      end
    end
  end
  if not tree then
    record.failure = {
      stage = "tree-connect",
      reason = terr and terr.reason,
      text = terr and terr.text,
      status = terr and terr.status,
    }
    stage("TREE_CONNECT " .. tostring(share_path), false, terr and terr.text)
    client:logoff()
    client:close()
    return record
  end
  record.server_name = record.server_name or initial_name
  record.tree = tree
  stage("TREE_CONNECT " .. share_path, true, string.format("share type: %s", tree.share_type_label))

  local pipe_name = opts.pipe or "netlogon"
  local pipe, perr = client:open_pipe(pipe_name)
  if not pipe then
    record.failure = {
      stage = "pipe-open",
      reason = perr and perr.reason,
      text = perr and perr.text,
      status = perr and perr.status,
    }
    stage("CREATE " .. pipe_name .. " (pipe-open stage)", false, perr and perr.text)
    client:logoff()
    client:close()
    return record
  end
  record.pipe = pipe
  stage("CREATE " .. pipe_name .. " (pipe-open stage)", true, "pipe handle acquired")

  local channel = dcerpc.new_channel(client, {})
  local ack, aerr = channel:bind({
    abstract_syntax = dcerpc.UUID.NETLOGON,
    major = dcerpc.NETLOGON_VERSION.major,
    minor = dcerpc.NETLOGON_VERSION.minor,
  })
  if not ack then
    record.failure = {
      stage = "dcerpc-bind",
      reason = aerr and aerr.reason,
      text = aerr and aerr.text,
      status = aerr and aerr.status,
    }
    stage("DCE/RPC BIND Netlogon 1.0", false, aerr and aerr.text)
    channel:close()
    client:logoff()
    client:close()
    return record
  end
  record.bind = ack
  record.channel = channel
  stage("DCE/RPC BIND Netlogon 1.0", true, string.format("accepted=%s assoc_group=0x%04X",
    tostring(ack.accepted), ack.assoc_group or 0))

  return record
end

-- Close the pipe, log off and drop the socket without raising, whatever state
-- the session is in. Returns the number of teardown steps that succeeded.
function M.close_netlogon_pipe(record)
  local closed = 0
  if record and record.channel then
    local ok = record.channel:close()
    if ok then
      closed = closed + 1
    end
  end
  if record and record.client then
    if record.client:logoff() then
      closed = closed + 1
    end
    record.client:close()
    closed = closed + 1
  end
  return closed
end

-- One authenticated exchange pair against the Netlogon pipe, used by the
-- scripts to make a statement about a single measurement instead of repeating
-- the transport logic.
--
-- Returns a measurement record:
--   { challenge = <8 bytes>|nil, authenticate = <table>|nil,
--     status = <NTSTATUS number>|nil, failure = {...}|nil }
function M.probe_zero_credential(record, opts)
  opts = opts or {}
  local measurement = {
    stage = opts.label or "zero-credential probe",
    negotiate_flags = opts.negotiate_flags or netlogon.NEG_PROBE_LEGACY,
    client_challenge_hex = hex(opts.client_challenge or string.rep("\0", 8)),
  }
  local channel = record.channel
  if not channel then
    measurement.failure = { stage = "state", reason = "no-channel", text = "no Netlogon channel is bound" }
    return measurement
  end
  local payload, status, failure = channel:call(netlogon.OPNUM.NETR_SERVER_REQ_CHALLENGE,
    netlogon.server_req_challenge(opts.primary_name or "", opts.computer_name or "",
      opts.client_challenge or string.rep("\0", 8)),
    "NetrServerReqChallenge")
  if not payload then
    measurement.failure = failure or { stage = "challenge", reason = "no-payload", text = "empty response" }
    return measurement
  end
  local challenge, err = netlogon.parse_server_req_challenge(payload)
  if not challenge then
    measurement.failure = { stage = "challenge-parse", reason = "decode", text = err }
    return measurement
  end
  measurement.challenge = challenge

  local auth_stub, auth_status, auth_failure = channel:call(netlogon.OPNUM.NETR_SERVER_AUTHENTICATE3,
    netlogon.server_authenticate3({
      primary_name = opts.primary_name or "",
      account_name = opts.account_name or "",
      computer_name = opts.computer_name or "",
      secure_channel_type = opts.secure_channel_type or netlogon.SECURE_CHANNEL_TYPES.ServerSecureChannel,
      client_credential = opts.client_credential or string.rep("\0", 8),
      negotiate_flags = measurement.negotiate_flags,
    }),
    "NetrServerAuthenticate3")
  if not auth_stub then
    measurement.failure = auth_failure or { stage = "authenticate", reason = "no-payload", text = "empty response" }
    measurement.status = auth_status
    return measurement
  end
  local authenticate, err2 = netlogon.parse_server_authenticate3(auth_stub)
  if not authenticate then
    measurement.failure = { stage = "authenticate-parse", reason = "decode", text = err2 }
    return measurement
  end
  measurement.authenticate = authenticate
  measurement.status = authenticate.error_code
  return measurement
end

-- The same exchange through the older NetrServerAuthenticate2 call, offered as
-- a fallback for implementations that reject opnum 26 with STATUS_NOT_SUPPORTED.
function M.probe_zero_credential_v2(record, opts)
  opts = opts or {}
  local measurement = {
    stage = (opts.label or "zero-credential probe") .. " (Authenticate2)",
    negotiate_flags = opts.negotiate_flags or netlogon.NEG_PROBE_LEGACY,
    client_challenge_hex = hex(opts.client_challenge or string.rep("\0", 8)),
  }
  local channel = record.channel
  if not channel then
    measurement.failure = { stage = "state", reason = "no-channel", text = "no Netlogon channel is bound" }
    return measurement
  end
  local payload, status, failure = channel:call(netlogon.OPNUM.NETR_SERVER_REQ_CHALLENGE,
    netlogon.server_req_challenge(opts.primary_name or "", opts.computer_name or "",
      opts.client_challenge or string.rep("\0", 8)),
    "NetrServerReqChallenge")
  if not payload then
    measurement.failure = failure or { stage = "challenge", reason = "no-payload", text = "empty response" }
    return measurement
  end
  local challenge, err = netlogon.parse_server_req_challenge(payload)
  if not challenge then
    measurement.failure = { stage = "challenge-parse", reason = "decode", text = err }
    return measurement
  end
  measurement.challenge = challenge
  local auth_stub, auth_status, auth_failure = channel:call(netlogon.OPNUM.NETR_SERVER_AUTHENTICATE2,
    netlogon.server_authenticate2({
      primary_name = opts.primary_name or "",
      account_name = opts.account_name or "",
      computer_name = opts.computer_name or "",
      secure_channel_type = opts.secure_channel_type or netlogon.SECURE_CHANNEL_TYPES.ServerSecureChannel,
      client_credential = opts.client_credential or string.rep("\0", 8),
      negotiate_flags = measurement.negotiate_flags,
    }),
    "NetrServerAuthenticate2")
  if not auth_stub then
    measurement.failure = auth_failure or { stage = "authenticate", reason = "no-payload", text = "empty response" }
    measurement.status = auth_status
    return measurement
  end
  local authenticate, err2 = netlogon.parse_server_authenticate2(auth_stub)
  if not authenticate then
    measurement.failure = { stage = "authenticate-parse", reason = "decode", text = err2 }
    return measurement
  end
  measurement.authenticate = authenticate
  measurement.status = authenticate.error_code
  return measurement
end

return M
