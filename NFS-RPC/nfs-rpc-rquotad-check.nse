local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Queries rquotad (100011) GETQUOTA for a sample UID and reports whether
disk quota accounting is disclosed, including over-quota usage.

Why it matters
- Quota values expose user activity levels and filesystem sizing,
  useful for planning resource-exhaustion abuse.
- An over-soft-quota answer proves the quota system is actively
  enforced and its limits are readable.

What the script does
1. Looks up rquotad in the rpcbind map.
2. Sends GETQUOTA for the export and sample UID 1000.
3. Reports the quota profile.

Safe operation: one read-only quota query.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
  111,
  "rpcbind",
  {"tcp"}
)

local SCRIPT_NAME = "nfs-rpc-rquotad-check"

local RISK_LEVEL = "🟡 MEDIUM"

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

NFS_T = {}

NFS_T.RPC_VERS = 2

NFS_T.MSG_CALL = 0
NFS_T.MSG_REPLY = 1

NFS_T.AUTH_NULL = 0
NFS_T.AUTH_SYS = 1
NFS_T.AUTH_SHORT = 2
NFS_T.AUTH_DES = 3
NFS_T.AUTH_KRB5 = 4
NFS_T.RPCSEC_GSS = 6

NFS_T.AUTH_NAMES = {
  [0] = "AUTH_NULL",
  [1] = "AUTH_SYS",
  [2] = "AUTH_SHORT",
  [3] = "AUTH_DES",
  [4] = "AUTH_KRB5",
  [6] = "RPCSEC_GSS",
}

NFS_T.AUTH_STATS = {
  [0] = "AUTH_OK",
  [1] = "AUTH_BADCRED",
  [2] = "AUTH_REJECTEDCRED",
  [3] = "AUTH_BADVERF",
  [4] = "AUTH_REJECTEDVERF",
  [5] = "AUTH_TOOWEAK",
  [6] = "AUTH_INVALIDRESP",
  [7] = "AUTH_REJECTEDCRED_ALIAS",
}

NFS_T.ACCEPT_STATS = {
  [0] = "SUCCESS",
  [1] = "PROG_UNAVAIL",
  [2] = "PROG_MISMATCH",
  [3] = "PROC_UNAVAIL",
  [4] = "GARBAGE_ARGS",
  [5] = "SYSTEM_ERR",
}

NFS_T.REJECT_STATS = {
  [0] = "RPC_MISMATCH",
  [1] = "AUTH_ERROR",
}

NFS_T.PROG_PORTMAP = 100000
NFS_T.PROG_NFS = 100003
NFS_T.PROG_MOUNT = 100005
NFS_T.PROG_NLOCKMGR = 100021
NFS_T.PROG_RQUOTA = 100011
NFS_T.PROG_RUSERS = 100002
NFS_T.PROG_YPBIND = 100007
NFS_T.PROG_STATD = 100024
NFS_T.PROG_SPRAY = 100012

NFS_T.PROG_NAMES = {
  [100000] = "portmap/rpcbind",
  [100003] = "nfs",
  [100005] = "mountd",
  [100021] = "nlockmgr",
  [100011] = "rquotad",
  [100002] = "rusersd",
  [100007] = "ypbind",
  [100024] = "statd",
  [100012] = "sprayd",
  [100026] = "ypupdated",
  [100028] = "ypxfrd",
  [100068] = "cachefsd",
  [100083] = "ttdbserverd",
  [300019] = "amd",
  [100029] = "rexd",
}

NFS_T.PROT_TCP = 6
NFS_T.PROT_UDP = 17
NFS_T.PROT_NAMES = { [6] = "tcp", [17] = "udp" }

NFS_T.PMAP_GETPORT = 3
NFS_T.PMAP_DUMP = 4
NFS_T.PMAP_CALLIT = 5

NFS_T.MOUNT_V1 = 1
NFS_T.MOUNT_V3 = 3
NFS_T.MOUNTPROC_NULL = 0
NFS_T.MOUNTPROC_MNT = 1
NFS_T.MOUNTPROC_DUMP = 2
NFS_T.MOUNTPROC_UMNT = 3
NFS_T.MOUNTPROC_EXPORT = 5

NFS_T.MNT_ERRORS = {
  [0] = "MNT_OK",
  [1] = "MNT_PERM",
  [2] = "MNT3ERR_NOENT",
  [5] = "MNT3ERR_IO",
  [13] = "MNT3ERR_ACCES",
  [22] = "MNT3ERR_NOTDIR",
  [63] = "MNT3ERR_INVAL",
  [10004] = "MNT3ERR_SERVERFAULT",
}

NFS_T.NFS_V2 = 2
NFS_T.NFS_V3 = 3
NFS_T.NFS_V4 = 4

NFS_T.NFSPROC_NULL = 0
NFS_T.NFSPROC_GETATTR = 1
NFS_T.NFSPROC_LOOKUP = 3
NFS_T.NFSPROC_READLINK = 5
NFS_T.NFSPROC_FSSTAT = 18
NFS_T.NFSPROC_FSINFO = 14
NFS_T.NFSPROC_ACCESS = 23

NFS_T.NFS_ERRORS = {
  [0] = "NFS_OK",
  [1] = "NFSERR_PERM",
  [2] = "NFSERR_NOENT",
  [5] = "NFSERR_IO",
  [13] = "NFSERR_ACCES",
  [20] = "NFSERR_NOTDIR",
  [21] = "NFSERR_ISDIR",
  [22] = "NFSERR_INVAL",
  [70] = "NFSERR_FBIG",
  [10008] = "NFSERR_STALE",
  [10044] = "NFSERR_WFLUSH",
}

NFS_T.FTYPE_NAMES = {
  [1] = "REG",
  [2] = "DIR",
  [3] = "BLK",
  [4] = "CHR",
  [5] = "LNK",
  [6] = "SOCK",
  [7] = "FIFO",
}

NFS_T.NLM_V4 = 4
NFS_T.NLMPROC_NULL = 0
NFS_T.NLMPROC_TEST = 1
NFS_T.NLMPROC_LOCK = 2
NFS_T.NLMPROC_FREE_ALL = 23

NFS_T.RUSERS_V2 = 2
NFS_T.RUSERSPROC_NUM = 1
NFS_T.RUSERSPROC_NAMES = 2
NFS_T.RUSERSPROC_ALLNAMES = 3

NFS_T.RQUOTA_V1 = 1
NFS_T.RQUOTAPROC_GETQUOTA = 1
NFS_T.RQUOTAPROC_GETACTIVEQUOTA = 2
NFS_T.RQUOTA_OK = 1
NFS_T.RQUOTA_NOQUOTA = 2
NFS_T.RQUOTA_EPERM = 3

NFS_T.YPBIND_V2 = 2
NFS_T.YPBINDPROC_DOMAIN = 1
NFS_T.YPBINDPROC_SETDOMAIN = 5

NFS_T.STATD_V1 = 1
NFS_T.SM_STAT = 1
NFS_T.SM_MON = 2
NFS_T.SM_UNMON = 3
NFS_T.SM_UNMON_ALL = 4
NFS_T.SM_NOTIFY = 6

NFS_T.SPRAY_V1 = 1
NFS_T.SPRAYPROC_SPRAY = 1
NFS_T.SPRAYPROC_GET = 2

NFS_T.RM_LAST = 0x80000000

NFS_T.WEAK_MODE_WRITE = 0x0002
NFS_T.WEAK_MODE_READ = 0x0004

NFS_T.ANONYMOUS_UID = 65534
NFS_T.ROOT_UID = 0

NFS_X = {}

function NFS_X.u32_enc(v)
  return string.char(math.floor(v / 16777216) % 256, math.floor(v / 65536) % 256, math.floor(v / 256) % 256, v % 256)
end

function NFS_X.u32_dec(s, off)
  off = off or 1
  local a, b, c, d = string.byte(s, off, off + 3)
  if a == nil then
    return nil, off
  end
  return a * 16777216 + b * 65536 + c * 256 + d, off + 4
end

function NFS_X.u64_enc(hi, lo)
  return NFS_X.u32_enc(hi) .. NFS_X.u32_enc(lo or 0)
end

function NFS_X.u64_dec(s, off)
  local hi, o = NFS_X.u32_dec(s, off)
  if hi == nil then
    return nil, off
  end
  local lo, o2 = NFS_X.u32_dec(s, o)
  if lo == nil then
    return nil, off
  end
  return hi * 4294967296 + lo, o2
end

function NFS_X.bool_enc(v)
  if v then
    return NFS_X.u32_enc(1)
  end
  return NFS_X.u32_enc(0)
end

function NFS_X.bool_dec(s, off)
  local v, o = NFS_X.u32_dec(s, off)
  if v == nil then
    return nil, off
  end
  return v ~= 0, o
end

function NFS_X.opaque_pad(n)
  return (4 - (n % 4)) % 4
end

function NFS_X.string_enc(s)
  s = s or ""
  return NFS_X.u32_enc(#s) .. s .. string.rep("\0", NFS_X.opaque_pad(#s))
end

function NFS_X.string_dec(s, off)
  local n, o = NFS_X.u32_dec(s, off)
  if n == nil then
    return nil, off
  end
  if n > 0 and #s < o + n - 1 then
    return nil, off
  end
  local val = string.sub(s, o, o + n - 1)
  return val, o + n + NFS_X.opaque_pad(n)
end

function NFS_X.opaque_enc(b)
  b = b or ""
  return NFS_X.u32_enc(#b) .. b .. string.rep("\0", NFS_X.opaque_pad(#b))
end

NFS_X.opaque_dec = NFS_X.string_dec

function NFS_X.uint_array_enc(arr)
  local out = NFS_X.u32_enc(arr and #arr or 0)
  for _, v in ipairs(arr or {}) do
    out = out .. NFS_X.u32_enc(v)
  end
  return out
end

function NFS_X.uint_array_dec(s, off)
  local n, o = NFS_X.u32_dec(s, off)
  if n == nil then
    return nil, off
  end
  local out = {}
  for _ = 1, n do
    local v, o2 = NFS_X.u32_dec(s, o)
    if v == nil then
      return nil, off
    end
    out[#out + 1] = v
    o = o2
  end
  return out, o
end

function NFS_X.string_array_enc(arr)
  local out = NFS_X.u32_enc(arr and #arr or 0)
  for _, v in ipairs(arr or {}) do
    out = out .. NFS_X.string_enc(v)
  end
  return out
end

function NFS_X.string_array_dec(s, off)
  local n, o = NFS_X.u32_dec(s, off)
  if n == nil then
    return nil, off
  end
  local out = {}
  for _ = 1, n do
    local v, o2 = NFS_X.string_dec(s, o)
    if v == nil then
      return nil, off
    end
    out[#out + 1] = v
    o = o2
  end
  return out, o
end

function NFS_X.fhandle_enc(fh)
  fh = fh or ""
  return NFS_X.opaque_enc(fh)
end

NFS_X.fhandle_dec = NFS_X.string_dec

function NFS_X.rm_enc(payload, last)
  local flag = last and NFS_T.RM_LAST or 0
  return NFS_X.u32_enc(flag + #payload) .. payload
end

function NFS_X.rm_dec(s, off)
  off = off or 1
  local hdr, o = NFS_X.u32_dec(s, off)
  if hdr == nil then
    return nil, nil, false
  end
  local last = hdr >= 2147483648
  local len = hdr - (last and 2147483648 or 0)
  if #s < o - 1 + len then
    return nil, len, last, len
  end
  return string.sub(s, o, o + len - 1), o + len, last, len
end

function NFS_X.next_xid(seed)
  return (seed or 0) + 1
end

function NFS_X.mode_bits(mode)
  local out = {}
  out.octal = string.format("%04o", mode % 4096)
  out.owner_r = math.floor(mode / 256) % 2 == 1
  out.owner_w = math.floor(mode / 128) % 2 == 1
  out.owner_x = math.floor(mode / 64) % 2 == 1
  out.group_r = math.floor(mode / 32) % 2 == 1
  out.group_w = math.floor(mode / 16) % 2 == 1
  out.group_x = math.floor(mode / 8) % 2 == 1
  out.other_r = math.floor(mode / 4) % 2 == 1
  out.other_w = math.floor(mode / 2) % 2 == 1
  out.other_x = mode % 2 == 1
  out.setuid = math.floor(mode / 2048) % 2 == 1
  out.setgid = math.floor(mode / 1024) % 2 == 1
  out.sticky = math.floor(mode / 512) % 2 == 1
  out.world_read = out.other_r
  out.world_write = out.other_w
  return out
end

function NFS_X.entropy_estimate(data)
  local seen = {}
  local distinct = 0
  local zeros = 0
  local maxrun = 0
  local run = 0
  local prev = nil
  for i = 1, #data do
    local b = string.byte(data, i, i)
    if not seen[b] then
      seen[b] = true
      distinct = distinct + 1
    end
    if b == 0 then
      zeros = zeros + 1
      run = run + 1
      if run > maxrun then
        maxrun = run
      end
    else
      run = 0
    end
    prev = b
  end
  return {
    distinct_bytes = distinct,
    zero_bytes = zeros,
    max_zero_run = maxrun,
    length = #data,
    high_entropy = distinct >= 16 and maxrun <= 2,
  }
end

NFS_B = {}

function NFS_B.cred(flavor, opaque)
  return NFS_X.u32_enc(flavor or NFS_T.AUTH_NULL) .. NFS_X.opaque_enc(opaque or "")
end

function NFS_B.authsys(stamp, machname, uid, gid, gids)
  return NFS_X.u32_enc(stamp or 1) .. NFS_X.string_enc(machname or "nse-audit") ..
    NFS_X.u32_enc(uid or NFS_T.ANONYMOUS_UID) .. NFS_X.u32_enc(gid or NFS_T.ANONYMOUS_UID) ..
    NFS_X.uint_array_enc(gids or {})
end

function NFS_B.rpc_call(xid, prog, vers, proc, cred_flavor, cred_opaque, payload)
  return NFS_X.u32_enc(xid) .. NFS_X.u32_enc(NFS_T.MSG_CALL) .. NFS_X.u32_enc(NFS_T.RPC_VERS) ..
    NFS_X.u32_enc(prog) .. NFS_X.u32_enc(vers) .. NFS_X.u32_enc(proc) ..
    NFS_B.cred(cred_flavor, cred_opaque) .. NFS_B.cred(NFS_T.AUTH_NULL, "") .. (payload or "")
end

function NFS_B.rm_call(xid, prog, vers, proc, cred_flavor, cred_opaque, payload)
  return NFS_X.rm_enc(NFS_B.rpc_call(xid, prog, vers, proc, cred_flavor, cred_opaque, payload), true)
end

function NFS_B.pmap_getport(xid, prog, vers, prot)
  return NFS_B.rm_call(xid, NFS_T.PROG_PORTMAP, 2, NFS_T.PMAP_GETPORT, NFS_T.AUTH_NULL, "",
    NFS_X.u32_enc(prog) .. NFS_X.u32_enc(vers) .. NFS_X.u32_enc(prot or NFS_T.PROT_TCP) .. NFS_X.u32_enc(0))
end

function NFS_B.pmap_dump(xid)
  return NFS_B.rm_call(xid, NFS_T.PROG_PORTMAP, 2, NFS_T.PMAP_DUMP, NFS_T.AUTH_NULL, "", "")
end

function NFS_B.pmap_callit(xid, prog, vers, proc, args)
  return NFS_B.rm_call(xid, NFS_T.PROG_PORTMAP, 2, NFS_T.PMAP_CALLIT, NFS_T.AUTH_NULL, "",
    NFS_X.u32_enc(prog) .. NFS_X.u32_enc(vers) .. NFS_X.u32_enc(proc) .. (args or ""))
end

function NFS_B.mount_null(xid, vers)
  return NFS_B.rm_call(xid, NFS_T.PROG_MOUNT, vers or NFS_T.MOUNT_V3, NFS_T.MOUNTPROC_NULL, NFS_T.AUTH_NULL, "", "")
end

function NFS_B.mount_mnt(xid, dirpath, vers, cred_flavor)
  return NFS_B.rm_call(xid, NFS_T.PROG_MOUNT, vers or NFS_T.MOUNT_V3, NFS_T.MOUNTPROC_MNT,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.string_enc(dirpath))
end

function NFS_B.mount_dump(xid)
  return NFS_B.rm_call(xid, NFS_T.PROG_MOUNT, NFS_T.MOUNT_V3, NFS_T.MOUNTPROC_DUMP, NFS_T.AUTH_NULL, "", "")
end

function NFS_B.mount_export(xid)
  return NFS_B.rm_call(xid, NFS_T.PROG_MOUNT, NFS_T.MOUNT_V3, NFS_T.MOUNTPROC_EXPORT, NFS_T.AUTH_NULL, "", "")
end

function NFS_B.nfs_null(xid, vers)
  return NFS_B.rm_call(xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_NULL, NFS_T.AUTH_NULL, "", "")
end

function NFS_B.nfs_getattr(xid, fhandle, vers, cred_flavor)
  return NFS_B.rm_call(xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_GETATTR,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.fhandle_enc(fhandle))
end

function NFS_B.nfs_lookup(xid, fhandle, name, vers, cred_flavor)
  return NFS_B.rm_call(xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_LOOKUP,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.fhandle_enc(fhandle) .. NFS_X.string_enc(name))
end

function NFS_B.nfs_readlink(xid, fhandle, vers, cred_flavor)
  return NFS_B.rm_call(xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_READLINK,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.fhandle_enc(fhandle))
end

function NFS_B.nfs_fsinfo(xid, fhandle, vers, cred_flavor)
  return NFS_B.rm_call(xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_FSINFO,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.fhandle_enc(fhandle))
end

function NFS_B.nfs_access(xid, fhandle, access, vers, cred_flavor, uid)
  local cred = NFS_B.authsys(2, "nse-audit", uid or NFS_T.ROOT_UID, NFS_T.ROOT_UID, {})
  return NFS_X.rm_enc(NFS_X.u32_enc(xid) .. NFS_X.u32_enc(NFS_T.MSG_CALL) .. NFS_X.u32_enc(NFS_T.RPC_VERS) ..
    NFS_X.u32_enc(NFS_T.PROG_NFS) .. NFS_X.u32_enc(vers or NFS_T.NFS_V3) .. NFS_X.u32_enc(NFS_T.NFSPROC_ACCESS) ..
    NFS_B.cred(NFS_T.AUTH_SYS, cred) .. NFS_B.cred(NFS_T.AUTH_NULL, "") ..
    NFS_X.fhandle_enc(fhandle) .. NFS_X.u32_enc(access or 0x3f), true)
end

function NFS_B.nlm_null(xid)
  return NFS_B.rm_call(xid, NFS_T.PROG_NLOCKMGR, NFS_T.NLM_V4, NFS_T.NLMPROC_NULL, NFS_T.AUTH_NULL, "", "")
end

function NFS_B.nlm_test(xid, cookie, caller, svid, fhandle)
  local holder = NFS_X.string_enc(caller or "nse-client") .. NFS_X.u32_enc(svid or 1234) ..
    NFS_X.opaque_enc(fhandle or "")
  return NFS_B.rm_call(xid, NFS_T.PROG_NLOCKMGR, NFS_T.NLM_V4, NFS_T.NLMPROC_TEST, NFS_T.AUTH_NULL, "",
    NFS_X.opaque_enc(cookie or "nse-cookie") .. NFS_X.bool_enc(false) .. holder)
end

function NFS_B.rusers_names(xid, vers)
  return NFS_B.rm_call(xid, NFS_T.PROG_RUSERS, vers or NFS_T.RUSERS_V2, NFS_T.RUSERSPROC_NAMES,
    NFS_T.AUTH_NULL, "", "")
end

function NFS_B.rusers_num(xid, vers)
  return NFS_B.rm_call(xid, NFS_T.PROG_RUSERS, vers or NFS_T.RUSERS_V2, NFS_T.RUSERSPROC_NUM,
    NFS_T.AUTH_NULL, "", "")
end

function NFS_B.rquota_getquota(xid, export_path, uid)
  return NFS_B.rm_call(xid, NFS_T.PROG_RQUOTA, NFS_T.RQUOTA_V1, NFS_T.RQUOTAPROC_GETQUOTA,
    NFS_T.AUTH_NULL, "", NFS_X.string_enc(export_path or "/export/public") .. NFS_X.u32_enc(uid or 1000))
end

function NFS_B.ypbind_domain(xid, domain)
  return NFS_B.rm_call(xid, NFS_T.PROG_YPBIND, NFS_T.YPBIND_V2, NFS_T.YPBINDPROC_DOMAIN,
    NFS_T.AUTH_NULL, "", NFS_X.string_enc(domain or "corp.example.com"))
end

function NFS_B.statd_stat(xid, mon_name)
  return NFS_B.rm_call(xid, NFS_T.PROG_STATD, NFS_T.STATD_V1, NFS_T.SM_STAT,
    NFS_T.AUTH_NULL, "", NFS_X.string_enc(mon_name or "nfs-client01"))
end

function NFS_B.spray_get(xid)
  return NFS_B.rm_call(xid, NFS_T.PROG_SPRAY, NFS_T.SPRAY_V1, NFS_T.SPRAYPROC_GET, NFS_T.AUTH_NULL, "", "")
end

function NFS_B.fattr3_enc(a)
  return NFS_X.u32_enc(a.type) .. NFS_X.u32_enc(a.mode) .. NFS_X.u32_enc(a.nlink or 1) ..
    NFS_X.u32_enc(a.uid or 0) .. NFS_X.u32_enc(a.gid or 0) ..
    NFS_X.u64_enc(math.floor((a.size or 0) / 4294967296), (a.size or 0) % 4294967296) ..
    NFS_X.u64_enc(math.floor((a.used or 0) / 4294967296), (a.used or 0) % 4294967296) ..
    NFS_X.u32_enc(0) .. NFS_X.u32_enc(0) ..
    NFS_X.u64_enc(0, a.fsid or 1) .. NFS_X.u64_enc(0, a.fileid or 1) ..
    NFS_X.u32_enc(a.atime or 1700000000) .. NFS_X.u32_enc(0) ..
    NFS_X.u32_enc(a.mtime or 1700000000) .. NFS_X.u32_enc(0) ..
    NFS_X.u32_enc(a.ctime or 1700000000) .. NFS_X.u32_enc(0)
end

NFS_P = {}

function NFS_P.parse_reply(data)
  local body, _, last, need = NFS_X.rm_dec(data, 1)
  if body == nil then
    return nil, need and ("short record: need " .. tostring(need) .. " bytes") or "empty record", last
  end
  local xid, off = NFS_X.u32_dec(body, 1)
  local mtype, off2 = NFS_X.u32_dec(body, off)
  if xid == nil or mtype ~= NFS_T.MSG_REPLY then
    return nil, "not an RPC reply"
  end
  local out = { xid = xid, last = last, body = body }
  local stat, off3 = NFS_X.u32_dec(body, off2)
  if stat == nil then
    return nil, "truncated reply header"
  end
  if stat ~= 0 then
    local rstat, off4 = NFS_X.u32_dec(body, off3)
    out.rejected = true
    out.reject_stat = rstat
    out.reject_name = NFS_T.REJECT_STATS[rstat] or tostring(rstat)
    if rstat == 1 then
      local astat, off5 = NFS_X.u32_dec(body, off4)
      out.auth_stat = astat
      out.auth_name = NFS_T.AUTH_STATS[astat] or tostring(astat)
      out.off = off5
    else
      out.off = off4
    end
    return out
  end
  local verf_flavor, off4 = NFS_X.u32_dec(body, off3)
  local verf_len, off5 = NFS_X.u32_dec(body, off4)
  if verf_flavor == nil then
    return nil, "truncated verifier"
  end
  out.verifier_flavor = verf_flavor
  out.verifier_flavor_name = NFS_T.AUTH_NAMES[verf_flavor] or tostring(verf_flavor)
  out.off = off5 + verf_len + NFS_X.opaque_pad(verf_len)
  local astat, off6 = NFS_X.u32_dec(body, out.off)
  if astat == nil then
    return nil, "truncated accept state"
  end
  out.accept_stat = astat
  out.accept_name = NFS_T.ACCEPT_STATS[astat] or tostring(astat)
  out.off = off6
  if astat == 2 then
    local lo, off7 = NFS_X.u32_dec(body, off6)
    local hi, off8 = NFS_X.u32_dec(body, off7)
    out.mismatch_low = lo
    out.mismatch_high = hi
    out.off = off8
  end
  return out
end

function NFS_P.parse_pmap_dump(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil
  end
  local out = {}
  local off = reply.off
  for _ = 1, 64 do
    local prog, o1 = NFS_X.u32_dec(reply.body, off)
    if prog == nil then
      return nil, "truncated dump list"
    end
    if prog == 0 then
      out.count = #out
      return out
    end
    local vers, o2 = NFS_X.u32_dec(reply.body, o1)
    local prot, o3 = NFS_X.u32_dec(reply.body, o2)
    local port, o4 = NFS_X.u32_dec(reply.body, o3)
    if port == nil then
      return nil, "truncated dump tuple"
    end
    out[#out + 1] = { prog = prog, vers = vers, prot = prot, port = port,
      prog_name = NFS_T.PROG_NAMES[prog] or tostring(prog), proto = NFS_T.PROT_NAMES[prot] or tostring(prot) }
    off = o4
  end
  out.count = #out
  return out
end

function NFS_P.parse_pmap_getport(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil
  end
  local port, _ = NFS_X.u32_dec(reply.body, reply.off)
  return port
end

function NFS_P.parse_mount_export(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil
  end
  local out = {}
  local off = reply.off
  for _ = 1, 32 do
    local more, o1 = NFS_X.u32_dec(reply.body, off)
    if more == nil then
      return nil, "truncated export list"
    end
    if more == 0 then
      break
    end
    local dir, o2 = NFS_X.string_dec(reply.body, o1)
    if dir == nil then
      return nil, "truncated export dir"
    end
    local groups = {}
    local goff = o2
    for _ = 1, 16 do
      local gmore, g1 = NFS_X.u32_dec(reply.body, goff)
      if gmore == nil then
        break
      end
      if gmore == 0 then
        goff = g1
        break
      end
      local gname, g2 = NFS_X.string_dec(reply.body, g1)
      if gname == nil then
        break
      end
      groups[#groups + 1] = gname
      goff = g2
    end
    out[#out + 1] = { dir = dir, groups = groups }
    off = goff
  end
  return out
end

function NFS_P.parse_mount_mnt(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil, "rpc-level failure"
  end
  local status, off = NFS_X.u32_dec(reply.body, reply.off)
  if status == nil then
    return nil, "truncated mount status"
  end
  local out = { status = status, status_name = NFS_T.MNT_ERRORS[status] or tostring(status) }
  if status == 0 then
    local fh, o2 = NFS_X.string_dec(reply.body, off)
    out.fhandle = fh
    local n, o3 = NFS_X.u32_dec(reply.body, o2)
    if n ~= nil and n > 0 and n <= 32 then
      out.auth_flavors = {}
      for _ = 1, n do
        local fl, o4 = NFS_X.u32_dec(reply.body, o3)
        if fl == nil then
          break
        end
        out.auth_flavors[#out.auth_flavors + 1] = fl
        o3 = o4
      end
    end
  end
  return out
end

function NFS_P.parse_mount_dump(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil
  end
  local out = {}
  local off = reply.off
  for _ = 1, 64 do
    local more, o1 = NFS_X.u32_dec(reply.body, off)
    if more == nil then
      break
    end
    if more == 0 then
      break
    end
    local host, o2 = NFS_X.string_dec(reply.body, o1)
    local dir, o3 = NFS_X.string_dec(reply.body, o2)
    if host ~= nil and dir ~= nil then
      out[#out + 1] = { host = host, dir = dir }
      off = o3
    else
      break
    end
  end
  return out
end

function NFS_P.parse_nfs_getattr(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil, "rpc-level failure"
  end
  local status, off = NFS_X.u32_dec(reply.body, reply.off)
  if status == nil then
    return nil, "truncated getattr"
  end
  local out = { status = status, status_name = NFS_T.NFS_ERRORS[status] or tostring(status) }
  if status == 0 then
    local ftype, o1 = NFS_X.u32_dec(reply.body, off)
    local mode, o2 = NFS_X.u32_dec(reply.body, o1)
    local nlink, o3 = NFS_X.u32_dec(reply.body, o2)
    local uid, o4 = NFS_X.u32_dec(reply.body, o3)
    local gid, o5 = NFS_X.u32_dec(reply.body, o4)
    local size, o6 = NFS_X.u64_dec(reply.body, o5)
    if mode == nil then
      return nil, "truncated fattr3"
    end
    out.ftype = ftype
    out.ftype_name = NFS_T.FTYPE_NAMES[ftype] or tostring(ftype)
    out.mode = mode
    out.mode_octal = string.format("%04o", mode % 4096)
    out.nlink = nlink
    out.uid = uid
    out.gid = gid
    out.size = size
    out.mode_bits = NFS_X.mode_bits(mode)
  end
  return out
end

function NFS_P.parse_nfs_lookup(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil, "rpc-level failure"
  end
  local status, off = NFS_X.u32_dec(reply.body, reply.off)
  if status == nil then
    return nil, "truncated lookup"
  end
  local out = { status = status, status_name = NFS_T.NFS_ERRORS[status] or tostring(status) }
  if status == 0 then
    local fh, o2 = NFS_X.string_dec(reply.body, off)
    out.fhandle = fh
    local has_attrs, o3 = NFS_X.bool_dec(reply.body, o2)
    if has_attrs then
      local ftype, a1 = NFS_X.u32_dec(reply.body, o3)
      local mode, a2 = NFS_X.u32_dec(reply.body, a1)
      local uid, a4 = NFS_X.u32_dec(reply.body, NFS_X.u32_dec(reply.body, a2))
      if mode ~= nil then
        out.mode = mode
        out.mode_octal = string.format("%04o", mode % 4096)
        out.ftype = ftype
        out.ftype_name = NFS_T.FTYPE_NAMES[ftype] or tostring(ftype)
        out.uid = uid
        out.mode_bits = NFS_X.mode_bits(mode)
      end
    end
  end
  return out
end

function NFS_P.parse_nfs_readlink(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil, "rpc-level failure"
  end
  local status, off = NFS_X.u32_dec(reply.body, reply.off)
  if status == nil then
    return nil, "truncated readlink"
  end
  local out = { status = status, status_name = NFS_T.NFS_ERRORS[status] or tostring(status) }
  if status == 0 then
    local target, o2 = NFS_X.string_dec(reply.body, off)
    out.target = target
  end
  return out
end

function NFS_P.parse_nfs_fsinfo(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil, "rpc-level failure"
  end
  local status, off = NFS_X.u32_dec(reply.body, reply.off)
  if status == nil then
    return nil, "truncated fsinfo"
  end
  local out = { status = status, status_name = NFS_T.NFS_ERRORS[status] or tostring(status) }
  if status == 0 then
    local rtmax, o1 = NFS_X.u32_dec(reply.body, off)
    local wtmax, o2 = NFS_X.u32_dec(reply.body, o1)
    local dtproto, o3 = NFS_X.u32_dec(reply.body, o2)
    out.rtmax = rtmax
    out.wtmax = wtmax
    out.dtpref = dtproto
  end
  return out
end

function NFS_P.parse_nfs_access(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil, "rpc-level failure"
  end
  local status, off = NFS_X.u32_dec(reply.body, reply.off)
  if status == nil then
    return nil, "truncated access"
  end
  local out = { status = status, status_name = NFS_T.NFS_ERRORS[status] or tostring(status) }
  if status == 0 then
    local has_attrs, o1 = NFS_X.bool_dec(reply.body, off)
    local skip = o1
    if has_attrs then
      skip = o1 + 84
    end
    local rights, o2 = NFS_X.u32_dec(reply.body, skip)
    out.rights = rights
    out.rights_octal = string.format("%03o", rights % 512)
  end
  return out
end

function NFS_P.parse_rusers_names(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil
  end
  local n, off = NFS_X.u32_dec(reply.body, reply.off)
  if n == nil then
    return nil
  end
  local out = { count = n, users = {} }
  local o = off
  for _ = 1, math.min(n, 32) do
    local uid, o1 = NFS_X.u32_dec(reply.body, o)
    local name, o2 = NFS_X.string_dec(reply.body, o1)
    local host, o3 = NFS_X.string_dec(reply.body, o2)
    local tty, o4 = NFS_X.string_dec(reply.body, o3)
    local stamp, o5 = NFS_X.u32_dec(reply.body, o4)
    if name == nil then
      break
    end
    out.users[#out.users + 1] = { uid = uid, name = name, host = host, tty = tty, stamp = stamp }
    o = o5
  end
  return out
end

function NFS_P.parse_rusers_num(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil
  end
  local n, _ = NFS_X.u32_dec(reply.body, reply.off)
  return n
end

function NFS_P.parse_rquota(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil, "rpc-level failure"
  end
  local status, off = NFS_X.u32_dec(reply.body, reply.off)
  if status == nil then
    return nil, "truncated rquota status"
  end
  local out = { status = status }
  if status == NFS_T.RQUOTA_OK then
    local bhard, o1 = NFS_X.u32_dec(reply.body, off)
    local bsoft, o2 = NFS_X.u32_dec(reply.body, o1)
    local cur, o3 = NFS_X.u32_dec(reply.body, o2)
    local fhard, o4 = NFS_X.u32_dec(reply.body, o3)
    local fsoft, o5 = NFS_X.u32_dec(reply.body, o4)
    local fcur, o6 = NFS_X.u32_dec(reply.body, o5)
    local btime, o7 = NFS_X.u32_dec(reply.body, o6)
    local ftime, o8 = NFS_X.u32_dec(reply.body, o7)
    out.bhard = bhard
    out.bsoft = bsoft
    out.cur = cur
    out.fhard = fhard
    out.fsoft = fsoft
    out.fcur = fcur
    out.btime = btime
    out.ftime = ftime
    out.over_soft = bsoft ~= nil and cur ~= nil and bsoft > 0 and cur >= bsoft
    out.over_hard = bhard ~= nil and cur ~= nil and bhard > 0 and cur >= bhard
  elseif status == NFS_T.RQUOTA_NOQUOTA then
    out.status_name = "NOQUOTA"
  elseif status == NFS_T.RQUOTA_EPERM then
    out.status_name = "EPERM"
  end
  return out
end

function NFS_P.parse_ypbind_domain(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil, "rpc-level failure"
  end
  local ok, off = NFS_X.u32_dec(reply.body, reply.off)
  if ok == nil then
    return nil, "truncated ypbind answer"
  end
  local out = { bound = ok == 1 }
  if out.bound then
    local addr, o2 = NFS_X.string_dec(reply.body, off)
    local port, o3 = NFS_X.u32_dec(reply.body, o2)
    out.ypserv_addr = addr
    out.ypserv_port = port
    out.off = o3
  end
  return out
end

function NFS_P.parse_statd_stat(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil, "rpc-level failure"
  end
  local stat, off = NFS_X.u32_dec(reply.body, reply.off)
  if stat == nil then
    return nil, "truncated sm_stat"
  end
  local out = { stat = stat }
  if stat == 1 then
    local state, o2 = NFS_X.u32_dec(reply.body, off)
    out.state = state
  end
  return out
end

function NFS_P.parse_spray_get(reply)
  if reply == nil or reply.accept_stat ~= 0 then
    return nil
  end
  local counter, o1 = NFS_X.u32_dec(reply.body, reply.off)
  local clock, o2 = NFS_X.u32_dec(reply.body, o1)
  return { counter = counter, clock = clock }
end

NFS_A = {}

function NFS_A.selftest()
  local failures = {}
  local function expect_eq(got, want, what)
    if got ~= want then
      failures[#failures + 1] = what .. ": got " .. tostring(got) .. " want " .. tostring(want)
    end
  end
  expect_eq(NFS_X.u32_dec(NFS_X.u32_enc(4294967295)), 4294967295, "u32 roundtrip max")
  expect_eq(NFS_X.u32_dec(NFS_X.u32_enc(1234567)), 1234567, "u32 roundtrip")
  expect_eq(NFS_X.u64_dec(NFS_X.u64_enc(1, 2)), 4294967298, "u64 roundtrip")
  expect_eq(select(1, NFS_X.string_dec(NFS_X.string_enc("hello"))), "hello", "string roundtrip")
  expect_eq(#NFS_X.string_enc("abc"), 8, "string xdr padding 3->8")
  expect_eq(#NFS_X.string_enc("abcd"), 8, "string xdr padding 4->8")
  local arr, _ = NFS_X.uint_array_dec(NFS_X.uint_array_enc({ 5, 6, 7 }), 1)
  expect_eq(arr and arr[2], 6, "uint array roundtrip")
  local sarr, _ = NFS_X.string_array_dec(NFS_X.string_array_enc({ "a", "bb", "ccc" }), 1)
  expect_eq(sarr and sarr[3], "ccc", "string array roundtrip")
  local body = NFS_X.u32_enc(7)
  local frame = NFS_X.rm_enc(body, true)
  expect_eq(#frame, 8, "rm framing length")
  local parsed, _, last = NFS_X.rm_dec(frame, 1)
  expect_eq(parsed, body, "rm roundtrip")
  expect_eq(last, true, "rm last flag")
  local call = NFS_B.rpc_call(42, 100003, 3, 1, NFS_T.AUTH_NULL, "", NFS_X.fhandle_enc("FH"))
  local xid, off = NFS_X.u32_dec(call, 1)
  local mtype, off2 = NFS_X.u32_dec(call, off)
  local rpcvers, off3 = NFS_X.u32_dec(call, off2)
  local prog, off4 = NFS_X.u32_dec(call, off3)
  expect_eq(xid, 42, "call xid")
  expect_eq(mtype, 0, "call mtype")
  expect_eq(rpcvers, 2, "call rpcvers")
  expect_eq(prog, 100003, "call prog")
  local fattr = NFS_B.fattr3_enc({ type = 2, mode = 509, uid = 0, gid = 0, size = 4096 })
  local ga = NFS_P.parse_nfs_getattr({ accept_stat = 0, body = NFS_X.u32_enc(0) .. fattr, off = 1 })
  expect_eq(ga and ga.mode_octal, "0775", "fattr3 mode roundtrip")
  expect_eq(ga and ga.ftype_name, "DIR", "fattr3 type")
  local mb = NFS_X.mode_bits(0x1a4)
  expect_eq(mb.world_read, true, "mode 0644 world read")
  expect_eq(mb.world_write, false, "mode 0644 world write")
  local ent = NFS_X.entropy_estimate(string.rep("\0", 30) .. "\1\2")
  expect_eq(ent.high_entropy, false, "entropy low pattern")
  local ent2 = NFS_X.entropy_estimate("aZ3kQ9wL2pR8mN5xJ7cV1bT4hG6dS0fY")
  expect_eq(ent2.high_entropy, true, "entropy high pattern")
  local dump_reply = { accept_stat = 0, off = 1, body =
    NFS_X.u32_enc(100003) .. NFS_X.u32_enc(3) .. NFS_X.u32_enc(6) .. NFS_X.u32_enc(2049) ..
    NFS_X.u32_enc(0) }
  local dump = NFS_P.parse_pmap_dump(dump_reply)
  expect_eq(dump and dump.count, 1, "pmap dump parse")
  expect_eq(dump and dump[1].prog_name, "nfs", "pmap dump name")
  if #failures > 0 then
    return false, table.concat(failures, "; ")
  end
  return true, "ONC-RPC XDR codec and NFS parsers verified"
end

NFS_TP = {}

NFS_TP.xid = 1000

local function nfs_session_new(host, port, args)
  return {
    host = host,
    port = port,
    args = {
      timeout = args.timeout or 8,
      maxrequests = args.maxrequests or 48,
      recv_window = args.recv_window or 3,
    },
    sock = nil,
    connected = false,
    closed = false,
    sent_bytes = 0,
    recv_bytes = 0,
    requests = 0,
    audit = {},
  }
end

function NFS_TP.audit(sess, event, detail)
  sess.audit[#sess.audit + 1] = tostring(event) .. ":" .. tostring(detail)
end

local function nfs_connect(sess)
  if sess.connected then
    return 1
  end
  if sess.requests >= sess.args.maxrequests then
    return nil, "request budget exhausted"
  end
  local sock = nmap.new_socket()
  sock:set_timeout(math.floor((sess.args.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, "tcp")
  if not ok then
    sock:close()
    return nil, "TCP connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  NFS_TP.audit(sess, "connect", sess.port .. "/tcp")
  return 1
end

local function nfs_close(sess)
  if sess and sess.sock and not sess.closed then
    pcall(sess.sock.close, sess.sock)
    sess.closed = true
    sess.connected = false
  end
end

local function nfs_send(sess, data)
  if sess.requests >= sess.args.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  sess.sent_bytes = sess.sent_bytes + #data
  local ok, err = sess.sock:send(data)
  if not ok then
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  NFS_TP.audit(sess, "send", #data .. "B")
  return 1
end

local function nfs_recv(sess)
  local buf = ""
  while true do
    local ok, dat = sess.sock:receive(65535)
    if ok then
      buf = buf .. dat
      sess.recv_bytes = sess.recv_bytes + #dat
      local body, _, _, need = NFS_X.rm_dec(buf, 1)
      if body ~= nil or need == nil then
        NFS_TP.audit(sess, "recv", #buf .. "B")
        return buf
      end
    else
      if #buf > 0 then
        NFS_TP.audit(sess, "recv", #buf .. "B")
        return buf
      end
      local err = dat
      if err == "TIMEOUT" or err == "EOF" then
        return nil, "timeout"
      end
      return nil, "receive failed: " .. tostring(err or "unknown")
    end
  end
end

local function nfs_rpc(sess, xid, prog, vers, proc, cred_flavor, cred_opaque, payload)
  local ok, err = nfs_connect(sess)
  if not ok then
    return nil, err
  end
  local ok2, err2 = nfs_send(sess, NFS_B.rm_call(xid, prog, vers, proc, cred_flavor, cred_opaque, payload))
  if not ok2 then
    return nil, err2
  end
  local raw, rerr = nfs_recv(sess)
  if raw == nil then
    return nil, rerr
  end
  local reply, perr = NFS_P.parse_reply(raw)
  if reply == nil then
    return nil, perr or "reply parse failed"
  end
  return reply
end

function NFS_TP.pmap_dump(host, args)
  local sess = nfs_session_new(host, args.rpcbind_port or 111, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_PORTMAP, 2, NFS_T.PMAP_DUMP, NFS_T.AUTH_NULL, "", "")
  nfs_close(sess)
  if reply == nil then
    return nil, err
  end
  local list, perr = NFS_P.parse_pmap_dump(reply)
  if list == nil then
    return nil, perr or "dump parse failed"
  end
  list.request_count = sess.requests
  return list
end

function NFS_TP.pmap_getport(host, prog, vers, args, prot)
  local sess = nfs_session_new(host, args.rpcbind_port or 111, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_PORTMAP, 2, NFS_T.PMAP_GETPORT, NFS_T.AUTH_NULL, "",
    NFS_X.u32_enc(prog) .. NFS_X.u32_enc(vers) .. NFS_X.u32_enc(prot or NFS_T.PROT_TCP) .. NFS_X.u32_enc(0))
  nfs_close(sess)
  if reply == nil then
    return nil, err
  end
  return NFS_P.parse_pmap_getport(reply)
end

function NFS_TP.mount_export(host, port, args)
  local sess = nfs_session_new(host, port or 20048, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_MOUNT, NFS_T.MOUNT_V3, NFS_T.MOUNTPROC_EXPORT,
    NFS_T.AUTH_NULL, "", "")
  nfs_close(sess)
  if reply == nil then
    return nil, err
  end
  return NFS_P.parse_mount_export(reply), sess
end

function NFS_TP.mount_mnt(host, port, dirpath, args, cred_flavor)
  local sess = nfs_session_new(host, port or 20048, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_MOUNT, NFS_T.MOUNT_V3, NFS_T.MOUNTPROC_MNT,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.string_enc(dirpath))
  local out = reply and NFS_P.parse_mount_mnt(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "mount reply parse failed"
  end
  return out
end

function NFS_TP.nfs_null(host, port, vers, args)
  local sess = nfs_session_new(host, port or 2049, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_NFS, vers, NFS_T.NFSPROC_NULL, NFS_T.AUTH_NULL, "", "")
  nfs_close(sess)
  return reply ~= nil, err
end

function NFS_TP.nfs_getattr(host, port, fhandle, vers, args, cred_flavor)
  local sess = nfs_session_new(host, port or 2049, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_GETATTR,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.fhandle_enc(fhandle))
  local out = reply and NFS_P.parse_nfs_getattr(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "getattr parse failed"
  end
  return out
end

function NFS_TP.nfs_lookup(host, port, fhandle, name, vers, args, cred_flavor)
  local sess = nfs_session_new(host, port or 2049, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_LOOKUP,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.fhandle_enc(fhandle) .. NFS_X.string_enc(name))
  local out = reply and NFS_P.parse_nfs_lookup(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "lookup parse failed"
  end
  return out
end

function NFS_TP.nfs_readlink(host, port, fhandle, vers, args, cred_flavor)
  local sess = nfs_session_new(host, port or 2049, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_READLINK,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.fhandle_enc(fhandle))
  local out = reply and NFS_P.parse_nfs_readlink(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "readlink parse failed"
  end
  return out
end

function NFS_TP.nfs_fsinfo(host, port, fhandle, vers, args, cred_flavor)
  local sess = nfs_session_new(host, port or 2049, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_FSINFO,
    cred_flavor or NFS_T.AUTH_NULL, "", NFS_X.fhandle_enc(fhandle))
  local out = reply and NFS_P.parse_nfs_fsinfo(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "fsinfo parse failed"
  end
  return out
end

function NFS_TP.nfs_access(host, port, fhandle, access, uid, vers, args)
  local sess = nfs_session_new(host, port or 2049, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local cred = NFS_B.authsys(2, "nse-audit", uid or NFS_T.ROOT_UID, NFS_T.ROOT_UID, {})
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_NFS, vers or NFS_T.NFS_V3, NFS_T.NFSPROC_ACCESS,
    NFS_T.AUTH_SYS, cred, NFS_X.fhandle_enc(fhandle) .. NFS_X.u32_enc(access or 0x3f))
  local out = reply and NFS_P.parse_nfs_access(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "access parse failed"
  end
  return out
end

function NFS_TP.nlm_probe(host, port, args)
  local sess = nfs_session_new(host, port or 4045, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local null_ok, nerr = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_NLOCKMGR, NFS_T.NLM_V4, NFS_T.NLMPROC_NULL,
    NFS_T.AUTH_NULL, "", "")
  local out = { null_ok = null_ok ~= nil }
  if null_ok == nil then
    nfs_close(sess)
    out.detail = tostring(nerr)
    return out
  end
  NFS_TP.xid = NFS_TP.xid + 1
  local test_reply, terr = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_NLOCKMGR, NFS_T.NLM_V4, NFS_T.NLMPROC_TEST,
    NFS_T.AUTH_NULL, "", NFS_X.opaque_enc("nse-cookie") .. NFS_X.bool_enc(false) ..
    NFS_X.string_enc("nse-client") .. NFS_X.u32_enc(1234) .. NFS_X.opaque_enc("TESTFH"))
  nfs_close(sess)
  if test_reply ~= nil then
    out.test_accepted = test_reply.accept_stat == 0
    out.accept_name = test_reply.accept_name
    if test_reply.accept_stat == 0 and test_reply.body then
      local locked, _ = NFS_X.bool_dec(test_reply.body, test_reply.off)
      out.locked = locked
    end
  else
    out.detail = tostring(terr)
  end
  return out
end

function NFS_TP.rusers(host, port, args, vers)
  local sess = nfs_session_new(host, port or 938, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_RUSERS, vers or NFS_T.RUSERS_V2, NFS_T.RUSERSPROC_NAMES,
    NFS_T.AUTH_NULL, "", "")
  local out = reply and NFS_P.parse_rusers_names(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "rusers parse failed"
  end
  return out
end

function NFS_TP.rquota(host, port, export_path, uid, args)
  local sess = nfs_session_new(host, port or 875, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_RQUOTA, NFS_T.RQUOTA_V1, NFS_T.RQUOTAPROC_GETQUOTA,
    NFS_T.AUTH_NULL, "", NFS_X.string_enc(export_path or "/export/public") .. NFS_X.u32_enc(uid or 1000))
  local out = reply and NFS_P.parse_rquota(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "rquota parse failed"
  end
  return out
end

function NFS_TP.ypbind_domain(host, port, domain, args)
  local sess = nfs_session_new(host, port or 944, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_YPBIND, NFS_T.YPBIND_V2, NFS_T.YPBINDPROC_DOMAIN,
    NFS_T.AUTH_NULL, "", NFS_X.string_enc(domain or "corp.example.com"))
  local out = reply and NFS_P.parse_ypbind_domain(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "ypbind parse failed"
  end
  return out
end

function NFS_TP.statd_stat(host, port, mon_name, args)
  local sess = nfs_session_new(host, port or 662, args)
  NFS_TP.xid = NFS_TP.xid + 1
  local reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_STATD, NFS_T.STATD_V1, NFS_T.SM_STAT,
    NFS_T.AUTH_NULL, "", NFS_X.string_enc(mon_name or "nfs-client01"))
  local out = reply and NFS_P.parse_statd_stat(reply) or nil
  nfs_close(sess)
  if out == nil then
    return nil, err or "statd parse failed"
  end
  return out
end

function NFS_TP.spray_profile(host, port, args)
  local sess = nfs_session_new(host, port or 780, args)
  local burst = 6
  local sent = 0
  NFS_TP.xid = NFS_TP.xid + 1
  local start_ok = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_SPRAY, NFS_T.SPRAY_V1, NFS_T.SPRAYPROC_SPRAY,
    NFS_T.AUTH_NULL, "", "")
  if start_ok ~= nil then
    sent = 1
  end
  NFS_TP.xid = NFS_TP.xid + 1
  local get_reply, err = nfs_rpc(sess, NFS_TP.xid, NFS_T.PROG_SPRAY, NFS_T.SPRAY_V1, NFS_T.SPRAYPROC_GET,
    NFS_T.AUTH_NULL, "", "")
  nfs_close(sess)
  local counts = get_reply and NFS_P.parse_spray_get(get_reply) or nil
  return {
    burst = burst,
    answered = sent,
    counter = counts and counts.counter or nil,
    reachable = get_reply ~= nil,
    detail = err,
  }
end

function NFS_TP.programs_of(dump, prog)
  local out = {}
  for _, t in ipairs(dump or {}) do
    if t.prog == prog then
      out[#out + 1] = t
    end
  end
  return out
end

function NFS_TP.ports_of(dump, prog)
  local out = {}
  for _, t in ipairs(NFS_TP.programs_of(dump, prog)) do
    out[t.port] = true
    out[#out + 1] = t.port
  end
  return out
end

function NFS_TP.find_export(export_list, dir)
  for _, e in ipairs(export_list or {}) do
    if e.dir == dir then
      return e
    end
  end
  return nil
end

NFS_TP.session_new = nfs_session_new
NFS_TP.connect = nfs_connect
NFS_TP.close = nfs_close
NFS_TP.send = nfs_send
NFS_TP.recv = nfs_recv
NFS_TP.rpc = nfs_rpc

function NFS_TP.export_options_text(entry)
  if entry == nil then
    return "-"
  end
  if #entry.groups == 0 then
    return "(world)"
  end
  return "(" .. table.concat(entry.groups, ",") .. ")"
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

local rpcbind_port_of = function(port)
  return tonumber(port.number) == 111 and port.number or 111
end

local function nfs_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - ONC-RPC audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The ONC-RPC audit did not complete against this endpoint", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function rpc_map(host, port, args)
  local dump, err = NFS_TP.pmap_dump(host, {
    timeout = args.timeout or 8,
    maxrequests = args.maxrequests or 48,
    recv_window = args.recv_window or 3,
    rpcbind_port = rpcbind_port_of(port),
  })
  if dump == nil then
    return nil, err
  end
  return {
    dump = dump,
    mountd = NFS_TP.programs_of(dump, NFS_T.PROG_MOUNT)[1],
    nfs_ports = NFS_TP.ports_of(dump, NFS_T.PROG_NFS),
    nlm_ports = NFS_TP.ports_of(dump, NFS_T.PROG_NLOCKMGR),
    statd_ports = NFS_TP.ports_of(dump, NFS_T.PROG_STATD),
    rquota_ports = NFS_TP.ports_of(dump, NFS_T.PROG_RQUOTA),
    rusers_ports = NFS_TP.ports_of(dump, NFS_T.PROG_RUSERS),
    ypbind_ports = NFS_TP.ports_of(dump, NFS_T.PROG_YPBIND),
    spray_ports = NFS_TP.ports_of(dump, NFS_T.PROG_SPRAY),
  }
end

local function first_port(ports, fallback)
  if ports ~= nil and ports[1] ~= nil then
    return ports[1]
  end
  return fallback
end

local function run_audit(host, port, args)
  local sections = {}
  local map, err = rpc_map(host, port, args)
  if map == nil then
    return nfs_incomplete("rpcbind DUMP failed: " .. tostring(err), sections, "rpcbind", err)
  end
  local qport = first_port(map.rquota_ports, nil)
  sections[#sections + 1] = { key = "rquotad Registration", value = {
    registered = tostring(qport ~= nil),
    port = tostring(qport or "-"),
  } }

  local remediation = {}
  local status_text
  if qport == nil then
    status_text = "INFORMATIONAL - rquotad is not registered with rpcbind (quota service absent)"
    add_finding("INFO", "rquotad not exposed", {
      subject = "rquota",
      evidence = "no 100011 registration in the rpcbind map",
      confidence = "high",
    })
    remediation["1. Decide"] = "Install rquotad only if user-facing quota reporting is required."
  else
    local q, qerr = NFS_TP.rquota(host, qport, "/export/public", 1000, {
      timeout = args.timeout or 8, maxrequests = args.maxrequests or 48, recv_window = args.recv_window or 3 })
    sections[#sections + 1] = { key = "GETQUOTA Probe (uid 1000)", value = {
      status = tostring(q and q.status),
      soft_blocks = tostring(q and q.bsoft or "-"),
      used_blocks = tostring(q and q.cur or "-"),
      over_soft = tostring(q and q.over_soft),
    } }
    if q ~= nil and q.status == NFS_T.RQUOTA_OK then
      status_text = "VULNERABLE - rquotad disclosed quota accounting (used " .. tostring(q.cur) ..
        " of soft " .. tostring(q.bsoft) .. " blocks)"
      add_finding("MEDIUM", "Quota accounting readable by anonymous callers", {
        subject = "rquota",
        evidence = "GETQUOTA answered status=OK used=" .. tostring(q.cur) .. " soft=" .. tostring(q.bsoft),
        confidence = "high",
        cvss = 5.0,
      })
      remediation["1. Restrict"] = "Firewall rquotad to the NFS client network; quota data is not needed by untrusted hosts."
    elseif q ~= nil and q.status == NFS_T.RQUOTA_NOQUOTA then
      status_text = "SECURE - rquotad answers NOQUOTA for the sample UID (no accounting disclosed)"
      add_finding("INFO", "No quota disclosure for the probe", {
        subject = "rquota",
        evidence = "GETQUOTA answered NOQUOTA",
        confidence = "high",
      })
      remediation["1. Maintain"] = "Keep quota reporting scoped to authenticated users."
    else
      status_text = "INFORMATIONAL - rquotad probe answered " .. tostring(q and q.status_name or qerr)
      add_finding("INFO", "rquotad answer recorded", {
        subject = "rquota",
        evidence = "status " .. tostring(q and q.status or "?"),
        confidence = "medium",
      })
      remediation["1. Re-run"] = "Re-run with an export-specific path."
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
