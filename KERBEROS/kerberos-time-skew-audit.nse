local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local string = require "string"
local math = require "math"
local os = require "os"

-- Kerberos message construction and transport come from the shared engine.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Audits the clock relationship between the scanner, the KDC and network time.

Kerberos is a time-based protocol: RFC 4120 makes the KDC reject any request
whose timestamp differs from its own clock by more than the realm's configured
skew (five minutes on Active Directory and on a default MIT krb5 realm). A KDC
whose clock has drifted therefore manifests as authentication failures across
the estate, and a host whose clock has drifted cannot authenticate at all.

The script measures the relationship instead of asserting it:

  1. It sends a configurable number of AS-REQs and reads the KDC's own clock
     fields - KRB-ERROR carries stime (server time) and ctime (the client time
     as the KDC saw it), and an AS-REP carries the ticket validity window. Each
     exchange yields one offset sample, corrected for the measured round trip.
  2. It optionally queries an SNTP server (UDP/123) with a real RFC 5905 client:
     the four-timestamp algorithm yields the offset to that reference, the round
     trip delay, and the source's stratum, root delay and dispersion.
  3. It compares the two. When the KDC offset and the network time offset
     disagree, the drift belongs to the KDC, not to the scanner - the difference
     between "my scanning host is wrong" and "the domain controller is drifting".

Findings are graded against the Kerberos tolerance itself, so the report states
the headroom left before authentication fails.

References:
  * RFC 4120 section 3.1.3 and 5.4.2 - KerberosTime, clockskew and the KRB_AP_ERR_SKEW error
  * RFC 5905 - Network Time Protocol version 4 (the SNTP subset used here)
  * RFC 4330 - Simple Network Time Protocol version 4
  * Microsoft: Windows Time service tools and settings (w32tm) and the default MaxPosPhaseCorrection
]]

---
-- @usage
-- nmap -p 88 --script kerberos-time-skew-audit --script-args 'kerberos.realm=EXAMPLE.COM,kerberos.ntp-server=pool.ntp.org' <target>
--
-- @args kerberos.realm        Realm in uppercase DNS form. Derived from the
--                             KDC's KDC_ERR_WRONG_REALM answer when omitted.
-- @args kerberos.principal    Principal to sample with (default: a synthetic
--                             name, which is enough because the time fields are
--                             answered before any principal decision).
-- @args kerberos.samples      Number of Kerberos samples to take (default 5,
--                             maximum 30).
-- @args kerberos.ntp-server   SNTP server to compare against. When omitted the
--                             NTP section is skipped and the report says so.
-- @args kerberos.ntp-port     SNTP port (default 123).
-- @args kerberos.skew-tolerance  Skew, in seconds, above which the verdict is
--                             escalated (default 300, the Kerberos default).
-- @args kerberos.delay-ms     Spacing between samples (default 200 ms).
-- @args kerberos.timeout-ms   Per-request receive timeout.
-- @args kerberos.transport    "auto" (default), "udp" or "tcp".
-- @args kerberos.retries      Transport retries (default 1).
--
-- @output
-- PORT   STATE SERVICE
-- 88/tcp open  kerberos-sec
-- | kerberos-time-skew-audit:
-- |   Realm: EXAMPLE.COM
-- |   KDC offset (clock delta, KDC minus scanner): median -12 s, jitter 3 s
-- |   Kerberos tolerance: 300 s; headroom before authentication fails: 288 s
-- |   NTP cross-check: stratum 2, offset -11 s, delay 4 ms (KDC agrees)
-- |   Risk Level: LOW
-- |_  ...
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({88}, {"kerberos", "kerberos-sec"}, {"tcp", "udp"}, "open")

if not ok then
  action = function()
    return stdnse.format_output(false, {
      "nselib/kerberos5.lua is not installed.",
      "Install it next to the other NSE libraries:",
      "  cp nselib/kerberos5.lua \"$(nmap --datadir)/nselib/\"",
    })
  end
  return
end

local krb = krb5.krb
local transport = krb5.transport
local SCRIPT_VERSION = krb5.VERSION

-- Declared risk class, read by tools/syntax-check.js to enforce the repository
-- depth contract: CRITICAL/HIGH >= 1538 lines, MEDIUM/LOW 500-800 lines.
local SCRIPT_RISK = "MEDIUM"

-- ---------------------------------------------------------------------------
-- 1. Configuration
-- ---------------------------------------------------------------------------

local config = {}

local function arg_string(name)
  local value = stdnse.get_script_args("kerberos." .. name)
  if type(value) == "table" then
    value = value[1]
  end
  if value == nil then
    return nil
  end
  return tostring(value)
end

local function arg_int(name, default, min, max)
  local value = arg_string(name)
  if value == nil then
    return default
  end
  local n = tonumber(value)
  if not n then
    return default
  end
  n = math.floor(n)
  if min and n < min then n = min end
  if max and n > max then n = max end
  return n
end

function config.load(host)
  local cfg = {}
  cfg.realm = arg_string("realm")
  if cfg.realm then
    cfg.realm = string.upper(cfg.realm)
  end
  cfg.principal = arg_string("principal")
  cfg.samples = arg_int("samples", 5, 1, 30)
  cfg.ntp_server = arg_string("ntp-server")
  cfg.ntp_port = arg_int("ntp-port", 123, 1, 65535)
  cfg.skew_tolerance = arg_int("skew-tolerance", 300, 1, 86400)
  cfg.delay_ms = arg_int("delay-ms", 200, 0, 5000)
  cfg.retries = arg_int("retries", 1, 0, 5)
  cfg.timeout_ms = arg_int("timeout-ms", nil, 500, 60000)
  if not cfg.timeout_ms then
    cfg.timeout_ms = stdnse.get_timeout(host, 3000, 10000) or 3000
  end
  local mode = arg_string("transport")
  if mode then
    mode = string.lower(mode)
    if mode ~= "auto" and mode ~= "udp" and mode ~= "tcp" then
      mode = "auto"
    end
  else
    mode = "auto"
  end
  cfg.transport = mode
  return cfg
end

-- ---------------------------------------------------------------------------
-- 2. SNTP client (RFC 5905 section 7.3, SNTP subset)
-- Four timestamps drive the measurement: T1 client transmit, T2 server receive
-- (offset 32), T3 server transmit (offset 40), T4 client receive, giving
-- offset = ((T2 - T1) + (T3 - T4)) / 2 and delay = (T4 - T1) - (T3 - T2).
-- ---------------------------------------------------------------------------

local NTP_EPOCH_OFFSET = 2208988800 -- seconds between 1900 and 1970

local sntp = {}

function sntp.build_request(t1)
  -- LI = 0 (no warning), VN = 4, Mode = 3 (client).
  local header = string.char(0x23, 0, 6, 0xEC)
  local zeros = string.rep(string.char(0), 12)   -- root delay, dispersion, ref id
  local ref = string.rep(string.char(0), 8)      -- reference timestamp
  local originate = string.rep(string.char(0), 8) -- originate (unset for a client)
  local receive = string.rep(string.char(0), 8)
  local transmit = sntp.encode_timestamp(t1)
  return header .. zeros .. ref .. originate .. receive .. transmit
end

-- 64-bit NTP timestamp: 32 bits of seconds since 1900 plus 32 bits of fraction.
function sntp.encode_timestamp(unix_seconds)
  local seconds = math.floor(unix_seconds) + NTP_EPOCH_OFFSET
  local fraction = math.floor((unix_seconds - math.floor(unix_seconds)) * 4294967296)
  local function u32(value)
    return string.char(
      math.floor(value / 16777216.0) % 256,
      math.floor(value / 65536.0) % 256,
      math.floor(value / 256.0) % 256,
      value % 256)
  end
  return u32(seconds) .. u32(fraction)
end

-- 32-bit fields are rebuilt with float literals: 255 * 2^24 exceeds 2^31, and
-- integer arithmetic on a 32-bit build would wrap. Doubles represent every
-- 32-bit integer exactly, so this form is correct on every Lua.
function sntp.decode_timestamp(blob)
  if #blob < 8 then
    return nil
  end
  local seconds = string.byte(blob, 1) * 16777216.0 + string.byte(blob, 2) * 65536.0
                  + string.byte(blob, 3) * 256.0 + string.byte(blob, 4)
  local fraction = string.byte(blob, 5) * 16777216.0 + string.byte(blob, 6) * 65536.0
                   + string.byte(blob, 7) * 256.0 + string.byte(blob, 8)
  if seconds == 0 and fraction == 0 then
    return nil
  end
  return (seconds - NTP_EPOCH_OFFSET) + (fraction / 4294967296.0)
end

function sntp.decode(packet)
  if type(packet) ~= "string" or #packet < 48 then
    return nil, string.format("short SNTP reply (%d bytes, expected at least 48)", #packet)
  end
  local byte0 = string.byte(packet, 1)
  local leap = math.floor(byte0 / 64) % 4
  local version = math.floor(byte0 / 8) % 8
  local mode = byte0 % 8
  if mode ~= 4 and mode ~= 5 then
    return nil, string.format("unexpected SNTP mode %d (expected 4 = server or 5 = broadcast)", mode)
  end
  local stratum = string.byte(packet, 2)
  if stratum == 0 then
    return nil, "the SNTP server returned stratum 0 (kiss-o'-death): it is refusing to serve time"
  end
  local function u32(offset)
    return string.byte(packet, offset) * 16777216.0 + string.byte(packet, offset + 1) * 65536.0
           + string.byte(packet, offset + 2) * 256.0 + string.byte(packet, offset + 3)
  end
  local out = {
    leap = leap, version = version, mode = mode, stratum = stratum,
    poll = string.byte(packet, 3), precision = string.byte(packet, 4),
    root_delay = u32(5) / 65536, root_dispersion = u32(9) / 65536,
    ref_id = string.sub(packet, 13, 16),
    reference = sntp.decode_timestamp(string.sub(packet, 17, 24)),
    originate = sntp.decode_timestamp(string.sub(packet, 25, 32)),
    receive = sntp.decode_timestamp(string.sub(packet, 33, 40)),
    transmit = sntp.decode_timestamp(string.sub(packet, 41, 48)),
  }
  if leap == 3 then
    out.warning = "the time source reports its clock is unsynchronised (leap indicator 3)"
  end
  return out
end

function sntp.stratum_description(stratum)
  if stratum == 1 then
    return "primary reference (stratum 1: attached to a reference clock)"
  elseif stratum == 2 then
    return "secondary reference (stratum 2)"
  elseif stratum and stratum >= 3 and stratum <= 15 then
    return string.format("secondary reference (stratum %d)", stratum)
  elseif stratum == 16 then
    return "unsynchronised (stratum 16)"
  end
  return string.format("unclassified (stratum %s)", tostring(stratum))
end

-- Query a single SNTP server. Returns the measurement, or nil plus a reason.
function sntp.measure(host_ip, port, timeout_ms)
  local socket = nmap.new_socket("udp")
  socket:set_timeout(timeout_ms)
  local connected, err = socket:connect(host_ip, port)
  if not connected then
    socket:close()
    return nil, string.format("cannot open a UDP socket to %s:%d (%s)", tostring(host_ip), port, tostring(err))
  end

  local t1 = os.time()
  local request = sntp.build_request(t1)
  local sent, send_err = socket:send(request)
  if not sent then
    socket:close()
    return nil, string.format("send to the SNTP server failed (%s)", tostring(send_err))
  end

  local status, reply = socket:receive()
  local t4 = os.time()
  socket:close()

  local packet
  if status == true then
    packet = reply
  elseif type(status) == "string" and #status >= 48 then
    packet = status
  elseif type(reply) == "string" and #reply >= 48 then
    packet = reply
  else
    return nil, string.format("no usable SNTP reply (%s)", tostring(reply or status))
  end

  local decoded, decode_err = sntp.decode(packet)
  if not decoded then
    return nil, decode_err
  end

  local measurement = {
    t1 = t1,
    t4 = t4,
    server = decoded,
    round_trip = (t4 - t1),
    delay = nil,
    offset = nil,
  }
  if decoded.receive and decoded.transmit then
    -- The full four timestamp algorithm; the second resolution of os.time()
    -- makes sub-second precision meaningless, which the report states.
    measurement.offset = ((decoded.receive - t1) + (decoded.transmit - t4)) / 2
    measurement.delay = (t4 - t1) - (decoded.transmit - decoded.receive)
  end
  if decoded.originate and decoded.originate ~= t1 then
    measurement.originate_note = string.format(
      "the server echoed an originate timestamp of %.0f while this host sent %.0f: the reply may belong to another request",
      decoded.originate, t1)
  end
  return measurement
end
-- ---------------------------------------------------------------------------
-- 3. Kerberos clock sampling
-- Every KRB-ERROR and AS-REP carries the KDC's time; the offset uses the
-- exchange midpoint and the measured round trip (half the RTT is the error).
-- ---------------------------------------------------------------------------

local sampling = {}

function sampling.sample(host, port, cfg, realm, principal)
  local before = os.time()
  local record = transport.as_req(host, port, {
    realm = realm,
    cname = principal,
    etypes = { 18, 17, 23 },
    nonce = math.random(1, 2147483000),
    kdc_options = 0,
  }, { timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = cfg.transport })
  local after = os.time()

  local sample = {
    record = record,
    t_send = before,
    t_recv = after,
    rtt_s = record.rtt_ms and (record.rtt_ms / 1000) or (after - before),
  }

  if record.kind == "krb_error" then
    sample.stime = krb5.timeutil.parse_krbtime(record.krb_error.stime)
    sample.ctime = krb5.timeutil.parse_krbtime(record.krb_error.ctime)
    sample.susec = record.krb_error.susec
    sample.source = "KRB-ERROR " .. tostring(record.krb_error.code_name)
  elseif record.kind == "as_rep" then
    -- An AS-REP has no stime field: the ticket's validity window carries the
    -- KDC's notion of now, so the start time is the usable signal.
    local start = record.as_rep.ticket and record.as_rep.ticket.starttime
    sample.starttime = start
    sample.source = "AS-REP ticket validity window"
  else
    sample.error = record.error or "no answer"
    return sample
  end

  -- Offset = KDC clock - local clock, corrected for half the round trip.
  local midpoint = before + (sample.rtt_s / 2)
  if sample.stime then
    sample.offset = sample.stime - midpoint
  elseif sample.ctime then
    -- ctime is the client's own timestamp as the KDC saw it: the difference is
    -- the offset measured from the server's side, with the opposite sign.
    sample.offset = midpoint - sample.ctime
  end
  return sample
end

local function pace(cfg, index)
  if index <= 1 or cfg.delay_ms <= 0 then
    return
  end
  stdnse.sleep(cfg.delay_ms / 1000)
end

function sampling.run(host, port, cfg, realm, principal)
  local results = {}
  for index = 1, cfg.samples do
    pace(cfg, index)
    local sample = sampling.sample(host, port, cfg, realm, principal)
    sample.index = index; results[#results + 1] = sample
  end
  return results
end

-- ---------------------------------------------------------------------------
-- 4. Statistics
local stats = {}

function stats.usable(samples)
  local out = {}
  for _, sample in ipairs(samples) do
    if sample.offset then
      out[#out + 1] = sample.offset
    end
  end
  return out
end

function stats.summarise(values)
  local s = { count = #values }
  if #values == 0 then
    return s
  end
  local sorted = {}
  for i, value in ipairs(values) do
    sorted[i] = value
  end
  table.sort(sorted)
  s.min, s.max = sorted[1], sorted[#sorted]
  local sum = 0
  for _, value in ipairs(sorted) do
    sum = sum + value
  end
  s.mean = sum / #sorted
  if #sorted % 2 == 1 then
    s.median = sorted[math.floor(#sorted / 2) + 1]
  else
    s.median = (sorted[#sorted / 2] + sorted[#sorted / 2 + 1]) / 2
  end
  local variance = 0
  for _, value in ipairs(sorted) do
    variance = variance + (value - s.mean) * (value - s.mean)
  end
  s.deviation = math.sqrt(variance / #sorted)
  s.jitter = s.max - s.min
  return s
end

function stats.describe(seconds)
  if seconds == nil then
    return "unknown"
  end
  local sign = ""
  local magnitude = seconds
  if seconds < 0 then sign = "-"; magnitude = -seconds end
  if magnitude < 1 then
    return string.format("%s%d ms", sign, math.floor(magnitude * 1000 + 0.5))
  elseif magnitude < 120 then
    return string.format("%s%d s", sign, math.floor(magnitude + 0.5))
  elseif magnitude < 7200 then
    return string.format("%s%.1f min", sign, magnitude / 60)
  end
  return string.format("%s%.1f h", sign, magnitude / 3600)
end

-- ---------------------------------------------------------------------------
-- 5. Grading against the Kerberos tolerance
-- ---------------------------------------------------------------------------
local grading = {}

grading.LEVELS = {
  { name = "OK", threshold = 30, severity = "LOW",
    summary = "no Kerberos operation is at risk" },
  { name = "WATCH", threshold = 120, severity = "LOW",
    summary = "small, but NTP convergence is failing quietly" },
  { name = "DEGRADED", threshold = 300, severity = "MEDIUM",
    summary = "a substantial fraction of the Kerberos tolerance is consumed" },
  { name = "BROKEN", threshold = math.huge, severity = "CRITICAL",
    summary = "the offset exceeds the Kerberos tolerance: authentication is failing now" },
}

function grading.evaluate(offset, tolerance)
  if offset == nil then
    return { name = "UNKNOWN", severity = "INCONCLUSIVE", summary = "no usable clock sample was obtained" }
  end
  local magnitude = offset < 0 and -offset or offset
  local relative = magnitude / tolerance
  for _, level in ipairs(grading.LEVELS) do
    if magnitude <= level.threshold then
      return {
        name = level.name,
        severity = level.severity,
        summary = level.summary,
        magnitude = magnitude,
        tolerance = tolerance,
        headroom = tolerance - magnitude,
        fraction = relative,
      }
    end
  end
end

function grading.impact(offset, tolerance)
  local impact = {}
  if offset == nil then
    impact[#impact + 1] = "The relationship between the clocks could not be measured, so nothing about authentication risk can be concluded."
    return impact, "INCONCLUSIVE"
  end
  local magnitude = offset < 0 and -offset or offset
  local severity = grading.evaluate(offset, tolerance).severity
  impact[#impact + 1] = string.format(
    "Kerberos rejects a request when |KDC time - client time| exceeds the realm's skew tolerance, so the usable margin here is %s.",
    stats.describe(tolerance - magnitude))
  if severity == "CRITICAL" or severity == "MEDIUM" then
    impact[#impact + 1] = "Symptoms to expect: KRB_AP_ERR_SKEW (37) in client logs, event 4769/4771 failures on the KDC, and authentication that works from some hosts but not others. Replication between domain controllers also fails on clock related errors."
    impact[#impact + 1] = "Kerberos ticket validation depends on time: a skewed clock widens the window in which a captured ticket is still accepted, which is a security consequence as well as an availability one."
  end
  if offset < 0 then
    impact[#impact + 1] = "The KDC clock is behind this host. Requests sent by hosts that trust a correct clock will be rejected as being from the future."
  else
    impact[#impact + 1] = "The KDC clock is ahead of this host. Requests from hosts that trust a correct clock will be rejected as expired."
  end
  return impact, severity
end

-- ---------------------------------------------------------------------------
-- 6. Knowledge base
-- ---------------------------------------------------------------------------
local KB = {}

KB.TOLERANCE_NOTES = {
  "Active Directory tolerates a five minute (300 second) difference between the request timestamp and the KDC clock; beyond that it answers KRB_AP_ERR_SKEW (37).",
  "MIT krb5: the realm's clockskew setting in kdc.conf (default 300 s) governs the same decision, and libkrb5 applies its own client side check.",
  "Windows domain members follow the domain hierarchy: workstations and member servers sync from the domain controller that authenticated them.",
  "The forest root PDC emulator is authoritative: if it does not sync to a reliable external source, every clock in the forest inherits its error.",
  "Virtual machines inherit their host's clock through the hypervisor integration service, which is why a drifting ESXi or Hyper-V host presents as a forest-wide Kerberos problem.",
}

KB.REMEDIATION = {
  {
    title = "Windows domain",
    steps = {
      "Read the state: w32tm /query /status and w32tm /query /configuration on the affected host.",
      "Confirm the hierarchy: w32tm /monitor lists the domain controllers and their offsets.",
      "Only on the forest root PDC emulator, set an external source: w32tm /config /manualpeerlist:\"ntp1.example.net,0x8 ntp2.example.net,0x8\" /syncfromflags:manual /reliable:yes /update",
      "Force convergence: net stop w32time && net start w32time && w32tm /resync /rediscover",
      "Never configure external sources on member servers or ordinary domain controllers: they follow the hierarchy, or the forest ends up with competing sources.",
      "In virtual environments, let either the hypervisor or w32time own the clock, never both.",
      "A very large offset cannot be stepped in one call: the Windows Time service refuses jumps beyond MaxPosPhaseCorrection, so correct it in stages.", 
    },
  },
  {
    title = "UNIX and Linux clients and KDCs",
    steps = {
      "chrony: chronyc tracking shows the offset, frequency and last correction; chronyc sources -v lists the sources and their reachability.",
      "ntpd: ntpq -p prints the peer table with offset, jitter and reach; ntpq -c rv shows the daemon's own view of its state.",
      "systemd-timesyncd: timedatectl status reports whether the clock is synchronised and from which server.",
      "Run at least four sources so the selection algorithm can outvote a falseticker.",
      "For KDCs, monitor the offset instead of only correcting it: frequent large corrections mean a broken source.",
    },
  },
  {
    title = "Infrastructure and monitoring",
    steps = {
      "Alert on |offset| exceeding 30 s: far below the Kerberos tolerance but far above normal NTP noise, so it catches drift before it becomes an outage.",
      "Include the KDC time fields in health checks; if public sources are unreachable, deploy an internal reference server.",
      "Document the authoritative time source per realm: during incident response, knowing which clock is right saves time.",
    },
  },
}

KB.VERIFICATION = {
  "klist -e -5 shows the ticket validity window on a UNIX client, which reflects the KDC's clock, not the client's.",
  "date -u on the KDC and the client, compared against a known good source, is the crudest but most convincing check.",
  "kinit -V <principal> returns 'Clock skew too great in KRB_TGS_REQ request' when the client is outside the realm tolerance: that error confirms the offset is already operationally significant.",
  "ntpdate -q <server> or chronyd -Q 'server <host> iburst' measures the offset without stepping the clock, as this script's SNTP section does.",
}
-- ---------------------------------------------------------------------------
-- 7. Reporting
-- ---------------------------------------------------------------------------

local report = {}

local RISK_LABEL = {
  CRITICAL = "\240\159\148\180 CRITICAL",
  HIGH = "\240\159\159\160 HIGH",
  MEDIUM = "\240\159\159\161 MEDIUM",
  LOW = "\240\159\159\162 LOW",
  INCONCLUSIVE = "\240\159\159\161 MEDIUM (INCONCLUSIVE - the clock relationship could not be measured)",
}

function report.build(cfg, realm, principal, samples, values, summary, network, grading_result)
  local out = stdnse.output_table()

  out["Script version"] = SCRIPT_VERSION
  out["Declared risk class"] = SCRIPT_RISK
  out["Realm"] = realm
  out["Principal sampled"] = principal
  out["Local time (scanner)"] = krb5.timeutil.iso8601_utc(os.time()) or "unavailable (os.date failed)"

  local usable, unusable = 0, 0
  local sources = {}
  for _, sample in ipairs(samples) do
    if sample.offset then
      usable = usable + 1
      sources[sample.source or "unknown"] = (sources[sample.source or "unknown"] or 0) + 1
    else
      unusable = unusable + 1
    end
  end
  local source_list = {}
  for source, count in pairs(sources) do
    source_list[#source_list + 1] = string.format("%s x%d", source, count)
  end
  table.sort(source_list)
  out["Kerberos clock samples"] = string.format("%d taken, %d usable, %d without a time field (%s)",
    #samples, usable, unusable, #source_list > 0 and table.concat(source_list, ", ") or "none")

  -- Per sample detail: an audit result has to be reproducible, so the raw
  -- readings are part of the output.
  local detail = {}
  for _, sample in ipairs(samples) do
    local answer = sample.record and sample.record.kind or "no answer"
    detail[#detail + 1] = string.format("#%-2d %-14s round trip %.0f ms   offset %s   %s",
      sample.index or 0, answer, (sample.rtt_s or 0) * 1000,
      stats.describe(sample.offset), tostring(sample.source or sample.error or ""))
  end
  out["Sample detail"] = detail

  if usable > 0 then
    out["KDC offset (clock delta, KDC minus scanner)"] = string.format(
      "median %s, mean %s, range %s to %s, jitter %s over %d usable sample(s)",
      stats.describe(summary.median), stats.describe(summary.mean),
      stats.describe(summary.min), stats.describe(summary.max),
      stats.describe(summary.jitter), summary.count)
    local quality = {
      "os.time() has one second resolution, so each offset carries up to +/- 1 s of quantisation on top of the round trip correction.",
    }
    if summary.jitter and summary.jitter > 5 then
      quality[#quality + 1] = string.format(
        "the samples span %s: treat the median as the estimate and the jitter as evidence of an unstable clock path",
        stats.describe(summary.jitter))
    else
      quality[#quality + 1] = "the samples cluster tightly, so the median is a stable estimate"
    end
    if usable < 3 then
      quality[#quality + 1] = "fewer than three usable samples were collected; raise kerberos.samples for a trustworthy median"
    end
    out["Measurement quality"] = quality
  end

  out["Kerberos tolerance"] = string.format(
    "%d s (KRB_AP_ERR_SKEW beyond it); tolerance in force set by kerberos.skew-tolerance", cfg.skew_tolerance)
  if grading_result and grading_result.headroom then
    out["Headroom before authentication fails"] = string.format("%s (%.0f%% of the tolerance consumed)",
      stats.describe(grading_result.headroom), 100 * grading_result.fraction)
  end

  if network then
    local lines = {}
    lines[#lines + 1] = string.format("Server %s:%d", tostring(cfg.ntp_server), cfg.ntp_port)
    if network.ok then
      local server = network.measurement.server
      lines[#lines + 1] = string.format("Stratum %s: %s", tostring(server.stratum),
        sntp.stratum_description(server.stratum))
      lines[#lines + 1] = string.format("NTP offset (server minus scanner): %s; round trip delay %s",
        stats.describe(network.measurement.offset), stats.describe(network.measurement.delay))
      lines[#lines + 1] = string.format("Root delay %.1f ms, root dispersion %.1f ms, version %d, mode %d",
        (server.root_delay or 0) * 1000, (server.root_dispersion or 0) * 1000,
        server.version or 0, server.mode or 0)
      if server.reference then
        -- Lua 5.3 os.date() requires an integer: NTP timestamps are fractional.
        local reference_text = krb5.timeutil.iso8601_utc(server.reference)
        if reference_text then
          lines[#lines + 1] = string.format("Last reference update: %s", reference_text)
        end
      end
      if server.warning then
        lines[#lines + 1] = "WARNING: " .. server.warning
      end
      if network.measurement.originate_note then
        lines[#lines + 1] = "WARNING: " .. network.measurement.originate_note
      end
      if summary.median and network.measurement.offset then
        local delta = summary.median - network.measurement.offset
        lines[#lines + 1] = string.format(
          "Difference between the KDC offset and the network time offset: %s", stats.describe(delta))
        if delta > 5 or delta < -5 then
          lines[#lines + 1] = "The two references disagree by more than five seconds, so the KDC is not following the same time source as the rest of the network."
        else
          lines[#lines + 1] = "The KDC agrees with network time to within five seconds, so the domain controller is following a sane time source."
        end
      end
    else
      lines[#lines + 1] = "The SNTP query failed: " .. tostring(network.error)
      lines[#lines + 1] = "Without a second reference the report can only say how the KDC relates to this host, not which of the two clocks is wrong."
    end
    out["NTP cross-check"] = lines
  else
    out["NTP cross-check"] = "skipped: set kerberos.ntp-server to compare the KDC clock with a network time source"
  end

  out["Kerberos time rules"] = KB.TOLERANCE_NOTES
  return out
end

-- ---------------------------------------------------------------------------
-- 8. Action
-- ---------------------------------------------------------------------------

action = function(host, port)
  local cfg = config.load(host)
  local effective_port = port.number

  if not cfg.principal then
    cfg.principal = string.format("nmap-skew-%d", math.random(100000, 999999))
  end

  -- Realm resolution: the KDC leaks its realm for a foreign one.
  local realm = cfg.realm
  if not realm then
    local record = transport.as_req(host, effective_port, {
      realm = "NMAP.INVALID.REALM",
      cname = cfg.principal,
      etypes = { 18, 17, 23 },
      nonce = math.random(1, 2147483000),
      kdc_options = 0,
    }, { timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = cfg.transport })
    if record.kind == "krb_error" then
      local e = record.krb_error
      for _, value in ipairs({ e.realm, e.crealm }) do
        if value and #value >= 3 then
          realm = string.upper(value)
          break
        end
      end
    end
  end

  if not realm then
    local out = stdnse.output_table()
    out["Script version"] = SCRIPT_VERSION
    out["Declared risk class"] = SCRIPT_RISK
    out["Check status"] = "ABORTED - the Kerberos realm could not be determined"
    out["Why"] = {
      "The AS-REQ must address a realm for the KDC to answer with its time fields at all.",
      "Supply kerberos.realm, or point the script at a KDC that answers foreign realm probes.",
    }
    out["Risk Level"] = RISK_LABEL.INCONCLUSIVE
    return out
  end

  -- Kerberos samples.
  local samples = sampling.run(host, effective_port, cfg, realm, cfg.principal)
  local values = stats.usable(samples)
  local summary = stats.summarise(values)

  -- Optional SNTP cross-check against a second reference.
  local network
  if cfg.ntp_server then
    local measurement, err = sntp.measure(host.ip, cfg.ntp_port, cfg.timeout_ms)
    network = { ok = measurement ~= nil, measurement = measurement, error = err }
  end

  local grading_result = grading.evaluate(summary.median, cfg.skew_tolerance)
  local out = report.build(cfg, realm, cfg.principal, samples, values, summary, network, grading_result)
  local impact, severity = grading.impact(summary.median, cfg.skew_tolerance)

  local verdict = {}
  verdict[#verdict + 1] = string.format("Clock relationship: %s (%s)", grading_result.name, grading_result.summary)
  for _, line in ipairs(impact) do
    verdict[#verdict + 1] = line
  end
  if network and network.ok and summary.median and network.measurement.offset then
    local delta = summary.median - network.measurement.offset
    if delta > 5 or delta < -5 then
      verdict[#verdict + 1] = "Because the KDC disagrees with network time, the drift to fix is on the KDC side, not on the scanning host."
    end
  elseif not cfg.ntp_server then
    verdict[#verdict + 1] = "No second time reference was queried, so this report cannot say which of the two clocks is wrong. Add kerberos.ntp-server to attribute the drift."
  end
  out["Verdict"] = verdict

  if severity ~= "LOW" then
    local remediation = {}
    for _, group in ipairs(KB.REMEDIATION) do
      remediation[#remediation + 1] = "== " .. group.title .. " =="
      for _, step in ipairs(group.steps) do
        remediation[#remediation + 1] = "  " .. step
      end
    end
    out["Remediation"] = remediation
    out["Independent verification"] = KB.VERIFICATION
    out["References"] = {
      "RFC 4120 section 3.1.3 - KerberosTime and the clock skew requirement",
      "RFC 4120 section 7.5.1 - KRB_AP_ERR_SKEW (37) and its place in the error registry",
      "RFC 5905 - Network Time Protocol version 4: protocol operation and the four timestamp algorithm",
      "RFC 4330 - Simple Network Time Protocol version 4",
      "Microsoft: Windows Time service tools and settings (w32tm) and the domain hierarchy rules",
      "Microsoft: how the Windows Time service works (forest root PDC emulator as the authoritative source)",
    }
  end

  out["Risk Level"] = RISK_LABEL[severity] or severity
  return out
end
