local shortport = require "shortport"
local sslcert = require "sslcert"
local datetime = require "datetime"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Checks the validity window of the presented TLS certificate against
the current time. Flags certificates that are already expired, not
yet valid, or expiring within a configurable warning threshold
(default 30 days, override with ssl-cert-expiry.warndays).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.ssl

local function to_epoch(value)
  if type(value) == "number" then
    return value
  end
  if type(value) == "table" and value.year then
    return os.time(value)
  end
  return nil
end

action = function(host, port)
  local status, cert = sslcert.getCertificate(host, port)
  if not status or not cert or not cert.validity then
    return "Could not retrieve certificate validity information."
  end

  local warndays = tonumber(stdnse.get_script_args("ssl-cert-expiry.warndays")) or 30
  local now = os.time()

  local not_before = to_epoch(cert.validity.notBefore)
  local not_after = to_epoch(cert.validity.notAfter)

  local out = stdnse.output_table()

  if not not_before or not not_after then
    return "Could not parse certificate validity timestamps."
  end

  local ok_before, before_str = pcall(datetime.format_timestamp, cert.validity.notBefore)
  local ok_after, after_str = pcall(datetime.format_timestamp, cert.validity.notAfter)

  out["Valid from"] = ok_before and before_str or tostring(cert.validity.notBefore)
  out["Valid until"] = ok_after and after_str or tostring(cert.validity.notAfter)

  local seconds_per_day = 86400
  local days_remaining = math.floor((not_after - now) / seconds_per_day)

  if now < not_before then
    out["Status"] = "NOT YET VALID - certificate start date is in the future"
  elseif now > not_after then
    local days_expired = math.floor((now - not_after) / seconds_per_day)
    out["Status"] = string.format("EXPIRED - certificate expired %d day(s) ago", days_expired)
  elseif days_remaining <= warndays then
    out["Status"] = string.format(
      "EXPIRING SOON - certificate expires in %d day(s) (warning threshold: %d)",
      days_remaining, warndays
    )
  else
    out["Status"] = string.format(
      "OK - certificate valid for %d more day(s)", days_remaining
    )
  end

  out["Warning threshold (days)"] = tostring(warndays)

  return out
end
