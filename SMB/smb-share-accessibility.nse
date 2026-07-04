local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Establishes an anonymous or guest SMB session (whichever succeeds
first) and then attempts a tree connect to a set of default and
administrative share names (IPC$, ADMIN$, C$, D$, print$) to report
which are reachable without valid domain credentials.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

hostrule = function(host)
  local ok, port = pcall(smb.get_port, host)
  return ok and port ~= nil
end

local SHARE_NAMES = { "IPC$", "ADMIN$", "C$", "D$", "print$" }

local function establish_session(state)
  local ok1, res1 = pcall(smb.start_session, state, { username = "", password = "", domain = "" })
  if ok1 and (res1 == true or type(res1) ~= "boolean") then
    return "anonymous null session"
  end
  local ok2, res2 = pcall(smb.start_session, state, { username = "guest", password = "", domain = "" })
  if ok2 and (res2 == true or type(res2) ~= "boolean") then
    return "guest session"
  end
  return nil
end

action = function(host)
  local out = stdnse.output_table()

  local status, state = pcall(smb.start, host)
  if not status or not state then
    return "Could not open an SMB connection to this host."
  end

  local neg_status = pcall(smb.negotiate_protocol, state, {})
  if not neg_status then
    pcall(smb.stop, state)
    return "SMB protocol negotiation failed."
  end

  local session_type = establish_session(state)
  if not session_type then
    pcall(smb.stop, state)
    out["Result"] = "Neither anonymous nor guest session could be established - default share accessibility could not be tested unauthenticated."
    return out
  end

  out["Session type used"] = session_type

  if type(smb.tree_connect) ~= "function" then
    pcall(smb.stop, state)
    out["Result"] = "The installed smb library does not expose a tree_connect function under this name; share accessibility could not be tested by this script."
    return out
  end

  local reachable = {}
  local unreachable = {}

  for _, share in ipairs(SHARE_NAMES) do
    local ok, tree_status = pcall(smb.tree_connect, state, share)
    if ok and tree_status then
      table.insert(reachable, share)
    else
      table.insert(unreachable, share)
    end
  end

  pcall(smb.stop, state)

  if #reachable > 0 then
    out["Shares reachable without domain credentials"] = reachable
  else
    out["Shares reachable without domain credentials"] = "None of the tested default/administrative shares were reachable."
  end

  if #unreachable > 0 then
    out["Shares not reachable"] = unreachable
  end

  return out
end
