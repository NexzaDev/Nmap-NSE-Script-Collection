#!/usr/bin/env node
/*
 * tools/nse-sim.js
 * ---------------------------------------------------------------------------
 * An in-process NSE harness: it executes a real .nse script inside a real
 * Lua 5.3 VM (fengari) with the NSE API shimmed, and answers the script's
 * socket traffic from a mock service implementation.
 *
 * Why this exists: "compiles" is not "works". The NSE socket contract is
 * emulated strictly after https://nmap.org/nsedoc/lib/nmap.html --
 *   * socket:send(data)          -> true | false, error
 *   * socket:receive()           -> true, data | false, "TIMEOUT"/"EOF"/...
 *   * socket:receive_bytes(n)    -> true, data | false, error
 *   * receive_bytes() returns everything currently buffered, which may be
 *     MORE bytes than requested and fewer than requested when the peer is
 *     slow. Scripts that assume exact framing fail here, as they would
 *     against a real KDC that coalesces TCP segments.
 *
 * Usage:
 *   node tools/nse-sim.js tools/tests/kerberos-asrep-roasting.test.js
 *   node tools/nse-sim.js --script KERBEROS/x.nse --mock tools/mocks/kdc.js --scenario '{"realm":"EXAMPLE.COM"}'
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { lua, lauxlib, lualib, to_luastring, to_jsstring } = require("fengari");

const REPO_ROOT = path.resolve(__dirname, "..");

const DEBUG_LEVELS = { 1: [], 2: [], 3: [], 4: [] };

function pushLuaString(L, value) {
  const bytes = Buffer.from(value, "binary");
  lua.lua_pushlstring(L, bytes, bytes.length);
}

function makeModule(L, obj) {
  lua.lua_newtable(L);
  const set = (name, value) => {
    if (typeof value === "function") lua.lua_pushjsfunction(L, value);
    else if (typeof value === "string") lua.lua_pushstring(L, to_luastring(value));
    else if (typeof value === "number") lua.lua_pushnumber(L, value);
    else if (typeof value === "boolean") lua.lua_pushboolean(L, value);
    else if (value === null || value === undefined) lua.lua_pushnil(L);
    else throw new Error(`unsupported module value for ${name}`);
    lua.lua_setfield(L, -2, to_luastring(name));
  };
  for (const [k, v] of Object.entries(obj)) set(k, v);
  return L;
}

// Lua preamble: implements the NSE socket object on top of the JS bridge
// `__nse.io`, registers the `bit` library (absent from fengari) and installs
// the module table so both require("x") and the globals resolve.
const PREAMBLE = `
local __nse = ...
__nse.debug_log = {}

local function push_debug(level, msg)
  __nse.debug_log[#__nse.debug_log + 1] = string.format("[%d] %s", level, msg)
end

local function __tohex(s)
  return (string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end))
end
local function __fromhex(h)
  return (string.gsub(h, "(%x%x)", function(b) return string.char(tonumber(b, 16)) end))
end

local function fmt_args(...)
  local n = select("#", ...)
  local parts = {}
  for i = 1, n do parts[i] = tostring((select(i, ...))) end
  return table.concat(parts, " ")
end

stdnse = {}
function stdnse.debug(level, fmt, ...)
  if level <= __nse.debug_level then push_debug(level, fmt and string.format(fmt, ...) or "") end
end
function stdnse.debug1(fmt, ...) stdnse.debug(1, fmt, ...) end
function stdnse.debug2(fmt, ...) stdnse.debug(2, fmt, ...) end
function stdnse.debug3(fmt, ...) stdnse.debug(3, fmt, ...) end
function stdnse.output_table() return {} end
function stdnse.format_output(success, t)
  if type(t) == "table" then return table.concat(t, "\\n") end
  return tostring(t)
end
function stdnse.get_timeout(host, default_ms, max_ms)
  local t = (host and host.times and host.times.timeout) or nil
  local base = default_ms or 5000
  if t then base = math.floor(t * 1000) end
  if max_ms and base > max_ms then base = max_ms end
  if base < 500 then base = 500 end
  return base
end
function stdnse.get_script_args(key)
  if type(key) == "table" then
    for _, k in ipairs(key) do
      local v = __nse.script_args[k]
      if v ~= nil then return v end
    end
    return nil
  end
  local v = __nse.script_args[key]
  if v == nil then
    -- allow the "kerberos.users" form to match a nested table
    local root, leaf = string.match(key or "", "^([^%.]+)%.(.+)$")
    if root and __nse.script_args[root] then
      local sub = __nse.script_args[root]
      if type(sub) == "table" then return sub[leaf] end
    end
  end
  return v
end
function stdnse.sleep(seconds)
  __nse.slept = (__nse.slept or 0) + (seconds or 0)
end
function stdnse.tohex(s) return (string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end)) end
function stdnse.fromhex(s) return (string.gsub(s, "(%x%x)", function(h) return string.char(tonumber(h, 16)) end)) end

nmap = {}
function nmap.clock_ms() return __nse.now_ms() end
function nmap.clock_mono_ms() return __nse.now_ms() end
function nmap.clock() return __nse.now_ms() / 1000 end
function nmap.timing_level() return 3 end
function nmap.verbosity() return 0 end
function nmap.debugging() return __nse.debug_level end
function nmap.address_family() return "inet" end
function nmap.set_port_state(host, port, state)
  __nse.port_state = state
  if port then port.state = state end
  return true
end
function nmap.get_port_state(host, port) return port and port.state or "open" end
nmap.registry = { args = __nse.script_args }

function nmap.new_socket(proto, af)
  local s = {
    _proto = proto or "tcp",
    _buf = "",
    _closed = false,
    _connected = false,
    _timeout = 1000,
  }
  function s:set_timeout(ms) self._timeout = ms; return true end
  function s:connect(host, port)
    self._host = (type(host) == "table" and (host.ip or host.name)) or host
    self._port = port
    self._connected = true
    return true
  end
  function s:bind() return true end
  function s:send(data)
    if self._closed then return false, "Trying to send through a closed socket" end
    if not self._connected then return false, "Trying to send through a closed socket" end
    local resp, err = __nse.io(self._proto, self._host, self._port, __tohex(data), self._timeout)
    if resp == nil then
      return true
    end
    self._buf = self._buf .. __fromhex(resp)
    return true
  end
  function s:receive()
    if self._closed then return false, "Trying to receive through a closed socket" end
    if #self._buf == 0 then __nse.advance(self._timeout); return false, "TIMEOUT" end
    local data = self._buf
    self._buf = ""
    return true, data
  end
  function s:receive_bytes(n)
    if self._closed then return false, "Trying to receive through a closed socket" end
    -- Real NSE hands back everything currently buffered, so this can return
    -- more (or fewer) bytes than requested.
    if #self._buf == 0 then __nse.advance(self._timeout); return false, "TIMEOUT" end
    local data = self._buf
    self._buf = ""
    return true, data
  end
  function s:receive_lines(n)
    if #self._buf == 0 then __nse.advance(self._timeout); return false, "TIMEOUT" end
    local data = self._buf
    self._buf = ""
    return true, data
  end
  function s:close() self._closed = true; return true end
  function s:get_info() return nil, "not available in the simulator" end
  return s
end

shortport = {}
function shortport.port_or_service(ports, services, protos, states)
  return function(host, port) return port ~= nil end
end
function shortport.portnumber(port, proto, states) return function() return true end end
function shortport.service(services, protos) return function() return true end end
function shortport.http(host, port) return true end

vulns = {}
__nse.vulns = {}
function vulns.add(host, port, id, title, details)
  __nse.vulns[#__nse.vulns + 1] = { id = id, title = title, port = port and port.number }
  return true
end
function vulns.add_vulns_to_output_table(...) return {} end
function vulns.Report() return { add = vulns.add } end

-- LuaBitOp equivalent on top of Lua 5.3 integer operators.
local bit = {}
local function to32(x) return math.floor(x) % 4294967296 end
local function from32(x) local v = to32(x); if v >= 2147483648 then v = v - 4294967296 end; return v end
function bit.band(a, b) return from32(to32(a) * 1 % 4294967296) * 0 + 0 end
bit = nil

-- io shim: NSE ships the standard io library, so scripts legitimately read
-- wordlists and SPN lists with io.open. The simulator maps it onto the real
-- filesystem through the JS bridge.
io = {}
function io.open(path, mode)
  mode = mode or "r"
  local handle, err = __nse.io_open(path, mode)
  if not handle then return nil, err end
  local file = { _id = handle, _closed = false }
  function file:lines()
    if self._closed then return nil end
    return function()
      local line = __nse.io_readline(self._id)
      if line == nil then return nil end
      return line
    end
  end
  function file:read(pattern)
    if self._closed then return nil end
    if pattern == "*a" or pattern == "*all" or pattern == nil then
      return __nse.io_readall(self._id)
    end
    return __nse.io_readline(self._id)
  end
  function file:close() self._closed = true; __nse.io_close(self._id); return true end
  file.write = function() return nil, "read-only simulator filesystem" end
  return file
end
function io.write(...) return true end
function io.stderr_write(...) return true end

__nse.push_debug = push_debug
__nse.fmt_args = fmt_args

-- Hard wall-clock watchdog: any script loop that fails to make progress ends
-- as a Lua error naming the source line instead of hanging the harness.
local __deadline = __nse.wall_ms() + (__nse.limit_ms or 20000)
debug.sethook(function()
  if __nse.wall_ms() > __deadline then
    error("SIMULATOR WATCHDOG: script exceeded " .. tostring(__nse.limit_ms) .. " ms" .. string.char(10) .. debug.traceback("", 2), 2)
  end
end, "", 2000)

return __nse
`;

// bit.band etc. need 64-bit safe integer math; implement with Lua 5.3 bitwise
// operators, which fengari supports natively, instead of arithmetic emulation.
const BIT_LIBRARY = `
bit = {}
local function op(f)
  return function(a, b, ...)
    local r = f(a, b)
    local extra = { ... }
    for i = 1, #extra do r = f(r, extra[i]) end
    return r
  end
end
bit.band = op(function(a, b) return a & b end)
bit.bor = op(function(a, b) return a | b end)
bit.bxor = op(function(a, b) return a ~ b end)
bit.bnot = function(a) return ~a end
bit.lshift = function(a, n) return a << n end
bit.rshift = function(a, n) return (a & 0xFFFFFFFF) >> n end
bit.arshift = function(a, n) return a >> n end
bit.rol = function(a, n) return ((a << n) | ((a & 0xFFFFFFFF) >> (32 - n))) & 0xFFFFFFFF end
bit.ror = function(a, n) return (((a & 0xFFFFFFFF) >> n) | (a << (32 - n))) & 0xFFFFFFFF end
bit.tobit = function(a) return a & 0xFFFFFFFF end
bit.tohex = function(a, n) return string.format("%08x", a & 0xFFFFFFFF) end
`;

function luaValueToJs(L, index, depth = 0) {
  if (depth > 12) return "<deep>";
  const type = lua.lua_type(L, index);
  switch (type) {
    case lua.LUA_TNIL: return null;
    case lua.LUA_TBOOLEAN: return lua.lua_toboolean(L, index);
    case lua.LUA_TNUMBER: return lua.lua_tonumber(L, index);
    case lua.LUA_TSTRING: return lua.lua_tojsstring(L, index);
    case lua.LUA_TTABLE: {
      const isArray = lua.lua_rawlen(L, index) > 0;
      const out = isArray ? [] : {};
      lua.lua_pushnil(L);
      while (lua.lua_next(L, index < 0 ? index - 1 : index) !== 0) {
        const keyType = lua.lua_type(L, -2);
        let key;
        if (keyType === lua.LUA_TSTRING) key = lua.lua_tojsstring(L, -2);
        else if (keyType === lua.LUA_TNUMBER) key = lua.lua_tonumber(L, -2);
        else key = "<key>";
        const value = luaValueToJs(L, -1, depth + 1);
        if (isArray && typeof key === "number") out[key - 1] = value;
        else out[key] = value;
        lua.lua_pop(L, 1);
      }
      return out;
    }
    default:
      return `<${lua.lua_typename(L, type)}>`;
  }
}

function createHost(hostSpec) {
  return Object.assign({
    ip: "10.0.0.10",
    name: null,
    targetname: null,
    times: { timeout: 3 },
  }, hostSpec || {});
}

function runScript(options) {
  const L = lauxlib.luaL_newstate();
  lualib.luaL_openlibs(L);

  const state = {
    nowMs: 1700000000000,
    slept: 0,
    debug_level: options.debugLevel || 0,
    script_args: options.args || {},
    vulns: [],
    port_state: null,
    ioCalls: 0,
  };

  const bridge = {
    script_args: options.args || {},
    debug_level: options.debugLevel || 0,
    slept: 0,
    vulns: [],
    io: null, // filled below
    now_ms: () => state.nowMs,
  };

  const mock = options.mock;
  const trace = process.env.NSE_SIM_TRACE === "1";
  bridge.io = (proto, host, port, payload, timeout) => {
    state.ioCalls += 1;
    state.nowMs += 3; // simulated RTT
    if (trace) console.error(`[io#${state.ioCalls}] ${proto} ${host}:${port} tx=${payload.length}B`);
    if (!mock) return [null, "TIMEOUT"];
    const result = mock.handle(payload, proto, { host, port });
    if (!result || !result.raw) {
      if (trace) console.error(`            (no response: ${(result && result.error) || "drop"})`);
      return [null, result && result.error ? "ERROR" : "TIMEOUT"];
    }
    if (trace) console.error(`            rx=${result.raw.length}B`);
    return [Buffer.from(result.raw).toString("hex"), null];
  };

  // Build __nse
  lua.lua_newtable(L);
  lua.lua_pushjsfunction(L, function (Lp) {
    const proto = lua.lua_tojsstring(Lp, 1);
    const host = lua.lua_tojsstring(Lp, 2);
    const port = lua.lua_tonumber(Lp, 3);
    const payload = Buffer.from(lua.lua_tojsstring(Lp, 4), "hex");
    const timeout = lua.lua_tonumber(Lp, 5);
    const [resp, err] = bridge.io(proto, host, port, payload, timeout);
    if (resp === null || resp === undefined) {
      lua.lua_pushnil(Lp);
      lua.lua_pushstring(Lp, to_luastring(err || "TIMEOUT"));
      return 2;
    }
    pushLuaString(Lp, resp);
    lua.lua_pushnil(Lp);
    return 2;
  });
  lua.lua_setfield(L, -2, to_luastring("io"));
  lua.lua_pushjsfunction(L, function (Lp) { lua.lua_pushnumber(Lp, state.nowMs); return 1; });
  lua.lua_setfield(L, -2, to_luastring("now_ms"));
  lua.lua_pushjsfunction(L, function (Lp) {
    state.nowMs += lua.lua_tonumber(Lp, 1) || 0;
    return 0;
  });
  lua.lua_setfield(L, -2, to_luastring("advance"));

  // File I/O bridge for the io shim. Paths are resolved relative to the
  // repository root so test fixtures and wordlists work from any cwd.
  const openFiles = new Map();
  let nextFileId = 1;
  const resolvePath = (p) => (path.isAbsolute(p) ? p : path.resolve(REPO_ROOT, p));
  lua.lua_pushjsfunction(L, function (Lp) {
    const rawPath = lua.lua_tojsstring(Lp, 1);
    try {
      const text = fs.readFileSync(resolvePath(rawPath), "utf8");
      const lines = text.split(/\r?\n/);
      const id = nextFileId++;
      openFiles.set(id, { lines, index: 0 });
      lua.lua_pushnumber(Lp, id);
      lua.lua_pushnil(Lp);
      return 2;
    } catch (err) {
      lua.lua_pushnil(Lp);
      lua.lua_pushstring(Lp, to_luastring(String(err.message || err)));
      return 2;
    }
  });
  lua.lua_setfield(L, -2, to_luastring("io_open"));
  lua.lua_pushjsfunction(L, function (Lp) {
    const id = lua.lua_tonumber(Lp, 1);
    const entry = openFiles.get(id);
    if (!entry || entry.index >= entry.lines.length) {
      lua.lua_pushnil(Lp);
      return 1;
    }
    const line = entry.lines[entry.index++];
    lua.lua_pushstring(Lp, to_luastring(line));
    return 1;
  });
  lua.lua_setfield(L, -2, to_luastring("io_readline"));
  lua.lua_pushjsfunction(L, function (Lp) {
    const entry = openFiles.get(lua.lua_tonumber(Lp, 1));
    if (!entry) {
      lua.lua_pushnil(Lp);
      return 1;
    }
    lua.lua_pushstring(Lp, to_luastring(entry.lines.slice(entry.index).join("\n")));
    entry.index = entry.lines.length;
    return 1;
  });
  lua.lua_setfield(L, -2, to_luastring("io_readall"));
  lua.lua_pushjsfunction(L, function (Lp) {
    openFiles.delete(lua.lua_tonumber(Lp, 1));
    return 0;
  });
  lua.lua_setfield(L, -2, to_luastring("io_close"));

  const wallStart = Date.now();
  lua.lua_pushjsfunction(L, function (Lp) { lua.lua_pushnumber(Lp, Date.now() - wallStart); return 1; });
  lua.lua_setfield(L, -2, to_luastring("wall_ms"));
  lua.lua_pushnumber(L, Number(process.env.NSE_SIM_LIMIT_MS || 20000));
  lua.lua_setfield(L, -2, to_luastring("limit_ms"));

  // Debug level / script args / vuln capture are plain Lua tables filled by JS
  lua.lua_pushnumber(L, options.debugLevel || 0);
  lua.lua_setfield(L, -2, to_luastring("debug_level"));

  lua.lua_newtable(L);
  for (const [k, v] of Object.entries(options.args || {})) {
    lua.lua_pushstring(L, to_luastring(v));
    lua.lua_setfield(L, -2, to_luastring(k));
  }
  lua.lua_setfield(L, -2, to_luastring("script_args"));

  lua.lua_newtable(L);
  lua.lua_setfield(L, -2, to_luastring("vulns"));

  const nseRef = lua.lua_gettop(L);
  lua.lua_pushvalue(L, nseRef);
  lua.lua_setglobal(L, to_luastring("__nse"));

  // Load the preamble with __nse as its single upvalue argument.
  const preambleFn = lua.lua_gettop(L);
  lua.lua_pushvalue(L, nseRef);
  if (lauxlib.luaL_loadstring(L, to_luastring(PREAMBLE)) !== lua.LUA_OK) {
    throw new Error("preamble failed to compile: " + lua.lua_tojsstring(L, -1));
  }
  lua.lua_pushvalue(L, nseRef);
  if (lua.lua_pcall(L, 1, 1, 0) !== lua.LUA_OK) {
    throw new Error("preamble failed: " + lua.lua_tojsstring(L, -1));
  }
  lua.lua_pop(L, 1); // preamble return value
  void preambleFn;

  if (lauxlib.luaL_loadstring(L, to_luastring(BIT_LIBRARY)) !== lua.LUA_OK) {
    throw new Error("bit library failed to compile: " + lua.lua_tojsstring(L, -1));
  }
  if (lua.lua_pcall(L, 0, 0, 0) !== lua.LUA_OK) {
    throw new Error("bit library failed: " + lua.lua_tojsstring(L, -1));
  }

  // module table: package.loaded[...] = the global the preamble created
  for (const name of ["nmap", "stdnse", "shortport", "vulns", "bit"]) {
    lua.lua_getglobal(L, to_luastring(name));
    lua.lua_getfield(L, -1, to_luastring("_G"));
    lua.lua_pop(L, 1);
    lua.lua_getglobal(L, to_luastring("package"));
    lua.lua_getfield(L, -1, to_luastring("loaded"));
    lua.lua_pushvalue(L, -3);
    lua.lua_setfield(L, -2, to_luastring(name));
    lua.lua_pop(L, 3);
  }

  // Preload the repository's nselib modules, emulating an installed Nmap data
  // directory (script -> require "kerberos5" -> nselib/kerberos5.lua).
  const nselibDir = path.join(REPO_ROOT, "nselib");
  const moduleFiles = fs.existsSync(nselibDir)
    ? fs.readdirSync(nselibDir).filter((f) => f.endsWith(".lua"))
    : [];
  for (const file of moduleFiles) {
    const mod = path.basename(file, ".lua");
    const modSource = fs.readFileSync(path.join(nselibDir, file));
    if (lauxlib.luaL_loadbuffer(L, modSource, modSource.length, to_luastring("@" + path.join("nselib", file))) !== lua.LUA_OK) {
      throw new Error(`module ${mod} failed to compile: ` + lua.lua_tojsstring(L, -1));
    }
    if (lua.lua_pcall(L, 0, 1, 0) !== lua.LUA_OK) {
      throw new Error(`module ${mod} failed to run: ` + lua.lua_tojsstring(L, -1));
    }
    lua.lua_getglobal(L, to_luastring("package"));
    lua.lua_getfield(L, -1, to_luastring("loaded"));
    lua.lua_pushvalue(L, -3);
    lua.lua_setfield(L, -2, to_luastring(mod));
    lua.lua_pop(L, 3);
  }

  const source = fs.readFileSync(options.scriptPath);
  const chunkName = to_luastring("@" + path.relative(REPO_ROOT, options.scriptPath));
  if (lauxlib.luaL_loadbuffer(L, source, source.length, chunkName) !== lua.LUA_OK) {
    const err = lua.lua_tojsstring(L, -1);
    lua.lua_close(L);
    return { error: "load: " + err };
  }
  if (lua.lua_pcall(L, 0, 0, 0) !== lua.LUA_OK) {
    const err = lua.lua_tojsstring(L, -1);
    lua.lua_close(L);
    return { error: "exec: " + err };
  }

  // host / port tables
  const host = createHost(options.host);
  lua.lua_newtable(L);
  for (const [k, v] of Object.entries(host)) {
    if (typeof v === "object" && v !== null) {
      lua.lua_newtable(L);
      for (const [kk, vv] of Object.entries(v)) {
        lua.lua_pushnumber(L, vv);
        lua.lua_setfield(L, -2, to_luastring(kk));
      }
      lua.lua_setfield(L, -2, to_luastring(k));
    } else if (typeof v === "number") {
      lua.lua_pushnumber(L, v);
      lua.lua_setfield(L, -2, to_luastring(k));
    } else if (v === null) {
      lua.lua_pushnil(L);
      lua.lua_setfield(L, -2, to_luastring(k));
    } else {
      lua.lua_pushstring(L, to_luastring(String(v)));
      lua.lua_setfield(L, -2, to_luastring(k));
    }
  }

  const portSpec = Object.assign({ number: 88, protocol: "tcp", state: "open", service: "kerberos" }, options.port || {});
  lua.lua_newtable(L);
  for (const [k, v] of Object.entries(portSpec)) {
    if (typeof v === "number") lua.lua_pushnumber(L, v);
    else if (typeof v === "string") lua.lua_pushstring(L, to_luastring(v));
    else lua.lua_pushnil(L);
    lua.lua_setfield(L, -2, to_luastring(k));
  }

  lua.lua_getglobal(L, to_luastring("action"));
  if (lua.lua_type(L, -1) !== lua.LUA_TFUNCTION) {
    lua.lua_close(L);
    return { error: "script does not define a global action function" };
  }
  // stack: ... action host port
  lua.lua_insert(L, -3); // action host port -> action on top requires host, port below
  const callStatus = lua.lua_pcall(L, 2, 1, 0);
  if (callStatus !== lua.LUA_OK) {
    const err = lua.lua_tojsstring(L, -1);
    lua.lua_close(L);
    return { error: "action: " + err };
  }
  if (trace) console.error("[sim] action returned");
  const output = luaValueToJs(L, -1);

  // pull debug log and vulns back out of __nse
  lua.lua_getglobal(L, to_luastring("__nse"));
  lua.lua_getfield(L, -1, to_luastring("debug_log"));
  const debugLog = luaValueToJs(L, -1) || [];
  lua.lua_pop(L, 1);
  lua.lua_getfield(L, -1, to_luastring("vulns"));
  const vulnsOut = luaValueToJs(L, -1) || [];
  lua.lua_pop(L, 1);
  lua.lua_getfield(L, -1, to_luastring("slept"));
  const slept = lua.lua_tonumber(L, -1);
  lua.lua_pop(L, 1);

  lua.lua_close(L);
  return { output, debug: debugLog, vulns: vulnsOut, slept, ioCalls: state.ioCalls };
}

function flatten(value, prefix = "", acc = []) {
  if (Array.isArray(value)) {
    value.forEach((v, i) => flatten(v, `${prefix}[${i}]`, acc));
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) flatten(v, prefix ? `${prefix}.${k}` : k, acc);
  } else {
    acc.push({ key: prefix, value });
  }
  return acc;
}

function runScenario(scenario) {
  const mockPath = path.resolve(REPO_ROOT, scenario.mock);
  delete require.cache[require.resolve(mockPath)];
  const mockModule = require(mockPath);
  const mock = mockModule.createMockKdc(scenario.kdc || {});
  const result = runScript({
    scriptPath: path.resolve(REPO_ROOT, scenario.script),
    args: scenario.args,
    port: scenario.port,
    host: scenario.host,
    debugLevel: scenario.debugLevel || 0,
    mock,
  });
  result.requests = mock.state.requests;
  result.mockState = mock.state;
  return result;
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error("usage: node tools/nse-sim.js <test-file.js>");
    process.exit(2);
  }
  const testPath = path.resolve(process.cwd(), args[0]);
  const spec = require(testPath);
  const scenarios = spec.scenarios || [];
  let failures = 0;

  for (const scenario of scenarios) {
    const result = runScenario(scenario);
    const assertions = [];
    if (result.error) {
      assertions.push({ ok: false, message: `script error: ${result.error}` });
    } else {
      const flat = flatten(result.output);
      for (const [key, expected] of Object.entries(scenario.expect || {})) {
        const hit = flat.find((entry) => entry.key === key || entry.key.startsWith(key));
        const actual = hit ? String(hit.value) : "<missing>";
        const ok = actual.includes(expected) || (expected === "<empty>" && actual === "<missing>");
        assertions.push({
          ok,
          message: `${key}: expected to contain "${expected}", got "${actual}"`,
        });
      }
      for (const rule of scenario.expectAll || []) {
        const found = JSON.stringify(result.output).includes(rule.contains);
        assertions.push({ ok: found === (rule.present !== false), message: `expectAll ${rule.contains}` });
      }
      if (scenario.maxIo !== undefined) {
        assertions.push({
          ok: result.ioCalls <= scenario.maxIo,
          message: `io calls: ${result.ioCalls} (max ${scenario.maxIo})`,
        });
      }
    }

    const failed = assertions.filter((a) => !a.ok);
    failures += failed.length;
    const status = failed.length === 0 && !result.error ? "PASS" : "FAIL";
    console.log(`[${status}] ${spec.name || path.basename(testPath)} / ${scenario.name}`);

    if (scenario.showOutput || failed.length > 0) {
      console.log("  ---- script output ----");
      if (result.error) {
        console.log("  error: " + result.error);
      } else {
        for (const line of JSON.stringify(result.output, null, 2).split("\n")) console.log("  " + line);
      }
      console.log("  ---- assertions ----");
      for (const a of assertions) console.log(`  ${a.ok ? "ok  " : "FAIL"} ${a.message}`);
      if (result.debug && result.debug.length) {
        console.log("  ---- debug ----");
        for (const line of result.debug.slice(0, 20)) console.log("  " + line);
      }
    }
  }

  console.log("");
  console.log(`scenarios: ${scenarios.length}, failed assertions: ${failures}`);
  process.exit(failures === 0 ? 0 : 1);
}

if (require.main === module) {
  main();
}

module.exports = { runScript, runScenario, createHost };
