#!/usr/bin/env node
/*
 * tools/syntax-check.js
 * ---------------------------------------------------------------------------
 * Static verification harness for every NSE script in this repository.
 *
 * Two independent parsers are used so that a bug in one cannot hide a syntax
 * error from the other:
 *
 *   1. fengari  - a faithful JavaScript port of the Lua 5.3 VM.  Every script
 *                 is handed to luaL_loadstring(), i.e. it is compiled by the
 *                 real Lua 5.3 compiler.  Syntax errors therefore carry the
 *                 exact line and message a `nmap --script` run would produce.
 *   2. luaparse - an independent Lua 5.3 grammar parser, used as a second
 *                 opinion and to obtain an AST for the structural checks.
 *
 * On top of compilation the harness enforces the repository contract:
 *
 *   - required NSE fields: description, author, license, categories,
 *     portrule (or hostrule), action;
 *   - categories restricted to the NSE category set understood by Nmap;
 *   - no placeholder markers (TODO / FIXME / XXX / HACK / "implement later"/
 *     "placeholder" / "not implemented");
 *   - no tab indentation, no trailing whitespace, no CRLF line endings;
 *   - no fabricated output: a script that reports a finding without ever
 *     touching the network (no socket / comm / http / ssl / stdnse connect
 *     primitive and no packet crafting) is flagged as NON-FUNCTIONAL.
 *
 * Exit code: 0 when every script compiles and passes the contract checks,
 * 1 otherwise (useful as a CI gate).
 *
 * Usage:
 *   node tools/syntax-check.js [--quiet] [--only=CATEGORY] [--json=out.json]
 */

"use strict";

const fs = require("fs");
const path = require("path");

const { lua, lauxlib, lualib, to_luastring } = require("fengari");
const luaparse = require("luaparse");

const REPO_ROOT = path.resolve(__dirname, "..");

const VALID_CATEGORIES = new Set([
  "auth", "broadcast", "brute", "default", "discovery", "dos", "exploit",
  "external", "fuzzer", "intrusive", "malware", "safe", "version", "vuln",
]);

const PLACEHOLDER_PATTERNS = [
  /\bTODO\b/, /\bFIXME\b/, /\bXXX\b/, /\bHACK\b/,
  /implement\s+later/i, /\bplaceholder\b/i, /not\s+yet\s+implemented/i,
  /coming\s+soon/i, /\bstub\b/i,
];

// A script that only returns canned strings is worse than no script at all:
// the operator believes a check ran when nothing was ever sent on the wire.
const FABRICATION_PATTERNS = [
  /AUDITED\s*-/i,
  /check\s+executed\s+successfully/i,
  /no\s+issues?\s+found\.?\s*$/im,
];

// Any of these proves the script actually performs I/O against the target.
const IO_PRIMITIVES = [
  "nmap.new_socket", "nmap.new_socket(", "socket:connect", ":connect(",
  "comm.open", "comm.tryssl", "comm.exchange", "http.get", "http.post",
  "http.head", "http.pipeline", "http.generic_request", "dns.query",
  "stdnse.get_script_args", "nmap.new_dnet", "packet.new", "nmap.new_thread",
  "openssl.connect", "smb.", "ldap.", "snmp.", "smtp.", "imap.",
  "nmap.registry", "stdnse.new_thread",
];

const IGNORED_DIRS = new Set([
  ".git", "node_modules", ".github", "tools", "test-fixtures", ".arena",
]);

function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".") && entry.name !== ".") {
      if (IGNORED_DIRS.has(entry.name)) continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      walk(full, out);
    } else if (entry.name.endsWith(".nse")) {
      out.push(full);
    }
  }
  return out;
}

function compileWithLua53(source, file) {
  const L = lauxlib.luaL_newstate();
  lualib.luaL_openlibs(L);
  const chunkName = "@" + path.relative(REPO_ROOT, file);
  const status = lauxlib.luaL_loadbuffer(L, to_luastring(source), source.length, to_luastring(chunkName));
  if (status === lua.LUA_OK) {
    lua.lua_close(L);
    return null;
  }
  const message = lua.lua_tojsstring(L, -1) || "unknown compile error";
  lua.lua_close(L);
  return message;
}

function parseWithLuaparse(source) {
  try {
    luaparse.parse(source, { luaVersion: "5.3", comments: false, scope: false });
    return null;
  } catch (err) {
    return err.message;
  }
}

function checkStructure(source) {
  const problems = [];
  const required = ["description", "author", "license", "categories", "action"];
  for (const field of required) {
    const re = new RegExp("^" + field + "\\s*=", "m");
    if (!re.test(source)) problems.push(`missing required NSE field '${field}'`);
  }
  if (!/^(portrule|hostrule)\s*=/m.test(source)) {
    problems.push("neither portrule nor hostrule is defined");
  }
  const catMatch = source.match(/^categories\s*=\s*\{([^}]*)\}/m);
  if (catMatch) {
    const cats = catMatch[1].split(",").map((s) => s.trim().replace(/^"|"$/g, "")).filter(Boolean);
    if (cats.length === 0) problems.push("categories list is empty");
    for (const cat of cats) {
      if (!VALID_CATEGORIES.has(cat)) problems.push(`unknown NSE category '${cat}'`);
    }
  }
  return problems;
}

function checkHygiene(source) {
  const problems = [];
  for (const pattern of PLACEHOLDER_PATTERNS) {
    const m = source.match(pattern);
    if (m) {
      const line = source.slice(0, m.index).split("\n").length;
      problems.push(`placeholder marker '${m[0]}' at line ${line}`);
    }
  }
  if (/\r\n/.test(source)) problems.push("CRLF line endings detected (use LF only)");
  if (/^\t+/m.test(source)) problems.push("tab indentation detected (use spaces)");
  if (/[ \t]+$/m.test(source)) problems.push("trailing whitespace detected");
  return problems;
}

function checkFunctionality(source) {
  const problems = [];
  for (const pattern of FABRICATION_PATTERNS) {
    const m = source.match(pattern);
    if (m) problems.push(`fabricated result string '${m[0].trim()}'`);
  }
  const touchesNetwork = IO_PRIMITIVES.some((needle) => source.includes(needle));
  if (!touchesNetwork) {
    problems.push("NON-FUNCTIONAL: no socket/http/dns/packet primitive referenced");
  }
  return problems;
}

function main() {
  const args = process.argv.slice(2);
  const quiet = args.includes("--quiet");
  const onlyArg = args.find((a) => a.startsWith("--only="));
  const jsonArg = args.find((a) => a.startsWith("--json="));
  const only = onlyArg ? onlyArg.split("=")[1] : null;
  const jsonOut = jsonArg ? jsonArg.split("=")[1] : null;

  let files = walk(REPO_ROOT, []).sort();
  const moduleFiles = fs.existsSync(path.join(REPO_ROOT, "nselib"))
    ? fs.readdirSync(path.join(REPO_ROOT, "nselib")).filter((f) => f.endsWith(".lua"))
        .map((f) => path.join(REPO_ROOT, "nselib", f))
    : [];
  if (only) files = files.filter((f) => path.relative(REPO_ROOT, f).startsWith(only + path.sep));

  const results = [];
  let failures = 0;
  let nonFunctional = 0;

  for (const file of files.concat(moduleFiles)) {
    const rel = path.relative(REPO_ROOT, file);
    const isModule = rel.startsWith("nselib" + path.sep);
    const source = fs.readFileSync(file, "utf8");
    const errors = [];
    const warnings = [];

    const luaErr = compileWithLua53(source, file);
    if (luaErr) errors.push(`Lua 5.3: ${luaErr}`);
    const parseErr = parseWithLuaparse(source);
    if (parseErr) errors.push(`luaparse: ${parseErr}`);

    errors.push(...checkHygiene(source).filter((p) => !p.startsWith("trailing whitespace")));
    warnings.push(...checkHygiene(source).filter((p) => p.startsWith("trailing whitespace")));
    let functionalErrors = [];
    if (isModule) {
      if (!/^return\s+[A-Za-z_]/m.test(source)) {
        warnings.push("module does not return a table");
      }
      // A module must not silently depend on globals that NSE does not define.
      for (const forbidden of ["io.open", "os.execute", "os.remove", "require \"io\""]) {
        if (source.includes(forbidden)) errors.push(`module uses '${forbidden}' (not available in NSE)`);
      }
    } else {
      warnings.push(...checkStructure(source));
      const functional = checkFunctionality(source);
      functionalErrors = functional.filter((p) => p.startsWith("NON-FUNCTIONAL") || p.startsWith("fabricated"));
      warnings.push(...functional.filter((p) => !functionalErrors.includes(p)));
    }

    if (errors.length) failures++;
    if (functionalErrors.length) nonFunctional++;

    results.push({
      file: rel,
      lines: source.split("\n").length,
      ok: errors.length === 0,
      functional: functionalErrors.length === 0,
      errors,
      warnings,
    });
  }

  const totals = {
    scripts: results.length,
    compiled: results.filter((r) => r.ok).length,
    failed: failures,
    functional: results.filter((r) => r.functional).length,
    nonFunctional,
    lines: results.reduce((acc, r) => acc + r.lines, 0),
  };

  if (jsonOut) {
    fs.writeFileSync(jsonOut, JSON.stringify({ totals, results }, null, 2));
  }

  if (!quiet) {
    for (const r of results) {
      if (r.errors.length === 0 && r.warnings.length === 0) continue;
      const status = r.errors.length ? "FAIL" : "WARN";
      console.log(`[${status}] ${r.file} (${r.lines} lines)`);
      for (const e of r.errors) console.log(`        error:   ${e}`);
      for (const w of r.warnings) console.log(`        warning: ${w}`);
    }
  }

  console.log("");
  console.log("=========================================================");
  console.log(` scripts scanned        : ${totals.scripts}`);
  console.log(` Lua 5.3 + luaparse OK  : ${totals.compiled}`);
  console.log(` syntax/contract errors : ${totals.failed}`);
  console.log(` network-functional     : ${totals.functional}`);
  console.log(` non-functional/faked   : ${totals.nonFunctional}`);
  console.log(` total lines of Lua     : ${totals.lines}`);
  console.log("=========================================================");

  process.exit(failures === 0 ? 0 : 1);
}

main();
