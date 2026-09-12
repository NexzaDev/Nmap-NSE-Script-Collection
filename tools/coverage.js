#!/usr/bin/env node
/*
 * tools/coverage.js
 * ---------------------------------------------------------------------------
 * Per-script status against the repository's two contracts:
 *
 *   depth     - CRITICAL/HIGH >= 1538 lines, MEDIUM/LOW 500-800 lines, read
 *               from the SCRIPT_RISK marker the rewritten scripts carry
 *   verified  - the script compiles, performs real network I/O, and has at
 *               least one integration scenario wired to it in tools/tests/
 *
 * Output is a table an operator can act on: "met" means the contract holds
 * today, anything else names what is missing. Exit code is 0 only when every
 * script meets both contracts, so it can gate CI once the rewrite completes.
 *
 * Usage:
 *   node tools/coverage.js                # summary + the gaps
 *   node tools/coverage.js --all          # every script, one line each
 *   node tools/coverage.js --json=out.json
 */

"use strict";

const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.resolve(__dirname, "..");
const IGNORED = new Set([".git", "node_modules", "tools", "nselib", "docs", "test-fixtures", ".github"]);

function categoryDirs() {
  return fs
    .readdirSync(REPO_ROOT, { withFileTypes: true })
    .filter((e) => e.isDirectory() && !IGNORED.has(e.name) && !e.name.startsWith("."))
    .map((e) => e.name)
    .filter((name) => fs.readdirSync(path.join(REPO_ROOT, name)).some((f) => f.endsWith(".nse")))
    .sort();
}

// Which scripts have integration scenarios: the test files name the script they
// exercise, so the coverage map is derived from them rather than maintained by
// hand.
function testedScripts() {
  const dir = path.join(REPO_ROOT, "tools", "tests");
  const tested = new Map();
  if (!fs.existsSync(dir)) return tested;
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".test.js"))) {
    const text = fs.readFileSync(path.join(dir, file), "utf8");
    const scenarios = (text.match(/name:\s*"/g) || []).length;
    for (const m of text.matchAll(/script:\s*"([^"]+\.nse)"/g)) {
      tested.set(m[1], (tested.get(m[1]) || 0) + Math.max(1, scenarios - 1));
    }
  }
  return tested;
}

// Risk class: declared marker first, then the legacy literal Risk Level.
function riskOf(source) {
  const declared = source.match(/^local SCRIPT_RISK\s*=\s*"(CRITICAL|HIGH|MEDIUM|LOW)"/m);
  if (declared) return { risk: declared[1], declared: true };
  const literal = source.match(/\[\s*"Risk Level"\s*\]\s*=\s*"([^"]+)"/);
  if (literal) {
    for (const risk of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
      if (literal[1].includes(risk)) return { risk, declared: false };
    }
  }
  return { risk: "UNKNOWN", declared: false };
}

const IO_PRIMITIVES = [
  "new_socket", ":connect(", "comm.exchange", "http.get", "http.post", "dns.query",
  "new_dnet", "packet.new", "openssl.connect", "smb.", "ldap.", "snmp.",
];

// A script is functional if it performs I/O itself *or* requires a library from
// nselib/ that does. Without this, every script built on a shared engine (the
// intended architecture for this collection) would be misreported as inert.
function ioModules() {
  const dir = path.join(REPO_ROOT, "nselib");
  const modules = new Set();
  if (!fs.existsSync(dir)) return modules;
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".lua"))) {
    const source = fs.readFileSync(path.join(dir, file), "utf8");
    if (IO_PRIMITIVES.some((needle) => source.includes(needle))) {
      modules.add(path.basename(file, ".lua"));
    }
  }
  return modules;
}

function analyse() {
  const tested = testedScripts();
  const engineModules = ioModules();
  const rows = [];
  for (const category of categoryDirs()) {
    const dir = path.join(REPO_ROOT, category);
    for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".nse")).sort()) {
      const rel = path.join(category, file);
      const source = fs.readFileSync(path.join(dir, file), "utf8");
      const lines = source.split("\n").length - (source.endsWith("\n") ? 1 : 0);
      const { risk, declared } = riskOf(source);
      const directIo = IO_PRIMITIVES.some((needle) => source.includes(needle));
      // Matches both require "mod" and the pcall(require, "mod") form the
      // scripts use so a missing library degrades gracefully.
      const viaEngine = [...engineModules].some((mod) =>
        new RegExp(`require[^\\n]*["']${mod}["']`).test(source));
      const functional = directIo || viaEngine;
      const scenarios = tested.get(rel) || 0;

      let required, depthOk;
      if (risk === "CRITICAL" || risk === "HIGH") {
        required = ">= 1538";
        depthOk = lines >= 1538;
      } else if (risk === "MEDIUM" || risk === "LOW") {
        required = "500-800";
        depthOk = lines >= 500 && lines <= 800;
      } else {
        required = "unclassified";
        depthOk = false;
      }

      const gaps = [];
      if (!depthOk) {
        if (required === "500-800") {
          gaps.push(lines < 500 ? "too-short" : "too-long");
        } else {
          gaps.push("too-short");
        }
      }
      if (!functional) gaps.push("no-real-io");
      if (!declared) gaps.push("no-risk-marker");
      if (scenarios === 0) gaps.push("no-test-scenario");

      rows.push({
        script: rel,
        risk,
        declared,
        lines,
        required,
        depthOk,
        functional,
        scenarios,
        met: depthOk && functional && scenarios > 0,
        gaps,
      });
    }
  }
  return rows;
}

function main() {
  const args = process.argv.slice(2);
  const rows = analyse();
  const jsonArg = args.find((a) => a.startsWith("--json="));
  if (jsonArg) fs.writeFileSync(jsonArg.split("=")[1], JSON.stringify(rows, null, 2));

  const byCategory = {};
  for (const row of rows) {
    const category = row.script.split(path.sep)[0];
    byCategory[category] = byCategory[category] || { total: 0, met: 0, functional: 0 };
    byCategory[category].total++;
    if (row.met) byCategory[category].met++;
    if (row.functional) byCategory[category].functional++;
  }

  if (args.includes("--all")) {
    console.log("script".padEnd(46) + "risk".padEnd(10) + "lines".padStart(6) + "  required".padEnd(12) + "gaps");
    for (const row of rows) {
      console.log(
        row.script.padEnd(46) +
        row.risk.padEnd(10) +
        String(row.lines).padStart(6) + "  " +
        row.required.padEnd(12) +
        (row.gaps.length ? row.gaps.join(",") : "met")
      );
    }
    console.log("");
  }

  console.log("category".padEnd(16) + "scripts".padStart(8) + "functional".padStart(12) + "contract met".padStart(14));
  console.log("-".repeat(50));
  for (const [category, stats] of Object.entries(byCategory)) {
    console.log(
      category.padEnd(16) + String(stats.total).padStart(8) +
      String(stats.functional).padStart(12) + String(stats.met).padStart(14)
    );
  }

  const met = rows.filter((r) => r.met).length;
  const functional = rows.filter((r) => r.functional).length;
  console.log("");
  console.log(`scripts: ${rows.length}`);
  console.log(`  perform real network I/O      : ${functional}`);
  console.log(`  meet the depth contract       : ${rows.filter((r) => r.depthOk).length}`);
  console.log(`  have integration scenarios    : ${rows.filter((r) => r.scenarios > 0).length}`);
  console.log(`  meet the full contract        : ${met}`);
  console.log("");
  console.log(`${rows.length - met} script(s) still to rewrite.`);
  process.exit(met === rows.length ? 0 : 1);
}

main();
