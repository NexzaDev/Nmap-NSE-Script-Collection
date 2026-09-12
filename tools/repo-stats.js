#!/usr/bin/env node
/*
 * tools/repo-stats.js
 * ---------------------------------------------------------------------------
 * Produces the ground-truth statistics used in README.md and docs/AUDIT.md.
 * Nothing here is hand-typed: every number is measured from the working tree
 * so the documentation can never drift away from the code.
 *
 * Usage:
 *   node tools/repo-stats.js                 # markdown table on stdout
 *   node tools/repo-stats.js --json=out.json # machine readable form
 *   node tools/repo-stats.js --write         # rewrite the README stats block
 */

"use strict";

const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.resolve(__dirname, "..");
const IGNORED_DIRS = new Set([
  ".git", "node_modules", "tools", "test-fixtures", ".github", "docs", ".arena",
]);

const DEPTH_BANDS = [
  { name: "stub", min: 0, max: 60 },
  { name: "shallow", min: 61, max: 300 },
  { name: "focused", min: 301, max: 700 },
  { name: "deep", min: 701, max: 1537 },
  { name: "spec-depth", min: 1538, max: Number.MAX_SAFE_INTEGER },
];

function categoryDirs() {
  return fs
    .readdirSync(REPO_ROOT, { withFileTypes: true })
    .filter((e) => e.isDirectory() && !IGNORED_DIRS.has(e.name) && !e.name.startsWith("."))
    .map((e) => e.name)
    .filter((name) => fs.readdirSync(path.join(REPO_ROOT, name)).some((f) => f.endsWith(".nse")))
    .sort();
}

function riskOf(source) {
  const m = source.match(/\[\s*"Risk Level"\s*\]\s*=\s*"([^"]+)"/);
  if (m) {
    const v = m[1];
    if (v.includes("CRITICAL")) return "CRITICAL";
    if (v.includes("HIGH")) return "HIGH";
    if (v.includes("MEDIUM")) return "MEDIUM";
    if (v.includes("LOW")) return "LOW";
    return "UNKNOWN";
  }
  return "UNKNOWN";
}

function measure() {
  const categories = [];
  let totals = { scripts: 0, lines: 0, byBand: {}, byRisk: {} };

  for (const cat of categoryDirs()) {
    const dir = path.join(REPO_ROOT, cat);
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".nse")).sort();
    const entry = {
      category: cat,
      scripts: files.length,
      lines: 0,
      risks: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
      bands: { stub: 0, shallow: 0, focused: 0, deep: 0, "spec-depth": 0 },
      files: [],
    };
    for (const f of files) {
      const source = fs.readFileSync(path.join(dir, f), "utf8");
      const lines = source.split("\n").length - (source.endsWith("\n") ? 1 : 0);
      const risk = riskOf(source);
      const band = DEPTH_BANDS.find((b) => lines >= b.min && lines <= b.max).name;
      entry.lines += lines;
      entry.risks[risk] = (entry.risks[risk] || 0) + 1;
      entry.bands[band]++;
      entry.files.push({ file: f, lines, risk, band });
      totals.byBand[band] = (totals.byBand[band] || 0) + 1;
      totals.byRisk[risk] = (totals.byRisk[risk] || 0) + 1;
    }
    totals.scripts += entry.scripts;
    totals.lines += entry.lines;
    categories.push(entry);
  }
  return { categories, totals };
}

function markdown(stats) {
  const lines = [];
  lines.push("| Category | Scripts | Lines | Avg/script | CRITICAL/HIGH | MEDIUM/LOW | Depth band distribution |");
  lines.push("|---|---:|---:|---:|---:|---:|---|");
  for (const c of stats.categories) {
    const ch = c.risks.CRITICAL + c.risks.HIGH;
    const ml = c.risks.MEDIUM + c.risks.LOW;
    const bands = Object.entries(c.bands)
      .filter(([, n]) => n > 0)
      .map(([b, n]) => `${b}:${n}`)
      .join(", ");
    lines.push(`| ${c.category} | ${c.scripts} | ${c.lines} | ${Math.round(c.lines / c.scripts)} | ${ch} | ${ml} | ${bands} |`);
  }
  lines.push(
    `| **TOTAL** | **${stats.totals.scripts}** | **${stats.totals.lines}** | **${Math.round(
      stats.totals.lines / stats.totals.scripts
    )}** | | | |`
  );
  return lines.join("\n");
}

function main() {
  const args = process.argv.slice(2);
  const jsonArg = args.find((a) => a.startsWith("--json="));
  const stats = measure();
  if (jsonArg) fs.writeFileSync(jsonArg.split("=")[1], JSON.stringify(stats, null, 2));
  console.log(markdown(stats));
  console.log("");
  console.log("Totals:", JSON.stringify(stats.totals));
}

main();
