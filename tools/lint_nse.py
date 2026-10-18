#!/usr/bin/env python3
"""Local quality gate for the Nmap NSE collection.

Checks performed on every *.nse file:
  1. Lua syntax validity (compiled with the bundled Lua interpreter via lupa).
  2. Absence of code comments ("--") outside of the mandatory NSE header
     metadata block.
  3. Presence of the mandatory NSE metadata fields.
  4. Presence of a "Risk Level" assignment inside action().
  5. Minimum functional line count for the declared risk level
     (CRITICAL/HIGH >= 1500, MEDIUM/LOW >= 800).

Usage:
    python3 tools/lint_nse.py                 # whole repository
    python3 tools/lint_nse.py HTTP DNS        # selected folders only
    python3 tools/lint_nse.py --strict        # treat size shortfalls as errors
"""

import json
import os
import re
import sys

try:
    from lupa import LuaRuntime
except ImportError:  # pragma: no cover
    LuaRuntime = None

RISKS = {
    "🔴 CRITICAL": 1500,
    "🟠 HIGH": 1500,
    "🟡 MEDIUM": 800,
    "🟢 LOW": 800,
}

HEADER_FIELDS = ("description", "author", "license", "categories")

RISK_RE = re.compile(r'out\w*\[\s*"Risk Level"\s*\]\s*=\s*"([^"]+)"')
RISK_CONST_RE = re.compile(r'^local\s+RISK_LEVEL\w*\s*=\s*"([^"]+)"', re.M)
RISK_VAR_USE_RE = re.compile(r'out\w*\[\s*"Risk Level"\s*\]\s*=\s*([A-Za-z_][%w_]*)')
HEADER_RISK_RE = re.compile(r'Risk Level"?\]?\s*=\s*"([^"]+)"')


def lua_runtime():
    if LuaRuntime is None:
        return None
    return LuaRuntime(unpack_returned_tuples=True)


def strip_header(text):
    """Return (header_lines, body) where body starts after the last metadata
    assignment of the NSE header block."""
    lines = text.split("\n")
    end = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("description") or stripped.startswith("author") or \
           stripped.startswith("license") or stripped.startswith("categories") or \
           stripped.startswith("portrule") or stripped.startswith("prerule") or \
           stripped.startswith("hostrule") or stripped.startswith("]==]") or \
           stripped.startswith("[[") or stripped == "":
            end = i
            continue
        if stripped.startswith("local ") or stripped.startswith("require"):
            continue
    return lines[:end + 1], lines[end + 1:]


def find_comments(text):
    """Yield (lineno, line) for every line containing a real Lua comment.

    The scanner understands single/double quoted strings (with escapes),
    long bracket strings of any level ([[...]], [==[...]==]) and only reports
    '--' sequences that appear in code position.
    """
    results = []
    i = 0
    n = len(text)
    line = 1
    col_start = {1: 0}
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            col_start[line] = i + 1
            i += 1
            continue
        if ch == "-" and text[i:i + 2] == "--":
            if text[i:i + 3] == "--[":
                m = re.match(r"--\[(=*)\[", text[i:])
                if m:
                    close = "]" + m.group(1) + "]"
                    end = text.find(close, i)
                    if end == -1:
                        end = n
                    else:
                        end += len(close)
                    i = end
                    continue
            results.append((line, text[col_start[line]:].split("\n")[0]))
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        if ch == "[":
            m = re.match(r"\[(=*)\[", text[i:])
            if m:
                close = "]" + m.group(1) + "]"
                end = text.find(close, i)
                if end == -1:
                    results.append((line, "unterminated long string"))
                    break
                segment = text[i:end + len(close)]
                line += segment.count("\n")
                col_start[line] = col_start.get(line, 0)
                i = end + len(close)
                continue
        if ch in "\"'":
            quote = ch
            i += 1
            while i < n:
                c = text[i]
                if c == "\\":
                    i += 2
                    continue
                if c == "\n":
                    line += 1
                    col_start[line] = i + 1
                    i += 1
                    break
                if c == quote:
                    i += 1
                    break
                i += 1
            continue
        i += 1
    return results


def check_file(path, runtime, strict=False):
    problems = []
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    count = len(lines)

    if runtime is not None:
        loader = runtime.eval("load")
        try:
            result = loader(text, "@" + path)
        except Exception as exc:  # noqa: BLE001
            result = (None, str(exc))
        if isinstance(result, tuple):
            chunk, err = result[0], result[1] if len(result) > 1 else None
        else:
            chunk, err = result, None
        if chunk is None:
            problems.append(f"SYNTAX: {err}")

    for field in HEADER_FIELDS:
        if not re.search(r"^%s\s*=" % field, text, re.M):
            problems.append(f"MISSING metadata field: {field}")
    if not re.search(r"^(portrule|prerule|hostrule)\s*=", text, re.M):
        problems.append("MISSING rule declaration (portrule/prerule/hostrule)")

    risk_match = RISK_RE.search(text) or HEADER_RISK_RE.search(text)
    risk = risk_match.group(1).strip() if risk_match else None
    if risk is None:
        const = RISK_CONST_RE.search(text)
        used = RISK_VAR_USE_RE.search(text)
        if const and used and used.group(1) == const.group(0).split()[1]:
            risk = const.group(1).strip()
        elif const and used:
            risk = const.group(1).strip()
    if risk not in RISKS:
        problems.append(f"MISSING/unknown Risk Level: {risk!r}")

    body_start = text.find("action = function")
    if body_start == -1:
        problems.append("MISSING action() function")

    comments = find_comments(text)
    for lineno, line in comments:
        problems.append(f"COMMENT at line {lineno}: {line.strip()[:80]}")

    minimum = RISKS.get(risk, 800)
    size_ok = count >= minimum
    if not size_ok:
        problems.append(f"SIZE: {count} lines < required {minimum} for {risk}")

    return {
        "path": path,
        "lines": count,
        "risk": risk,
        "minimum": minimum,
        "size_ok": size_ok,
        "problems": problems,
    }


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    strict = "--strict" in argv
    argv = [a for a in argv if not a.startswith("--")]
    folders = argv if argv else sorted(
        d for d in os.listdir(root)
        if os.path.isdir(os.path.join(root, d)) and not d.startswith(".")
        and d not in ("test-fixtures", "tools", ".github")
    )

    runtime = lua_runtime()
    if runtime is None:
        print("WARNING: lupa is not installed; Lua syntax checking disabled", file=sys.stderr)

    results = []
    for folder in folders:
        fdir = os.path.join(root, folder)
        if not os.path.isdir(fdir):
            continue
        for name in sorted(os.listdir(fdir)):
            if not name.endswith(".nse"):
                continue
            results.append(check_file(os.path.join(fdir, name), runtime, strict))

    bad = [r for r in results if r["problems"]]
    short = [r for r in results if not r["size_ok"]]
    print(f"checked: {len(results)} scripts, {len(bad)} with problems, {len(short)} below size target")
    for r in results:
        flag = "OK  " if not r["problems"] else "FAIL"
        print("%s %-46s %5d lines  %-14s (min %d)" % (
            flag, os.path.relpath(r["path"], root), r["lines"], r["risk"], r["minimum"]))
        for problem in r["problems"]:
            print(f"       - {problem}")

    with open(os.path.join(root, ".lint-report.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)

    if strict and short:
        return 1
    return 1 if any(p.startswith(("SYNTAX", "MISSING", "COMMENT")) for r in results for p in r["problems"]) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
