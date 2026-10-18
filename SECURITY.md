# Security Policy

## Scope

This repository contains **defensive, informational** Nmap NSE scripts intended for authorized security auditing. "Security" issues in this context generally fall into two categories:

1. **Script bugs** — false positives/negatives, crashes, or scripts behaving unsafely (e.g., unintended writes, hangs, or excessive load against a target).
2. **Responsible use concerns** — questions about whether a script's behavior crosses from "informational" into "intrusive" territory.

This project does **not** knowingly include exploitation or destructive-action code. If you believe a script goes beyond informational/defensive checking, please report it (see below) rather than opening a public issue with exploit details.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest release (main branch) | ✅ |
| Older tagged releases        | ⚠️ Best-effort only |

## Reporting a Vulnerability or Unsafe Script Behavior

**Please do not open a public GitHub Issue for:**
- Reports that include working exploitation payloads or techniques beyond what the script already documents
- Anything that could be misused to cause harm if published openly

**Instead:**
1. Use GitHub's **private vulnerability reporting** feature if enabled for this repo (Security tab → "Report a vulnerability"), or
2. Open a regular issue titled generically (e.g., "Possible unsafe behavior in ftp-writable-dirs") **without** technical exploitation detail, and a maintainer will follow up to get details privately.

**For everything else** (false positives, crashes, incorrect risk classification, general bugs), a normal public [GitHub Issue](../../issues) is fine and preferred — it helps other users too.

## What to Include in a Report

- Script name and version/commit hash
- Nmap version and OS
- Exact command used (redact real target hostnames/IPs if sensitive)
- Expected behavior vs. actual behavior
- Any error output or stack trace

## Disclosure Timeline

As a community-maintained project, response times are best-effort. We aim to:
- Acknowledge reports within 7 days
- Provide a fix or mitigation plan within 30 days for confirmed issues

Thank you for helping keep this project safe and reliable for defensive security use.
