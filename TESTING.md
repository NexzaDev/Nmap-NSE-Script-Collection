# Testing Guide

This project includes a local Docker-based test environment so that every NSE script can be validated against a real (but deliberately insecure) target — not just read for correctness.

> ⚠️ **These targets are intentionally vulnerable/misconfigured.** Only run this on your own machine, on an isolated network (e.g. your laptop with no other devices affected). Never expose these ports outside `localhost`, never run this on a shared or production network, and never point these containers at the public internet.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed
- [Nmap](https://nmap.org/download.html) 7.40 or later installed
- This repository cloned locally

## 1. Start the test targets

From the root of the repository:

```bash
docker compose up -d
```

This starts three containers:

| Service | Port (host) | Purpose |
|---|---|---|
| `http-target` | `localhost:8080` | Plain HTTP server with no security headers — for testing HTTP scripts |
| `ftp-target` | `localhost:2121` | FTP server with anonymous login enabled — for testing FTP scripts |
| `redis-target` | `localhost:6380` | Redis with authentication disabled — for testing the Redis database script |

Confirm they're running:

```bash
docker compose ps
```

## 2. Run the scripts against the targets

### HTTP scripts

```bash
nmap -p 8080 --script ./HTTP/http-security-headers.nse localhost
nmap -p 8080 --script ./HTTP/http-cookie-flags.nse localhost
nmap -p 8080 --script HTTP/*.nse localhost -p 8080
```

Expected result: scripts should report **missing security headers** (no `Strict-Transport-Security`, no `Content-Security-Policy`, no `X-Frame-Options`, etc.), since plain Nginx doesn't set these by default.

### FTP scripts

```bash
nmap -p 2121 --script ./FTP/ftp-anonymous-login.nse localhost
nmap -p 2121 --script FTP/*.nse localhost -p 2121
```

Expected result: `ftp-anonymous-login` should report that **anonymous login is allowed**, and `ftp-cleartext-check` should flag that credentials are sent unencrypted.

### Database scripts (Redis)

```bash
nmap -p 6380 --script ./DATABASE/redis-unauth-check.nse localhost
```

*(Adjust the script filename to match whatever your Redis script is actually called in the `DATABASE/` folder.)*

Expected result: the script should report that **Redis is accessible without authentication**.

## 3. Verify a script is NOT producing false positives

To sanity-check that a script correctly reports "no issue found" on a hardened target, you can temporarily harden the fixture (e.g., add security headers to `test-fixtures/http/index.html`'s Nginx config) and confirm the script's output changes accordingly. This isn't automated yet — see the "Future Improvements" section below.

## 4. Tear down

When you're done testing:

```bash
docker compose down
```

This stops and removes the containers. Your Nmap scripts and the rest of the repo are untouched.

## Adding tests for a new script

When contributing a new script (see [CONTRIBUTING.md](CONTRIBUTING.md)):

1. If an existing target in `docker-compose.yml` can be (mis)configured to exercise your script, use it.
2. If not, add a new service to `docker-compose.yml` following the existing pattern — comment clearly what misconfiguration it represents and which script(s) it's for.
3. Document the expected command and expected output in this file, under the matching category section.

## Future Improvements

- [ ] Automate the "expected output" checks in CI (currently manual)
- [ ] Add a hardened variant of each target to test for false positives
- [ ] Expand coverage to SMB, SSL/TLS, DNS, and remaining DATABASE scripts
