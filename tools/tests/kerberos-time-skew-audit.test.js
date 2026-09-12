"use strict";
/*
 * Integration scenarios for KERBEROS/kerberos-time-skew-audit.nse.
 *
 * The mock answers Kerberos on port 88 with a configurable clock offset and
 * SNTP on port 123 with an independent RFC 5905 implementation, so the script's
 * offset maths and its cross-check logic are exercised end to end.
 */

const path = require("path");
const { createMockKdc } = require("../mocks/kdc.js");
const { createMockSntp } = require("../mocks/sntp.js");

const REALM = "EXAMPLE.COM";

// Dispatches on the destination port, exactly as a host running both services
// would: the script opens its own UDP socket to 123 for the NTP query.
function combined(handler, ntpHandler) {
  return {
    state: { requests: [] },
    handle(payload, proto, ctx) {
      if (ctx && ctx.port === 123) return ntpHandler(payload);
      return handler(payload, proto, ctx);
    },
  };
}

function scenarioWith({ kdc, sntp }) {
  return combined(createMockKdc(kdc).handle, createMockSntp(sntp).handle);
}

module.exports = {
  name: "kerberos-time-skew-audit",
  scenarios: [
    {
      name: "KDC clock is 400 s ahead: beyond the Kerberos tolerance",
      script: "KERBEROS/kerberos-time-skew-audit.nse",
      mock: "tools/mocks/kdc.js",
      mockFactory: () => scenarioWith({
        kdc: { realm: REALM, accounts: {}, timeOffsetSeconds: 400 },
        sntp: { offsetSeconds: 0 },
      }),
      args: { "kerberos.realm": REALM, "kerberos.samples": "3", "kerberos.delay-ms": "0", "kerberos.retries": "0" },
      expect: {
        "Realm": REALM,
        "Risk Level": "CRITICAL",
        "Verdict[0]": "Clock relationship: BROKEN",
      },
    },
    {
      name: "KDC clock is 200 s ahead: degraded, headroom reported",
      script: "KERBEROS/kerberos-time-skew-audit.nse",
      mock: "tools/mocks/kdc.js",
      mockFactory: () => scenarioWith({
        kdc: { realm: REALM, accounts: {}, timeOffsetSeconds: 200 },
        sntp: { offsetSeconds: 0 },
      }),
      args: { "kerberos.realm": REALM, "kerberos.samples": "3", "kerberos.delay-ms": "0", "kerberos.retries": "0" },
      expect: {
        "Risk Level": "MEDIUM",
        "Verdict[0]": "DEGRADED",
        "Headroom before authentication fails": "100 s",
      },
    },
    {
      name: "clocks agree: no drift, NTP cross-check confirms the KDC",
      script: "KERBEROS/kerberos-time-skew-audit.nse",
      mock: "tools/mocks/kdc.js",
      mockFactory: () => scenarioWith({
        kdc: { realm: REALM, accounts: {}, timeOffsetSeconds: 0 },
        sntp: { offsetSeconds: 0 },
      }),
      args: {
        "kerberos.realm": REALM,
        "kerberos.samples": "3",
        "kerberos.ntp-server": "ntp.example.net",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Risk Level": "LOW",
        "NTP cross-check[1]": "stratum 2",
        "NTP cross-check[6]": "agrees with network time",
      },
    },
    {
      name: "KDC drifts while network time is correct: the KDC is named as the faulty side",
      script: "KERBEROS/kerberos-time-skew-audit.nse",
      mock: "tools/mocks/kdc.js",
      mockFactory: () => scenarioWith({
        kdc: { realm: REALM, accounts: {}, timeOffsetSeconds: 250 },
        sntp: { offsetSeconds: 0 },
      }),
      args: {
        "kerberos.realm": REALM,
        "kerberos.samples": "3",
        "kerberos.ntp-server": "ntp.example.net",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Risk Level": "MEDIUM",
      },
      expectAll: [
        { contains: "the drift to fix is on the KDC side" },
        { contains: "The two references disagree by more than five seconds" },
        { contains: "Remediation" },
      ],
    },
    {
      name: "unreachable NTP server is reported, not silently ignored",
      script: "KERBEROS/kerberos-time-skew-audit.nse",
      mock: "tools/mocks/kdc.js",
      mockFactory: () => scenarioWith({
        kdc: { realm: REALM, accounts: {}, timeOffsetSeconds: 10 },
        sntp: { silent: true },
      }),
      args: {
        "kerberos.realm": REALM,
        "kerberos.samples": "2",
        "kerberos.ntp-server": "ntp.example.net",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
        "kerberos.timeout-ms": "600",
      },
      expect: {
        "NTP cross-check[1]": "SNTP query failed",
      },
    },
    {
      name: "unsynchronised time source is surfaced as a warning",
      script: "KERBEROS/kerberos-time-skew-audit.nse",
      mock: "tools/mocks/kdc.js",
      mockFactory: () => scenarioWith({
        kdc: { realm: REALM, accounts: {}, timeOffsetSeconds: 5 },
        sntp: { offsetSeconds: 5, unsynchronised: true },
      }),
      args: {
        "kerberos.realm": REALM,
        "kerberos.samples": "2",
        "kerberos.ntp-server": "ntp.example.net",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expectAll: [{ contains: "WARNING: the time source reports its clock is unsynchronised" }],
    },
    {
      name: "no realm obtainable: explicit refusal",
      script: "KERBEROS/kerberos-time-skew-audit.nse",
      mock: "tools/mocks/kdc.js",
      mockFactory: () => scenarioWith({
        // The KDC answers nothing at all for a foreign realm and the mock
        // sends no realm-bearing error, so no realm can be derived.
        kdc: { realm: REALM, accounts: {}, leakRealm: false },
        sntp: { offsetSeconds: 0 },
      }),
      args: { "kerberos.samples": "2", "kerberos.delay-ms": "0", "kerberos.retries": "0" },
      expect: {
        "Check status": "ABORTED",
        "Risk Level": "INCONCLUSIVE",
      },
    },
  ],
};
