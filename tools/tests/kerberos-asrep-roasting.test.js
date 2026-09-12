"use strict";
/*
 * Integration scenarios for KERBEROS/kerberos-asrep-roasting.nse.
 *
 * Each scenario wires a mock KDC to the script and asserts on the real
 * classified output, so a regression in the DER encoder, the response parser,
 * the classifier or the probe engine fails the build.
 */

const REALM = "EXAMPLE.COM";

const accounts = {
  "svc-backup": { preauth: false, etype: 23, kvno: 2 },
  "kiosk-01": { preauth: false, etype: 18, kvno: 1 },
  "jsmith": { preauth: true, etypes: [18, 17, 23], salt: REALM },
  "locked-out": { state: "disabled" },
};

module.exports = {
  name: "kerberos-asrep-roasting",
  scenarios: [
    {
      name: "roastable RC4 service account + preauth-enforced user",
      script: "KERBEROS/kerberos-asrep-roasting.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: { "kerberos.realm": REALM, "kerberos.users": "svc-backup,jsmith" },
      expect: {
        "Realm": REALM,
        "Risk Level": "CRITICAL",
        "AS-REP roasting candidates (pre-authentication DISABLED)[0]": "svc-backup",
        "Pre-authentication enforced[0]": "jsmith",
        "Offline cracking cost (estimates, not measurements)[0]": "worst-case etype",
        "AS-REP material (masked; enable kerberos.show-hashes to print)[0]": "svc-backup",
        "Transport behaviour[0]": "answered",
      },
    },
    {
      name: "AS-REP hash printing is opt-in and produces a crackable artefact",
      script: "KERBEROS/kerberos-asrep-roasting.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: {
        "kerberos.realm": REALM,
        "kerberos.users": "svc-backup",
        "kerberos.show-hashes": "true",
      },
      expect: {
        "Risk Level": "CRITICAL",
        "AS-REP material (sensitive: treat as credential)[0]": "$krb5asrep$23$svc-backup@EXAMPLE.COM",
      },
    },
    {
      name: "AES-only roastable account is HIGH, not CRITICAL",
      script: "KERBEROS/kerberos-asrep-roasting.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: { "kerberos.realm": REALM, "kerberos.users": "kiosk-01" },
      expect: {
        "Risk Level": "HIGH",
        "AS-REP roasting candidates (pre-authentication DISABLED)[0]": "kiosk-01",
      },
    },
    {
      name: "clean realm: every principal requires pre-authentication",
      script: "KERBEROS/kerberos-asrep-roasting.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: { "kerberos.realm": REALM, "kerberos.users": "jsmith" },
      expect: {
        "Risk Level": "LOW",
        "Pre-authentication enforced[0]": "jsmith",
        "Verdict[0]": "require pre-authentication",
      },
    },
    {
      name: "wrong realm supplied: KDC leaks the real realm and probes are retried",
      script: "KERBEROS/kerberos-asrep-roasting.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: { "kerberos.realm": "WRONG.REALM", "kerberos.users": "svc-backup" },
      expect: {
        "Realm": REALM,
        "Realm retry": "repeated",
        "Risk Level": "CRITICAL",
        "AS-REP roasting candidates (pre-authentication DISABLED)[0]": "svc-backup",
      },
    },
    {
      name: "unknown principal is reported as an enumeration oracle, not as a finding",
      script: "KERBEROS/kerberos-asrep-roasting.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: { "kerberos.realm": REALM, "kerberos.users": "nosuchuser,jsmith" },
      expect: {
        "Principals not found (enumeration oracle)": "nosuchuser",
        "Risk Level": "LOW",
      },
    },
    {
      name: "disabled account aborts the probe queue (lockout protection)",
      script: "KERBEROS/kerberos-asrep-roasting.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: { "kerberos.realm": REALM, "kerberos.users": "locked-out,jsmith,svc-backup", "kerberos.retries": "0", "kerberos.delay-ms": "0" },
      expect: {
        "Probe engine": "ABORTED",
        "Verdict": "INCONCLUSIVE",
      },
      maxIo: 4,
    },
    {
      name: "UDP is dropped: transport falls back to TCP and still classifies",
      script: "KERBEROS/kerberos-asrep-roasting.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts, tcpOnly: true },
      args: { "kerberos.realm": REALM, "kerberos.users": "svc-backup", "kerberos.retries": "1", "kerberos.delay-ms": "0" },
      expect: {
        "Risk Level": "CRITICAL",
        "Transport behaviour[0]": "TCP/88",
      },
    },
    {
      name: "first datagram dropped: retry logic recovers the answer",
      script: "KERBEROS/kerberos-asrep-roasting.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts, dropFirst: 1 },
      args: { "kerberos.realm": REALM, "kerberos.users": "svc-backup", "kerberos.retries": "2", "kerberos.delay-ms": "0" },
      expect: {
        "Risk Level": "CRITICAL",
        "AS-REP roasting candidates (pre-authentication DISABLED)[0]": "svc-backup",
      },
    },
  ],
};
