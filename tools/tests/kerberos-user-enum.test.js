"use strict";
/*
 * Integration scenarios for KERBEROS/kerberos-user-enum.nse.
 */

const REALM = "EXAMPLE.COM";

const accounts = {
  "jsmith": { preauth: true, etypes: [18, 17], salt: REALM },
  "legacy-app": { preauth: true, etypes: [23, 18], salt: "LEGACYAPP" },
  "svc-backup": { preauth: false, etype: 23, kvno: 3 },
  "old-admin": { state: "disabled" },
};

module.exports = {
  name: "kerberos-user-enum",
  scenarios: [
    {
      name: "mixed directory: existing, roastable, disabled and unknown principals",
      script: "KERBEROS/kerberos-user-enum.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: {
        "kerberos.realm": REALM,
        "kerberos.users": "jsmith,svc-backup,nosuchuser,old-admin",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Realm": REALM,
        "Result summary": "existing 3, unknown 1",
        "Existing principals[0]": "jsmith",
        "Principals with pre-authentication DISABLED (roastable)[0]": "svc-backup",
        "Risk Level": "CRITICAL",
      },
    },
    {
      name: "weak crypto on an existing account is reported with its etype list",
      script: "KERBEROS/kerberos-user-enum.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: {
        "kerberos.realm": REALM,
        "kerberos.users": "legacy-app",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Existing principals[0]": "rc4-hmac",
        "Risk Level": "HIGH",
      },
    },
    {
      name: "lockout guard aborts the queue when an account is disabled",
      script: "KERBEROS/kerberos-user-enum.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: {
        "kerberos.realm": REALM,
        "kerberos.users": "old-admin,jsmith,svc-backup",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Probe engine": "ABORTED",
        "Risk Level": "MEDIUM",
      },
      maxIo: 4,
    },
    {
      name: "no realm and no KDC leak: the run refuses to guess",
      script: "KERBEROS/kerberos-user-enum.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts, leakRealm: false },
      args: { "kerberos.users": "jsmith", "kerberos.delay-ms": "0", "kerberos.retries": "0" },
      expect: {
        "Check status": "ABORTED",
        "Risk Level": "INCONCLUSIVE",
      },
    },
    {
      name: "no candidates supplied: explicit refusal instead of a fabricated list",
      script: "KERBEROS/kerberos-user-enum.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts },
      args: { "kerberos.realm": REALM },
      expect: {
        "Check status": "no candidate principals",
        "Risk Level": "INCONCLUSIVE",
      },
    },
  ],
};
