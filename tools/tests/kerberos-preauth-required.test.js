"use strict";
/*
 * tools/tests/kerberos-preauth-required.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KERBEROS/kerberos-preauth-required.nse.
 *
 * tools/mocks/kdc.js answers on port 88 and records every AS-REQ it decoded,
 * including the padata types it carried. The scenarios therefore assert both
 * sides of the claim: what the report says, and what the KDC actually saw.
 */

const PORT = { number: 88, protocol: "tcp", state: "open", service: "kerberos-sec" };

function scenario(name, options) {
  return Object.assign({
    name,
    script: "KERBEROS/kerberos-preauth-required.nse",
    mock: "tools/mocks/kdc.js",
    port: PORT,
    args: Object.assign({ "kerberos.realm": "EXAMPLE.COM" }, options.args || {}),
    kdc: options.kdc,
    host: options.host,
    expect: options.expect,
    verify: options.verify,
  }, options.scenario || {});
}

module.exports = {
  name: "kerberos-preauth-required",
  scenarios: [
    scenario("an exempt account, a covered account and a name that does not exist", {
      args: { "kerberos.accounts": "svc-backup,svc-sql,nope" },
      kdc: {
        realm: "EXAMPLE.COM",
        accounts: { "svc-backup": { preauth: false }, "svc-sql": { preauth: true } },
      },
      expect: {
        "Policy coverage": "1 of 3 account(s) do not require pre-authentication",
        "Accounts": "svc-backup -> exempt",
        "Findings": "PREAUTH-NOT-REQUIRED",
        "Risk Level": "MEDIUM",
      },
      verify: (result, state) => {
        const seen = state.asReqs;
        const probed = seen.map((r) => String(r.cname).toLowerCase()).sort();
        return [
          { ok: probed.includes("svc-backup") && probed.includes("svc-sql"), message: `the KDC was asked about the two accounts (asked: ${probed.join(", ")})` },
          { ok: seen.every((r) => r.padataTypes.length === 0), message: "every AS-REQ arrived without padata, so the AS-REP is a real roast" },
          { ok: seen.every((r) => r.realm === "EXAMPLE.COM"), message: "every AS-REQ addressed the resolved realm" },
        ];
      },
    }),

    scenario("a realm that enforces pre-authentication for every account", {
      args: { "kerberos.accounts": "jsmith,admin" },
      kdc: { realm: "EXAMPLE.COM", accounts: { "jsmith": { preauth: true }, "admin": { preauth: true } } },
      expect: {
        "Policy coverage": "0 of 2 account(s) do not require pre-authentication",
        "Findings": "PREAUTH-ENFORCED",
        "Risk Level": "INFO",
      },
    }),

    scenario("a KDC that answers every name alike cannot be used as an oracle", {
      args: { "kerberos.accounts": "jsmith" },
      kdc: { realm: "EXAMPLE.COM", accounts: { "jsmith": { preauth: true } }, answerUnknownPrincipals: true },
      expect: {
        "Calibration": "-> covered",
        "Findings": "POLICY-INCONCLUSIVE",
        "Risk Level": "MEDIUM",
      },
    }),

    scenario("a disabled account is reported and stops the run", {
      args: { "kerberos.accounts": "old-svc,svc-sql" },
      kdc: {
        realm: "EXAMPLE.COM",
        accounts: { "old-svc": { preauth: true, state: "disabled" }, "svc-sql": { preauth: false } },
      },
      expect: {
        "Policy coverage": "1 disabled or locked",
        "Findings": "LOCKED-ACCOUNT-ENCOUNTERED",
      },
      verify: (result, state) => {
        const names = state.asReqs.map((r) => String(r.cname).toLowerCase());
        return [
          { ok: names.includes("old-svc"), message: "the disabled account was probed" },
          { ok: !names.includes("svc-sql"), message: "the run stopped before the account after the locked one" },
        ];
      },
    }),

    scenario("a silent KDC produces an unreachable realm, not a policy claim", {
      args: { "kerberos.accounts": "jsmith" },
      kdc: { realm: "EXAMPLE.COM", accounts: { "jsmith": { preauth: true } }, dropFirst: 99 },
      expect: {
        "Policy coverage": "no account could be placed on either side of the policy",
        "Findings": "KDC-UNREACHABLE",
        "Risk Level": "MEDIUM",
      },
    }),

    scenario("the AS-REP material is only printed when it is asked for", {
      args: { "kerberos.accounts": "svc-backup", "kerberos.show-hashes": "true" },
      kdc: { realm: "EXAMPLE.COM", accounts: { "svc-backup": { preauth: false } } },
      expect: {
        "Accounts": "$krb5asrep$23$svc-backup@EXAMPLE.COM$",
      },
    }),

    scenario("the account list is deduplicated and capped by kerberos.max-accounts", {
      args: {
        "kerberos.accounts": "svc-backup,SVC-BACKUP,svc-sql,unused-one,unused-two",
        "kerberos.max-accounts": "2",
      },
      kdc: {
        realm: "EXAMPLE.COM",
        accounts: { "svc-backup": { preauth: false }, "svc-sql": { preauth: true } },
      },
      expect: {
        "Accounts probed": "2 of at most 2",
      },
      verify: (result, state) => {
        const names = state.asReqs.map((r) => String(r.cname).toLowerCase()).filter((n) => n.indexOf("nmap-nonexistent") !== 0);
        return [
          { ok: names.length === 2, message: `exactly two account AS-REQs were sent (sent ${names.length})` },
          { ok: !names.includes("unused-one") && !names.includes("unused-two"), message: "the cap stopped the list before the unused names" },
        ];
      },
    }),
  ],
};
