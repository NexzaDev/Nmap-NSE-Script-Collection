"use strict";
/*
 * tools/tests/kerberos-realm-discovery.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KERBEROS/kerberos-realm-discovery.nse.
 *
 * One mock service answers on port 88: tools/mocks/kdc.js, an independent
 * ASN.1 implementation that shares no code with the engine under test. The
 * scenarios drive the three discovery paths (leak, candidate confirmation and
 * name derivation), the refusal path, the unclassified-answer path and the
 * silent KDC, and assert on the wire what the report claims.
 */

const path = require("path");

const PORT = { number: 88, protocol: "tcp", state: "open", service: "kerberos-sec" };

function scenario(name, options) {
  return Object.assign({
    name,
    script: "KERBEROS/kerberos-realm-discovery.nse",
    mock: "tools/mocks/kdc.js",
    port: PORT,
    args: Object.assign({}, options.args || {}),
    kdc: options.kdc,
    host: options.host,
    expect: options.expect,
  }, options.scenario || {});
}

module.exports = {
  name: "kerberos-realm-discovery",
  scenarios: [
    scenario("a foreign realm probe names the realm the KDC serves", {
      kdc: { realm: "CORP.EXAMPLE.COM", accounts: { "jsmith": { preauth: true } } },
      expect: {
        "Discovered realm": "CORP.EXAMPLE.COM",
        "Method": "KDC_ERR_WRONG_REALM",
        "Confidence": "HIGH",
        "Risk Level": "INFO",
        "Findings": "REALM-DISCLOSED",
      },
    }),

    scenario("a supplied realm is confirmed by the answer about the probe principal", {
      args: { "kerberos.realm": "example.com" },
      kdc: { realm: "EXAMPLE.COM", accounts: { "jsmith": { preauth: true } } },
      expect: {
        "Discovered realm": "EXAMPLE.COM",
        "Confidence": "HIGH",
      },
    }),

    scenario("a KDC that does not leak is still resolved from the target's own name", {
      host: { ip: "10.0.0.10", name: "dc01.corp.example.com", targetname: "dc01.corp.example.com" },
      kdc: { realm: "CORP.EXAMPLE.COM", leakRealm: false, accounts: { "jsmith": { preauth: true } } },
      expect: {
        "Discovered realm": "CORP.EXAMPLE.COM",
        "Candidate matrix": "the target's own name",
        "Confidence": "HIGH",
      },
    }),

    scenario("a refusal is classified as a redirect, not as a confirmation", {
      args: { "kerberos.realm-candidates": "EXAMPLE.COM,EXAMPLE.NET" },
      kdc: { realm: "CORP.EXAMPLE.COM", accounts: { "jsmith": { preauth: true } } },
      expect: {
        "Candidate matrix": "refused",
        "Findings": "REALM-REDIRECTED",
      },
    }),

    scenario("an unlisted error code is reported as an unclassified answer", {
      kdc: { realm: "EXAMPLE.COM", errorCode: 60 },
      expect: {
        "Confidence": "INCONCLUSIVE",
        "Risk Level": "MEDIUM",
        "Findings": "REALM-NOT-DISCOVERED",
      },
    }),

    scenario("a silent KDC is reported instead of guessed at", {
      kdc: { realm: "EXAMPLE.COM", dropFirst: 99 },
      expect: {
        "Discovered realm": "not determined",
        "Confidence": "INCONCLUSIVE",
        "Risk Level": "MEDIUM",
      },
    }),
  ],
};
