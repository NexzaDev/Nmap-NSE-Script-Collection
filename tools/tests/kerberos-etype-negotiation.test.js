"use strict";
/*
 * tools/tests/kerberos-etype-negotiation.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KERBEROS/kerberos-etype-negotiation.nse.
 *
 * The mock KDC is an independent ASN.1 implementation, so the matrix this
 * script builds has to come from the wire: the etype the AS-REP was encrypted
 * with, and the PA-ETYPE-INFO2 entries in the KDC_ERR_PREAUTH_REQUIRED answer.
 */

const PORT = { number: 88, protocol: "tcp", state: "open", service: "kerberos-sec" };

function scenario(name, options) {
  return Object.assign({
    name,
    script: "KERBEROS/kerberos-etype-negotiation.nse",
    mock: "tools/mocks/kdc.js",
    port: PORT,
    args: Object.assign({ "kerberos.realm": "EXAMPLE.COM", "kerberos.principal": "jsmith" }, options.args || {}),
    kdc: options.kdc,
    host: options.host,
    expect: options.expect,
  }, options.scenario || {});
}

module.exports = {
  name: "kerberos-etype-negotiation",
  scenarios: [
    scenario("a realm that accepts AES and RC4 and refuses DES", {
      kdc: {
        realm: "EXAMPLE.COM",
        accounts: { jsmith: { preauth: true, etypes: [18, 17, 23] } },
      },
      args: { "kerberos.etypes": "18,23,16" },
      expect: {
        "Negotiation matrix": "accepted",
        "Matrix summary": "2 accepted, 1 refused, 0 undecided of 3 probed",
        "Risk Level": "INFO",
        "Findings": "NEGOTIATION-MAPPED",
      },
    }),

    scenario("the salt and parameters come from PA-ETYPE-INFO2", {
      kdc: {
        realm: "EXAMPLE.COM",
        accounts: { jsmith: { preauth: true, etypes: [18], salt: "EXAMPLE.COMjsmith" } },
      },
      args: { "kerberos.etypes": "18" },
      expect: {
        "Negotiation matrix": "EXAMPLE.COMjsmith",
        "Matrix summary": "1 accepted",
      },
    }),

    scenario("a KDC that applies its own priority is reported as such", {
      kdc: {
        realm: "EXAMPLE.COM",
        accounts: { jsmith: { preauth: true, etypes: [23, 17, 18] } },
      },
      args: { "kerberos.etypes": "18,23" },
      expect: {
        "KDC preference": "23, 17, 18",
      },
    }),

    scenario("DES is flagged when a historic realm still accepts it", {
      kdc: {
        realm: "EXAMPLE.COM",
        acceptsEtype: [16, 23],
        accounts: { jsmith: { preauth: true, etypes: [16, 23] } },
      },
      args: { "kerberos.etypes": "16,23" },
      expect: {
        "Negotiation matrix": "DES-CBC-CRC",
        "Findings": "DES-ACCEPTED",
      },
    }),

    scenario("an unknown probe principal makes every type undecided", {
      kdc: {
        realm: "EXAMPLE.COM",
        accounts: { "someone-else": { preauth: true } },
      },
      args: { "kerberos.principal": "nmap-etype-probe", "kerberos.etypes": "18,23" },
      expect: {
        "Matrix summary": "0 accepted, 0 refused, 2 undecided",
        "Findings": "NEGOTIATION-INCONCLUSIVE",
        "Risk Level": "MEDIUM",
      },
    }),

    scenario("a realm that refuses the whole catalogue is reported, not glossed over", {
      kdc: {
        realm: "EXAMPLE.COM",
        accounts: { jsmith: { preauth: true, etypes: [18] } },
        acceptsEtype: [18, 17],
      },
      args: { "kerberos.etypes": "23,16" },
      expect: {
        "Matrix summary": "0 accepted, 2 refused",
        "Findings": "NO-COMMON-TYPE",
        "Risk Level": "HIGH",
      },
    }),

    scenario("verbose mode adds the transcript", {
      kdc: {
        realm: "EXAMPLE.COM",
        accounts: { jsmith: { preauth: true, etypes: [18] } },
      },
      args: { "kerberos.etypes": "18", "kerberos.verbose": "true" },
      expect: {
        "Protocol transcript": "AS-REQ offer",
      },
    }),
  ],
};
