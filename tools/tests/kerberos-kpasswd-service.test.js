"use strict";
/*
 * tools/tests/kerberos-kpasswd-service.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KERBEROS/kerberos-kpasswd-service.nse.
 *
 * Two mock services, dispatched by destination port as a real network would:
 *
 *   port 88  -> tools/mocks/kdc.js       the realm oracle (error 68)
 *   port 464 -> tools/mocks/kpasswd.js   RFC 3244 framing, AP-REQ and KRB-PRIV
 *
 * The mock decodes the two byte length prefix and the change request's version
 * field itself, so every scenario is an assertion about bytes on the wire. The
 * verify hooks check the same facts the report claims: how many messages were
 * framed correctly, which version each change request carried, and that the
 * mock never had to record a protocol error.
 */

const { createMockKdc } = require("../mocks/kdc");
const { createMockKpasswd } = require("../mocks/kpasswd");

const PORT = { number: 464, protocol: "tcp", state: "open", service: "kpasswd" };

function composite({ kdc = {}, kpasswd = {} } = {}) {
  const kdcMock = createMockKdc(Object.assign({
    realm: "EXAMPLE.COM",
    accounts: { jsmith: { preauth: true } },
  }, kdc));
  const kpasswdMock = createMockKpasswd(Object.assign({}, kpasswd));
  const state = { requests: [], kdc: kdcMock.state, kpasswd: kpasswdMock.state };
  return {
    state,
    handle(payload, proto, meta) {
      const port = meta && meta.port;
      if (port === 88) return kdcMock.handle(payload, proto, meta);
      if (port === 464) return kpasswdMock.handle(payload, proto, meta);
      return { raw: null, error: `no mock service on port ${port}` };
    },
  };
}

function scenario(name, options) {
  const mocks = composite(options.mocks || {});
  return Object.assign({
    name,
    script: "KERBEROS/kerberos-kpasswd-service.nse",
    port: PORT,
    args: Object.assign({ "kerberos.realm": "EXAMPLE.COM" }, options.args || {}),
    mockFactory: () => mocks,
    expect: options.expect,
    verify: (result, state) => {
      const checks = [];
      const say = (ok, message) => checks.push({ ok, message });
      const kp = state.kpasswd;
      say(kp.protocolErrors.length === 0,
        `framing seen by the service: ${kp.protocolErrors.length ? kp.protocolErrors.join(" | ") : "every message carried a correct two byte prefix"}`);
      const changeVersions = kp.messages.filter((m) => m.type === "krb_priv").map((m) => m.version);
      if (options.expectVersions !== false) {
        const seen = new Set(changeVersions);
        say(seen.has(0xff80) && seen.has(0xff81),
          `the service saw both version probes (versions: ${changeVersions.map((v) => (v === null ? "none" : "0x" + v.toString(16))).join(", ") || "none"})`);
      }
      if (options.verify) options.verify({ result, kpasswd: kp, say, checks });
      return checks;
    },
  }, options.scenario || {});
}

module.exports = {
  name: "kerberos-kpasswd-service",
  scenarios: [
    scenario("a healthy service refuses the synthetic ticket and the unprotected change", {
      expect: {
        "Transports": "KRB_AP_ERR_BAD_INTEGRITY",
        "Findings": "KPASSWD-REFUSES-BEFORE-DECRYPT",
        "Risk Level": "INFO",
      },
      verify: ({ kpasswd, say }) => {
        say(kpasswd.messages.filter((m) => m.type === "ap_req").length === 2,
          `two AP-REQs reached the service, one per transport (${kpasswd.messages.filter((m) => m.type === "ap_req").length})`);
      },
    }),

    scenario("a service that answers the unverifiable ticket with an AP-REP", {
      mocks: { kpasswd: { apRep: true } },
      expect: {
        "Findings": "KPASSWD-ACCEPTS-UNVERIFIED-TICKET",
        "Risk Level": "HIGH",
      },
    }),

    scenario("a service that returns a success result code before authenticating anyone", {
      mocks: { kpasswd: { acceptsUnauthenticatedChange: true } },
      expect: {
        "Findings": "KPASSWD-UNAUTHENTICATED-CHANGE",
        "Risk Level": "HIGH",
      },
    }),

    scenario("a password service that answers UDP but not TCP", {
      mocks: { kpasswd: { udpOnly: true } },
      expect: {
        "Findings": "KPASSWD-TCP-BLOCKED",
        "Risk Level": "MEDIUM",
      },
    }),

    scenario("a service that answers neither transport is not reported as healthy", {
      mocks: { kpasswd: { dropFirst: 99 } },
      expectVersions: false,
      expect: {
        "Transports": "no answer",
        "Findings": "KPASSWD-UNREACHABLE",
        "Risk Level": "INCONCLUSIVE",
      },
    }),

    scenario("an answer whose length prefix does not match its frame", {
      mocks: { kpasswd: { badPrefix: true } },
      expect: {
        "Findings": "KPASSWD-FRAMING-INCORRECT",
        "Risk Level": "LOW",
      },
    }),

    scenario("an answer that is not decodable ASN.1 is reported as malformed", {
      mocks: { kpasswd: { malformedAnswer: true, changeNoAnswer: false } },
      expect: {
        "Transports": "malformed",
      },
    }),

    scenario("verbose mode adds the per-probe transcript", {
      args: { "kerberos.verbose": "true" },
      expect: {
        "Protocol transcript": "request=",
      },
    }),
  ],
};
