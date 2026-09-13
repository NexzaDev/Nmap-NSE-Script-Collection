"use strict";
/*
 * tools/tests/kerberos-pac-validation.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KERBEROS/kerberos-pac-validation.nse.
 *
 * The mock KDC on port 88 answers the per-etype matrix, the whole-catalogue
 * probe (twice over: the policy probe and the repeat-stability samples), the
 * machine-account oracle and the padata capability matrix. Its `padataPolicy`
 * and `maskCycle` knobs make policy differences observable, which is what the
 * scenarios are built on.
 */

const { createMockKdc } = require("../mocks/kdc");

const PORT = { number: 88, protocol: "tcp", state: "open", service: "kerberos-sec" };

const BASE_ACCOUNTS = {
  "dc01$": { preauth: true },
  "krbtgt": { preauth: true },
};

function scenario(name, options) {
  const mock = createMockKdc(Object.assign({
    realm: "EXAMPLE.COM",
    accounts: JSON.parse(JSON.stringify(BASE_ACCOUNTS)),
  }, options.kdc || {}));
  return Object.assign({
    name,
    script: "KERBEROS/kerberos-pac-validation.nse",
    port: PORT,
    args: Object.assign({
      "kerberos.realm": "EXAMPLE.COM",
      "kerberos.principal": "DC01$",
      "kerberos.calibration": "krbtgt",
    }, options.args || {}),
    mockFactory: () => mock,
    expect: options.expect,
    verify: (result, state) => {
      const checks = [];
      const say = (ok, message) => checks.push({ ok, message });
      const asReqs = state.asReqs || [];
      if ((state.drops || 0) > 0) {
        say(state.requests.length > 0, `the probes reached the mock (${state.requests.length} request(s), all dropped)`);
      } else {
        say(asReqs.length >= 12, `the matrix sent a real request per type (${asReqs.length} AS-REQs decoded)`);
        const single = asReqs.filter((r) => (r.etypes || []).length === 1);
        say(single.length >= 10, `per-etype requests offered exactly one type (${single.length})`);
        const catalogue = asReqs.filter((r) => (r.etypes || []).length > 1);
        say(catalogue.length >= 4, `the catalogue probes offered the whole list (${catalogue.length})`);
      }
      if (options.verify) options.verify({ state, asReqs, say, checks });
      return checks;
    },
  }, options.scenario || {});
}

module.exports = {
  name: "kerberos-pac-validation",
  scenarios: [
    scenario("a controller that still answers RC4 keeps the forgery path open", {
      kdc: { acceptsEtype: [17, 18, 23] },
      expect: {
        "Encryption type policy": "RC4-HMAC is accepted",
        "Findings": "RC4-ACCEPTED",
        "Risk Level": "HIGH",
      },
      verify: ({ say, state }) => {
        say(state.asReqs.some((r) => JSON.stringify(r.etypes) === "[23]"),
          "an AS-REQ offering only RC4-HMAC (23) was sent");
      },
    }),

    scenario("a controller that refuses RC4 and negotiates AES only", {
      kdc: { acceptsEtype: [17, 18] },
      expect: {
        "Encryption type policy": "RC4-HMAC is not accepted",
        "Mask agreement": "agree",
      },
    }),

    scenario("a machine account that never pre-authenticates is caught by the ticket facts", {
      kdc: {
        acceptsEtype: [17, 18, 23],
        accounts: { "dc01$": { preauth: false, etype: 18, kvno: 4 }, "krbtgt": { preauth: true } },
      },
      expect: {
        "Findings": "ASREP-WITHOUT-PREAUTH",
        "Ticket facts": "kvno",
        "Risk Level": "HIGH",
      },
    }),

    scenario("a KDC that processes the PKINIT padata type", {
      kdc: { acceptsEtype: [17, 18], padataPolicy: { "16": "processed", "2": "processed" } },
      expect: {
        "Padata matrix": "PA-PK-AS-REQ",
        "Padata findings": "PADATA-TYPES-SUPPORTED",
      },
      verify: ({ state }) => {
        const facts = [];
        facts.push({ ok: (state.asReqs || []).length > 0, message: "the padata probes were sent as AS-REQs" });
        return facts;
      },
    }),

    scenario("a KDC that answers a name it does not have exactly like a real one", {
      kdc: { acceptsEtype: [17, 18], answerUnknownPrincipals: true },
      expect: {
        "Account oracle": "calibration krbtgt answered KDC_ERR_PREAUTH_REQUIRED",
        "Findings": "ACCOUNT-ORACLE-UNIFORM",
      },
    }),

    scenario("two policies behind one name are reported as an unstable endpoint", {
      kdc: { acceptsEtype: [17, 18], maskCycle: [0x00030000, 0x00060000] },
      expect: {
        "Repeat stability": "disagreed",
        "Stability differences": "advertised mask",
        "Risk Level": "MEDIUM",
      },
    }),

    scenario("a silent controller produces no policy claim at all", {
      kdc: { acceptsEtype: [17, 18, 23], dropFirst: 99 },
      expect: {
        "Risk Level": "INCONCLUSIVE",
        "Findings": "KDC-UNREACHABLE",
      },
    }),

    scenario("verbose mode records the per-type transcript", {
      args: { "kerberos.verbose": "true" },
      kdc: { acceptsEtype: [17, 18, 23] },
      expect: {
        "Protocol transcript": "verdict=",
      },
    }),
  ],
};
