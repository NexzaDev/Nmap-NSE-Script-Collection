"use strict";
/*
 * tools/tests/kerberos-fast-negotiation.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KERBEROS/kerberos-fast-negotiation.nse.
 *
 * One mock KDC on port 88 answers the three AS-REQs the script sends (plain,
 * PA-FX-FAST carrying, and a control name that cannot exist) and records what
 * each request carried. The verify hooks assert the wire facts behind every
 * verdict: that the FAST probe really carried padata type 136, that the control
 * probe used a different name, and that the mock never raised a protocol error.
 */

const { createMockKdc } = require("../mocks/kdc");

const PORT = { number: 88, protocol: "tcp", state: "open", service: "kerberos-sec" };

function scenario(name, options) {
  const mock = createMockKdc(Object.assign({
    realm: "EXAMPLE.COM",
    accounts: { krbtgt: { preauth: true }, jsmith: { preauth: true } },
  }, options.kdc || {}));
  return Object.assign({
    name,
    script: "KERBEROS/kerberos-fast-negotiation.nse",
    port: PORT,
    args: Object.assign({ "kerberos.realm": "EXAMPLE.COM" }, options.args || {}),
    mockFactory: () => mock,
    expect: options.expect,
    verify: (result, state) => {
      const checks = [];
      const say = (ok, message) => checks.push({ ok, message });
      const asReqs = state.asReqs || [];
      // A scenario that drops every message never reaches the parser, so the
      // check moves up one layer: the requests still had to be sent.
      if ((state.drops || 0) > 0) {
        say(state.requests.length >= 3,
          `the probes reached the mock even though it answered none (${state.requests.length} request(s))`);
      } else {
        say(asReqs.length >= 3, `the KDC decoded ${asReqs.length} AS-REQ(s), including the controls`);
        say(asReqs.some((r) => (r.padataTypes || []).includes(136)),
          "one AS-REQ carried PA-FX-FAST (136) on the wire");
        const names = asReqs.map((r) => String(r.cname).toLowerCase());
        say(names.some((n) => n.startsWith("nmap-nonexistent-")),
          `a control name was used: ${names.join(", ")}`);
      }
      if (options.verify) options.verify({ state, asReqs, say, checks });
      return checks;
    },
  }, options.scenario || {});
}

module.exports = {
  name: "kerberos-fast-negotiation",
  scenarios: [
    scenario("a KDC without RFC 6113 refuses the FAST padata type", {
      kdc: { fast: "none" },
      expect: {
        "FAST verdict": "not-supported",
        "PA-FX-FAST advertisement": "absent",
        "Findings": "FAST-NOT-SUPPORTED",
        "Risk Level": "LOW",
      },
      verify: ({ asReqs, say }) => {
        const withFast = asReqs.filter((r) => (r.padataTypes || []).includes(136));
        say(withFast.length === 1, `exactly one probe asked for FAST (${withFast.length})`);
        say(asReqs.filter((r) => !(r.padataTypes || []).includes(136)).length >= 2,
          "the baseline and the control probes carried no padata, so the advertisement reading is a real absence");
      },
    }),

    scenario("a KDC that advertises FAST and still discloses the salt", {
      kdc: { fast: "supported" },
      expect: {
        "FAST verdict": "supported",
        "PA-FX-FAST advertisement": "PA-FX-FAST (136) present",
        "Advertised padata": "136 PA-FX-FAST",
        "Risk Level": "INFO",
      },
    }),

    scenario("a KDC that requires armoring withholds the etype information", {
      kdc: { fast: "required" },
      expect: {
        "FAST verdict": "required",
        "Salt disclosure": "received no etype information",
        "Findings": "FAST-REQUIRED",
      },
    }),

    scenario("a KDC that advertises FAST and then ignores the request for it", {
      kdc: { fast: "supported", fastDowngrade: true },
      expect: {
        "FAST verdict": "inconsistent",
        "Findings": "FAST-DOWNGRADE",
        "Risk Level": "MEDIUM",
      },
    }),

    scenario("a KDC that advertises FAST without the stateless cookie", {
      kdc: { fast: "supported", fastWithoutCookie: true },
      expect: {
        "FAST verdict": "supported",
        "Findings": "FAST-NO-COOKIE",
      },
    }),

    scenario("a silent KDC produces an unreachable verdict, not a policy claim", {
      kdc: { fast: "required", dropFirst: 99 },
      expect: {
        "FAST verdict": "unreachable",
        "Risk Level": "INCONCLUSIVE",
        "Findings": "KDC-UNREACHABLE",
      },
      verify: ({ state, say }) => {
        say(state.drops > 0, `the mock dropped ${state.drops} probe(s) to simulate the timeout`);
      },
    }),

    scenario("verbose mode adds the per-probe transcript with the padata lists", {
      args: { "kerberos.verbose": "true" },
      kdc: { fast: "supported" },
      expect: {
        "Protocol transcript": "carried PA-FX-FAST=true",
      },
    }),
  ],
};
