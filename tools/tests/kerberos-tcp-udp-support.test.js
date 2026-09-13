"use strict";
/*
 * tools/tests/kerberos-tcp-udp-support.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KERBEROS/kerberos-tcp-udp-support.nse.
 *
 * The mock KDC answers on both transports from one scenario object, so the
 * script's per-transport measurements are assertions about real datagrams and
 * real length-prefixed frames.
 */

const PORT = { number: 88, protocol: "tcp", state: "open", service: "kerberos-sec" };

function scenario(name, options) {
  return Object.assign({
    name,
    script: "KERBEROS/kerberos-tcp-udp-support.nse",
    mock: "tools/mocks/kdc.js",
    port: PORT,
    args: Object.assign({ "kerberos.realm": "EXAMPLE.COM", "kerberos.principal": "jsmith" }, options.args || {}),
    kdc: options.kdc,
    expect: options.expect,
  }, options.scenario || {});
}

module.exports = {
  name: "kerberos-tcp-udp-support",
  scenarios: [
    scenario("a healthy KDC answers on both transports with correct framing", {
      kdc: { realm: "EXAMPLE.COM", accounts: { jsmith: { preauth: true } } },
      expect: {
        "Transport measurements": "UDP",
        "TCP framing": "matched the frame",
        "Findings": "TCP-FRAMING-OK",
      },
    }),

    scenario("a TCP-only path is reported as blocked UDP, not as failure", {
      kdc: { realm: "EXAMPLE.COM", accounts: { jsmith: { preauth: true } }, tcpOnly: true },
      expect: {
        "Findings": "UDP-TRANSPORT-BLOCKED",
        "Risk Level": "LOW",
      },
    }),

    scenario("a datagram that is too large is reported with its TCP fallback", {
      kdc: { realm: "EXAMPLE.COM", accounts: { jsmith: { preauth: true } }, udpTooBig: true },
      expect: {
        "Datagram fallback": "RESPONSE_TOO_BIG",
        "Findings": "UDP-TOO-BIG-FALLBACK",
      },
    }),

    scenario("one TCP connection carries the configured number of messages", {
      args: { "kerberos.tcp-messages": "3" },
      kdc: { realm: "EXAMPLE.COM", accounts: { jsmith: { preauth: true } } },
      expect: {
        "TCP connection reuse": "3 of 3",
        "Findings": "TCP-CONNECTION-REUSE",
      },
    }),

    scenario("a KDC that answers nothing on either transport is reported as unreachable", {
      kdc: { realm: "EXAMPLE.COM", accounts: { jsmith: { preauth: true } }, dropFirst: 99 },
      expect: {
        "Transport measurements": "unanswered",
        "Findings": "KDC-TRANSPORTS-UNREACHABLE",
      },
    }),

    scenario("verbose mode adds the transcript", {
      args: { "kerberos.verbose": "true" },
      kdc: { realm: "EXAMPLE.COM", accounts: { jsmith: { preauth: true } } },
      expect: {
        "Protocol transcript": "engine layer",
      },
    }),
  ],
};
