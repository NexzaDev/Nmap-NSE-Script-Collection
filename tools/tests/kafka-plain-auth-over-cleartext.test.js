"use strict";
/*
 * tools/tests/kafka-plain-auth-over-cleartext.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-plain-auth-over-cleartext.nse.
 *
 * Each scenario is a listener with a different transport personality: a
 * SASL_PLAINTEXT broker that offers PLAIN, the same broker behind TLS, a TLS
 * listener that refuses the ClientHello with an alert, a plaintext protocol that
 * answers the hello with its own error frame, a listener that offers only SCRAM,
 * a broker that accepts the generated sentinel, one that answers Metadata
 * anonymously, one that has connections.max.reauth.ms set, one that goes quiet on
 * SaslHandshake, and a port that never answers at all.
 *
 * The assertions check the two questions the script keeps apart: what the
 * transport is, and what the credential path is. The verify hooks check the wire:
 * that the ClientHello was really sent and counted, that exactly one PLAIN attempt
 * crossed it, and that the generated password never appears in the report.
 */

const { createMockKafka } = require("../mocks/kafka");

const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };

function scenario(name, options) {
  const mock = createMockKafka(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/kafka-plain-auth-over-cleartext.nse",
    port: PORT,
    args: Object.assign({ "kafka.timeout": "2000" }, options.args || {}),
    mockFactory: () => mock,
    expect: options.expect,
    expectAll: options.expectAll,
    verify: (result, state) => {
      const checks = [];
      const say = (ok, message) => checks.push({ ok, message });
      say((state.protocolErrors || []).length === 0,
        `the mock decoded every request without a protocol error (${JSON.stringify(state.protocolErrors)})`);
      say((state.violations || []).length === 0,
        `no request could change broker state (violations: ${JSON.stringify(state.violations)})`);
      const output = JSON.stringify(result.output === undefined ? result : result.output);
      say(!output.includes("not-a-credential"),
        "the generated sentinel password is not printed anywhere in the report");
      if (options.verify) options.verify({ state, result, say, output });
      return checks;
    },
  }, options.scenario || {});
}

module.exports = {
  name: "kafka-plain-auth-over-cleartext",
  scenarios: [
    scenario("a SASL_PLAINTEXT listener that offers PLAIN discloses the credential", {
      broker: { mechanisms: ["PLAIN", "SCRAM-SHA-256"], allowEveryoneIfNoAclFound: false },
      expect: {
        "Risk Level": "MEDIUM",
        "Target": "Transport verdict: cleartext-offered (protocol-exchange evidence)",
        "Findings": "KAFKA-PLAIN-CREDENTIALS-OVER-CLEARTEXT",
        "SASL": "Mechanisms offered: PLAIN, SCRAM-SHA-256",
      },
      expectAll: [
        { contains: "listener.security.protocol.map=SASL_PLAINTEXT:9092", present: true },
        { contains: "\\0<password:", present: true },
        { contains: "SaslAuthenticate payload", present: true },
        { contains: "byte(s): a zero byte, the username", present: true },
        { contains: "SASL_PLAINTEXT", present: true },
        { contains: "Listener protocol: SASL_PLAINTEXT: the principal is authenticated", present: true },
      ],
      verify: ({ state, result, say, output }) => {
        say(state.tlsHellosOnPlaintext === 1, "the ClientHello was sent to a plaintext listener once");
        say(state.tlsHellos === 0, "no TLS handshake was negotiated on this listener");
        say(state.saslAttempts.length === 1, `exactly one authentication attempt was made (${state.saslAttempts.length})`);
        say(state.saslAttempts[0].mechanism === "PLAIN", "the attempt used the PLAIN mechanism");
        say(state.saslAttempts[0].bytes > 8, `the token carried a user and a password (${state.saslAttempts[0].bytes} bytes)`);
        say(String(result.output["Finding summary"]).includes("MEDIUM x2"),
          `the headline tally counts both medium findings (${result.output["Finding summary"]})`);
        say(!output.includes("nmap-sentinel-"), "the password is described by length, not by value");
      },
    }),

    scenario("the same listener behind TLS is a hardening note, not a disclosure", {
      broker: { mechanisms: ["PLAIN", "SCRAM-SHA-256"], tls: true, anonymousAllowed: false },
      expect: {
        "Risk Level": "LOW",
        "Target": "Transport verdict: encrypted-plain (tls-reply evidence)",
        "Findings": "KAFKA-PLAIN-OFFERED",
        "Listener transport": "Cipher suite: TLS_AES_128_GCM_SHA256 (strong",
      },
      expectAll: [
        { contains: "Negotiated version: TLS 1.3", present: true },
        { contains: "ClientHello sent:", present: true },
        { contains: "KAFKA-PLAIN-CREDENTIALS-OVER-CLEARTEXT", present: false },
        { contains: "the listener answered the ClientHello with TLS", present: true },
      ],
      verify: ({ state, say }) => {
        say(state.tlsNegotiated !== null && state.tlsNegotiated !== undefined,
          "the mock completed a ServerHello, so the classification is not a guess");
        say(state.tlsHellos === 1, "one ClientHello reached the TLS listener");
        say(state.tlsHellosOnPlaintext === 0, "the hello was never treated as plaintext");
      },
    }),

    scenario("a TLS listener that refuses the hello is still classified as TLS", {
      broker: { mechanisms: ["PLAIN"], tls: "alert", tlsAlert: 40, topics: [] },
      expect: {
        "Risk Level": "LOW",
        "Target": "Transport verdict: encrypted-plain (tls-reply evidence)",
        "Listener transport": "Alert:",
        "Findings": "KAFKA-PLAIN-OFFERED",
      },
      expectAll: [
        { contains: "handshake_failure", present: true },
        { contains: "ClientHello sent:", present: true },
        { contains: "KAFKA-PLAIN-CREDENTIALS-OVER-CLEARTEXT", present: false },
      ],
      verify: ({ state, say }) => {
        say(state.tlsHellos === 1, "the alert answered a real ClientHello");
        say(state.tlsNegotiated === null || state.tlsNegotiated === undefined,
          "no handshake was negotiated: the listener refused it, and the report says so");
      },
    }),

    scenario("a plaintext protocol that answers the hello is classified from its bytes", {
      broker: { mechanisms: ["PLAIN"], tls: "junk" },
      expect: {
        "Risk Level": "MEDIUM",
        "Target": "Transport verdict: cleartext-offered (non-tls-reply evidence)",
        "Findings": "KAFKA-PLAIN-CREDENTIALS-OVER-CLEARTEXT",
        "Listener transport": "First bytes of the reply:",
      },
      expectAll: [
        { contains: "is not a TLS record", present: true },
        { contains: "hello was answered by something that is not a TLS record", present: true },
      ],
      verify: ({ state, say, output }) => {
        say(output.includes("48 54 54 50"), "the hex preview quotes the bytes that answered (HTTP)");
        say(state.tlsHellosOnPlaintext === 1, "the non-TLS reply was counted as a plaintext answer");
      },
    }),

    scenario("a cleartext listener that offers only SCRAM does not publish a password", {
      broker: { mechanisms: ["SCRAM-SHA-256", "SCRAM-SHA-512"], topics: [] },
      expect: {
        "Risk Level": "LOW",
        "Target": "Transport verdict: cleartext-other-mechanism",
        "Findings": "KAFKA-CLEARTEXT-LISTENER-NO-PLAIN",
        "SASL": "mechanism-not-offered",
      },
      expectAll: [
        { contains: "UNSUPPORTED_SASL_MECHANISM", present: true },
        { contains: "KAFKA-PLAIN-CREDENTIALS-OVER-CLEARTEXT", present: false },
        { contains: "SCRAM: yes", present: true },
      ],
      verify: ({ state, say }) => {
        say(state.saslAttempts.length === 0,
          `no credential was sent to a listener that does not accept it (${state.saslAttempts.length} attempts)`);
        say(state.tlsHellosOnPlaintext === 1, "the transport was still classified from the hello");
      },
    }),

    scenario("a broker that accepts the generated sentinel authenticates an unknown identity", {
      broker: { mechanisms: ["PLAIN"], acceptAnyPlain: true },
      expect: {
        "Risk Level": "MEDIUM",
        "Findings": "KAFKA-SENTINEL-CREDENTIAL-ACCEPTED",
        "SASL": "accepted",
      },
      expectAll: [
        { contains: "generated probe credential", present: true },
        { contains: "cleartext-accepted", present: true },
        { contains: "nmap-plain-probe-", present: true },
      ],
      verify: ({ state, say }) => {
        say(state.saslAttempts.length === 1, "one attempt was made");
        say(state.saslAttempts[0].user !== undefined, "the mock recorded which identity authenticated");
        say(/nmap-plain-probe-\d{6}/.test(state.saslAttempts[0].user || ""),
          `the attempted name is a generated probe identity (${state.saslAttempts[0].user})`);
      },
    }),

    scenario("Metadata is answered before any SASL exchange", {
      broker: {
        mechanisms: ["PLAIN"],
        topics: [
          { name: "payments", partitions: 2, replicas: [1], isr: [1], internal: false, leader: 1 },
          { name: "orders", partitions: 3, replicas: [1], isr: [1], internal: false, leader: 1 },
        ],
      },
      expect: {
        "Risk Level": "MEDIUM",
        "Findings": "KAFKA-ANONYMOUS-METADATA-DESPITE-SASL",
        "Protocol probe": "Metadata: 2 topics",
      },
      expectAll: [
        { contains: "Metadata v", present: true },
        { contains: "answering it before authentication tells an unauthenticated caller", present: true },
      ],
    }),

    scenario("a broker that requires re-authentication does not raise the session finding", {
      broker: { mechanisms: ["PLAIN"], reauthMs: 300000 },
      expect: {
        "Risk Level": "MEDIUM",
        "Configuration": "connections.max.reauth.ms",
      },
      expectAll: [
        { contains: "KAFKA-REAUTH-NOT-CONFIGURED", present: false },
        { contains: "300000", present: true },
      ],
      verify: ({ state, result, say }) => {
        const config = JSON.stringify(result.output["Configuration"]);
        say(/connections\.max\.reauth\.ms\s+300000/.test(config),
          `the configured value is echoed from the broker response (${config})`);
      },
    }),

    scenario("a broker that never answers SaslHandshake leaves the credential path unproven", {
      broker: { mechanisms: ["PLAIN"], dropApis: [17], topics: [] },
      expect: {
        "Risk Level": "LOW",
        "Target": "Transport verdict: cleartext-no-sasl",
        "Findings": "KAFKA-CLEARTEXT-UNKNOWN-MECHANISMS",
      },
      expectAll: [
        { contains: "no mechanism list was readable", present: true },
        { contains: "KAFKA-PLAIN-CREDENTIALS-OVER-CLEARTEXT", present: false },
      ],
      verify: ({ state, say }) => {
        say(state.saslAttempts.length === 0, "nothing was attempted when the mechanism list was unreadable");
        say(state.tlsHellosOnPlaintext === 1, "the transport was still classified from the hello");
      },
    }),

    scenario("a port that accepts the connection and never answers is UNKNOWN, not cleartext", {
      broker: { silent: true },
      expect: {
        "Risk Level": "UNKNOWN",
        "Target": "No Kafka response was received",
      },
      expectAll: [
        { contains: "no answer to a", present: true },
        { contains: "KAFKA-PLAIN-CREDENTIALS-OVER-CLEARTEXT", present: false },
        { contains: "Method limits", present: true },
      ],
      verify: ({ state, say }) => {
        say(state.tlsHellosOnPlaintext === 1, "the hello really was sent and really went unanswered");
        say(state.tlsHellos === 0, "nothing was negotiated, so no transport claim was made");
      },
    }),

    scenario("the verbose transcript names every stage of the exchange", {
      broker: { mechanisms: ["PLAIN", "SCRAM-SHA-256"], allowEveryoneIfNoAclFound: true },
      args: { "kafka.verbose": "true", "kafka.client-id": "nse-audit-9" },
      expect: {
        "Probe transcript": "sasl_plain:",
        "Target": "Client id nse-audit-9",
      },
      expectAll: [
        { contains: "api_versions:", present: true },
        { contains: "sasl_handshake:", present: true },
        { contains: "describe_configs:", present: true },
        { contains: "allow.everyone.if.no.acl.found", present: true },
      ],
    }),

    scenario("an operator-supplied credential is attempted instead of a sentinel", {
      broker: { mechanisms: ["PLAIN"], plainCredentials: { "svc-audit": "s3cr3t-audit" } },
      args: { "kafka.user": "svc-audit", "kafka.password": "s3cr3t-audit" },
      expect: {
        "Risk Level": "MEDIUM",
        "SASL": "accepted",
        "SASL": "operator supplied",
      },
      expectAll: [
        { contains: "KAFKA-SUPPLIED-CREDENTIAL-ACCEPTED", present: true },
        { contains: "KAFKA-SENTINEL-CREDENTIAL-ACCEPTED", present: false },
        { contains: "s3cr3t-audit", present: false },
      ],
      verify: ({ state, say, output }) => {
        say(state.saslAttempts[0].user === "svc-audit",
          `the operator's identity was the one attempted (${state.saslAttempts[0].user})`);
        say(!output.includes("s3cr3t-audit"), "the supplied password is never echoed into the report");
      },
    }),
  ],
};
