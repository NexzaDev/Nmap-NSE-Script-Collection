"use strict";
/*
 * tools/tests/kafka-sasl-mechanism-audit.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-sasl-mechanism-audit.nse.
 *
 * Every scenario is a different SCRAM deployment: one that salts every account
 * with the same value, one that salts per account and answers uniformly, one
 * that leaks which accounts exist through the second message of the exchange,
 * one whose salt changes per exchange, one with a 1000-iteration count, one that
 * only offers PLAIN, one with SCRAM-SHA-1, a broker whose supplied credential
 * really completes the exchange, a silent port and a broker that never answers
 * SaslHandshake.
 *
 * The assertions check what the run makes of each deployment; the verify hooks
 * check the wire: how many first messages were read, that exactly one exchange
 * was completed per candidate name, and that the generated wrong password never
 * appears in the report.
 */

const { createMockKafka } = require("../mocks/kafka");

const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };

function scenario(name, options) {
  const mock = createMockKafka(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/kafka-sasl-mechanism-audit.nse",
    port: PORT,
    args: Object.assign({ "kafka.timeout": "2000" }, options.args || {}),
    // The interpreter this suite runs in is two orders of magnitude slower than
    // the Lua an operator executes, and the audit derives real SCRAM proofs.
    limitMs: options.limitMs || 120000,
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
      const output = JSON.stringify(result.output);
      say(!output.includes("not-the-password"),
        "the generated wrong password is never printed in the report");
      if (options.verify) options.verify({ state, result, say, output });
      return checks;
    },
  }, options.scenario || {});
}

module.exports = {
  name: "kafka-sasl-mechanism-audit",
  scenarios: [
    scenario("one salt for every account is measured across names that cannot be accounts", {
      broker: { mechanisms: ["SCRAM-SHA-256"], scramCredentials: {} },
      expect: {
        "Risk Level": "MEDIUM",
        "Findings": "KAFKA-SCRAM-SHARED-SALT",
        "SCRAM server-first message": "Salt policy: shared",
      },
      expectAll: [
        { contains: "identical", present: true },
        { contains: "Iterations: min 4096", present: true },
        { contains: "nmap-absent-", present: true },
        { contains: "SCRAM-SHA-256", present: true },
      ],
      verify: ({ state, say, output }) => {
        const attempts = state.saslAttempts.length;
        // three server-first messages (two absent names and one repeat) plus the
        // two messages of the baseline exchange.
        say(attempts === 5, `five SASL messages were sent in total (${attempts})`);
        say(state.scram === null, "the mock's exchange state was left clean");
        say(output.includes("fingerprint"), "the salt is reported by fingerprint");
      },
    }),

    scenario("per-account salts and a uniform answer are reported as the RFC behaviour", {
      broker: {
        mechanisms: ["SCRAM-SHA-512", "SCRAM-SHA-256"],
        scramRandomSalt: true,
        scramUniformErrors: true,
        scramCredentials: { "svc-audit": "real-pass" },
      },
      args: { "kafka.names": "svc-audit" },
      expect: {
        "Risk Level": "INFO",
        "SCRAM server-first message": "Salt policy: per-user",
        "User enumeration oracle": "Every candidate was answered with the baseline token",
        "Mechanisms offered": "Proof based: 2",
      },
      expectAll: [
        { contains: "KAFKA-SCRAM-USER-ENUMERATION", present: false },
        { contains: "KAFKA-SCRAM-SHARED-SALT", present: false },
        { contains: "KAFKA-SASL-MECHANISMS-AUDITED", present: true },
        { contains: "SCRAM-SHA-512", present: true },
      ],
      verify: ({ state, say }) => {
        say(state.saslAttempts.length === 7,
          `three salt reads and two completed exchanges were sent (${state.saslAttempts.length})`);
      },
    }),

    scenario("an unknown account and a wrong password are answered differently", {
      broker: {
        mechanisms: ["SCRAM-SHA-256"],
        scramRandomSalt: true,
        scramCredentials: { "svc-etl": "a-real-password" },
      },
      args: { "kafka.names": "svc-etl" },
      expect: {
        "Risk Level": "MEDIUM",
        "Findings": "KAFKA-SCRAM-USER-ENUMERATION",
        "User enumeration oracle": "Answers that differed from the baseline: 1",
      },
      expectAll: [
        { contains: "e=unknown-user", present: true },
        { contains: "e=invalid-proof", present: true },
        { contains: "svc-etl", present: true },
      ],
      verify: ({ state, say }) => {
        const users = state.saslAttempts.map((a) => a.user);
        say(users.some((u) => /^nmap-absent-\d{6}$/.test(u || "")),
          `a name that cannot exist was tested (${JSON.stringify(users)})`);
        say(users.includes("svc-etl"), "the supplied candidate name was tested");
      },
    }),

    scenario("a salt that changes between two exchanges is reported as a defect", {
      broker: { mechanisms: ["SCRAM-SHA-256"], scramSaltPerExchange: true },
      expect: {
        "Risk Level": "LOW",
        "Findings": "KAFKA-SCRAM-SALT-PER-EXCHANGE",
        "SCRAM server-first message": "Salt policy: per-exchange",
      },
      expectAll: [
        { contains: "two exchanges, two salts", present: true },
        { contains: "KAFKA-SCRAM-SHARED-SALT", present: false },
      ],
    }),

    scenario("an iteration count below the floor is graded against the RFC", {
      broker: { mechanisms: ["SCRAM-SHA-256"], scramIterations: 1000 },
      args: { "kafka.iterations-min": "4096" },
      expect: {
        "Risk Level": "MEDIUM",
        "Findings": "KAFKA-SCRAM-LOW-ITERATIONS",
        "SCRAM server-first message": "Iterations: min 1000",
      },
      expectAll: [
        { contains: "below the RFC 5802 floor", present: true },
        { contains: "i=1000", present: true },
      ],
    }),

    scenario("a listener that only offers PLAIN has no proof-based mechanism", {
      broker: { mechanisms: ["PLAIN"] },
      expect: {
        "Risk Level": "MEDIUM",
        "Findings": "KAFKA-PLAIN-ONLY-MECHANISMS",
        "Target": "Composite verdict: plain-only",
        "SCRAM server-first message": "No SCRAM variant is offered by this listener.",
      },
      expectAll: [
        { contains: "sends the password itself", present: true },
        { contains: "PLAIN", present: true },
      ],
      verify: ({ state, say }) => {
        // only the handshake: no exchange is attempted when no SCRAM variant is
        // offered, so no credential is sent to a listener that cannot use it.
        say(state.saslAttempts.length === 0,
          `no authentication was attempted (${state.saslAttempts.length} messages)`);
      },
    }),

    scenario("SCRAM-SHA-1 alone is audited and marked as the weakest accepted mechanism", {
      broker: { mechanisms: ["SCRAM-SHA-1"] },
      expect: {
        "Findings": "KAFKA-SCRAM-SHA1-OFFERED",
        "Mechanisms offered": "SCRAM-SHA-1",
      },
      expectAll: [
        { contains: "(deprecated)", present: true },
        { contains: "the guarantee is only that of the weakest mechanism", present: true },
      ],
      verify: ({ state, say }) => {
        say(state.saslAttempts.length > 0, "the exchange was still audited for the SHA-1 variant");
      },
    }),

    scenario("a supplied credential completes the exchange and the server signature verifies", {
      broker: {
        mechanisms: ["SCRAM-SHA-256"],
        scramRandomSalt: true,
        scramIterations: 8,
        scramCredentials: { "svc-audit": "s3cr3t-audit" },
      },
      args: { "kafka.user": "svc-audit", "kafka.password": "s3cr3t-audit" },
      expect: {
        "Findings": "KAFKA-SCRAM-CREDENTIAL-VERIFIED",
        "SCRAM server-first message": "Salt policy: per-user",
      },
      expectAll: [
        { contains: "The exchange with the supplied account finished with the server signature verified", present: true },
        { contains: "s3cr3t-audit", present: false },
        { contains: "KAFKA-SCRAM-USER-ENUMERATION", present: false },
      ],
      verify: ({ state, say }) => {
        const users = state.saslAttempts.map((a) => a.user);
        say(users.includes("svc-audit"), "the supplied account was the one completed");
      },
    }),

    scenario("without candidate names the oracle is not claimed either way", {
      broker: { mechanisms: ["SCRAM-SHA-256"], scramRandomSalt: true },
      expect: {
        "User enumeration oracle": "no claim is made either way",
      },
      expectAll: [
        { contains: "KAFKA-SCRAM-USER-ENUMERATION", present: false },
        { contains: "Candidates tested by completing the exchange: 0", present: true },
      ],
    }),

    scenario("a silent port is UNKNOWN, not a clean result", {
      broker: { silent: true },
      expect: {
        "Risk Level": "UNKNOWN",
        "Target": "No SASL response was received",
      },
      expectAll: [
        { contains: "Method limits and rubric", present: true },
        { contains: "KAFKA-SCRAM-SHARED-SALT", present: false },
      ],
      verify: ({ state, say }) => {
        say(state.saslAttempts.length === 0, "nothing was attempted against a port that never answers");
      },
    }),

    scenario("a listener that never answers the handshake is reported as unreachable", {
      broker: { mechanisms: ["SCRAM-SHA-256"], dropApis: [17] },
      expect: {
        "Risk Level": "UNKNOWN",
        "Target": "the SaslHandshake was not answered",
      },
      expectAll: [
        { contains: "nothing is claimed about its mechanisms", present: true },
        { contains: "KAFKA-SASL-AUDIT-INCONCLUSIVE", present: false },
      ],
    }),

    scenario("the verbose transcript names every stage of the exchange", {
      broker: {
        mechanisms: ["SCRAM-SHA-512"],
        scramRandomSalt: true,
        scramUniformErrors: true,
        scramIterations: 100000,
      },
      args: { "kafka.verbose": "true", "kafka.client-id": "nse-sasl-audit" },
      expect: {
        "Probe transcript": "scram_first_1:",
        "Target": "Client id nse-sasl-audit",
        "SCRAM server-first message": "Iterations: min 100000",
      },
      expectAll: [
        { contains: "sasl_handshake:", present: true },
        { contains: "scram_complete_1:", present: true },
        { contains: "strong", present: true },
      ],
    }),
  ],
};
