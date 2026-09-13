"use strict";
/*
 * tools/tests/rabbitmq-amqp-protocol-handshake.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/rabbitmq-amqp-protocol-handshake.nse.
 *
 * Every scenario is a different listener personality as it appears on the wire:
 * a stock 3.13 broker, a broker that offers to authenticate nobody, a broker
 * whose failed logins name the account, a broker that accepts the credential,
 * a broker that answers nothing after start-ok, an amqps listener that cannot
 * answer a plaintext protocol, and a management port that answers AMQP with
 * HTTP. The assertions check what the report claims about each one; the verify
 * hooks check the wire: that the script never sent a frame that could change
 * broker state, that the mock decoded every frame, and that the authentication
 * attempt only happened when a credential was supplied.
 */

const { createMockRabbitMQ } = require("../mocks/rabbitmq");

const AMQP_PORT = { number: 5672, protocol: "tcp", state: "open", service: "amqp" };
const AMQPS_PORT = { number: 5671, protocol: "tcp", state: "open", service: "amqps" };

function scenario(name, options) {
  const mock = createMockRabbitMQ(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/rabbitmq-amqp-protocol-handshake.nse",
    port: options.port || AMQP_PORT,
    args: Object.assign({ "rabbitmq.timeout": "2000" }, options.args || {}),
    mockFactory: () => mock,
    expect: options.expect,
    expectAll: options.expectAll,
    verify: (result, state) => {
      const checks = [];
      const say = (ok, message) => checks.push({ ok, message });
      say((state.protocolErrors || []).length === 0,
        `the mock decoded every frame without a protocol error (${JSON.stringify(state.protocolErrors)})`);
      say((state.violations || []).length === 0,
        `no frame could change broker state (violations: ${JSON.stringify(state.violations)})`);
      if (options.verify) options.verify({ state, result, say });
      return checks;
    },
  }, options.scenario || {});
}

module.exports = {
  name: "rabbitmq-amqp-protocol-handshake",
  scenarios: [
    scenario("a stock broker discloses its identity, capabilities and mechanisms before authenticating", {
      expect: {
        "Target": "Composite verdict: handshake-read",
        "AMQP connection.start": "Product: RabbitMQ 3.13.7",
        "Server capabilities": "consumer_cancel_notify",
        "SASL mechanisms": "PLAIN",
        "Authentication": "Attempted: no",
        "AMQP 1.0 on this port": "refuses-the-1.0-header-with-its-own",
        "Finding summary": "LOW x",
        "Risk Level": "LOW",
      },
      expectAll: [
        { contains: "RabbitMQ 3.13.7" },
        { contains: "cluster name: rabbit@node1" },
        { contains: "The broker describes itself before authentication" },
        { contains: "RABBITMQ-CLUSTER-NAME-DISCLOSURE" },
        { contains: "RABBITMQ-PASSWORD-MECHANISM-ON-PLAINTEXT" },
        { contains: "RABBITMQ-AMQP10-NOT-OFFERED" },
        { contains: "rabbitmq-diagnostics listeners" },
      ],
      verify: ({ state, result, say }) => {
        const headers = state.protocolHeaders.map((h) => `${h.major}.${h.minor}.${h.revision}`);
        say(headers.includes("0.9.1"), `the 0-9-1 protocol header reached the broker (${headers})`);
        say(headers.includes("3.0.0"), `the 1.0 protocol header was sent on its own connection (${headers})`);
        say(state.lastMechanism === undefined && (state.amqpAttempts || []).length === 0,
          "no credential was sent when the operator supplied none");
        const level = result.output["Risk Level"];
        say(level === "LOW", `a stock broker is graded LOW, not ${level}`);
      },
    }),

    scenario("a broker that offers ANONYMOUS is graded HIGH and the report says why", {
      broker: { mechanisms: ["ANONYMOUS", "PLAIN", "AMQPLAIN"], acceptAnonymous: true },
      expect: {
        "Target": "Composite verdict: anonymous-mechanism",
        "SASL mechanisms": "ANONYMOUS",
        "Risk Level": "HIGH",
      },
      expectAll: [
        { contains: "RABBITMQ-ANONYMOUS-MECHANISM-OFFERED" },
        { contains: "The broker offers to authenticate nobody" },
        { contains: "the broker advertises an anonymous mechanism" },
      ],
      verify: ({ state, say }) => {
        say((state.amqpAttempts || []).length === 0,
          "the anonymous mechanism was reported without a credential being offered");
      },
    }),

    scenario("a refused login is quoted, because the reason enumerates accounts", {
      broker: { closeRefusalReason: true },
      args: { "rabbitmq.user": "guest", "rabbitmq.password": "guest" },
      expect: {
        "Authentication": "Attempted: yes",
        "Target": "Composite verdict: handshake-read",
      },
      expectAll: [
        { contains: "Verdict: refused-localhost-restriction" },
        { contains: "RABBITMQ-LOGIN-FAILURE-NAMES-THE-ACCOUNT" },
        { contains: "can only connect via localhost" },
      ],
      verify: ({ state, say }) => {
        const attempt = (state.amqpAttempts || [])[0];
        say(!!attempt, "the broker saw an authentication attempt");
        say(attempt && attempt.mechanism === "PLAIN",
          `PLAIN was chosen over AMQPLAIN (${attempt && attempt.mechanism})`);
        say(attempt && attempt.user === "guest", "the attempt carried the account the operator supplied");
      },
    }),

    scenario("a valid credential is proven by a tune and an opened vhost", {
      broker: { credentials: { "svc-audit": "audit-pass" } },
      args: { "rabbitmq.user": "svc-audit", "rabbitmq.password": "audit-pass", "rabbitmq.verbose": "true" },
      expect: {
        "Authentication": "Verdict: accepted",
        "Findings": "RABBITMQ-CREDENTIAL-ACCEPTED",
        "Risk Level": "LOW",
      },
      expectAll: [
        { contains: "Verdict: accepted" },
        { contains: "vhost / opened" },
        { contains: "the identity is real" },
      ],
      verify: ({ state, result, say }) => {
        say(state.openedVhosts.includes("/"), "connection.open reached the broker and was accepted");
        const text = JSON.stringify(result.output);
        say(!text.includes("RABBITMQ-LOGIN-FAILURE-NAMES-THE-ACCOUNT"),
          "an accepted login is not reported as an enumeration oracle");
      },
    }),

    scenario("an AMQPLAIN broker is audited with the mechanism the operator selected", {
      broker: { mechanisms: ["AMQPLAIN"] },
      args: { "rabbitmq.user": "legacy", "rabbitmq.password": "legacy-pass", "rabbitmq.mechanism": "AMQPLAIN" },
      expect: {
        "Target": "Requested mechanism: AMQPLAIN",
        "SASL mechanisms": "AMQPLAIN",
      },
      expectAll: [{ contains: "Offered: AMQPLAIN" }, { contains: "RABBITMQ-PASSWORD-MECHANISM-ON-PLAINTEXT" }],
      verify: ({ state, say }) => {
        const attempt = (state.amqpAttempts || [])[0];
        say(attempt && attempt.form === "AMQPLAIN",
          `the start-ok carried a field table rather than a NUL-separated pair (${attempt && attempt.form})`);
      },
    }),

    scenario("a requested mechanism the broker does not offer is reported, not guessed at", {
      broker: { mechanisms: ["PLAIN"] },
      args: { "rabbitmq.user": "svc", "rabbitmq.password": "svc", "rabbitmq.mechanism": "EXTERNAL",
        "rabbitmq.verbose": "true" },
      expect: {
        "Authentication": "Verdict: mechanism-not-offered",
      },
      expectAll: [
        { contains: "the requested mechanism is not in the broker's list" },
        { contains: "EXTERNAL is not offered by this broker" },
      ],
      verify: ({ state, say }) => {
        say((state.amqpAttempts || []).length === 0,
          "no start-ok was sent for a mechanism the broker never offered");
      },
    }),

    scenario("a broker that answers a failed login with silence is reported as silent", {
      broker: { credentials: { "nobody": "not-the-password" }, authenticationFailureClose: false },
      args: { "rabbitmq.user": "nobody", "rabbitmq.password": "wrong" },
      expect: {
        "Authentication": "Verdict: no-answer",
      },
      expectAll: [
        { contains: "RABBITMQ-LOGIN-FAILURE-IS-SILENT" },
        { contains: "authentication_failure_close" },
      ],
      verify: ({ state, say }) => {
        say((state.amqpAttempts || []).length === 1, "the credential was offered exactly once");
      },
    }),

    scenario("an amqps listener is classified as TLS and the credential findings change meaning", {
      port: AMQPS_PORT,
      broker: { tls: true, mechanisms: ["EXTERNAL", "PLAIN"] },
      args: { "rabbitmq.timeout": "1000" },
      expect: {
        "Target": "Composite verdict: tls-listener",
        "Risk Level": "INFO",
      },
      expectAll: [
        { contains: "RABBITMQ-CONFIGURED-FOR-TLS" },
        { contains: "the port answered a TLS ClientHello" },
        { contains: "this is the amqps listener" },
      ],
      verify: ({ state, result, say }) => {
        say(state.tlsHellos.length >= 1, "the TLS probe reached the listener as a ClientHello");
        const text = JSON.stringify(result.output);
        say(!text.includes("RABBITMQ-PASSWORD-MECHANISM-ON-PLAINTEXT"),
          "a TLS listener is not reported as sending passwords over an unencrypted transport");
        say(state.plaintextOnTlsPort >= 1, "the plaintext header reached the TLS listener and was refused");
      },
    }),

    scenario("a management port answers the AMQP header with HTTP and is reported as such", {
      broker: { httpOnAmqpPort: true, mechanisms: [] },
      expect: {
        "Target": "Composite verdict: http-listener",
      },
      expectAll: [
        { contains: "RABBITMQ-MANAGEMENT-PORT" },
        { contains: "answered with an HTTP response" },
      ],
      verify: ({ state, say }) => {
        say((state.amqpFrames || []).length === 0,
          "the script did not try to speak AMQP frames to a port that answered HTTP");
      },
    }),

    scenario("a listener that answers the 1.0 header is reported as serving both protocols", {
      broker: { protocolMismatch: "amqp1" },
      expect: {
        "AMQP 1.0 on this port": "answers-the-1.0-header",
        "Target": "Composite verdict: handshake-read",
      },
      expectAll: [
        { contains: "RABBITMQ-AMQP10-AVAILABLE" },
        { contains: "the amqp1_0 plugin is loaded" },
      ],
      verify: ({ state, say }) => {
        const headers = state.protocolHeaders.map((h) => `${h.major}.${h.minor}.${h.revision}`);
        say(headers[0] === "0.9.1" && headers[1] === "3.0.0",
          `the 0-9-1 header was sent first, so the 1.0 answer describes the same listener (${headers})`);
      },
    }),

    scenario("a broker with a thin capability list is described capability by capability", {
      broker: {
        capabilities: { publisher_confirms: true, authentication_failure_close: true },
      },
      expect: {
        "Server capabilities": "Not advertised:",
      },
      expectAll: [
        { contains: "consumer_cancel_notify" },
        { contains: "connection_blocked" },
        { contains: "NOT ADVERTISED" },
        { contains: "RABBITMQ-CAPABILITY-NOT-ADVERTISED" },
      ],
      verify: ({ state, say }) => {
        say(state.protocolErrors.length === 0, "the reduced capability table still decoded cleanly");
      },
    }),
  ],
};
