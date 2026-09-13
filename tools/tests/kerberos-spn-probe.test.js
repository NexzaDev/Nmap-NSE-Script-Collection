"use strict";
/*
 * Integration scenarios for KERBEROS/kerberos-spn-probe.nse.
 *
 * The mock resolves service principals the way a KDC does: the SPN lookup
 * happens before ticket decryption, so an unknown SPN yields
 * KDC_ERR_S_PRINCIPAL_UNKNOWN while a registered one yields a decryption error.
 * The calibration probe then decides whether that oracle is trustworthy.
 */

const REALM = "EXAMPLE.COM";

const spns = {
  "MSSQLSvc/db01:1433": { etype: 23 },
  "MSSQLSvc/db01.example.com:1433": { etype: 23 },
  "HTTP/intranet": { etype: 18 },
  "cifs/fs01": { etype: 18 },
  "HOST/ws01": { etype: 18 },
  "vpn/gw01": { etype: 23 },
};

module.exports = {
  name: "kerberos-spn-probe",
  scenarios: [
    {
      name: "registered high-value SPNs are discovered and ranked",
      script: "KERBEROS/kerberos-spn-probe.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts: {}, spns },
      args: {
        "kerberos.realm": REALM,
        "kerberos.targets": "db01,intranet,fs01,ws01,gw01",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Realm": REALM,
        "Risk Level": "HIGH",
        "Registered service principals[0]": "exists",
        "Kerberoasting exposure ranking[0]": "MSSQLSvc",
        "Oracle calibration[0]": "calibration:",
      },
    },
    {
      name: "explicit SPN list probes exactly what was asked for",
      script: "KERBEROS/kerberos-spn-probe.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts: {}, spns },
      args: {
        "kerberos.realm": REALM,
        "kerberos.spn-list": "test-fixtures/kerberos-spn-list.txt",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Probe summary": "candidates",
        "Risk Level": "HIGH",
      },
    },
    {
      name: "an oracle that answers uniformly is reported as inconclusive",
      script: "KERBEROS/kerberos-spn-probe.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts: {}, spns, errorCode: 41 },
      args: {
        "kerberos.realm": REALM,
        "kerberos.targets": "db01",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Oracle calibration[0]": "does not distinguish",
        "Risk Level": "MEDIUM",
      },
    },
    {
      name: "nothing registered: the run reports a clean inventory honestly",
      script: "KERBEROS/kerberos-spn-probe.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts: {}, spns: {} },
      args: {
        "kerberos.realm": REALM,
        "kerberos.targets": "nosuchhost",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Risk Level": "LOW",
        "Verdict[0]": "No probed service principal is registered",
      },
    },
    {
      name: "no targets supplied: explicit refusal with usage instead of a fabricated scan",
      script: "KERBEROS/kerberos-spn-probe.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts: {}, spns },
      args: { "kerberos.realm": REALM },
      expect: {
        "Check status": "no SPN targets were supplied",
        "Risk Level": "INCONCLUSIVE",
      },
    },
    {
      name: "a supplied ticket is decoded, validated and reported before use",
      script: "KERBEROS/kerberos-spn-probe.nse",
      mock: "tools/mocks/kdc.js",
      kdc: { realm: REALM, accounts: {}, spns: { "HTTP/intranet": { etype: 23, ticketAccepted: true } } },
      args: {
        "kerberos.realm": REALM,
        "kerberos.targets": "intranet",
        "kerberos.spn-classes": "HTTP",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
        "kerberos.ticket": "6e8197",  // truncated AP-REQ: must be reported as a problem, never silently used
      },
      expect: {
        "Ticket mode": "supplied ticket",
        "Supplied ticket inspection[0]": "shape:",
      },
    },
  ],
};
