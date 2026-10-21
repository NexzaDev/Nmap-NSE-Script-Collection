# 🏭 ICS / SCADA Security Audits

**16 Nmap NSE scripts** for auditing industrial control systems directly on the wire:

**Covers:**

- Eleven complete protocol codec stacks (Modbus/TCP with MBAP framing, MEI-14 device identification, coil/register decoding and exception grading; BACnet/IP BVLC framing with Who-Is, I-Am and confirmed ReadProperty including context tags; DNP3 FT3 data-link frames with CRC-16 and link-status control; EtherNet/IP encapsulation with CIP identity-item parsing; FINS/TCP node search and memory-area reads; Tridium Niagara Fox hello; HART-IP unique-identifier sessions; IEC 60870-5-104 APCI U-format TESTFR/STARTDT handshake; MELSEC 3E binary device reads; PROFINET DCP Identify block decoding; S7comm TPKT/COTP setup with PDU negotiation and SZL module identification) plus a budgeted TCP/UDP session layer

**The suite covers the ICS attack surface that matters:**

- Anonymous process reads (coils, registers, data memory, device words)
- The sentinel write-channel probe
- PLC/controller fingerprinting
- Telecontrol startup exposure and unauthenticated engineering sessions

**Every probe is bounded and non-destructive:**

- Identification and read operations only
- The single write test targets sentinel address 65535 which cannot map to any physical output
- No process values are changed and no state is modified on any device.

**Ports:** 502, 47808/udp, 20000, 44818, 9600, 1911, 5094/udp, 2404, 5007, 34964/udp, 102 | **Protocols:** Modbus/TCP, BACnet/IP, DNP3, EtherNet/IP (CIP), FINS, Fox/Niagara, HART-IP, IEC 60870-5-104, MELSEC 3E, PROFINET DCP, S7comm | **Total lines of Lua:** 27,612

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [bacnet-device-whois-leak](#1-bacnet-device-whois-leak---bacnet-who-is-device-enumeration) | 🔴 CRITICAL | vuln, safe | 1719 |
| 2 | [fox-niagara-unauth-check](#2-fox-niagara-unauth-check---tridium-niagara-fox-unauthenticated-session-check) | 🔴 CRITICAL | vuln, safe | 1725 |
| 3 | [modbus-unauth-read-coils](#3-modbus-unauth-read-coils---anonymous-modbus-coil-read-test) | 🔴 CRITICAL | vuln, safe | 1738 |
| 4 | [modbus-unauth-read-holding](#4-modbus-unauth-read-holding---anonymous-modbus-holding-register-read-test) | 🔴 CRITICAL | vuln, safe | 1737 |
| 5 | [modbus-unauth-write-risk](#5-modbus-unauth-write-risk---modbus-write-channel-sentinel-probe) | 🔴 CRITICAL | vuln, safe | 1737 |
| 6 | [dnp3-unauth-link-status](#6-dnp3-unauth-link-status---dnp3-unauthenticated-link-status-probe) | 🟠 HIGH | discovery, safe | 1723 |
| 7 | [fins-omron-plc-dump](#7-fins-omron-plc-dump---finstcp-omron-data-memory-read-test) | 🟠 HIGH | discovery, safe | 1722 |
| 8 | [s7comm-plc-fingerprint](#8-s7comm-plc-fingerprint---s7comm-plc-transport--module-fingerprint) | 🟠 HIGH | discovery, safe | 1727 |
| 9 | [bacnet-read-property-leak](#9-bacnet-read-property-leak---bacnet-readproperty-object-name-disclosure) | 🟡 MEDIUM | discovery, safe | 1730 |
| 10 | [ethernetip-identity-dump](#10-ethernetip-identity-dump---ethernetip-listidentity-controller-dump) | 🟡 MEDIUM | discovery, safe | 1723 |
| 11 | [iec104-apci-test](#11-iec104-apci-test---iec-60870-5-104-apci-startup-handshake-test) | 🟡 MEDIUM | discovery, safe | 1720 |
| 12 | [melsec-mitsubishi-probe](#12-melsec-mitsubishi-probe---melsec-3e-mitsubishi-plc-memory-probe) | 🟡 MEDIUM | discovery, safe | 1722 |
| 13 | [modbus-device-id-leak](#13-modbus-device-id-leak---modbus-device-identification-disclosure) | 🟡 MEDIUM | discovery, safe | 1731 |
| 14 | [hart-ip-device-probe](#14-hart-ip-device-probe---hart-ip-field-device-unique-id-probe) | 🟢 LOW | discovery, safe | 1720 |
| 15 | [modbus-unit-id-scan](#15-modbus-unit-id-scan---modbus-unit-identifier-scan) | 🟢 LOW | discovery, safe | 1718 |
| 16 | [profinet-dcp-discovery](#16-profinet-dcp-discovery---profinet-dcp-identify-discovery) | 🟢 LOW | discovery, safe | 1720 |

---

### 1. **bacnet-device-whois-leak** - BACnet Who-Is Device Enumeration
**Description:** Sends a BACnet Who-Is broadcast and decodes the I-Am answers - device

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends an unconfirmed Who-Is APDU.
- Decodes I-Am responses (device instance, max APDU, vendor).
- Grades the enumeration exposure.
- Why it matters: Any host that reaches UDP 47808 can enumerate the entire BMS: device instances are the keys for all later read/write operations. BACnet has no authentication; an exposed 47808 is an exposed building.
- Safety: one broadcast read-only query.

**How to Execute:**
```bash
nmap -p 47808 --script bacnet-device-whois-leak plc01.plant.example.com

# Tuned request budget
nmap -p 47808 --script bacnet-device-whois-leak --script-args 'bacnet-device-whois-leak.timeout=8,bacnet-device-whois-leak.maxrequests=48,bacnet-device-whois-leak.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| bacnet-device-whois-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - BACnet device enumerated: instance 56832 (vendor 5)
```

---

### 2. **fox-niagara-unauth-check** - Tridium Niagara Fox Unauthenticated Session Check
**Description:** Sends the Tridium Niagara Fox hello frame and grades whether a Fox

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends the fox a 0 -1 hello frame.
- Decodes the hello acknowledgement (version, host, brand).
- Flags accepted sessions as critical exposure.
- Why it matters: Unauthenticated Fox sessions exposed station metadata, user lists and historically full station access (Fox vulnerabilities used at ewater/utility scale). The hello answer leaks host name, Niagara version and platform.
- Safety: one hello frame; no station objects are read.

**How to Execute:**
```bash
nmap -p 1911 --script fox-niagara-unauth-check plc01.plant.example.com

# Tuned request budget
nmap -p 1911 --script fox-niagara-unauth-check --script-args 'fox-niagara-unauth-check.timeout=8,fox-niagara-unauth-check.maxrequests=48,fox-niagara-unauth-check.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| fox-niagara-unauth-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Fox session accepted without credentials (version 35, host niagara-ax-supervisor)
```

---

### 3. **modbus-unauth-read-coils** - Anonymous Modbus Coil Read Test
**Description:** Reads coil states (function code 1) from the first live unit without

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends Read Coils (FC 1) for addresses 0-7.
- Decodes the coil bitmap or the exception answer.
- Flags readable process state as a critical exposure.
- Why it matters: Coils mirror the physical process (pumps, breakers, valves); reading them anonymously is reconnaissance for targeted manipulation. Modbus has no authentication - network segmentation is the only control, and this probe tests exactly that.
- Safety: one read request; no writes are issued.

**How to Execute:**
```bash
nmap -p 502 --script modbus-unauth-read-coils plc01.plant.example.com

# Tuned request budget
nmap -p 502 --script modbus-unauth-read-coils --script-args 'modbus-unauth-read-coils.timeout=8,modbus-unauth-read-coils.maxrequests=48,modbus-unauth-read-coils.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| modbus-unauth-read-coils:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - process coil states readable without authentication (8 coils)
```

---

### 4. **modbus-unauth-read-holding** - Anonymous Modbus Holding Register Read Test
**Description:** Reads holding registers (function code 3) anonymously - setpoints,

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends Read Holding Registers (FC 3) for addresses 0-3.
- Decodes register values or the exception answer.
- Grades the disclosure.
- Why it matters: Holding registers carry the process brain: setpoints, alarm limits, recipe values. Anonymous reads enable precise, targeted manipulation later. Regulatory frameworks (IEC 62443) require zone segmentation exactly against this class of exposure.
- Safety: one read request; no writes are issued.

**How to Execute:**
```bash
nmap -p 502 --script modbus-unauth-read-holding plc01.plant.example.com

# Tuned request budget
nmap -p 502 --script modbus-unauth-read-holding --script-args 'modbus-unauth-read-holding.timeout=8,modbus-unauth-read-holding.maxrequests=48,modbus-unauth-read-holding.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| modbus-unauth-read-holding:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - holding registers readable without authentication (4 registers)
```

---

### 5. **modbus-unauth-write-risk** - Modbus Write Channel Sentinel Probe
**Description:** Probes whether the Modbus write channel is open: a Write Single Coil

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends FC 5 to address 65535 (out-of-range sentinel, no physical point).
- Reads the exception code: 02 = writes accepted, 01 = writes blocked.
- Grades the manipulation risk.
- Why it matters: An open write channel plus network reachability is the full Stuxnet- class primitive: any intruder in the segment can command the process. The sentinel address makes the probe safe by construction.
- Safety: the probe address cannot map to any real output; no process state changes.

**How to Execute:**
```bash
nmap -p 502 --script modbus-unauth-write-risk plc01.plant.example.com

# Tuned request budget
nmap -p 502 --script modbus-unauth-write-risk --script-args 'modbus-unauth-write-risk.timeout=8,modbus-unauth-write-risk.maxrequests=48,modbus-unauth-write-risk.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| modbus-unauth-write-risk:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - write function code is accepted; any segment intruder can command outputs
```

---

### 6. **dnp3-unauth-link-status** - DNP3 Unauthenticated Link-Status Probe
**Description:** Sends a DNP3 data-link REQUEST_LINK_STATUS frame and grades whether

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Builds an FT3 frame with control byte 0x49 (request link status).
- Decodes the outstation's LINK_STATUS/ACK answer.
- Grades the link exposure.
- Why it matters: DNP3 link-layer answers confirm a live outstation and expose the link state without any master authentication. Link-layer access is the stepping stone to application-layer reads (unsolicited responses, cold restarts).
- Safety: one read-only link control frame; no application objects are touched.

**How to Execute:**
```bash
nmap -p 20000 --script dnp3-unauth-link-status plc01.plant.example.com

# Tuned request budget
nmap -p 20000 --script dnp3-unauth-link-status --script-args 'dnp3-unauth-link-status.timeout=8,dnp3-unauth-link-status.maxrequests=48,dnp3-unauth-link-status.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| dnp3-unauth-link-status:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - outstation answers link-status requests from an unauthenticated master (LINK_STATUS)
```

---

### 7. **fins-omron-plc-dump** - FINS/TCP OMRON Data-Memory Read Test
**Description:** Sends a FINS/TCP memory-area read for the DM work area and reports

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Sends a memory-area word read (DM area, address 0, 2 words).
- Decodes the FINS response and end code.
- Grades the memory exposure.
- Why it matters: FINS carries no authentication; an open 9600 allows full memory reads and program writes from the network. Data-memory content leaks process setpoints and state directly.
- Safety: one two-word read; no writes are issued.

**How to Execute:**
```bash
nmap -p 9600 --script fins-omron-plc-dump plc01.plant.example.com

# Tuned request budget
nmap -p 9600 --script fins-omron-plc-dump --script-args 'fins-omron-plc-dump.timeout=8,fins-omron-plc-dump.maxrequests=48,fins-omron-plc-dump.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| fins-omron-plc-dump:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - OMRON PLC data memory readable without authentication (2 words)
```

---

### 8. **s7comm-plc-fingerprint** - S7comm PLC Transport & Module Fingerprint
**Description:** Fingerprints a Siemens S7 PLC: completes the COTP/TPKT transport

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Establishes COTP and performs the S7 setup-communication exchange.
- Reads the negotiated PDU length.
- Reads SZL 0x0111 for the module identification string.
- Why it matters: The module identification names the CPU (314/315/1518) and firmware, mapping to S7comm-plus advisories and default-security posture. An open 102 with successful negotiation proves full S7comm reachability - the protocol behind Stuxnet-class attacks.
- Safety: transport setup and identification reads only; no program or data writes.

**How to Execute:**
```bash
nmap -p 102 --script s7comm-plc-fingerprint plc01.plant.example.com

# Tuned request budget
nmap -p 102 --script s7comm-plc-fingerprint --script-args 's7comm-plc-fingerprint.timeout=8,s7comm-plc-fingerprint.maxrequests=48,s7comm-plc-fingerprint.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| s7comm-plc-fingerprint:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - S7comm channel usable without authentication (PDU 480, ident CPU 315-2 PN/DP v3.15)
```

---

### 9. **bacnet-read-property-leak** - BACnet ReadProperty Object-Name Disclosure
**Description:** Sends a confirmed ReadProperty request for the device object's

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Builds a confirmed ReadProperty APDU (object device, property 77).
- Decodes the ComplexACK value or the error answer.
- Grades the disclosure.
- Why it matters: Object names expose process topology (AHU names, zone controllers), letting an attacker target specific building functions. Combined with Who-Is this is full unauthenticated BMS enumeration.
- Safety: one read-only property request.

**How to Execute:**
```bash
nmap -p 47808 --script bacnet-read-property-leak plc01.plant.example.com

# Tuned request budget
nmap -p 47808 --script bacnet-read-property-leak --script-args 'bacnet-read-property-leak.timeout=8,bacnet-read-property-leak.maxrequests=48,bacnet-read-property-leak.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| bacnet-read-property-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - controller object name disclosed: AHU-01-Master-Controller
```

---

### 10. **ethernetip-identity-dump** - EtherNet/IP ListIdentity Controller Dump
**Description:** Sends an EtherNet/IP ListIdentity encapsulation request and decodes

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends ListIdentity (command 0x63).
- Decodes the identity item (product, revision, vendor, device type).
- Grades the disclosure.
- Why it matters: The identity item names the exact controller family and firmware, mapping directly to public advisories (CISA advisories list specific 1769/1756 revisions). Port 44818 is frequently exposed through DMZ misconfigurations.
- Safety: one read-only encapsulation request.

**How to Execute:**
```bash
nmap -p 44818 --script ethernetip-identity-dump plc01.plant.example.com

# Tuned request budget
nmap -p 44818 --script ethernetip-identity-dump --script-args 'ethernetip-identity-dump.timeout=8,ethernetip-identity-dump.maxrequests=48,ethernetip-identity-dump.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| ethernetip-identity-dump:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - controller identity disclosed: 1769-L16ER/B NET LINX rev 28.11
```

---

### 11. **iec104-apci-test** - IEC 60870-5-104 APCI Startup Handshake Test
**Description:** Performs the IEC 60870-5-104 transport handshake: sends TESTFR-act

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends TESTFR-act and decodes TESTFR-con.
- Sends STARTDT-act and decodes STARTDT-con.
- Grades the telecontrol exposure.
- Why it matters: A completing handshake proves the telecontrol channel is usable by any network peer; IEC 104 has no built-in authentication. The class of attacks (command injection into RTUs) starts exactly with this handshake.
- Safety: transport frames only; no ASDUs (commands) are sent.

**How to Execute:**
```bash
nmap -p 2404 --script iec104-apci-test plc01.plant.example.com

# Tuned request budget
nmap -p 2404 --script iec104-apci-test --script-args 'iec104-apci-test.timeout=8,iec104-apci-test.maxrequests=48,iec104-apci-test.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| iec104-apci-test:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - IEC-104 startup completed without authentication (TESTFR + STARTDT confirmed)
```

---

### 12. **melsec-mitsubishi-probe** - MELSEC 3E Mitsubishi PLC Memory Probe
**Description:** Sends a MELSEC 3E binary frame reading word device D0 and reports

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends a 3E read-word command for D0 (2 points).
- Decodes the end code and word values.
- Grades the memory exposure.
- Why it matters: The 3E protocol reads and writes every device (D/W/M) with no authentication; open 5007 is direct process access. Device word values expose setpoints and interlock states.
- Safety: one two-point read; no writes are issued.

**How to Execute:**
```bash
nmap -p 5007 --script melsec-mitsubishi-probe plc01.plant.example.com

# Tuned request budget
nmap -p 5007 --script melsec-mitsubishi-probe --script-args 'melsec-mitsubishi-probe.timeout=8,melsec-mitsubishi-probe.maxrequests=48,melsec-mitsubishi-probe.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| melsec-mitsubishi-probe:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - MELSEC device memory readable without authentication (2 words)
```

---

### 13. **modbus-device-id-leak** - Modbus Device Identification Disclosure
**Description:** Reads the Modbus device identification objects (vendor, product code,

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends Read Device Identification (MEI 14, Read Device ID code 1).
- Decodes the vendor/product/revision objects.
- Grades the disclosure.
- Why it matters: Vendor/product/revision identify the exact PLC model, which maps to known CVEs and default configurations. The data is readable by any TCP client that can reach port 502.
- Safety: one read-only identification request.

**How to Execute:**
```bash
nmap -p 502 --script modbus-device-id-leak plc01.plant.example.com

# Tuned request budget
nmap -p 502 --script modbus-device-id-leak --script-args 'modbus-device-id-leak.timeout=8,modbus-device-id-leak.maxrequests=48,modbus-device-id-leak.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| modbus-device-id-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - device identification disclosed to unauthenticated callers: Schneider BMXP342020 rev 2.80
```

---

### 14. **hart-ip-device-probe** - HART-IP Field Device Unique-ID Probe
**Description:** Sends a HART-IP session frame with command 0 (Read Unique Identifier)

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends HART-IP request with HART command 0.
- Decodes device type and unique address.
- Renders the instrument inventory probe.
- Why it matters: The unique identifier maps the field instrument (transmitters, valve positioners) to its device type - the inventory of the process edge. HART-IP gateways commonly expose 5094 to plant networks unbound.
- Safety: one read-only device identity command.

**How to Execute:**
```bash
nmap -p 5094 --script hart-ip-device-probe plc01.plant.example.com

# Tuned request budget
nmap -p 5094 --script hart-ip-device-probe --script-args 'hart-ip-device-probe.timeout=8,hart-ip-device-probe.maxrequests=48,hart-ip-device-probe.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| hart-ip-device-probe:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - HART field device answered: type 782 (unique a1:b2:c3:d4:e5)
```

---

### 15. **modbus-unit-id-scan** - Modbus Unit Identifier Scan
**Description:** Scans Modbus/TCP unit identifiers 1-16 with a Read Device

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends MEI-14 device identification to each unit id (bounded 16).
- Counts units answering without an exception.
- Renders the live-unit map.
- Why it matters: Live unit IDs map every PLC/RTU behind a gateway - the inventory an attacker enumerates first. Silent gateways that answer for absent units mask the real topology.
- Safety: read-only identification requests.

**How to Execute:**
```bash
nmap -p 502 --script modbus-unit-id-scan plc01.plant.example.com

# Tuned request budget
nmap -p 502 --script modbus-unit-id-scan --script-args 'modbus-unit-id-scan.timeout=8,modbus-unit-id-scan.maxrequests=48,modbus-unit-id-scan.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| modbus-unit-id-scan:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - 2 Modbus unit(s) answered: 1, 2
```

---

### 16. **profinet-dcp-discovery** - PROFINET DCP Identify Discovery
**Description:** Sends a PROFINET DCP Identify request and decodes the device name and

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends a DCP Identify (service 5) request.
- Decodes the name and IP blocks.
- Renders the IO island discovery probe.
- Why it matters: DCP Identify reveals station names and IP configuration - the map of the PROFINET IO island used for later engineering-protocol attacks. DCP is unauthenticated by design and responds to any requester.
- Safety: one read-only identify request; no set operations.

**How to Execute:**
```bash
nmap -p 34964 --script profinet-dcp-discovery plc01.plant.example.com

# Tuned request budget
nmap -p 34964 --script profinet-dcp-discovery --script-args 'profinet-dcp-discovery.timeout=8,profinet-dcp-discovery.maxrequests=48,profinet-dcp-discovery.recv_window=3' plc01.plant.example.com
```

**Sample Output:**
```
| profinet-dcp-discovery:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - PROFINET device identified: pn-io-station-01
```

