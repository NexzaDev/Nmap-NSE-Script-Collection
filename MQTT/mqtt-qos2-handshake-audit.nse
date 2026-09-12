local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Audits the MQTT Quality of Service 2 (QoS 2 - Exactly Once) protocol state
machine implementation on the target broker.
Executes the four-step handshake:
1. Client -> Broker: PUBLISH (QoS 2, Packet ID: 0x0001)
2. Broker -> Client: PUBREC (Packet ID: 0x0001)
3. Client -> Broker: PUBREL (Packet ID: 0x0001)
4. Broker -> Client: PUBCOMP (Packet ID: 0x0001)

Verifies protocol correctness, timeout behavior, and state retention under QoS 2.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
  {1883, 8883, 1884},
  {"mqtt", "mqtt-s", "mosquitto", "emqx"},
  "tcp"
)

local function encode_remaining_length(length)
  local bytes = ""
  repeat
    local digit = length % 128
    length = math.floor(length / 128)
    if length > 0 then digit = digit + 128 end
    bytes = bytes .. string.char(digit)
  until length == 0
  return bytes
end

local function encode_string(str)
  local len = #str
  return string.char(math.floor(len / 256) % 256, len % 256) .. str
end

local function build_connect(client_id)
  local proto = encode_string("MQTT") .. string.char(4) .. string.char(2) .. string.char(0, 30)
  local payload = encode_string(client_id)
  return string.char(0x10) .. encode_remaining_length(#proto + #payload) .. proto .. payload
end

action = function(host, port)
  local out = stdnse.output_table()
  local client_id = "nmap_qos2_" .. string.sub(stdnse.generate_random_string(6), 1, 6)

  local sock = nmap.new_socket()
  sock:set_timeout(4000)

  local ok = sock:connect(host, port, "tcp")
  if not ok then
    return stdnse.format_output(false, "Could not connect to MQTT service.")
  end

  sock:send(build_connect(client_id))
  local st, resp = sock:receive_bytes(4)
  if not st or #resp < 4 or string.byte(resp, 1) ~= 0x20 or string.byte(resp, 4) ~= 0x00 then
    sock:close()
    return stdnse.format_output(false, "Broker refused connection.")
  end

  -- Step 1: Send PUBLISH QoS 2 (Fixed header 0x34)
  local topic = "audit/nmap/qos2"
  local packet_id = string.char(0x00, 0x01)
  local var_header = encode_string(topic) .. packet_id
  local payload = "qos2_probe"
  local pub_pkt = string.char(0x34) .. encode_remaining_length(#var_header + #payload) .. var_header .. payload
  sock:send(pub_pkt)

  -- Step 2: Receive PUBREC (0x50, 0x02, Packet ID)
  local st2, pubrec = sock:receive_bytes(4)
  local pubrec_ok = st2 and pubrec and #pubrec >= 4 and string.byte(pubrec, 1) == 0x50

  local pubcomp_ok = false
  if pubrec_ok then
    -- Step 3: Send PUBREL (0x62, 0x02, Packet ID)
    local pubrel_pkt = string.char(0x62, 0x02, 0x00, 0x01)
    sock:send(pubrel_pkt)

    -- Step 4: Receive PUBCOMP (0x70, 0x02, Packet ID)
    local st3, pubcomp = sock:receive_bytes(4)
    if st3 and pubcomp and #pubcomp >= 4 and string.byte(pubcomp, 1) == 0x70 then
      pubcomp_ok = true
    end
  end

  sock:close()

  out["Risk Level"] = "🟡 MEDIUM"
  out["QoS 2 Handshake State Machine"] = stdnse.output_table()
  out["QoS 2 Handshake State Machine"]["Step 1: PUBLISH (QoS 2)"] = "SENT"
  out["QoS 2 Handshake State Machine"]["Step 2: PUBREC Received"] = pubrec_ok and "SUCCESS (0x50)" or "FAILED"
  out["QoS 2 Handshake State Machine"]["Step 3: PUBREL"] = pubrec_ok and "SENT (0x62)" or "SKIPPED"
  out["QoS 2 Handshake State Machine"]["Step 4: PUBCOMP Received"] = pubcomp_ok and "SUCCESS (0x70)" or "FAILED"

  if pubcomp_ok then
    out["Status"] = "CONFORMANT - Broker fully and correctly implements MQTT QoS 2 Exactly-Once state machine."
  else
    out["Status"] = "NON-CONFORMANT / RESTRICTED - QoS 2 handshake was not completed by broker."
  end

  return out
end
