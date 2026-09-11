/**
 * Cyber Threat Dataset for Unidirectional IP Traffic (Physical Data Diode Gateway)
 * Realistic SCADA/ICS, IoT, Military & Industrial Enclave Threat Profiles.
 */

const THREAT_DATABASE = {
  NORMAL_TELEMETRY: {
    id: "NORM-104",
    name: "Normal SCADA Sensor Telemetry",
    category: "Legitimate Baseline",
    severity: "Low",
    protocol: "UDP",
    srcIp: "192.168.10.45",
    dstIp: "10.0.4.120",
    srcPort: 50201,
    dstPort: 502,
    service: "Modbus-UDP / Enclave Telemetry",
    threatScore: 6,
    confidence: 99.4,
    entropy: 3.12,
    payloadSize: 64,
    iatVariance: 0.04, // Regular 100ms periodic timing
    modbusFunction: "0x04 (Read Input Registers)",
    description: "Standard unidirectional SCADA sensor report (temperature, turbine RPM, valve pressure) transmitted from external plant monitoring station to isolated SCADA historian.",
    payloadHex: "00 01 00 00 00 06 01 04 00 10 00 04 43 7a 00 00 41 20 00 00 44 9a 00 00 00 00 00 00 5f 7b 3a 92",
    payloadAscii: "......Cz..A ..D......._{:.",
    headers: {
      l2: { name: "Ethernet II", srcMac: "00:1A:2B:3C:4D:5E", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "192.168.10.45", dstIp: "10.0.4.120", ttl: 64, protocol: "17 (UDP)", length: 84, checksum: "0x4A21", flags: "DF (Don't Fragment)" },
      l4: { name: "UDP Header", srcPort: 50201, dstPort: 502, length: 64, checksum: "0x1A4F" },
      l7: { name: "Modbus-UDP", transId: "0x0001", protoId: "0x0000", unitId: "1", functionCode: "0x04 (Read Input Registers)", registerStart: "0x0010", registerCount: "4" }
    },
    xaiFeatures: [
      { name: "Payload Shannon Entropy", value: "3.12 bits/B", impact: "Normal Structured Data", weight: 4, color: "#10b981" },
      { name: "Inter-Arrival Jitter (IAT)", value: "0.04s (Regular 100ms)", impact: "Predictable Sensor Pulse", weight: 3, color: "#10b981" },
      { name: "Modbus Protocol Heuristic", value: "Read-Only 0x04", impact: "Allowed Telemetry Rule", weight: 2, color: "#10b981" },
      { name: "Volumetric Rate", value: "10 pkts/sec", impact: "Within Baseline (Max 100)", weight: 3, color: "#10b981" }
    ],
    explanation: "Traffic matches normal baseline profile. Read-only Modbus function code over UDP with low entropy (3.12) and steady 100ms periodic timing typical of industrial sensor telemetry.",
    recommendedActions: [
      { action: "ALLOW_AND_LOG", title: "Allow & Log to Secure Historian", desc: "Forward packet through RX photodiode buffer to the internal isolated database." }
    ]
  },

  SCADA_INJECTION: {
    id: "ATK-MODBUS-09",
    name: "Blind SCADA Modbus Command Injection",
    category: "SCADA / ICS Tampering",
    severity: "Critical",
    protocol: "UDP",
    srcIp: "192.168.10.198",
    dstIp: "10.0.4.15",
    srcPort: 49152,
    dstPort: 502,
    service: "Modbus-UDP / Unit 1 Reactor Control",
    threatScore: 96,
    confidence: 98.2,
    entropy: 4.88,
    payloadSize: 84,
    iatVariance: 0.12,
    modbusFunction: "0x10 (Write Multiple Registers - Overwrite Setpoint)",
    description: "Malicious adversary injecting blind unauthorized write commands across the unidirectional gateway to force PLC cooling valves to 0% override, exploiting the lack of return ACKs.",
    payloadHex: "00 4b 00 00 00 11 01 10 00 01 00 04 08 00 00 00 00 00 00 7f ff 21 44 49 4f 44 45 5f 4f 56 52 44",
    payloadAscii: ".K...............!..DIODE_OVRD",
    headers: {
      l2: { name: "Ethernet II", srcMac: "E4:5D:51:7A:88:12", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "192.168.10.198", dstIp: "10.0.4.15", ttl: 58, protocol: "17 (UDP)", length: 104, checksum: "0xB39E", flags: "DF" },
      l4: { name: "UDP Header", srcPort: 49152, dstPort: 502, length: 84, checksum: "0x89C2" },
      l7: { name: "Modbus-UDP", transId: "0x004B", protoId: "0x0000", unitId: "1", functionCode: "0x10 (Write Multiple Registers)", registerStart: "0x0001 (Setpoint)", registerCount: "4", dataPayload: "0x7FFF (Max Override)" }
    },
    xaiFeatures: [
      { name: "Prohibited Modbus Function", value: "0x10 (Write Multiple)", impact: "Severe Violation", weight: 44, color: "#f43f5e" },
      { name: "Target Memory Region", value: "Holding Register 0x0001", impact: "Safety Override Attempt", weight: 28, color: "#f43f5e" },
      { name: "Signature Marker", value: "DIODE_OVRD magic string", impact: "Known Exploit Signature", weight: 16, color: "#f59e0b" },
      { name: "Zero-Return Blind Tx", value: "No Handshake Validation", impact: "Asymmetric Attack Pattern", weight: 12, color: "#f43f5e" }
    ],
    explanation: "AI Neural Gateway intercepted an unauthorized Modbus Write Multiple Registers command (0x10) targeting critical safety PLC registers. In a physical diode setup, blind writes risk immediate kinetic harm.",
    recommendedActions: [
      { action: "ISOLATE_RX_QUEUE", title: "Emergency Drop at RX Buffer", desc: "Instantly drop packet at RX photodiode interface before it reaches the internal SCADA switch." },
      { action: "TRIGGER_OPTICAL_SHUTTER", title: "Engage Physical Optical Shutter", desc: "Mechanically block 850nm laser beam to physically sever the unidirectional link." },
      { action: "ALERT_SOC_CRITICAL", title: "Dispatch Tier-3 Industrial CERT Alert", desc: "Notify Plant Safety Operations Center and Incident Response Team immediately." }
    ]
  },

  COVERT_TIMING: {
    id: "ATK-TIMING-33",
    name: "Covert Timing Channel Exfiltration",
    category: "Covert Channel",
    severity: "High",
    protocol: "UDP",
    srcIp: "192.168.10.77",
    dstIp: "10.0.4.99",
    srcPort: 38291,
    dstPort: 514,
    service: "Syslog-UDP Tunnel",
    threatScore: 89,
    confidence: 94.1,
    entropy: 4.10,
    payloadSize: 128,
    iatVariance: 3.94, // Artificial bimodal delay variance encoding binary bits!
    modbusFunction: "N/A (Encapsulated Syslog)",
    description: "Adversary exfiltrates confidential credentials across the diode by manipulating inter-packet arrival times (IPAT) to encode binary bits (e.g. 20ms = 0, 100ms = 1).",
    payloadHex: "3c 31 34 3e 53 45 43 55 52 49 54 59 5f 4c 4f 47 3a 20 53 79 73 74 65 6d 20 4f 4b 20 54 49 4d 45",
    payloadAscii: "<14>SECURITY_LOG: System OK TIME",
    headers: {
      l2: { name: "Ethernet II", srcMac: "52:54:00:12:34:56", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "192.168.10.77", dstIp: "10.0.4.99", ttl: 61, protocol: "17 (UDP)", length: 148, checksum: "0x78D1", flags: "DF" },
      l4: { name: "UDP Header", srcPort: 38291, dstPort: 514, length: 128, checksum: "0x44F0" },
      l7: { name: "Syslog Protocol", facility: "1 (User)", severity: "6 (Info)", msg: "SECURITY_LOG: System OK TIME" }
    },
    xaiFeatures: [
      { name: "Inter-Arrival Jitter (IAT)", value: "Bimodal Distribution (Δt=20ms/100ms)", impact: "Covert Bit Modulation", weight: 42, color: "#f43f5e" },
      { name: "Kolmogorov-Smirnov Test", value: "D-stat = 0.84 (p < 0.001)", impact: "Non-Random Artificial Jitter", weight: 32, color: "#f43f5e" },
      { name: "Payload Masquerade", value: "Legitimate Syslog Form", impact: "Stealth DPI Evasion", weight: 15, color: "#f59e0b" },
      { name: "Channel Bandwidth Est.", value: "48 bps covert leak rate", impact: "Active Exfiltration", weight: 11, color: "#f43f5e" }
    ],
    explanation: "AI Statistical Timing Classifier identified artificial bimodality in packet arrival delays. While packet content mimics benign syslog, the timing variance reveals an active covert exfiltration channel.",
    recommendedActions: [
      { action: "INJECT_TIMING_JITTER", title: "Enable Jitter Buffer Scrambling", desc: "Pass unidirectional stream through a random delay queue to disrupt covert timing synchronization." },
      { action: "QUARANTINE_SRC", title: "Quarantine Source Ingress IP", desc: "Block sender 192.168.10.77 at external aggregation switch." }
    ]
  },

  HIGH_ENTROPY_EXFIL: {
    id: "ATK-EXFIL-72",
    name: "High-Entropy Encrypted Data Exfiltration",
    category: "Data Exfiltration",
    severity: "High",
    protocol: "UDP",
    srcIp: "192.168.10.112",
    dstIp: "10.0.4.55",
    srcPort: 58210,
    dstPort: 9001,
    service: "Raw UDP Custom Tunnel",
    threatScore: 92,
    confidence: 96.5,
    entropy: 7.94, // Max entropy is 8.0 bits/byte!
    payloadSize: 1024,
    iatVariance: 0.18,
    modbusFunction: "N/A (Raw Binary)",
    description: "Adversary smuggling encrypted archive (AES-256 / compressed CAD blueprints) disguised inside custom UDP telemetry packets across the unidirectional gateway.",
    payloadHex: "7e a8 12 9c 54 f3 d0 41 89 e2 33 b1 fe a5 77 19 c0 34 8f 2e 9a d4 e7 11 88 c5 3d 72 b9 0f 6e 4a",
    payloadAscii: "~...T..A..3...w..4......=.r..nJ",
    headers: {
      l2: { name: "Ethernet II", srcMac: "A8:20:66:44:11:00", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "192.168.10.112", dstIp: "10.0.4.55", ttl: 64, protocol: "17 (UDP)", length: 1044, checksum: "0x12DF", flags: "DF" },
      l4: { name: "UDP Header", srcPort: 58210, dstPort: 9001, length: 1024, checksum: "0xFA22" },
      l7: { name: "Unidentified Binary Payload", magicBytes: "0x7EA8129C", entropyScore: "7.94 bits/byte" }
    },
    xaiFeatures: [
      { name: "Shannon Entropy", value: "7.94 / 8.00 bits/B", impact: "Cryptographic / Compressed High Randomness", weight: 48, color: "#f43f5e" },
      { name: "Payload Size Anomaly", value: "1024 Bytes (Max MTU)", impact: "Volumetric High Density", weight: 26, color: "#f59e0b" },
      { name: "Unrecognized L7 Protocol", value: "Non-Whitelisted Port 9001", impact: "Zero-Day Tunnel Risk", weight: 22, color: "#f43f5e" }
    ],
    explanation: "Shannon Entropy calculation measured 7.94 bits/byte (baseline is <4.5 for SCADA). Uncompressed industrial telemetry never exhibits cryptographic randomness, confirming illegal data exfiltration.",
    recommendedActions: [
      { action: "DROP_HIGH_ENTROPY", title: "Drop High-Entropy Payloads", desc: "Discard all packets exceeding entropy ceiling of 5.5 bits/byte." },
      { action: "FORENSIC_CAPTURE", title: "Mirror to Forensic Decryption Sandbox", desc: "Dump byte stream to offline enclave storage for cryptanalysis." }
    ]
  },

  VOLUMETRIC_FLOOD: {
    id: "ATK-FLOOD-88",
    name: "Unidirectional UDP Volumetric Photodiode Flood",
    category: "Denial of Service (DoS)",
    severity: "Critical",
    protocol: "UDP",
    srcIp: "192.168.10.201",
    dstIp: "10.0.4.254",
    srcPort: 63102,
    dstPort: 53,
    service: "DNS-Amplified Flood Stream",
    threatScore: 95,
    confidence: 99.1,
    entropy: 4.62,
    payloadSize: 1472,
    iatVariance: 0.001, // Extremely rapid bursts (1ms interval)
    modbusFunction: "N/A (DNS/UDP Burst)",
    description: "High-rate packet flood attempting to exhaust the RX photodiode FIFO buffer, causing packet drop and blind desynchronization of internal critical monitoring systems.",
    payloadHex: "00 00 01 00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 ff 00 01 20 20 20",
    payloadAscii: ".............example.com....   ",
    headers: {
      l2: { name: "Ethernet II", srcMac: "DE:AD:BE:EF:00:01", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "192.168.10.201", dstIp: "10.0.4.254", ttl: 128, protocol: "17 (UDP)", length: 1492, checksum: "0x9810", flags: "MF (More Fragments)" },
      l4: { name: "UDP Header", srcPort: 63102, dstPort: 53, length: 1472, checksum: "0x0000" },
      l7: { name: "DNS Query Flood", queryType: "ANY (*)", queryTarget: "example.com" }
    },
    xaiFeatures: [
      { name: "Burst Packet Velocity", value: "24,000 pkts/sec", impact: "Buffer Overrun Hazard", weight: 46, color: "#f43f5e" },
      { name: "MTU Max Size", value: "1472 Payload Bytes", impact: "Bandwidth Saturation", weight: 28, color: "#f43f5e" },
      { name: "Inter-Arrival Rate", value: "<0.001s Burst Rate", impact: "Micro-Burst Flood", weight: 24, color: "#f43f5e" }
    ],
    explanation: "Volumetric rate exceeded 20,000 packets/sec, saturating the optical receiver ring buffer. The physical diode allows no TCP flow control (backpressure), making hardware FIFO buffer protection vital.",
    recommendedActions: [
      { action: "RATE_LIMIT_INGRESS", title: "Enforce Hardware Token Bucket", desc: "Throttle ingress laser power switch to enforce a strict 1,000 pkt/sec cap." },
      { action: "ENGAGE_SHUTTER", title: "Trigger Optical Shutter Cutoff", desc: "Sever the laser link to protect downstream historian servers." }
    ]
  },

  MALFORMED_HEADER: {
    id: "ATK-HEADER-19",
    name: "Malformed IPv4 Header & Protocol Smuggling",
    category: "Protocol Violation",
    severity: "Medium",
    protocol: "Raw IP",
    srcIp: "192.168.10.33",
    dstIp: "10.0.4.10",
    srcPort: 0,
    dstPort: 0,
    service: "Custom Raw IP Smuggling",
    threatScore: 78,
    confidence: 91.7,
    entropy: 5.14,
    payloadSize: 96,
    iatVariance: 0.25,
    modbusFunction: "N/A",
    description: "Illegal IP header options and invalid protocol number (Proto 254) attempting to exploit parser vulnerabilities inside the receiving FPGA/host operating system.",
    payloadHex: "45 00 00 60 1c 46 40 00 40 fe d9 c1 c0 a8 0a 21 0a 00 04 0a 99 88 77 66 55 44 33 22 11 00 ff ee",
    payloadAscii: "E..`.F@.@......!......wfUD3\"....",
    headers: {
      l2: { name: "Ethernet II", srcMac: "00:11:22:33:44:55", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "192.168.10.33", dstIp: "10.0.4.10", ttl: 64, protocol: "254 (Experimental/Smuggling)", length: 96, checksum: "0xD9C1", flags: "Reserved bit set" },
      l4: { name: "Raw Layer 4", status: "Invalid Protocol Header" },
      l7: { name: "Raw Smuggled Bytecode", payloadLength: 96 }
    },
    xaiFeatures: [
      { name: "Undefined Protocol Number", value: "IP Proto 254", impact: "RFC Compliance Failure", weight: 45, color: "#f43f5e" },
      { name: "Header Flag Violation", value: "Reserved 'Evil' Bit Set", impact: "Malformed Header", weight: 35, color: "#f59e0b" },
      { name: "Zero Port Numbers", value: "Port 0 / Invalid L4", impact: "Parser Desync Attempt", weight: 20, color: "#f43f5e" }
    ],
    explanation: "Packet uses invalid IP Protocol 254 and illegal reserved bit flags. In a unidirectional gateway, malformed packets are weaponized to crash the RX decoder since no ICMP error can be returned.",
    recommendedActions: [
      { action: "STRICT_RFC_DROP", title: "Enforce Strict RFC IP Validation", desc: "Drop non-standard protocols before passing to destination network." },
      { action: "PATCH_FPGA_PARSER", title: "Verify FPGA Framing Logic", desc: "Ensure hardware photodiode driver ignores invalid frames." }
    ]
  },

  DDOS_AMPLIFICATION: {
    id: "ATK-DDOS-01",
    name: "DDoS Amplification Flood",
    category: "DDoS",
    severity: "Critical",
    protocol: "UDP",
    srcIp: "10.20.14.8",
    dstIp: "10.0.4.15",
    srcPort: 45231,
    dstPort: 443,
    service: "UDP Flood / Ingress Diode Saturation",
    threatScore: 97,
    confidence: 97.3,
    entropy: 6.82,
    payloadSize: 1420,
    iatVariance: 0.002,
    modbusFunction: "N/A",
    description: "Distributed reflective UDP amplification flood flooding the ingress optical photodiode at 29,400 packets/sec to cause catastrophic FIFO queue loss.",
    payloadHex: "ff ff ff ff 54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 00 2a 2a 2a 2a 2a 2a 2a",
    payloadAscii: "....TSource Engine Query.*******",
    headers: {
      l2: { name: "Ethernet II", srcMac: "52:54:00:12:34:56", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "10.20.14.8", dstIp: "10.0.4.15", ttl: 48, protocol: "17 (UDP)", length: 1448, checksum: "0x7F10", flags: "DF" },
      l4: { name: "UDP Header", srcPort: 45231, dstPort: 443, length: 1428, checksum: "0x22C1" },
      l7: { name: "Amplified Reflection Stream", floodRate: "29.4k pps", burstVolume: "364 Mbps" }
    },
    xaiFeatures: [
      { name: "Extreme Packet Rate", value: "29,432 pkts/sec", impact: "Buffer Exhaustion", weight: 48, color: "#f43f5e" },
      { name: "Throughput Surge", value: "364 Mbps", impact: "Line Rate Saturation", weight: 32, color: "#f43f5e" },
      { name: "Single Destination Concentration", value: "99.8% to 10.0.4.15", impact: "Targeted DoS", weight: 24, color: "#f43f5e" },
      { name: "Baseline Deviation", value: "+840% above norm", impact: "Massive Anomaly", weight: 20, color: "#f59e0b" }
    ],
    whyFlagged: [
      "✓ High packet rate (>25,000 pkts/sec)",
      "✓ High flow frequency and micro-bursting",
      "✓ Unusual destination concentration (10.0.4.15)",
      "✓ Abnormal packet-size distribution (1420B jumbo)",
      "✓ Large deviation from learned baseline (+840%)"
    ],
    dnsIntel: { domain: "amp-reflector.ntp-pool.net", queryType: "ANY", responseIp: "10.20.14.8", queryCount: 2840, dgaScore: 0.12, anomaly: "CRITICAL FLOOD" },
    tlsMetadata: { version: "N/A (Raw UDP Flood)", sni: "N/A", ja3: "none", ja3s: "none", ja4: "none", cipher: "Plaintext UDP", payloadStatus: "RAW PACKET FLOOD" },
    quicMetadata: { version: "None", cid: "N/A", packetStats: "29.4k pkts/s", status: "Unconnected Flood" },
    geo: { country: "India", region: "Gujarat", city: "Ahmedabad", isp: "Enterprise Fiber Hub", confidence: "LOW / ESTIMATE", disclaimer: "Approximate IP-based geolocation. Traffic may be spoofed or relayed via upstream transit." },
    behavior: { flows: 1420, packets: 182940, bytes: "248.5 MB", pps: 29432, bps: "364 Mbps", avgDuration: "71.4 sec", burstRate: "EXTREME", anomalyScore: 0.98 },
    explanation: "DDoS amplification flood targeting destination 10.0.4.15 across unidirectional photodiode. Because unidirectional gateways provide no backchannel TCP feedback, volumetric flood causes hardware buffer loss.",
    recommendedActions: [
      { action: "RATE_LIMIT", title: "Enforce Hardware Rate Limiter", desc: "Cap ingress UDP bandwidth at 50 Mbps." },
      { action: "ENGAGE_SHUTTER", title: "Engage Optical Shutter", desc: "Drop physical shutter to isolate high-security enclave." }
    ]
  },

  PORT_SCAN: {
    id: "ATK-SCAN-04",
    name: "Asymmetric Port & Subnet Sweep",
    category: "Scan",
    severity: "High",
    protocol: "TCP SYN / UDP Probe",
    srcIp: "10.12.4.21",
    dstIp: "10.0.4.18",
    srcPort: 54102,
    dstPort: 80,
    service: "Horizontal Port Reconnaissance",
    threatScore: 88,
    confidence: 94.2,
    entropy: 4.12,
    payloadSize: 40,
    iatVariance: 0.005,
    modbusFunction: "N/A",
    description: "Rapid systematic port scan probing ports 21, 22, 80, 443, 502, 102, 44818. Adversary receives no SYN-ACK return due to diode physics, but sends speculative probes.",
    payloadHex: "00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 00 28 12 34 40 00 40 06 b3 44 0a 0c 04 15 0a 00",
    payloadAscii: "..............E..(.4@.@..D......",
    headers: {
      l2: { name: "Ethernet II", srcMac: "00:0C:29:84:1A:FE", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "10.12.4.21", dstIp: "10.0.4.18", ttl: 64, protocol: "6 (TCP SYN)", length: 40, checksum: "0xB344", flags: "SYN Only" },
      l4: { name: "TCP Header", srcPort: 54102, dstPort: 80, seqNum: "0x3841A01", flags: "SYN (No ACK Expected)" }
    },
    xaiFeatures: [
      { name: "Port Dispersal Frequency", value: "240 Unique Ports/sec", impact: "Recon Sweep Pattern", weight: 44, color: "#f59e0b" },
      { name: "Zero ACK Expectation", value: "Blind SYN Flood", impact: "Asymmetric Scanning", weight: 30, color: "#f59e0b" },
      { name: "Low Payload Size", value: "40 Bytes per Probe", impact: "Header-Only Probing", weight: 18, color: "#f59e0b" }
    ],
    whyFlagged: [
      "✓ High flow frequency across multiple port targets",
      "✓ Repeated connection attempts without handshakes",
      "✓ Abnormal destination port entropy (240 ports/min)",
      "✓ Zero application payload content"
    ],
    dnsIntel: { domain: "recon-node-04.local", queryType: "PTR", responseIp: "10.12.4.21", queryCount: 88, dgaScore: 0.15, anomaly: "SCAN PROBE" },
    tlsMetadata: { version: "N/A", sni: "N/A", ja3: "none", ja3s: "none", ja4: "none", cipher: "SYN Probe", payloadStatus: "UNENCRYPTED HEADERS" },
    quicMetadata: { version: "None", cid: "N/A", packetStats: "840 probes", status: "Scanning" },
    geo: { country: "India", region: "Karnataka", city: "Bengaluru", isp: "Cloud Transit Gateway", confidence: "LOW / ESTIMATE", disclaimer: "Approximate IP-based estimate from router BGP table." },
    behavior: { flows: 884, packets: 4210, bytes: "168.4 KB", pps: 340, bps: "108 Kbps", avgDuration: "1.1 sec", burstRate: "HIGH", anomalyScore: 0.88 },
    explanation: "Attacker attempting horizontal port enumeration across the diode gateway. Even though unidirectional diodes block return traffic, blind probes can trigger PLC state anomalies.",
    recommendedActions: [
      { action: "DROP_SYN", title: "Drop Ingress SYN without Pre-Auth", desc: "Filter unauthorized TCP SYN packets." }
    ]
  },

  C2_BEACON: {
    id: "ATK-C2-07",
    name: "Command & Control (C2) Periodic Beacon",
    category: "C2",
    severity: "High",
    protocol: "UDP / Encrypted",
    srcIp: "172.16.8.44",
    dstIp: "10.0.4.55",
    srcPort: 49812,
    dstPort: 8443,
    service: "Encrypted C2 Channel / Blind Beacon",
    threatScore: 91,
    confidence: 91.5,
    entropy: 7.74,
    payloadSize: 256,
    iatVariance: 0.015,
    modbusFunction: "N/A",
    description: "Strict periodic heartbeat pulse every exactly 5.00s transmitting encrypted instructions into internal enclave, bypassing traditional stateful firewalls.",
    payloadHex: "17 03 03 01 00 2a b8 91 4f 01 c2 99 d4 e5 88 12 77 90 fa 1b bc de ad be ef 00 11 22 33 44 55 66",
    payloadAscii: ".....*..O.....w........\"3DUf",
    headers: {
      l2: { name: "Ethernet II", srcMac: "00:50:56:A1:B2:C3", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "172.16.8.44", dstIp: "10.0.4.55", ttl: 54, protocol: "17 (UDP)", length: 284, checksum: "0x4C90", flags: "DF" },
      l4: { name: "UDP Header", srcPort: 49812, dstPort: 8443, length: 264, checksum: "0x88AA" },
      l7: { name: "Encrypted C2 Frame", beaconInterval: "5.000s exact", entropy: "7.74 bits/B" }
    },
    xaiFeatures: [
      { name: "Deterministic Periodicity", value: "Exact 5.00s Interval", impact: "Heartbeat Beacon Signature", weight: 46, color: "#f43f5e" },
      { name: "High Shannon Entropy", value: "7.74 bits/Byte", impact: "Encrypted Payload", weight: 30, color: "#f59e0b" },
      { name: "Non-Standard Port", value: "Port 8443 UDP", impact: "Policy Deviation", weight: 20, color: "#f59e0b" }
    ],
    whyFlagged: [
      "✓ Abnormal inter-arrival time (Deterministic 5.000s beacon)",
      "✓ High Shannon entropy (7.74 bits/B)",
      "✓ Deviation from learned ICS sensor baseline",
      "✓ Non-standard protocol mapping (UDP/8443)"
    ],
    dnsIntel: { domain: "beacon-sync.darkops-c2.org", queryType: "A", responseIp: "172.16.8.44", queryCount: 176, dgaScore: 0.89, anomaly: "C2 BEACON" },
    tlsMetadata: { version: "TLS 1.3", sni: "beacon-sync.darkops-c2.org", ja3: "e7d705a328636224e7fb39214e66b4b4", ja3s: "a95ca7e0234032a39281a02b4e88ff12", ja4: "t13d1516h2_8daaf6152771_b4b3f81e2891", cipher: "TLS_CHACHA20_POLY1305_SHA256", payloadStatus: "🔒 ENCRYPTED" },
    quicMetadata: { version: "None", cid: "N/A", packetStats: "420 beacons", status: "Heartbeat Active" },
    geo: { country: "India", region: "Delhi", city: "New Delhi", isp: "National Backbone Transit", confidence: "LOW / ESTIMATE", disclaimer: "Approximate IP-based estimate. Subject to routing tunnels." },
    behavior: { flows: 420, packets: 1260, bytes: "354.2 KB", pps: 4.2, bps: "9.4 Kbps", avgDuration: "5.0 sec", burstRate: "PERIODIC", anomalyScore: 0.91 },
    explanation: "Periodic C2 beaconing detected over unidirectional stream. Machine learning classifier detected exact 5.00s inter-arrival time signature with high entropy (7.74) typical of covert malware command channels.",
    recommendedActions: [
      { action: "ISOLATE_DST", title: "Airgap Quarantine Host 10.0.4.55", desc: "Isolate destination host from internal SCADA bus." }
    ]
  },

  DGA_DNS: {
    id: "ATK-DGA-11",
    name: "DGA / Algorithmic DNS Tunneling",
    category: "DGA/DNS",
    severity: "High",
    protocol: "DNS over UDP",
    srcIp: "192.168.3.77",
    dstIp: "10.0.4.2",
    srcPort: 58210,
    dstPort: 53,
    service: "DNS Query Stream",
    threatScore: 86,
    confidence: 89.6,
    entropy: 6.95,
    payloadSize: 110,
    iatVariance: 0.18,
    modbusFunction: "N/A",
    description: "Algorithmic pseudo-random domain generation (DGA) encoding binary data inside DNS labels to bypass unidirectional content filters.",
    payloadHex: "00 1a 01 00 00 01 00 00 00 00 00 00 13 78 6a 39 34 66 32 30 62 61 71 39 38 7a 71 31 39 30 07 65",
    payloadAscii: ".............xj94f20baq98zq190.e",
    headers: {
      l2: { name: "Ethernet II", srcMac: "00:1A:2B:EE:FF:11", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "192.168.3.77", dstIp: "10.0.4.2", ttl: 60, protocol: "17 (UDP)", length: 138, checksum: "0x6A19", flags: "DF" },
      l4: { name: "UDP Header", srcPort: 58210, dstPort: 53, length: 118, checksum: "0x918F" },
      l7: { name: "DNS Query", domain: "xj94f20baq98zq190.exfil-cluster.net", recordType: "TXT" }
    },
    xaiFeatures: [
      { name: "Domain Consonant-Vowel Entropy", value: "4.82 n-gram entropy", impact: "DGA Algorithm Pattern", weight: 48, color: "#f43f5e" },
      { name: "TXT Query Frequency", value: "140 TXT pkts/min", impact: "DNS Tunneling Indicator", weight: 32, color: "#f59e0b" },
      { name: "Label Length Anomaly", value: "32 chars / label", impact: "Data Smuggling Pattern", weight: 20, color: "#f59e0b" }
    ],
    whyFlagged: [
      "✓ High domain label character entropy (4.82 bits)",
      "✓ High frequency of TXT / NULL record queries",
      "✓ Known DGA Markov chain anomaly score > 0.85",
      "✓ Deviation from benign sensor hostname baseline"
    ],
    dnsIntel: { domain: "xj94f20baq98zq190.exfil-cluster.net", queryType: "TXT", responseIp: "185.220.101.5", queryCount: 294, dgaScore: 0.94, anomaly: "HIGH DGA" },
    tlsMetadata: { version: "N/A", sni: "N/A", ja3: "none", ja3s: "none", ja4: "none", cipher: "Plain DNS", payloadStatus: "UNENCRYPTED LABELS" },
    quicMetadata: { version: "None", cid: "N/A", packetStats: "294 queries", status: "Active Queries" },
    geo: { country: "India", region: "Tamil Nadu", city: "Chennai", isp: "Coastal Gateway Telemetry", confidence: "LOW / ESTIMATE", disclaimer: "Approximate IP-based estimate." },
    behavior: { flows: 294, packets: 882, bytes: "97.4 KB", pps: 18.2, bps: "16.4 Kbps", avgDuration: "0.4 sec", burstRate: "MODERATE", anomalyScore: 0.86 },
    explanation: "DGA algorithmic DNS tunneling detected. Adversary encodes stolen system state into high-entropy randomized DNS subdomains transmitted through the diode.",
    recommendedActions: [
      { action: "BLOCK_DNS_TUNNEL", title: "Enforce Strict DNS Whitelist", desc: "Block non-whitelisted FQDNs at ingress parser." }
    ]
  },

  ENCRYPTED_MALWARE: {
    id: "ATK-MALWARE-18",
    name: "Encrypted Malware Delivery (Zero-Decryption Profiling)",
    category: "Encrypted Malware",
    severity: "Critical",
    protocol: "TLS 1.3 / QUIC",
    srcIp: "185.190.24.110",
    dstIp: "10.0.4.88",
    srcPort: 52140,
    dstPort: 443,
    service: "HTTPS / TLS 1.3 Tunnel",
    threatScore: 94,
    confidence: 93.8,
    entropy: 7.92,
    payloadSize: 1380,
    iatVariance: 0.08,
    modbusFunction: "N/A",
    description: "Encrypted exploit payload transmitted across optical diode. Inspected purely via TLS metadata, JA3/JA4 fingerprints, and packet timing without decrypting payload.",
    payloadHex: "16 03 01 02 00 01 00 01 fc 03 03 b2 19 4e 20 89 a1 77 fa 01 bc de 90 28 41 82 71 89 22 10 44 99",
    payloadAscii: "..........N ..w...(A.q.\".D.",
    headers: {
      l2: { name: "Ethernet II", srcMac: "00:22:44:66:88:AA", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "185.190.24.110", dstIp: "10.0.4.88", ttl: 51, protocol: "17 (UDP/QUIC)", length: 1420, checksum: "0x5E81", flags: "DF" },
      l4: { name: "QUIC/UDP Header", srcPort: 52140, dstPort: 443, length: 1400, checksum: "0x1133" },
      l7: { name: "TLS 1.3 Handshake Client Hello", ja3: "72c039320224b77e8a93e7d705a32863", ja4: "t13d1516h2_8daaf6152771_b4b3f81e2891" }
    },
    xaiFeatures: [
      { name: "Malicious JA3 Fingerprint", value: "72c0393202... (Cobalt Strike)", impact: "Known Threat Actor Signature", weight: 52, color: "#f43f5e" },
      { name: "High Entropy Stream", value: "7.92 bits/Byte", impact: "AES Encrypted Payload", weight: 26, color: "#f59e0b" },
      { name: "SNI / Cert Discrepancy", value: "Fake update.microsoft-service.cc", impact: "Typosquatting Masquerade", weight: 22, color: "#f43f5e" }
    ],
    whyFlagged: [
      "✓ JA3/JA4 fingerprint matches known Cobalt Strike / AsyncRAT profile",
      "✓ Extreme payload Shannon entropy (7.92 bits/B)",
      "✓ Suspicious SNI domain with recent registration",
      "✓ Uncharacteristic flow burst for unidirectional industrial diode"
    ],
    dnsIntel: { domain: "update.microsoft-service.cc", queryType: "A", responseIp: "185.190.24.110", queryCount: 64, dgaScore: 0.88, anomaly: "TYPOSQUAT MALWARE" },
    tlsMetadata: { version: "TLS 1.3", sni: "update.microsoft-service.cc", ja3: "72c039320224b77e8a93e7d705a32863", ja3s: "a95ca7e0234032a39281a02b4e88ff12", ja4: "t13d1516h2_8daaf6152771_b4b3f81e2891", cipher: "TLS_AES_256_GCM_SHA384", payloadStatus: "🔒 ENCRYPTED (Zero Decryption - Metadata Profiling Only)" },
    quicMetadata: { version: "QUIC v1 (RFC 9000)", cid: "9f018e44ba12", packetStats: "18,294 pkts, 14.2 MB", status: "Encrypted Stream" },
    geo: { country: "India", region: "West Bengal", city: "Kolkata", isp: "Industrial Gateway Node", confidence: "LOW / ESTIMATE", disclaimer: "Approximate IP-based estimate. Actual origin obscured by encrypted tunnel." },
    behavior: { flows: 182, packets: 18294, bytes: "14.2 MB", pps: 257, bps: "1.6 MB/s", avgDuration: "42.0 sec", burstRate: "HIGH", anomalyScore: 0.94 },
    explanation: "Encrypted malware delivery classified without decrypting application data. Fingerprinted via JA3 (72c03932...) and JA4 matching active threat actor campaigns targeting critical infrastructure.",
    recommendedActions: [
      { action: "DROP_JA3", title: "Block JA3 Fingerprint Hash", desc: "Drop all ingress traffic matching JA3 hash 72c03932..." },
      { action: "QUARANTINE_88", title: "Quarantine Host 10.0.4.88", desc: "Isolate host 10.0.4.88 from internal control network." }
    ]
  },

  EXFILTRATION: {
    id: "ATK-EXFIL-22",
    name: "Slow-Drip Encrypted Exfiltration",
    category: "Exfiltration",
    severity: "Critical",
    protocol: "UDP / Custom",
    srcIp: "192.168.3.77",
    dstIp: "10.0.4.77",
    srcPort: 60102,
    dstPort: 9001,
    service: "High-Entropy Exfil Stream",
    threatScore: 92,
    confidence: 88.9,
    entropy: 7.96,
    payloadSize: 512,
    iatVariance: 1.45,
    modbusFunction: "N/A",
    description: "Compressed and encrypted sensitive telemetry archives being smuggled out through one-way data diode via low-and-slow rate to evade volumetric threshold alarms.",
    payloadHex: "1f 8b 08 00 00 00 00 00 00 03 ed bd 07 60 1c 49 96 25 26 2f 6d ca 7b 7f 4e f0 19 82 89 2b 88 12",
    payloadAscii: "...........`..I.%&/m.{.N....+...",
    headers: {
      l2: { name: "Ethernet II", srcMac: "00:1A:2B:3C:4D:99", dstMac: "00:50:56:C0:00:08", etherType: "0x0800 (IPv4)" },
      l3: { name: "IPv4 Header", srcIp: "192.168.3.77", dstIp: "10.0.4.77", ttl: 64, protocol: "17 (UDP)", length: 540, checksum: "0x34AC", flags: "DF" },
      l4: { name: "UDP Header", srcPort: 60102, dstPort: 9001, length: 520, checksum: "0x7788" },
      l7: { name: "GZIP Archive Header", magic: "0x1F8B (GZIP)", entropy: "7.96 bits/B" }
    },
    xaiFeatures: [
      { name: "Max Shannon Entropy", value: "7.96 bits/Byte", impact: "Encrypted Archive Smuggling", weight: 50, color: "#f43f5e" },
      { name: "Magic Byte Header", value: "0x1F8B (GZIP Stream)", impact: "Archive File Sign", weight: 28, color: "#f43f5e" },
      { name: "Low-and-Slow Timing", value: "1.45s Jitter Pattern", impact: "Evasion Technique", weight: 22, color: "#f59e0b" }
    ],
    whyFlagged: [
      "✓ Maximum Shannon entropy (7.96 / 8.00 bits/B)",
      "✓ Compressed/encrypted file signature (0x1F8B GZIP)",
      "✓ Abnormal byte-to-packet ratio",
      "✓ Timing evasion: low burst rate spread over 2 hours"
    ],
    dnsIntel: { domain: "exfil-drop.darknet-relay.to", queryType: "A", responseIp: "192.168.3.77", queryCount: 92, dgaScore: 0.91, anomaly: "DATA EXFIL" },
    tlsMetadata: { version: "Custom Encrypted", sni: "exfil-drop.darknet-relay.to", ja3: "3b5074b1b3f1e1a4d6f8e7d705a32863", ja3s: "none", ja4: "t13d1516h2_custom", cipher: "AES-256-CBC Encrypted", payloadStatus: "🔒 ENCRYPTED (Preserves Privacy / Heuristic Detection)" },
    quicMetadata: { version: "None", cid: "N/A", packetStats: "1,240 pkts", status: "Exfiltration Stream" },
    geo: { country: "India", region: "Telangana", city: "Hyderabad", isp: "Cyber Cyber Hub Transit", confidence: "LOW / ESTIMATE", disclaimer: "Approximate IP-based estimate." },
    behavior: { flows: 142, packets: 6840, bytes: "3.4 MB", pps: 24, bps: "128 Kbps", avgDuration: "84 sec", burstRate: "LOW-AND-SLOW", anomalyScore: 0.92 },
    explanation: "Data exfiltration detected across unidirectional gateway. Despite lacking return ACK channels, attacker uses UDP streaming with high entropy (7.96) and GZIP signatures to extract intellectual property.",
    recommendedActions: [
      { action: "TRIGGER_SHUTTER", title: "Emergency Laser Shutter Sever", desc: "Drop optical shutter immediately to stop data leakage." }
    ]
  }
};

/**
 * Top Suspicious Sources Table Data
 */
const SUSPICIOUS_SOURCES_DATA = [
  { ip: "10.20.14.8", threat: "DDoS", score: 98, flows: 1420, packets: 182940, bytes: "248.5 MB", firstSeen: "21:14:02", lastSeen: "21:27:53", key: "DDOS_AMPLIFICATION", status: "ACTIVE", evidence: "OBSERVED + AI PREDICTION" },
  { ip: "10.12.4.21", threat: "Scanner", score: 94, flows: 884, packets: 4210, bytes: "168.4 KB", firstSeen: "21:18:22", lastSeen: "21:27:45", key: "PORT_SCAN", status: "ACTIVE", evidence: "OBSERVED + AI PREDICTION" },
  { ip: "172.16.8.44", threat: "C2", score: 91, flows: 420, packets: 1260, bytes: "354.2 KB", firstSeen: "20:55:10", lastSeen: "21:27:50", key: "C2_BEACON", status: "MONITORED", evidence: "OBSERVED + AI PREDICTION" },
  { ip: "192.168.3.77", threat: "Exfil", score: 87, flows: 142, packets: 6840, bytes: "3.4 MB", firstSeen: "21:05:40", lastSeen: "21:27:12", key: "EXFILTRATION", status: "ACTIVE", evidence: "OBSERVED + AI PREDICTION" },
  { ip: "192.168.10.198", threat: "SCADA Injection", score: 96, flows: 423, packets: 18294, bytes: "14.2 MB", firstSeen: "21:26:42", lastSeen: "21:27:53", key: "SCADA_INJECTION", status: "CRITICAL", evidence: "OBSERVED + AI PREDICTION" },
  { ip: "185.190.24.110", threat: "Encrypted Malware", score: 94, flows: 182, packets: 18294, bytes: "14.2 MB", firstSeen: "21:22:15", lastSeen: "21:27:30", key: "ENCRYPTED_MALWARE", status: "ACTIVE", evidence: "OBSERVED + AI PREDICTION" }
];

/**
 * PCAP Replay Sample Capture Profiles
 */
const PCAP_PROFILES = [
  {
    id: "pcap-scada",
    name: "scada_modbus_unidirectional_attack.pcap",
    description: "Physical diode capture showing blind 0x10 register sabotage override with 1-way UDP traffic.",
    totalPackets: 1284392,
    durationSec: 180,
    dominantThreat: "SCADA_INJECTION",
    throughputMbps: 18.4,
    pps: 2840
  },
  {
    id: "pcap-ddos",
    name: "ddos_amplification_diode_flood.pcap",
    description: "High-volume UDP reflection flood saturating optical receiver queue at 29.4k pkts/sec.",
    totalPackets: 3840210,
    durationSec: 240,
    dominantThreat: "DDOS_AMPLIFICATION",
    throughputMbps: 364.0,
    pps: 29432
  },
  {
    id: "pcap-c2",
    name: "c2_covert_timing_exfiltration.pcap",
    description: "Subtle periodic timing jitter and encrypted exfiltration across physical data diode link.",
    totalPackets: 890450,
    durationSec: 300,
    dominantThreat: "C2_BEACON",
    throughputMbps: 4.2,
    pps: 820
  },
  {
    id: "pcap-mixed",
    name: "mixed_enterprise_unidirectional_capture.pcap",
    description: "Full enterprise enclave capture with SCADA telemetry, DNS queries, and multi-vector anomalies.",
    totalPackets: 5410980,
    durationSec: 600,
    dominantThreat: "ENCRYPTED_MALWARE",
    throughputMbps: 84.5,
    pps: 12400
  }
];

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { THREAT_DATABASE, SUSPICIOUS_SOURCES_DATA, PCAP_PROFILES };
}
