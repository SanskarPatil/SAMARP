# Real-traffic evidence: capture and evaluate

The jury review's top gap is that detection has only been measured on synthetic traffic. Two tested scripts turn
real captures into benchmark files:

| Script | Input | Answers |
|---|---|---|
| `scripts/evaluate.py --background X.pcap --address-plan P.yaml` | real **normal** traffic | false incidents per hour on real traffic (+ recall of synthetic attacks injected over it) |
| `scripts/evaluate_pcap.py --pcap X.pcap --labels X.labels.json --address-plan P.yaml` | a labelled capture from an isolated lab | recall / precision per PS class on that capture |

**Limit (stated in every report):** replay is header-only. DNS names and TLS / JA3 / JA4 are not parsed from raw
packets, so `dga`, `dns` and `tls_quic` see no input on a PCAP (NOT_OBSERVABLE, never "benign"). `scan`, `c2`,
`ddos`, `reflection` and `exfil` run on the real headers. A DNS / TLS metadata extractor (or Suricata EVE ingest)
is the step that closes this.

Captures contain payload bytes. `*.pcap` / `*.pcapng` are gitignored; only aggregated results (with the capture's
SHA-256) go into `benchmarks/`. Do not share or commit the capture.

## Part 1 - real normal traffic (Windows, 1-2 hours)

1. Install Wireshark (with Npcap) and capture on your active Wi-Fi / Ethernet interface while using the laptop
   normally (browsing, video, updates, cloud sync) for 1-2 hours.
2. **File -> Save As -> type `Wireshark/tcpdump/... - pcap`** (classic pcap, not pcapng) to
   `captures\home_normal.pcap`. Already pcapng? `"C:\Program Files\Wireshark\editcap.exe" -F pcap in.pcapng captures\home_normal.pcap`
3. `copy config\address_plan_home.example.yaml config\address_plan_home.yaml` and set `dns_resolver` to your
   router (`ipconfig` -> Default Gateway).
4. Plugged in: `python scripts\evaluate.py --background captures\home_normal.pcap --address-plan config\address_plan_home.yaml`

The report is labelled "REAL benign capture"; its benign-only section is the real false-alert rate.

## Part 2 - labelled lab capture (optional, larger effort)

Use only an **isolated network you own** (for example a VirtualBox host-only network with your own VMs), never a
shared, college or internet-facing network. Generate each traffic pattern with the PS-named tools following their
own documentation (links on slide 6), capture the whole session as classic pcap, and record the epoch start / end
time (`date +%s`) of each pattern. Copy `config/address_plan_lab.example.yaml` and adapt the inside prefix.

Labels file (`X.labels.json`), one entry per labelled pattern:

```json
[
  {"attack_id": "e1", "ps_letter": "e", "variant": "what you ran",
   "key_ips": ["192.168.56.10"], "t_start": 1790400000, "t_end": 1790400060}
]
```

`ps_letter`: a DDoS / reflection, b C2, c DGA / DNS, d encrypted sessions, e scanning, f exfiltration.
`key_ips`: the addresses that identify the pattern in an alert (target for floods; source host for scans, C2, exfil).
Classes c and d will show as not observable on header-only replay (see Limit above).
