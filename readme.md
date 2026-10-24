# PacketLens

**A Go-based offline network traffic analyzer for learning, portfolio, and open-source use.**

PacketLens reads PCAP files and turns raw packets into structured connection statistics, visible TLS hostnames (SNI), application labels, and light DNS summaries — without decrypting HTTPS.

> **v1 focus:** offline analysis only. Live capture is a planned post-v1 learning step, not part of this release.

## What problem it solves

Wireshark shows every packet. PacketLens answers higher-level questions from a capture:

- Which **connections** (flows) appeared, with packet/byte counts and timing?
- Which **TLS SNI hostnames** were visible, and which **applications** do they map to?
- What **DNS** queries/responses (UDP/53) showed up, when present?

It is a learning and portfolio project — not a production monitoring product, firewall, or threat scanner.

## Features (v1)

- **PCAP reading** with per-packet timestamps
- **Ethernet / IPv4 / IPv6 / TCP / UDP** header parsing
- **Bidirectional flow tracking** for TCP and UDP: packets, captured bytes, first/last seen, duration
- **Optional flow identity** from TLS SNI (hostname + classified application)
- **TCP stream reassembly** (including basic out-of-order handling) for ClientHello inspection
- **TLS SNI extraction** when ClientHello/SNI is visible
- **Application classification** via `config/app_domains.json`
- **Light DNS analysis** on UDP port 53 (queries, response codes, A/AAAA resolutions)
- **Terminal summaries** and **JSON report** export
- **Automated tests** (`go test ./...`)

## How it works

```text
PCAP File
   |
   v
Ethernet → IPv4 / IPv6
   |
   v
TCP or UDP
   |
   +-- FlowTracker (connection stats + optional SNI identity)
   |
   +-- TCP only → stream reassembly → TLS ClientHello / SNI → classify
   |
   +-- UDP/53 → DNS parse → DNS stats
   |
   v
Terminal summary + JSON report
```

**Flow tracking** and **TCP stream reassembly** are separate on purpose:

- A *flow* is one bidirectional conversation (endpoints + protocol) with volume/timing stats.
- A *stream* rebuilds ordered bytes in one direction so application data (like TLS ClientHello) can be inspected.

## Requirements

- Go on your `PATH`
- A PCAP file
- Application rules in `config/app_domains.json` (run from the repo root so this path resolves)

## Quick start

```bash
git clone https://github.com/Parikshitexe/packetlens.git
cd packetlens

go test ./...

go run ./cmd/packetlens --help
go run ./cmd/packetlens --input .\traffic_2.pcap
go run ./cmd/packetlens --input .\traffic_2.pcap --verbose
go run ./cmd/packetlens --input .\traffic_2.pcap --output .\report.json
```

## Configuration

`config/app_domains.json` maps domain suffixes to application names.

- Exact domain or subdomain matches (e.g. `cursor.sh` matches `api2.cursor.sh`)
- Unmatched hostnames are labelled `Unknown` (hostname was seen; no rule matched)
- `Unknown` does **not** mean SNI extraction failed

## Example results

On one sample capture (`traffic_2.pcap`), a previous run observed roughly:

- **17,387** packets
- **29** unique TLS hostnames
- Application observations such as Wix, Google, Cursor, ChatGPT, OpenAI, plus `Unknown`

Figures vary by capture. They are hostname *observations*, not a count of unique websites visited or unique TCP connections.

After v1, the same run also prints a **Connections** table (top flows by bytes) and a **DNS Summary** when UDP/53 traffic is present.

## JSON report

`--output` writes indented JSON including:

| Field | Meaning |
|--------|---------|
| `total_packets` | Packets read from the PCAP |
| `total_flows` | Bidirectional TCP/UDP flows tracked |
| `connections` | Per-flow endpoints, protocol, packets, bytes, timing, optional hostname/application |
| `hostnames` | SNI hostname observations + application label |
| `applications` | Aggregated observation counts by application |
| `dns` | UDP/53 query/response stats, top names, A/AAAA resolutions |

**Bytes** on a flow are the sum of PCAP **captured frame lengths**, not IP-payload-only sizes.

**Duration** is `last_seen - first_seen` inside the capture window. If the PCAP starts mid-connection, duration is not the full real-world session length.

## Limitations

- Offline PCAP only (no live capture in v1)
- No TLS decryption; only visible handshake metadata (e.g. SNI)
- SNI may be missing (Encrypted ClientHello, non-TLS, truncated capture)
- IPv6 extension headers are not fully walked; VLAN tags are not specially handled
- TCP reassembly is educational-grade (wraparound, complex overlaps, memory limits remain)
- DNS is UDP/53 only; DNS names are not auto-merged onto flows (avoids incorrect guesses)
- Not a security enforcement, blocking, or malware-detection product

## Project structure

```text
packetlens/
├── cmd/packetlens/          # CLI, report types, report tests
├── config/app_domains.json  # Application domain rules
├── internal/pcap/           # PCAP reader, parsers, flows, streams, TLS, DNS
├── go.mod
├── LICENSE
└── README.md
```

## Learning goals

This project is intentionally scoped for **engineering skill**, resume, and open-source showcasing:

- Binary protocol parsing in Go
- Flow keys, bidirectional identity, and connection statistics
- Separating stream reassembly from flow accounting
- Metadata-based classification with honest limits
- CLI + structured JSON reporting and tests

## What's next (post-v1)

- **Live packet capture** (e.g. Npcap on Windows) reusing the same analysis pipeline
- Targeted reliability work driven by real capture failures (VLAN, IPv6 extensions, TCP edge cases)
- Optional small API or UI only after the offline analyzer stays the source of truth

## License

MIT — see [LICENSE](LICENSE).
