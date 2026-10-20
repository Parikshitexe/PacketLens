# PacketLens

**A lightweight network traffic analyzer written in Go.**

PacketLens reads packet capture (PCAP) files, parses network protocols, tracks TCP flows, reassembles TCP streams, extracts visible TLS Server Name Indication (SNI) hostnames, and classifies observed hostnames into applications.

## Features

- **PCAP processing:** Read and process packets from capture files.
- **Protocol parsing:** Parse Ethernet, IPv4, IPv6, and TCP headers.
- **Flow tracking:** Track TCP flows and packet/byte counts.
- **TCP stream reassembly:** Reassemble TCP payloads, including supported out-of-order segments.
- **TLS SNI extraction:** Extract hostnames from supported TLS ClientHello messages when SNI is visible.
- **Application classification:** Classify hostnames using configurable domain rules.
- **CLI flags:** Select input files and enable verbose packet logging.
- **JSON reports:** Export hostname observations and application summaries.
- **Automated tests:** Test protocol-related functionality, stream reassembly, classification, and JSON report generation.

## How It Works

```text
PCAP File
   |
   v
Ethernet Parsing
   |
   v
IPv4 / IPv6 Parsing
   |
   v
TCP Parsing and Flow Tracking
   |
   v
TCP Stream Reassembly
   |
   v
TLS ClientHello / SNI Extraction
   |
   v
Hostname Classification
   |
   v
Terminal Summary + JSON Report
```

## Requirements

- Go installed and available on your PATH.
- A PCAP file to analyze.
- Application rules in `config/app_domains.json`.

## Run PacketLens

Clone the repository and enter its directory:

```bash
git clone https://github.com/Parikshitexe/packetlens.git
cd packetlens
```

Run the automated tests:

```bash
go test ./...
```

Display command-line help:

```bash
go run ./cmd/packetlens --help
```

Analyze a PCAP file:

```bash
go run ./cmd/packetlens --input <pcap file>
```

Enable verbose packet logs:

```bash
go run ./cmd/packetlens --input <pcap file> --verbose
```

Export a JSON report:

```bash
go run ./cmd/packetlens --input <pcap file> --output ./report.json
```

You can combine verbose logging and JSON export:

```bash
go run ./cmd/packetlens --input <pcap file> --verbose --output ./report.json
```

## Configuration

Application classification rules are stored in `config/app_domains.json`.

Rules associate domain suffixes with application names. Add or modify rules to customize classification for the hostnames observed in your captures.

## Example Results

In one sample run, PacketLens processed:

- **17,387 packets**
- **29 unique observed hostnames**
- **5 named application categories:** Wix, Google, Cursor, ChatGPT, and OpenAI
- Additional hostnames classified as `Unknown`

These figures describe one capture file, not a performance benchmark or a guarantee for other PCAP files.

## JSON Report

The JSON report includes:

- Input filename
- Total packets processed
- Number of unique hostnames
- Per-hostname observation counts and application labels
- Application-level observation summaries

## Limitations

- Hostname discovery depends on visible TLS ClientHello information and SNI availability.
- Packet captures may omit packets or begin mid-connection, which can affect stream reassembly and hostname extraction.
- Application classification depends on the configured domain rules; unrecognized hostnames are labelled `Unknown`.
- Observation counts represent extracted hostname observations, not guaranteed unique TCP connections.
- PacketLens does not decrypt TLS application payloads.
- This project is a learning and portfolio project, not a production-grade network monitoring or security enforcement system.

## Project Structure

```text
packetlens/
├── cmd/
│   └── packetlens/
│       ├── main.go
│       ├── report.go
│       └── report_test.go
├── config/
│   └── app_domains.json
├── internal/
│   └── pcap/
│       ├── reader.go
│       ├── ethernet.go
│       ├── ipv4.go
│       ├── ipv6.go
│       ├── tcp.go
│       ├── udp.go
│       ├── flow.go
│       ├── flow_tracker.go
│       ├── tcp_stream.go
│       ├── tcp_stream_test.go
│       ├── tls.go
│       ├── application.go
│       └── application_test.go
├── go.mod
└── README.md
```

## Future Improvements

- Improve TCP retransmission and sequence-number wraparound handling.
- Add more protocol and malformed-packet test cases.
- Expand application classification rules.
- Improve reporting and performance for large capture files.

## License

Choose and add a license before distributing the project for reuse.