package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Parikshitexe/packetlens/internal/pcap"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: packetlens <pcap-file>")
	}

	filename := os.Args[1]

	reader, err := pcap.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer reader.Close()

	packetNumber := 0
	tracker := pcap.NewFlowTracker()
	streamTracker := pcap.NewTCPStreamTracker()
	reportedTLS := make(map[pcap.TCPStreamKey]bool)
	hostnameCounts := make(map[string]int)

	for {
		packet, err := reader.NextPacket()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal(err)
		}

		packetNumber++
		ethernet, err := pcap.ParseEthernet(packet.Data)

		if err != nil {
			log.Println("Ethernet parsing failed:", err)
			continue
		}

		fmt.Printf(
			"Ethernet | Src: %s | Dst: %s | EtherType: 0x%x (%s)\n",
			ethernet.SourceMAC,
			ethernet.DestinationMAC,
			ethernet.EtherType,
			pcap.ProtocolName(ethernet.EtherType),
		)

		fmt.Printf(
			"Packet #%d | Time: %s | Captured: %d bytes | Original: %d bytes\n",
			packetNumber,
			packet.Timestamp.Format("15:04:05.000000"),
			packet.CapturedLength,
			packet.OriginalLength,
		)

		var (
			sourceIP       string
			destinationIP  string
			protocol       uint8
			ipHeaderLength int
			ipTotalLength  int
		)

		switch ethernet.EtherType {
		case 0x0800: // IPv4
			ipv4, err := pcap.ParseIPv4(packet.Data[14:])
			if err != nil {
				log.Println("IPv4 parsing failed:", err)
				continue
			}

			sourceIP = ipv4.SourceIP.String()
			destinationIP = ipv4.DestinationIP.String()
			protocol = ipv4.Protocol
			ipHeaderLength = int(ipv4.HeaderLength)
			ipTotalLength = int(ipv4.TotalLength)

		case 0x86dd: // IPv6
			ipv6, err := pcap.ParseIPv6(packet.Data[14:])
			if err != nil {
				log.Println("IPv6 parsing failed:", err)
				continue
			}

			sourceIP = ipv6.SourceIP.String()
			destinationIP = ipv6.DestinationIP.String()
			protocol = ipv6.NextHeader
			ipHeaderLength = 40
			ipTotalLength = 40 + int(ipv6.PayloadLength)

		default:
			// Ignore unsupported Ethernet types.
			continue
		}

		if protocol == 6 {
			// TCP processing goes here.

			ipStart := 14
			ipEnd := ipStart + ipTotalLength

			if ipEnd > len(packet.Data) || ipEnd < ipStart+ipHeaderLength {
				log.Println("Invalid IP packet length")
				continue
			}

			tcpStart := ipStart + ipHeaderLength
			tcpData := packet.Data[tcpStart:ipEnd]

			tcp, err := pcap.ParseTCP(tcpData)
			if err != nil {
				log.Println("TCP parsing failed:", err)
				continue
			}

			if len(tcp.Payload) > 0 &&
				(tcp.SourcePort == 443 || tcp.DestinationPort == 443) {
				fmt.Printf(
					"TLS DEBUG | SrcPort: %d | DstPort: %d | First bytes: % x\n",
					tcp.SourcePort,
					tcp.DestinationPort,
					tcp.Payload[:min(12, len(tcp.Payload))],
				)
			}

			fmt.Printf(
				"TCP | Src Port: %d | Dst Port: %d | Payload: %d bytes\n",
				tcp.SourcePort,
				tcp.DestinationPort,
				len(tcp.Payload),
			)

			source := pcap.Endpoint{
				IP:   sourceIP,
				Port: tcp.SourcePort,
			}

			destination := pcap.Endpoint{
				IP:   destinationIP,
				Port: tcp.DestinationPort,
			}

			flow, direction, isNew := tracker.Track(
				source,
				destination,
				protocol,
				uint64(packet.CapturedLength),
			)

			streamKey := pcap.TCPStreamKey{
				Flow:      flow.Key,
				Direction: direction,
			}

			syn := tcp.Flags&0x02 != 0

			reassembled := streamTracker.Add(
				streamKey,
				tcp.SequenceNumber,
				syn,
				tcp.Payload,
			)

			if !reportedTLS[streamKey] &&
				len(reassembled) >= 9 &&
				reassembled[0] == 0x16 &&
				reassembled[5] == 0x01 {

				hostname, err := pcap.ParseTLSClientHello(reassembled)

				if err != nil {
					if err.Error() != "incomplete TLS record" {
						fmt.Printf("TLS parsing error: %v\n", err)
						reportedTLS[streamKey] = true
					}
				} else {
					if hostname != "" {
						hostnameCounts[hostname]++
						fmt.Printf("TLS ClientHello | SNI: %s\n", hostname)
					} else {
						fmt.Println("TLS ClientHello detected, but no SNI hostname found")
					}

					reportedTLS[streamKey] = true
				}
			}

			if isNew {
				fmt.Println("NEW FLOW")
			}

			fmt.Printf(
				"Flow | %s:%d ↔ %s:%d | Packets: %d | Bytes: %d | Direction: %d\n",
				flow.Key.A.IP,
				flow.Key.A.Port,
				flow.Key.B.IP,
				flow.Key.B.Port,
				flow.PacketCount,
				flow.Bytes,
				direction,
			)

		}

	}

	fmt.Printf("\nTotal packets: %d\n", packetNumber)
	fmt.Println("\nUnique Hostnames")
	fmt.Println("------------------------------")

	for hostname, count := range hostnameCounts {
		fmt.Printf("%-40s %d connections\n", hostname, count)
	}

	fmt.Printf("\nTotal unique hostnames: %d\n", len(hostnameCounts))
}
