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
		}

	}

	fmt.Printf("\nTotal packets: %d\n", packetNumber)
}
