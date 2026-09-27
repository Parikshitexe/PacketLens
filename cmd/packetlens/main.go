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
	}

	fmt.Printf("\nTotal packets: %d\n", packetNumber)
}
