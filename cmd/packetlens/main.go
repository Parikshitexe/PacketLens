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
		if ethernet.EtherType == 0x0800 {
			ipv4, err := pcap.ParseIPv4(packet.Data[14:])
		
			if err != nil {
				log.Println("IPv4 parsing failed:", err)
				continue
			}
		
			fmt.Printf(
				"IPv4 | Src: %s | Dst: %s | Protocol: %d | Length: %d\n",
				ipv4.SourceIP,
				ipv4.DestinationIP,
				ipv4.Protocol,
				ipv4.TotalLength,
			)
		
			if ipv4.Protocol == 6 {
				ipStart := 14
				ipEnd := ipStart + int(ipv4.TotalLength)
			
				if ipEnd > len(packet.Data) {
					log.Println("IPv4 packet extends beyond captured data")
					continue
				}
			
				tcpStart := ipStart + int(ipv4.HeaderLength)
			
				if tcpStart > ipEnd {
					log.Println("invalid TCP start position")
					continue
				}
			
				tcpData := packet.Data[tcpStart:ipEnd]
			
				tcp, err := pcap.ParseTCP(tcpData)
			
				if err != nil {
					log.Println("TCP parsing failed:", err)
					continue
				}
			
				fmt.Printf(
					"TCP | Src Port: %d | Dst Port: %d | Header: %d | Payload: %d bytes\n",
					tcp.SourcePort,
					tcp.DestinationPort,
					tcp.HeaderLength,
					len(tcp.Payload),
				)
			
				source := pcap.Endpoint{
					IP:   ipv4.SourceIP.String(),
					Port: tcp.SourcePort,
				}
			
				destination := pcap.Endpoint{
					IP:   ipv4.DestinationIP.String(),
					Port: tcp.DestinationPort,
				}
			
				flow, direction, isNew := tracker.Track(
					source,
					destination,
					ipv4.Protocol,
					uint64(packet.CapturedLength),
				)
			
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

				fmt.Printf(
					"TCP | Src Port: %d | Dst Port: %d | Header: %d | Payload: %d bytes\n",
					tcp.SourcePort,
					tcp.DestinationPort,
					tcp.HeaderLength,
					len(tcp.Payload),
				)
				
				if len(tcp.Payload) > 0 {
					fmt.Printf("Payload bytes: %x\n", tcp.Payload)
				}
			}
		}
	}

	fmt.Printf("\nTotal packets: %d\n", packetNumber)
}
