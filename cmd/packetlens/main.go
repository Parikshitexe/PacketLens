package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Parikshitexe/packetlens/internal/pcap"
)

func transportProtocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("%d", protocol)
	}
}

func formatEndpoint(ep pcap.Endpoint) string {
	return fmt.Sprintf("%s:%d", ep.IP, ep.Port)
}

func main() {
	inputFile := flag.String("input", "", "Path to the PCAP file")
	verbose := flag.Bool("verbose", false, "Enable detailed packet logs")
	output := flag.String("output", "", "Path to write JSON report")

	flag.Parse()

	if *inputFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	classifier, err := pcap.LoadApplicationClassifier(
		"config/app_domains.json",
	)
	if err != nil {
		log.Fatalf("Failed to load application rules: %v", err)
	}

	filename := *inputFile

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

		if *verbose {
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

		// Only TCP (6) and UDP (17) enter the flow table for v1.
		if protocol != 6 && protocol != 17 {
			continue
		}

		ipStart := 14
		ipEnd := ipStart + ipTotalLength

		if ipEnd > len(packet.Data) || ipEnd < ipStart+ipHeaderLength {
			log.Println("Invalid IP packet length")
			continue
		}

		transportData := packet.Data[ipStart+ipHeaderLength : ipEnd]

		switch protocol {
		case 6: // TCP
			tcp, err := pcap.ParseTCP(transportData)
			if err != nil {
				log.Println("TCP parsing failed:", err)
				continue
			}

			if *verbose {
				fmt.Printf(
					"TCP | Src Port: %d | Dst Port: %d | Payload: %d bytes\n",
					tcp.SourcePort,
					tcp.DestinationPort,
					len(tcp.Payload),
				)
			}

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
				packet.Timestamp,
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
					} else {
						fmt.Println("TLS ClientHello detected, but no SNI hostname found")
					}

					reportedTLS[streamKey] = true
				}
			}

			if *verbose {
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

		case 17: // UDP
			udp, err := pcap.ParseUDP(transportData)
			if err != nil {
				log.Println("UDP parsing failed:", err)
				continue
			}

			if *verbose {
				fmt.Printf(
					"UDP | Src Port: %d | Dst Port: %d | Length: %d\n",
					udp.SourcePort,
					udp.DestinationPort,
					udp.Length,
				)
			}

			source := pcap.Endpoint{
				IP:   sourceIP,
				Port: udp.SourcePort,
			}
			destination := pcap.Endpoint{
				IP:   destinationIP,
				Port: udp.DestinationPort,
			}

			flow, direction, isNew := tracker.Track(
				source,
				destination,
				protocol,
				uint64(packet.CapturedLength),
				packet.Timestamp,
			)

			if *verbose {
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

	}

	fmt.Printf("\nTotal packets: %d\n", packetNumber)

	flows := tracker.Flows()
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].Bytes == flows[j].Bytes {
			a := formatEndpoint(flows[i].Key.A)
			b := formatEndpoint(flows[j].Key.A)
			return a < b
		}
		return flows[i].Bytes > flows[j].Bytes
	})

	fmt.Println("\nConnections")
	fmt.Println("---------------------------------------------")
	fmt.Printf("Total flows: %d\n", len(flows))

	const maxConnectionsDisplay = 20
	displayCount := len(flows)
	if displayCount > maxConnectionsDisplay {
		displayCount = maxConnectionsDisplay
	}

	for i := 0; i < displayCount; i++ {
		flow := flows[i]
		fmt.Printf(
			"%s ↔ %s | %s | packets=%d bytes=%d duration=%s\n",
			formatEndpoint(flow.Key.A),
			formatEndpoint(flow.Key.B),
			transportProtocolName(flow.Key.Protocol),
			flow.PacketCount,
			flow.Bytes,
			flow.Duration().Round(time.Millisecond),
		)
	}
	if len(flows) > maxConnectionsDisplay {
		fmt.Printf("... and %d more flows\n", len(flows)-maxConnectionsDisplay)
	}

	fmt.Println("\nUnique Hostnames")
	fmt.Println("---------------------------------------------")

	type HostnameStat struct {
		Hostname    string
		Connections int
	}

	stats := make([]HostnameStat, 0, len(hostnameCounts))

	for hostname, count := range hostnameCounts {
		stats = append(stats, HostnameStat{
			Hostname:    hostname,
			Connections: count,
		})
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Connections == stats[j].Connections {
			return stats[i].Hostname < stats[j].Hostname
		}
		return stats[i].Connections > stats[j].Connections
	})

	for _, stat := range stats {
		fmt.Printf("%-40s %d observations\n",
			stat.Hostname,
			stat.Connections,
		)
	}

	fmt.Printf("\nTotal unique hostnames: %d\n", len(stats))

	applicationCounts := make(map[string]int)

	for hostname, count := range hostnameCounts {
		application := classifier.ClassifyHostname(hostname)
		applicationCounts[application] += count
	}

	fmt.Println("\nUnknown Hostnames")
	fmt.Println("---------------------------------------------")

	unknownCount := 0

	for hostname, count := range hostnameCounts {
		if classifier.ClassifyHostname(hostname) == "Unknown" {
			fmt.Printf("%-40s %d observed streams\n", hostname, count)
			unknownCount += count
		}
	}

	fmt.Printf("Unknown hostname entries: %d\n", unknownCount)

	fmt.Println("\nApplication Summary")
	fmt.Println("---------------------------------------------")

	type ApplicationStat struct {
		Name        string
		Connections int
	}

	appStats := make([]ApplicationStat, 0, len(applicationCounts))

	for name, count := range applicationCounts {
		appStats = append(appStats, ApplicationStat{
			Name:        name,
			Connections: count,
		})
	}

	sort.Slice(appStats, func(i, j int) bool {
		if appStats[i].Connections == appStats[j].Connections {
			return appStats[i].Name < appStats[j].Name
		}
		return appStats[i].Connections > appStats[j].Connections
	})

	for _, stat := range appStats {
		fmt.Printf("%-20s %d observations\n",
			stat.Name,
			stat.Connections,
		)
	}
	if *output != "" {
		hostnameReports := make([]HostnameReport, 0, len(stats))

		for _, stat := range stats {
			hostnameReports = append(hostnameReports, HostnameReport{
				Hostname:     stat.Hostname,
				Observations: stat.Connections,
				Application:  classifier.ClassifyHostname(stat.Hostname),
			})
		}

		applicationReports := make(
			[]ApplicationReport,
			0,
			len(appStats),
		)

		for _, stat := range appStats {
			applicationReports = append(applicationReports, ApplicationReport{
				Name:         stat.Name,
				Observations: stat.Connections,
			})
		}

		connectionReports := make([]ConnectionReport, 0, len(flows))
		for _, flow := range flows {
			connectionReports = append(connectionReports, ConnectionReport{
				EndpointA:    formatEndpoint(flow.Key.A),
				EndpointB:    formatEndpoint(flow.Key.B),
				Protocol:     transportProtocolName(flow.Key.Protocol),
				PacketCount:  flow.PacketCount,
				Bytes:        flow.Bytes,
				FirstSeen:    flow.FirstSeen.UTC().Format(time.RFC3339Nano),
				LastSeen:     flow.LastSeen.UTC().Format(time.RFC3339Nano),
				DurationSecs: flow.Duration().Seconds(),
			})
		}

		report := PacketLensReport{
			InputFile:       filepath.Base(filename),
			TotalPackets:    packetNumber,
			TotalFlows:      len(flows),
			UniqueHostnames: len(stats),
			Connections:     connectionReports,
			Hostnames:       hostnameReports,
			Applications:    applicationReports,
		}

		if err := WriteJSONReport(*output, report); err != nil {
			log.Fatalf("Failed to write JSON report: %v", err)
		}

		fmt.Printf("\nJSON report written to %s\n", *output)
	}

}
