package pcap

import "fmt"

type UDPPacket struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
}

func ParseUDP(data []byte) (*UDPPacket, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packet too small for UDP header")
	}

	sourcePort := uint16(data[0])<<8 | uint16(data[1])
	destinationPort := uint16(data[2])<<8 | uint16(data[3])
	length := uint16(data[4])<<8 | uint16(data[5])

	packet := &UDPPacket{
		SourcePort:      sourcePort,
		DestinationPort: destinationPort,
		Length:          length,
	}

	return packet, nil
}