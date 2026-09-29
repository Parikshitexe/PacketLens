package pcap

import "fmt"

type TCPPacket struct {
    SourcePort      uint16
    DestinationPort uint16
}

func ParseTCP(data []byte) (*TCPPacket, error) {
    if len(data) < 20 {
        return nil, fmt.Errorf("packet too small for TCP header")
    }

    sourcePort := uint16(data[0])<<8 | uint16(data[1])
    destinationPort := uint16(data[2])<<8 | uint16(data[3])

    packet := &TCPPacket{
        SourcePort:      sourcePort,
        DestinationPort: destinationPort,
    }

    return packet, nil
}