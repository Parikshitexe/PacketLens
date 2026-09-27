package pcap

import (
	"encoding/hex"
	"fmt"
)

type EthernetFrame struct {
	DestinationMAC string
	SourceMAC      string
	EtherType      uint16
}

func ParseEthernet(data []byte) (*EthernetFrame, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("packet too small for Ethernet header")
	}

	destinationMAC := hex.EncodeToString(data[0:6])
	sourceMAC := hex.EncodeToString(data[6:12])

	etherType := uint16(data[12])<<8 | uint16(data[13])

	frame := &EthernetFrame{
		DestinationMAC: destinationMAC,
		SourceMAC:      sourceMAC,
		EtherType:      etherType,
	}

	return frame, nil
}

func ProtocolName(etherType uint16) string {
    switch etherType {
    case 0x0800:
        return "IPv4"
    case 0x86dd:
        return "IPv6"
    case 0x0806:
        return "ARP"
    default:
        return "Unknown"
    }
}
