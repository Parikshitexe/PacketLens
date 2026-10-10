package pcap

import (
	"encoding/binary"
	"fmt"
	"net"
)

type IPv6Packet struct {
	Version       uint8
	PayloadLength uint16
	NextHeader    uint8
	HopLimit      uint8
	SourceIP      net.IP
	DestinationIP net.IP
}

func ParseIPv6(data []byte) (*IPv6Packet, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("packet too small for IPv6 header")
	}

	version := data[0] >> 4
	if version != 6 {
		return nil, fmt.Errorf("invalid IPv6 version: %d", version)
	}

	payloadLength := binary.BigEndian.Uint16(data[4:6])
	nextHeader := data[6]
	hopLimit := data[7]

	sourceIP := net.IP(data[8:24]).To16()
	destinationIP := net.IP(data[24:40]).To16()

	packet := &IPv6Packet{
		Version:       version,
		PayloadLength: payloadLength,
		NextHeader:    nextHeader,
		HopLimit:      hopLimit,
		SourceIP:      sourceIP,
		DestinationIP: destinationIP,
	}

	return packet, nil
}
