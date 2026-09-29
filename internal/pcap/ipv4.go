package pcap

import (
    "fmt"
    "net"
)

type IPv4Packet struct {
    Version        uint8
    HeaderLength   uint8
    TotalLength    uint16
    TTL            uint8
    Protocol       uint8
    SourceIP       net.IP
    DestinationIP  net.IP
}

func ParseIPv4(data []byte) (*IPv4Packet, error) {
    if len(data) < 20 {
        return nil, fmt.Errorf("packet too small for IPv4 header")
    }

    version := data[0] >> 4
    headerLength := (data[0] & 0x0f) * 4

    totalLength := uint16(data[2])<<8 | uint16(data[3])

    ttl := data[8]
    protocol := data[9]

    sourceIP := net.IPv4(
        data[12],
        data[13],
        data[14],
        data[15],
    )

    destinationIP := net.IPv4(
        data[16],
        data[17],
        data[18],
        data[19],
    )

    packet := &IPv4Packet{
        Version:       version,
        HeaderLength:  headerLength,
        TotalLength:   totalLength,
        TTL:           ttl,
        Protocol:      protocol,
        SourceIP:      sourceIP,
        DestinationIP: destinationIP,
    }

    return packet, nil
}