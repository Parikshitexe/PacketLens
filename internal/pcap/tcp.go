package pcap

import (
    "encoding/binary"
    "fmt"
)

type TCPPacket struct {
    SourcePort      uint16
    DestinationPort uint16
    SequenceNumber      uint32
    AcknowledgmentNumber uint32
    HeaderLength    uint8
    Flags           uint16
    Payload         []byte
}

func ParseTCP(data []byte) (*TCPPacket, error) {
    if len(data) < 20 {
        return nil, fmt.Errorf("packet too small for TCP header")
    }

    sourcePort := uint16(data[0])<<8 | uint16(data[1])
    destinationPort := uint16(data[2])<<8 | uint16(data[3])

    
    sequenceNumber := binary.BigEndian.Uint32(data[4:8])
    acknowledgmentNumber := binary.BigEndian.Uint32(data[8:12])


    // TCP Data Offset tells us where the payload starts.
    // It is stored in 32-bit words, so multiply by 4.
    headerLength := (data[12] >> 4) * 4

    if headerLength < 20 {
        return nil, fmt.Errorf("invalid TCP header length: %d", headerLength)
    }

    if int(headerLength) > len(data) {
        return nil, fmt.Errorf("TCP header extends beyond packet")
    }

    flags := uint16(data[13])

    payload := data[headerLength:]

    return &TCPPacket{
        SourcePort:           sourcePort,
    DestinationPort:      destinationPort,
    SequenceNumber:       sequenceNumber,
    AcknowledgmentNumber: acknowledgmentNumber,
    HeaderLength:         headerLength,
    Flags:                flags,
    Payload:              payload,
    }, nil
}