package pcap

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	dnsHeaderLen = 12

	DNSTypeA    uint16 = 1
	DNSTypeAAAA uint16 = 28
)

// DNSMessage is a lightly parsed DNS query or response (UDP/53).
type DNSMessage struct {
	TransactionID uint16
	IsResponse    bool
	ResponseCode  uint8
	Questions     []DNSQuestion
	Answers       []DNSResourceRecord
}

type DNSQuestion struct {
	Name string
	Type uint16
}

type DNSResourceRecord struct {
	Name string
	Type uint16
	TTL  uint32
	// IP is set for A and AAAA answers; empty for other types.
	IP string
}

// DNSStats accumulates DNS observations across a capture.
type DNSStats struct {
	Queries       int
	Responses     int
	QueryNames    map[string]int
	ResponseCodes map[uint8]int
	// Resolutions maps a queried/answered name to A/AAAA addresses seen.
	Resolutions map[string]map[string]struct{}
}

func NewDNSStats() *DNSStats {
	return &DNSStats{
		QueryNames:    make(map[string]int),
		ResponseCodes: make(map[uint8]int),
		Resolutions:   make(map[string]map[string]struct{}),
	}
}

func (s *DNSStats) Observe(msg *DNSMessage) {
	if msg == nil {
		return
	}

	if msg.IsResponse {
		s.Responses++
		s.ResponseCodes[msg.ResponseCode]++
		for _, answer := range msg.Answers {
			if answer.IP == "" || answer.Name == "" {
				continue
			}
			ips, ok := s.Resolutions[answer.Name]
			if !ok {
				ips = make(map[string]struct{})
				s.Resolutions[answer.Name] = ips
			}
			ips[answer.IP] = struct{}{}
		}
		return
	}

	s.Queries++
	for _, q := range msg.Questions {
		if q.Name == "" {
			continue
		}
		s.QueryNames[q.Name]++
	}
}

// ParseDNS parses a DNS message from a UDP payload.
// It supports compressed names and extracts A/AAAA answers when present.
func ParseDNS(data []byte) (*DNSMessage, error) {
	if len(data) < dnsHeaderLen {
		return nil, fmt.Errorf("DNS message too short")
	}

	id := binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])

	msg := &DNSMessage{
		TransactionID: id,
		IsResponse:    flags&0x8000 != 0,
		ResponseCode:  uint8(flags & 0x000f),
	}

	offset := dnsHeaderLen

	for i := 0; i < int(qdCount); i++ {
		name, next, err := readDNSName(data, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+4 > len(data) {
			return nil, fmt.Errorf("truncated DNS question")
		}
		qType := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 4 // type + class

		msg.Questions = append(msg.Questions, DNSQuestion{
			Name: name,
			Type: qType,
		})
	}

	for i := 0; i < int(anCount); i++ {
		name, next, err := readDNSName(data, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+10 > len(data) {
			return nil, fmt.Errorf("truncated DNS answer")
		}

		rrType := binary.BigEndian.Uint16(data[offset : offset+2])
		// class at offset+2
		ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdLength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(data) {
			return nil, fmt.Errorf("truncated DNS rdata")
		}

		rdata := data[offset : offset+int(rdLength)]
		offset += int(rdLength)

		record := DNSResourceRecord{
			Name: name,
			Type: rrType,
			TTL:  ttl,
		}

		switch rrType {
		case DNSTypeA:
			if len(rdata) == net.IPv4len {
				record.IP = net.IP(rdata).To4().String()
			}
		case DNSTypeAAAA:
			if len(rdata) == net.IPv6len {
				record.IP = net.IP(rdata).To16().String()
			}
		}

		msg.Answers = append(msg.Answers, record)
	}

	return msg, nil
}

func readDNSName(msg []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 4)
	jumped := false
	originalOffset := offset
	maxJumps := 10

	for {
		if offset >= len(msg) {
			return "", 0, fmt.Errorf("DNS name extends beyond message")
		}

		length := int(msg[offset])
		if length == 0 {
			offset++
			break
		}

		// Compression pointer: top two bits set.
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(msg) {
				return "", 0, fmt.Errorf("truncated DNS name pointer")
			}
			pointer := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3fff)
			if !jumped {
				originalOffset = offset + 2
				jumped = true
			}
			offset = pointer
			maxJumps--
			if maxJumps < 0 {
				return "", 0, fmt.Errorf("DNS name pointer loop")
			}
			continue
		}

		if length&0xc0 != 0 {
			return "", 0, fmt.Errorf("unsupported DNS name label type")
		}

		offset++
		if offset+length > len(msg) {
			return "", 0, fmt.Errorf("DNS label extends beyond message")
		}
		labels = append(labels, string(msg[offset:offset+length]))
		offset += length
	}

	next := offset
	if jumped {
		next = originalOffset
	}

	name := strings.Join(labels, ".")
	return strings.ToLower(name), next, nil
}

// DNSResponseCodeName returns a short label for common RCODEs.
func DNSResponseCodeName(code uint8) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", code)
	}
}
