package pcap

import (
	"encoding/binary"
	"net"
	"testing"
)

func appendDNSName(buf []byte, name string) []byte {
	if name == "" {
		return append(buf, 0)
	}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
			start = i + 1
		}
	}
	return append(buf, 0)
}

func TestParseDNS_Query(t *testing.T) {
	// Header: ID=0x1234, flags=0 (query), qd=1
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[4:6], 1) // qdcount

	msg = appendDNSName(msg, "www.Example.COM")
	msg = append(msg, 0x00, 0x01) // type A
	msg = append(msg, 0x00, 0x01) // class IN

	parsed, err := ParseDNS(msg)
	if err != nil {
		t.Fatalf("ParseDNS() error: %v", err)
	}
	if parsed.IsResponse {
		t.Fatal("expected query")
	}
	if len(parsed.Questions) != 1 {
		t.Fatalf("questions = %d, want 1", len(parsed.Questions))
	}
	if parsed.Questions[0].Name != "www.example.com" {
		t.Errorf("name = %q, want www.example.com", parsed.Questions[0].Name)
	}
	if parsed.Questions[0].Type != DNSTypeA {
		t.Errorf("type = %d, want A", parsed.Questions[0].Type)
	}
}

func TestParseDNS_ResponseAWithCompression(t *testing.T) {
	// Build: question example.com A, answer with pointer back to question name.
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0xABCD)
	binary.BigEndian.PutUint16(msg[2:4], 0x8000) // response, NOERROR
	binary.BigEndian.PutUint16(msg[4:6], 1)       // qd
	binary.BigEndian.PutUint16(msg[6:8], 1)       // an

	msg = appendDNSName(msg, "example.com")
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A IN

	// Answer name = pointer to offset 12 (start of question name)
	msg = append(msg, 0xc0, 0x0c)
	msg = append(msg, 0x00, 0x01)             // type A
	msg = append(msg, 0x00, 0x01)             // class IN
	msg = append(msg, 0x00, 0x00, 0x00, 0x3c) // TTL 60
	msg = append(msg, 0x00, 0x04)             // rdlength
	msg = append(msg, 93, 184, 216, 34)       // 93.184.216.34

	parsed, err := ParseDNS(msg)
	if err != nil {
		t.Fatalf("ParseDNS() error: %v", err)
	}
	if !parsed.IsResponse {
		t.Fatal("expected response")
	}
	if parsed.ResponseCode != 0 {
		t.Errorf("rcode = %d, want 0", parsed.ResponseCode)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(parsed.Answers))
	}
	if parsed.Answers[0].Name != "example.com" {
		t.Errorf("answer name = %q", parsed.Answers[0].Name)
	}
	if parsed.Answers[0].IP != "93.184.216.34" {
		t.Errorf("answer IP = %q", parsed.Answers[0].IP)
	}
}

func TestParseDNS_ResponseAAAA(t *testing.T) {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[2:4], 0x8000)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], 1)

	msg = appendDNSName(msg, "ipv6.example")
	msg = append(msg, 0x00, 0x1c, 0x00, 0x01) // AAAA IN

	msg = append(msg, 0xc0, 0x0c)
	msg = append(msg, 0x00, 0x1c, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00, 0x01, 0x2c) // TTL
	msg = append(msg, 0x00, 0x10)
	ip := net.ParseIP("2001:db8::1").To16()
	msg = append(msg, ip...)

	parsed, err := ParseDNS(msg)
	if err != nil {
		t.Fatalf("ParseDNS() error: %v", err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].IP == "" {
		t.Fatalf("expected AAAA IP, got %+v", parsed.Answers)
	}
	if net.ParseIP(parsed.Answers[0].IP).String() != net.ParseIP("2001:db8::1").String() {
		t.Errorf("AAAA IP = %q", parsed.Answers[0].IP)
	}
}

func TestDNSStats_Observe(t *testing.T) {
	stats := NewDNSStats()

	stats.Observe(&DNSMessage{
		Questions: []DNSQuestion{{Name: "a.example", Type: DNSTypeA}},
	})
	stats.Observe(&DNSMessage{
		Questions: []DNSQuestion{{Name: "a.example", Type: DNSTypeA}},
	})
	stats.Observe(&DNSMessage{
		IsResponse:   true,
		ResponseCode: 0,
		Answers: []DNSResourceRecord{
			{Name: "a.example", Type: DNSTypeA, IP: "1.2.3.4"},
		},
	})
	stats.Observe(&DNSMessage{
		IsResponse:   true,
		ResponseCode: 3,
	})

	if stats.Queries != 2 || stats.Responses != 2 {
		t.Fatalf("queries=%d responses=%d", stats.Queries, stats.Responses)
	}
	if stats.QueryNames["a.example"] != 2 {
		t.Errorf("query count = %d", stats.QueryNames["a.example"])
	}
	if stats.ResponseCodes[0] != 1 || stats.ResponseCodes[3] != 1 {
		t.Errorf("rcodes = %#v", stats.ResponseCodes)
	}
	if _, ok := stats.Resolutions["a.example"]["1.2.3.4"]; !ok {
		t.Fatal("expected resolution a.example -> 1.2.3.4")
	}
}

func TestParseDNS_TooShort(t *testing.T) {
	if _, err := ParseDNS([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short message")
	}
}
