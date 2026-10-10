
package pcap

import "testing"


func TestTCPStreamOutOfOrder(t *testing.T) {
	tracker := NewTCPStreamTracker()
	key := TCPStreamKey{}

	// SYN has sequence number 99.
	// First payload byte is expected at sequence 100.
	tracker.Add(key, 99, true, nil)

	// Later bytes arrive first.
	got := tracker.Add(key, 105, false, []byte("WORLD"))
	if string(got) != "" {
		t.Fatalf("expected empty stream, got %q", got)
	}

	// Earlier bytes arrive; pending bytes should now join.
	got = tracker.Add(key, 100, false, []byte("HELLO"))
	if string(got) != "HELLOWORLD" {
		t.Fatalf("expected HELLOWORLD, got %q", got)
	}
}


func TestTCPStreamDuplicate(t *testing.T) {
	tracker := NewTCPStreamTracker()
	key := TCPStreamKey{}

	tracker.Add(key, 100, false, []byte("HELLO"))
	got := tracker.Add(key, 100, false, []byte("HELLO"))

	if string(got) != "HELLO" {
		t.Fatalf("duplicate was appended: %q", got)
	}
}
