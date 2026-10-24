package pcap

import (
	"testing"
	"time"
)

func TestFlowTracker_BidirectionalSameKey(t *testing.T) {
	tracker := NewFlowTracker()
	t1 := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 1, 1, 12, 0, 5, 0, time.UTC)

	a := Endpoint{IP: "10.0.0.1", Port: 50000}
	b := Endpoint{IP: "10.0.0.2", Port: 443}

	flow1, dir1, isNew1 := tracker.Track(a, b, 6, 100, t1)
	if !isNew1 {
		t.Fatal("first packet should create a new flow")
	}
	if dir1 != DirectionAToB {
		t.Fatalf("direction = %d, want DirectionAToB", dir1)
	}

	flow2, dir2, isNew2 := tracker.Track(b, a, 6, 50, t2)
	if isNew2 {
		t.Fatal("reverse packet should not create a new flow")
	}
	if dir2 != DirectionBToA {
		t.Fatalf("direction = %d, want DirectionBToA", dir2)
	}
	if flow1 != flow2 {
		t.Fatal("both directions should update the same Flow pointer")
	}

	if flow1.PacketCount != 2 {
		t.Errorf("PacketCount = %d, want 2", flow1.PacketCount)
	}
	if flow1.Bytes != 150 {
		t.Errorf("Bytes = %d, want 150", flow1.Bytes)
	}
	if !flow1.FirstSeen.Equal(t1) {
		t.Errorf("FirstSeen = %v, want %v", flow1.FirstSeen, t1)
	}
	if !flow1.LastSeen.Equal(t2) {
		t.Errorf("LastSeen = %v, want %v", flow1.LastSeen, t2)
	}
	if flow1.Duration() != 5*time.Second {
		t.Errorf("Duration = %v, want 5s", flow1.Duration())
	}

	flows := tracker.Flows()
	if len(flows) != 1 {
		t.Fatalf("Flows() len = %d, want 1", len(flows))
	}
}

func TestFlowTracker_OutOfOrderTimestamps(t *testing.T) {
	tracker := NewFlowTracker()
	later := time.Date(2024, 1, 1, 12, 0, 10, 0, time.UTC)
	earlier := time.Date(2024, 1, 1, 12, 0, 1, 0, time.UTC)

	src := Endpoint{IP: "192.168.1.1", Port: 1234}
	dst := Endpoint{IP: "192.168.1.2", Port: 80}

	flow, _, _ := tracker.Track(src, dst, 6, 10, later)
	tracker.Track(src, dst, 6, 10, earlier)

	if !flow.FirstSeen.Equal(earlier) {
		t.Errorf("FirstSeen = %v, want earliest %v", flow.FirstSeen, earlier)
	}
	if !flow.LastSeen.Equal(later) {
		t.Errorf("LastSeen = %v, want latest %v", flow.LastSeen, later)
	}
}

func TestFlow_DurationZeroWhenMissingTimes(t *testing.T) {
	flow := &Flow{}
	if flow.Duration() != 0 {
		t.Errorf("Duration = %v, want 0", flow.Duration())
	}
}

func TestFlow_SetIdentityFirstWins(t *testing.T) {
	flow := &Flow{}

	flow.SetIdentity("", "Ignored")
	if flow.Hostname != "" || flow.Application != "" {
		t.Fatal("empty hostname must not set identity")
	}

	flow.SetIdentity("api.example.com", "Example")
	if flow.Hostname != "api.example.com" || flow.Application != "Example" {
		t.Fatalf("identity = %q / %q", flow.Hostname, flow.Application)
	}

	flow.SetIdentity("other.example.com", "Other")
	if flow.Hostname != "api.example.com" || flow.Application != "Example" {
		t.Fatal("later SetIdentity must not overwrite existing hostname")
	}
}

func TestFlowTracker_UDPSeparateFromTCP(t *testing.T) {
	tracker := NewFlowTracker()
	ts := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	a := Endpoint{IP: "10.0.0.1", Port: 53000}
	b := Endpoint{IP: "10.0.0.2", Port: 53}

	tcpFlow, _, _ := tracker.Track(a, b, 6, 100, ts)
	udpFlow, _, isNewUDP := tracker.Track(a, b, 17, 60, ts)

	if !isNewUDP {
		t.Fatal("UDP should create a separate flow from TCP even with same endpoints")
	}
	if tcpFlow == udpFlow {
		t.Fatal("TCP and UDP flows must be distinct")
	}
	if udpFlow.Key.Protocol != 17 {
		t.Errorf("UDP flow protocol = %d, want 17", udpFlow.Key.Protocol)
	}

	// Reverse UDP direction still maps to the same UDP flow.
	_, _, isNewReverse := tracker.Track(b, a, 17, 40, ts.Add(time.Second))
	if isNewReverse {
		t.Fatal("reverse UDP packet should not create a new flow")
	}
	if udpFlow.PacketCount != 2 || udpFlow.Bytes != 100 {
		t.Errorf("UDP flow packets=%d bytes=%d, want 2 and 100", udpFlow.PacketCount, udpFlow.Bytes)
	}
	if len(tracker.Flows()) != 2 {
		t.Fatalf("Flows() len = %d, want 2 (one TCP, one UDP)", len(tracker.Flows()))
	}
}
