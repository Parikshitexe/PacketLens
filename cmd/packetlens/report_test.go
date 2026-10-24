package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSONReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")

	report := PacketLensReport{
		InputFile:       `captures\traffic.pcap`,
		TotalPackets:    100,
		TotalFlows:      1,
		UniqueHostnames: 2,
		Connections: []ConnectionReport{
			{
				EndpointA:    "10.0.0.1:50000",
				EndpointB:    "10.0.0.2:443",
				Protocol:     "TCP",
				PacketCount:  10,
				Bytes:        1500,
				FirstSeen:    "2024-01-01T12:00:00Z",
				LastSeen:     "2024-01-01T12:00:05Z",
				DurationSecs: 5,
				Hostname:     "example.com",
				Application:  "Example",
			},
		},
		Hostnames: []HostnameReport{
			{
				Hostname:     "example.com",
				Observations: 3,
				Application:  "Example",
			},
			{
				Hostname:     "unknown.example",
				Observations: 1,
				Application:  "Unknown",
			},
		},
		Applications: []ApplicationReport{
			{Name: "Example", Observations: 3},
			{Name: "Unknown", Observations: 1},
		},
		DNS: DNSReport{
			Queries:   2,
			Responses: 1,
			QueryNames: []DNSNameCountReport{
				{Name: "example.com", Count: 2},
			},
			ResponseCodes: []DNSResponseCodeReport{
				{Code: "NOERROR", Count: 1},
			},
			Resolutions: []DNSResolutionReport{
				{Name: "example.com", IPs: []string{"93.184.216.34"}},
			},
		},
	}

	if err := WriteJSONReport(path, report); err != nil {
		t.Fatalf("WriteJSONReport() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	var got PacketLensReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if got.InputFile != "traffic.pcap" {
		t.Errorf("input_file = %q, want %q", got.InputFile, "traffic.pcap")
	}

	if got.TotalPackets != 100 {
		t.Errorf("total_packets = %d, want 100", got.TotalPackets)
	}

	if got.UniqueHostnames != 2 {
		t.Errorf("unique_hostnames = %d, want 2", got.UniqueHostnames)
	}

	if got.TotalFlows != 1 {
		t.Errorf("total_flows = %d, want 1", got.TotalFlows)
	}

	if len(got.Connections) != 1 {
		t.Fatalf("got %d connections, want 1", len(got.Connections))
	}

	if got.Connections[0].Protocol != "TCP" {
		t.Errorf("connection protocol = %q, want TCP", got.Connections[0].Protocol)
	}

	if got.Connections[0].Hostname != "example.com" {
		t.Errorf("connection hostname = %q, want example.com", got.Connections[0].Hostname)
	}

	if got.Connections[0].Application != "Example" {
		t.Errorf("connection application = %q, want Example", got.Connections[0].Application)
	}

	if len(got.Hostnames) != 2 {
		t.Fatalf("got %d hostnames, want 2", len(got.Hostnames))
	}

	if got.Hostnames[1].Application != "Unknown" {
		t.Errorf("unknown application was not preserved")
	}

	if len(got.Applications) != 2 {
		t.Errorf("got %d applications, want 2", len(got.Applications))
	}

	if got.DNS.Queries != 2 || got.DNS.Responses != 1 {
		t.Errorf("dns queries/responses = %d/%d, want 2/1", got.DNS.Queries, got.DNS.Responses)
	}

	if len(got.DNS.Resolutions) != 1 || got.DNS.Resolutions[0].Name != "example.com" {
		t.Errorf("dns resolutions not preserved: %+v", got.DNS.Resolutions)
	}
}
