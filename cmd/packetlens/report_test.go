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
		UniqueHostnames: 2,
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

	if len(got.Hostnames) != 2 {
		t.Fatalf("got %d hostnames, want 2", len(got.Hostnames))
	}

	if got.Hostnames[1].Application != "Unknown" {
		t.Errorf("unknown application was not preserved")
	}

	if len(got.Applications) != 2 {
		t.Errorf("got %d applications, want 2", len(got.Applications))
	}
}
