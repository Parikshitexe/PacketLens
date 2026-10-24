package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type HostnameReport struct {
	Hostname     string `json:"hostname"`
	Observations int    `json:"observations"`
	Application  string `json:"application"`
}

type ApplicationReport struct {
	Name         string `json:"name"`
	Observations int    `json:"observations"`
}

// ConnectionReport is one bidirectional flow observed in the capture.
// Bytes is the sum of captured frame lengths (PCAP captured length), not
// necessarily IP payload size.
type ConnectionReport struct {
	EndpointA    string  `json:"endpoint_a"`
	EndpointB    string  `json:"endpoint_b"`
	Protocol     string  `json:"protocol"`
	PacketCount  uint64  `json:"packet_count"`
	Bytes        uint64  `json:"bytes"`
	FirstSeen    string  `json:"first_seen"`
	LastSeen     string  `json:"last_seen"`
	DurationSecs float64 `json:"duration_secs"`
	Hostname     string  `json:"hostname,omitempty"`
	Application  string  `json:"application,omitempty"`
}

type PacketLensReport struct {
	InputFile       string              `json:"input_file"`
	TotalPackets    int                 `json:"total_packets"`
	TotalFlows      int                 `json:"total_flows"`
	UniqueHostnames int                 `json:"unique_hostnames"`
	Connections     []ConnectionReport  `json:"connections"`
	Hostnames       []HostnameReport    `json:"hostnames"`
	Applications    []ApplicationReport `json:"applications"`
}

func WriteJSONReport(path string, report PacketLensReport) error {
	report.InputFile = filepath.Base(report.InputFile)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
