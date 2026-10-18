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

type PacketLensReport struct {
	InputFile       string              `json:"input_file"`
	TotalPackets    int                 `json:"total_packets"`
	UniqueHostnames int                 `json:"unique_hostnames"`
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
