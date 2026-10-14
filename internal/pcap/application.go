package pcap

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type DomainRule struct {
	Domain      string `json:"domain"`
	Application string `json:"application"`
}

type AppDomainConfig struct {
	Rules []DomainRule `json:"rules"`
}

type ApplicationClassifier struct {
	rules []DomainRule
}

func LoadApplicationClassifier(path string) (*ApplicationClassifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read application config: %w", err)
	}

	var config AppDomainConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse application config: %w", err)
	}

	for _, rule := range config.Rules {
		if strings.TrimSpace(rule.Domain) == "" ||
			strings.TrimSpace(rule.Application) == "" {
			return nil, fmt.Errorf("domain and application must not be empty")
		}
	}

	return &ApplicationClassifier{
		rules: config.Rules,
	}, nil
}

func (c *ApplicationClassifier) ClassifyHostname(hostname string) string {
	host := strings.ToLower(strings.TrimSuffix(
		strings.TrimSpace(hostname), ".",
	))

	for _, rule := range c.rules {
		domain := strings.ToLower(strings.TrimSpace(rule.Domain))
		domain = strings.TrimSuffix(domain, ".")

		if host == domain || strings.HasSuffix(host, "."+domain) {
			return rule.Application
		}
	}

	return "Unknown"
}
