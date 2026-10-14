package pcap

import "testing"

func TestClassifyHostname(t *testing.T) {
	classifier := &ApplicationClassifier{
		rules: []DomainRule{
			{Domain: "cursor.sh", Application: "Cursor"},
			{Domain: "google.com", Application: "Google"},
			{Domain: "wix.com", Application: "Wix"},
		},
	}

	tests := []struct {
		hostname string
		want     string
	}{
		{"api2.cursor.sh", "Cursor"},
		{"mail.google.com", "Google"},
		{"accounts.google.com", "Google"},
		{"www.wix.com", "Wix"},
		{"notgoogle.com", "Unknown"},
		{"unknown.example", "Unknown"},
	}

	for _, tt := range tests {
		got := classifier.ClassifyHostname(tt.hostname)

		if got != tt.want {
			t.Errorf(
				"ClassifyHostname(%q) = %q, want %q",
				tt.hostname,
				got,
				tt.want,
			)
		}
	}
}
