
package pcap

import (
	"encoding/binary"
	"fmt"
)

func ParseTLSClientHello(data []byte) (string, error) {
	if len(data) < 9 {
		return "", fmt.Errorf("TLS data too short")
	}

	// TLS Handshake record
	if data[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake record")
	}

	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLength {
		return "", fmt.Errorf("incomplete TLS record")
	}

	// ClientHello handshake message
	if data[5] != 0x01 {
		return "", fmt.Errorf("not a ClientHello")
	}

	hello := data[9 : 5+recordLength]

	// Skip legacy version (2 bytes) and random (32 bytes).
	if len(hello) < 34 {
		return "", fmt.Errorf("ClientHello too short")
	}
	pos := 34

	// Session ID
	if pos >= len(hello) {
		return "", fmt.Errorf("missing session ID")
	}
	sessionIDLength := int(hello[pos])
	pos++
	if pos+sessionIDLength > len(hello) {
		return "", fmt.Errorf("invalid session ID length")
	}
	pos += sessionIDLength

	// Cipher suites
	if pos+2 > len(hello) {
		return "", fmt.Errorf("missing cipher suites length")
	}
	cipherLength := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	if pos+cipherLength > len(hello) {
		return "", fmt.Errorf("invalid cipher suites length")
	}
	pos += cipherLength

	// Compression methods
	if pos >= len(hello) {
		return "", fmt.Errorf("missing compression methods")
	}
	compressionLength := int(hello[pos])
	pos++
	if pos+compressionLength > len(hello) {
		return "", fmt.Errorf("invalid compression methods length")
	}
	pos += compressionLength

	// Extensions
	if pos == len(hello) {
		return "", fmt.Errorf("no extensions found")
	}
	if pos+2 > len(hello) {
		return "", fmt.Errorf("missing extensions length")
	}
	extensionsLength := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2

	extensionsEnd := pos + extensionsLength
	if extensionsEnd > len(hello) {
		return "", fmt.Errorf("invalid extensions length")
	}

	for pos+4 <= extensionsEnd {
		extensionType := binary.BigEndian.Uint16(hello[pos : pos+2])
		extensionLength := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		pos += 4

		if pos+extensionLength > extensionsEnd {
			return "", fmt.Errorf("invalid extension length")
		}

		// SNI extension type is 0.
		if extensionType == 0 {
			extension := hello[pos : pos+extensionLength]

			if len(extension) < 5 {
				return "", fmt.Errorf("SNI extension too short")
			}

			nameType := extension[2]
			nameLength := int(binary.BigEndian.Uint16(extension[3:5]))

			if nameType != 0 || 5+nameLength > len(extension) {
				return "", fmt.Errorf("invalid SNI hostname")
			}

			return string(extension[5 : 5+nameLength]), nil
		}

		pos += extensionLength
	}

	return "", fmt.Errorf("SNI hostname not found")
}
