package pcap

import "time"

type Endpoint struct {
	IP   string
	Port uint16
}

type FlowKey struct {
	A        Endpoint
	B        Endpoint
	Protocol uint8
}

type Direction uint8

const (
	DirectionAToB Direction = iota
	DirectionBToA
)

type Flow struct {
	Key         FlowKey
	PacketCount uint64
	Bytes       uint64
	FirstSeen   time.Time
	LastSeen    time.Time
	// Hostname and Application are optional identity from TLS SNI (or later
	// sources). Empty means unknown for this flow.
	Hostname    string
	Application string
}

// Duration is the time between the first and last packet observed for this
// flow in the capture. It reflects the capture window, not necessarily the
// full lifetime of the real TCP/UDP connection.
func (f *Flow) Duration() time.Duration {
	if f.FirstSeen.IsZero() || f.LastSeen.IsZero() {
		return 0
	}
	return f.LastSeen.Sub(f.FirstSeen)
}

// SetIdentity records the first non-empty hostname (and its application label)
// on this flow. Later calls do not overwrite an existing hostname.
func (f *Flow) SetIdentity(hostname, application string) {
	if hostname == "" || f.Hostname != "" {
		return
	}
	f.Hostname = hostname
	f.Application = application
}

func NewFlowKey(
	source Endpoint,
	destination Endpoint,
	protocol uint8,
) (FlowKey, Direction) {

	if source.IP < destination.IP ||
		(source.IP == destination.IP && source.Port <= destination.Port) {

		return FlowKey{
			A:        source,
			B:        destination,
			Protocol: protocol,
		}, DirectionAToB
	}

	return FlowKey{
		A:        destination,
		B:        source,
		Protocol: protocol,
	}, DirectionBToA
}