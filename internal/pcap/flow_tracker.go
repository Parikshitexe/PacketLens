package pcap

import "time"

type FlowTracker struct {
	flows map[FlowKey]*Flow
}

func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		flows: make(map[FlowKey]*Flow),
	}
}

func (t *FlowTracker) Track(
	source Endpoint,
	destination Endpoint,
	protocol uint8,
	bytes uint64,
	timestamp time.Time,
) (*Flow, Direction, bool) {

	key, direction := NewFlowKey(
		source,
		destination,
		protocol,
	)

	flow, exists := t.flows[key]

	if !exists {
		flow = &Flow{
			Key:       key,
			FirstSeen: timestamp,
			LastSeen:  timestamp,
		}

		t.flows[key] = flow
	} else {
		if flow.FirstSeen.IsZero() || timestamp.Before(flow.FirstSeen) {
			flow.FirstSeen = timestamp
		}
		if timestamp.After(flow.LastSeen) {
			flow.LastSeen = timestamp
		}
	}

	flow.PacketCount++
	flow.Bytes += bytes

	return flow, direction, !exists
}

// Flows returns all tracked flows. The order is not guaranteed; callers
// should sort if they need a stable presentation order.
func (t *FlowTracker) Flows() []*Flow {
	flows := make([]*Flow, 0, len(t.flows))
	for _, flow := range t.flows {
		flows = append(flows, flow)
	}
	return flows
}
