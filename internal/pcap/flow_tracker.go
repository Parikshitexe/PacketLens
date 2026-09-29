package pcap

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
) (*Flow, Direction, bool) {

    key, direction := NewFlowKey(
        source,
        destination,
        protocol,
    )

    flow, exists := t.flows[key]

    if !exists {
        flow = &Flow{
            Key: key,
        }

        t.flows[key] = flow
    }

    flow.PacketCount++
    flow.Bytes += bytes

    return flow, direction, !exists
}