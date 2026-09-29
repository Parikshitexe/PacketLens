package pcap

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