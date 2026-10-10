
package pcap

type TCPStreamKey struct {
	Flow      FlowKey
	Direction Direction
}

type tcpStream struct {
	initialized bool
	nextExpected uint32
	data         []byte
	pending      map[uint32][]byte
}

type TCPStreamTracker struct {
	streams map[TCPStreamKey]*tcpStream
}

func NewTCPStreamTracker() *TCPStreamTracker {
	return &TCPStreamTracker{
		streams: make(map[TCPStreamKey]*tcpStream),
	}
}

func (t *TCPStreamTracker) Add(
	key TCPStreamKey,
	seq uint32,
	syn bool,
	payload []byte,
) []byte {
	stream, exists := t.streams[key]
	if !exists {
		stream = &tcpStream{
			pending: make(map[uint32][]byte),
		}
		t.streams[key] = stream
	}

	// SYN consumes one sequence number.
	if syn {
		if !stream.initialized {
			stream.initialized = true
			stream.nextExpected = seq + 1
		}
		seq++
	} else if !stream.initialized {
		// Fallback when capture starts mid-connection.
		stream.initialized = true
		stream.nextExpected = seq
	}

	if len(payload) == 0 {
		return stream.data
	}

	// Ignore already-received bytes and trim partial overlap.
	if seq < stream.nextExpected {
		overlap := stream.nextExpected - seq

		if overlap >= uint32(len(payload)) {
			return stream.data
		}

		payload = payload[overlap:]
		seq = stream.nextExpected
	}

	// This segment starts after a missing byte range.
	if seq > stream.nextExpected {
		if _, exists := stream.pending[seq]; !exists {
			stream.pending[seq] = append([]byte(nil), payload...)
		}
		return stream.data
	}

	// Append contiguous bytes.
	stream.data = append(stream.data, payload...)
	stream.nextExpected += uint32(len(payload))

	// Add any pending segment that now fits.
	for {
		next, exists := stream.pending[stream.nextExpected]
		if !exists {
			break
		}

		delete(stream.pending, stream.nextExpected)
		stream.data = append(stream.data, next...)
		stream.nextExpected += uint32(len(next))
	}

	return stream.data
}
