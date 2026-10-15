
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

	
	// Add pending segments that overlap or begin at nextExpected.
	for {
		var pendingSeq uint32
		var pendingData []byte
		found := false

		for seq, data := range stream.pending {
			end := seq + uint32(len(data))

			// This segment is entirely behind the current position.
			if end <= stream.nextExpected {
				delete(stream.pending, seq)
				continue
			}

			// Segment overlaps nextExpected or starts exactly there.
			if seq <= stream.nextExpected {
				if !found || seq < pendingSeq {
					pendingSeq = seq
					pendingData = data
					found = true
				}
			}
		}

		if !found {
			break
		}

		delete(stream.pending, pendingSeq)

		overlap := stream.nextExpected - pendingSeq
		pendingData = pendingData[overlap:]

		stream.data = append(stream.data, pendingData...)
		stream.nextExpected += uint32(len(pendingData))
	}

	return stream.data
}
