package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

type Reader struct {
	file    *os.File
	order   binary.ByteOrder
	versionMajor uint16
	versionMinor uint16
	snapLen uint32
	network uint32
}

type Packet struct {
	Timestamp     time.Time
	CapturedLength uint32
	OriginalLength uint32
	Data           []byte
}

func Open(filename string) (*Reader, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	var magic uint32

	if err := binary.Read(file, binary.LittleEndian, &magic); err != nil {
		file.Close()
		return nil, err
	}

	var order binary.ByteOrder

	switch magic {
	case 0xa1b2c3d4:
		order = binary.BigEndian
	case 0xd4c3b2a1:
		order = binary.LittleEndian
	default:
		file.Close()
		return nil, fmt.Errorf("unsupported PCAP format: magic number 0x%x", magic)
	}

	reader := &Reader{
		file:  file,
		order: order,
	}

	if err := binary.Read(file, order, &reader.versionMajor); err != nil {
		file.Close()
		return nil, err
	}

	if err := binary.Read(file, order, &reader.versionMinor); err != nil {
		file.Close()
		return nil, err
	}

	var thisZone int32
	var sigFigs uint32

	binary.Read(file, order, &thisZone)
	binary.Read(file, order, &sigFigs)

	if err := binary.Read(file, order, &reader.snapLen); err != nil {
		file.Close()
		return nil, err
	}

	if err := binary.Read(file, order, &reader.network); err != nil {
		file.Close()
		return nil, err
	}

	return reader, nil
}

func (r *Reader) NextPacket() (*Packet, error) {
	var tsSec uint32
	var tsUsec uint32
	var capturedLength uint32
	var originalLength uint32

	err := binary.Read(r.file, r.order, &tsSec)

	if err == io.EOF {
		return nil, io.EOF
	}

	if err != nil {
		return nil, err
	}

	if err := binary.Read(r.file, r.order, &tsUsec); err != nil {
		return nil, err
	}

	if err := binary.Read(r.file, r.order, &capturedLength); err != nil {
		return nil, err
	}

	if err := binary.Read(r.file, r.order, &originalLength); err != nil {
		return nil, err
	}

	data := make([]byte, capturedLength)

	if _, err := io.ReadFull(r.file, data); err != nil {
		return nil, err
	}

	packet := &Packet{
		Timestamp:      time.Unix(int64(tsSec), int64(tsUsec)*1000),
		CapturedLength: capturedLength,
		OriginalLength: originalLength,
		Data:           data,
	}

	return packet, nil
}

func (r *Reader) Close() error {
	return r.file.Close()
}