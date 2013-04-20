package bitmessage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	encVarstring "github.com/spearson78/guardian/encoding/varstring"
)

type parserState struct {
	magicPos      int // if == 4 means all magic bytes have been found and is ready to read data.
	pos           int
	payloadLength int
	command       string
	checksum      uint32
}

// readMessage parses a BitMessage message in the protocol-defined format and
// outputs the name of the command in the message, plus the payload content.
// It verifies that the content matches the checksum in the message header and
// throws an error otherwise.
func readMessage(r io.Reader) (command string, buf io.Reader, err error) {
	b := make([]byte, 512)
	p := parserState{}

	data := new(bytes.Buffer)

	// The first bytes aren't necessarily the beginning of a message, because
	// the TCP stream can be in an unknown state - in case there is a bug in
	// the network parser for example.
	// Find the beginning of the message, marked by magic bytes.

	for {
		var n int
		// Read at least 20 bytes because it's useless to proceed without
		// knowing the payload length. If the remote server doesn't give the
		// data this will block. In the common case, 'r' is a net.Conn with a
		// deadline set, so it shouldn't be a problem.

		n, err = io.ReadAtLeast(r, b, 20)
		for p.pos = 0; p.pos < n && p.magicPos != 4; p.pos++ {
			if b[p.pos] == magicHeaderSlice[p.magicPos] {
				p.magicPos += 1
			} else {
				p.magicPos = 0
			}
		}
		if p.magicPos == 4 {
			if len(b) > p.pos {
				// Save the extra bytes that were read unnecessarily.
				data.Write(b[p.pos:n])
			}
			break
		}
	}
	// Read the message header, including the checksum. The header's length is 20 bytes at least.
	missingData := 20 - data.Len()
	if _, err = io.CopyN(data, r, int64(missingData)); err != nil {
		return "", nil, fmt.Errorf("readMessage: error reading header: %v", err.Error())
	}
	if err := parseHeaderFields(&p, data); err != nil {
		return p.command, nil, fmt.Errorf("readMessage: %v", err.Error())
	}
	// TODO performance: depending on the command type, pipe directly do disk
	// instead of keeping all in memory?
	//
	// TODO performance: keep an arena of reusable byte slices.

	// There might be still some bytes left in 'data'. Calculate how much we
	// still have to read now.
	missingData = p.payloadLength - data.Len()
	// Copy the remaining bytes from reader to 'data'.
	if _, err := io.CopyN(data, r, int64(missingData)); err != nil && err != io.EOF {
		return p.command, nil, err
	}
	if data.Len() != p.payloadLength {
		return p.command, nil, fmt.Errorf("readMessage: stream ended before we could get the payload data, wanted length %d, got %d", p.payloadLength, data.Len())
	}
	if checksum := sha512HashPrefix(data.Bytes()); p.checksum != checksum {
		return p.command, nil, fmt.Errorf("readMessage: checksum mismatch: message advertised %x, calculated %x", p.checksum, checksum)
	}
	return p.command, data, nil
}

func parseHeaderFields(p *parserState, data io.Reader) (err error) {
	if p.command, err = parseCommand(data); err != nil {
		return fmt.Errorf("headerFields: %v", err.Error())
	}
	p.payloadLength = int(readUint32(data))
	if p.payloadLength > maxPayloadLength {
		return fmt.Errorf("headerFields: advertised payload length too large, aborting.")
	}
	p.checksum = readUint32(data)
	return nil
}

func parseCommand(r io.Reader) (command string, err error) {
	cmd := make([]byte, 12)
	if _, err = io.ReadFull(r, cmd); err != nil {
		return "", fmt.Errorf("parseCommand error: %v", err.Error())
	}
	cmd = bytes.TrimRight(cmd, "\x00")
	return string(cmd), nil
}

func parseVersion(r io.Reader) (versionMessage, error) {
	v := &binaryVersionMessage{}
	check(binary.Read(r, binary.BigEndian, v))
	fmt.Println("version", v.Version)
	fmt.Println("addr recv", parseIP(v.AddrRecv.IP))

	userAgent, _, _ := encVarstring.ReadVarString(r)
	streams := readVarIntList(r)
	version := versionMessage{*v, userAgent, streams}
	return version, nil
}

func parseAddr(r io.Reader) ([]NetworkAddress, error) {
	return readNetworkAddressList(r)
}
