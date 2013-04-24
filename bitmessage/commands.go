package bitmessage

import (
	"bytes"
	"io"
	"net"
	"time"
)

// When a node creates an outgoing connection, it will immediately advertise
// its version. The remote node will respond with its version. No futher
// communication is possible until both peers have exchanged their version.
func writeVersion(w io.Writer, dest *net.TCPAddr) {
	buf := new(bytes.Buffer)
	putInt32(buf, protocolVersion)
	// bitfield of features to be enabled for this connection.
	// uint64
	putUint64(buf, services)
	// standard UNIX timestamp in seconds
	// int64
	putInt64(buf, time.Now().Unix())
	// The network address of the node receiving this message (not including
	// the time or stream number)
	check(writeNetworkAddress(buf, dest))
	// The network address of the node emitting this message (not including
	// the time or stream number and the ip itself is ignored by the receiver)
	check(writeNetworkAddress(buf, nil))

	// Random nonce used to detect connections to self.
	putUint64(buf, nonce)

	// User Agent (0x00 if string is 0 bytes long).
	// varstring already encoded.
	putBytes(buf, userAgent)

	// The stream numbers that the emitting node is interested in.
	// var_int_list	already encoded.
	putBytes(buf, streamNumbers)

	writeMessage(w, "version", buf.Bytes())
}

// The verack message is sent in reply to version. This message consists of
// only a message header with the command string "verack".
func writeVerack(w io.Writer) {
	writeMessage(w, "verack", []byte{})
}

// Provide information on known nodes of the network. Non-advertised nodes
// should be forgotten after typically 3 hours.
// func writeAddr

// InvMessage allows a node to advertise its knowledge of one or more objects.
// It can be received unsolicited, or in reply to getmessages.
// Maximum payload length: 50000 items.
// func writeInv

// getdata is used in response to an inv message to retrieve the content of a specific object after filtering known elements.
// Payload (maximum payload length: 50000 entries):
func writeGetData(w io.Writer, invs []inventoryVector) {
	buf := new(bytes.Buffer)
	check(writeInventoryVector(buf, invs))
	writeMessage(w, "getdata", buf.Bytes())
}
