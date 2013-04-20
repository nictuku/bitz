package bitmessage

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"

	encVarstring "github.com/spearson78/guardian/encoding/varstring"
)

func init() {

	buf := new(bytes.Buffer)
	// Don't attract attention to this client just yet, use the vanilla client
	// user agent.
	// encVarstring.WriteVarString(userAgent, "/bitz:1/")
	encVarstring.WriteVarString(buf, "/PyBitmessage:0.2.8/")
	userAgent = buf.Bytes()

	buf = new(bytes.Buffer)
	putVarIntList(buf, []uint64{1})
	streamNumbers = buf.Bytes()

	err := binary.Read(rand.Reader, binary.LittleEndian, &nonce)
	if err != nil {
		log.Fatal("nonce number generator failed. Aborting startup.")
	}
}

var (
	// These values should never be changed after they are written for the first time.
	nonce         uint64                                 // Filled by init().
	services      = uint64(ConnectionServiceNodeNetwork) // Only one bit is used for now.
	streamNumbers = []byte{}                             // Only using stream 1 for now. 
	userAgent     = []byte{}                             // Filled by init().

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
	putUint64(buf, 31312830129)

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
