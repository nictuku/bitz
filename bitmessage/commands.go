package bitmessage

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"

	encVarint "github.com/spearson78/guardian/encoding/varint"
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
	streams := []int{1}
	if _, err := encVarint.WriteVarInt(buf, uint64(len(streams))); err != nil {
		log.Fatalln("streams length.", err.Error())

	}
	for _, v := range streams {
		if _, err := encVarint.WriteVarInt(buf, uint64(v)); err != nil {
			log.Fatalln("streams.", err.Error())
		}
	}
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
	/*
		v := VersionMessage{
			Version:   1,
			Services:  services, // | other bits.
			Timestamp: int64(time.Now().Unix()),
			Nonce:     31312830129, // XXX
			// User Agent (0x00 if string is 0 bytes long)
			UserAgent: userAgent.Bytes(),
			// The stream numbers that the emitting node is interested in.
			StreamNumbers: streamNumbers.Bytes(),
		}
		log.Println("nodes", nodes)
		for ipPort, node := range nodes {

			if node.conn == nil {
				log.Println("nil")
				if !node.lastContacted.IsZero() && time.Since(node.lastContacted) < nodeConnectionRetryPeriod {
					// 
					continue
				}

				node.conn, err = net.Dial("tcp", string(ipPort))
				//node.lastContacted = time.Now()

				if err != nil {
					log.Printf("error connecting to node %v: %v", ipPort, err)
					continue
				}
				log.Println("establishing connection")
				tcp, ok := node.conn.RemoteAddr().(*net.TCPAddr)
				if !ok {
					log.Println("programming error? sendVersion RemoteAddr not *TCPAddr.")
					continue
				}

				p := new(bytes.Buffer)

				// Identifies protocol version being used by the node.
				// int32

				if err = binary.Write(p, binary.BigEndian, v.Version); err != nil {
					log.Println("send version error", err.Error())
				}
				// bitfield of features to be enabled for this connection.
				// uint64
				if err = binary.Write(p, binary.BigEndian, v.Services); err != nil {
					log.Println("send version error", err.Error())
				}
				// standard UNIX timestamp in seconds
				// int64
				if err = binary.Write(p, binary.BigEndian, v.Timestamp); err != nil {
					log.Println("send version error", err.Error())
				}
				// The network address of the node receiving this message (not including
				// the time or stream number)
				writeNetworkAddress(p, tcp)
				// The network address of the node emitting this message (not including
				// the time or stream number and the ip itself is ignored by the receiver)
				writeNetworkAddress(p, nil)

				// Random nonce used to detect connections to self.

				if err = binary.Write(p, binary.BigEndian, v.Nonce); err != nil {
					log.Println("send version error", err.Error())
				}
				// User Agent (0x00 if string is 0 bytes long)
				if err = binary.Write(p, binary.BigEndian, v.UserAgent); err != nil {
					log.Println("send version error", err.Error())
				}
				// The stream numbers that the emitting node is interested in.
				if err = binary.Write(p, binary.BigEndian, v.StreamNumbers); err != nil {
					log.Println("send version error", err.Error())
				}
				b := p.Bytes()
				writeMessage(node.conn, "version", b)
			}

		}
	*/
}
