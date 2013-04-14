package bitmessage

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"time"

	encVarint "github.com/spearson78/guardian/encoding/varint"
	encVarstring "github.com/spearson78/guardian/encoding/varstring"
)

// This file implements functions typically performed when the node is
// starting up - be it the inital run for this client or when the process is
// restarted.

var bootstrapNodes = [][]string{
	//{"bootstrap8080.bitmessage.org", "8080"},
	//{"bootstrap8444.bitmessage.org", "8444"},
	// good:
	//{"217.91.97.196", "8444"},

	{"192.168.11.8", "8444"},
}

// findBootStrapNodes uses DNS resolution for finding bootstrap nodes for the
// network. The list of DNS hosts was obtained from the original client source
// in 2013-04-14. TODO: provide our own bootstrap nodes.
func findBootstrapNodes() (nodes []net.TCPAddr) {
	// XXX randomize.
	for _, node := range bootstrapNodes {
		if addrs, err := net.LookupIP(node[0]); err != nil {
			// XXX spammy.
			log.Printf("findBootStrapNodes LookupAddr %v: error %v", node[0], err.Error())
		} else {
			if port, err := strconv.Atoi(node[1]); err == nil {
				for _, addr := range addrs {
					nodes = append(nodes, net.TCPAddr{addr, port})
				}

			}
		}

	}
	return nodes
}

const nodeConnectionRetryPeriod = time.Minute * 30

// When a node creates an outgoing connection, it will immediately advertise
// its version. The remote node will respond with its version. No futher
// communication is possible until both peers have exchanged their version.

func sendVersion(nodes nodeMap) {
	// XXX move this to writeVersion, similar to writeNetworkAddress.

	var err error
	services := uint64(ConnectionServiceNodeNetwork) // + other bitfields.
	//	t := time.Now().Second()
	userAgent := new(bytes.Buffer)
	//encVarstring.WriteVarString(userAgent, "/bitz:1/")
	// Don't attract attention just yet.
	encVarstring.WriteVarString(userAgent, "/PyBitmessage:0.2.8/")
	streams := []int{1}
	streamNumbers := new(bytes.Buffer)

	encVarint.WriteVarInt(streamNumbers, uint64(len(streams)))
	for _, v := range streams {
		encVarint.WriteVarInt(streamNumbers, uint64(v))
	}

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
}

func c(err error) {
	if err != nil {
		log.Println("error", err.Error())
	}
}
