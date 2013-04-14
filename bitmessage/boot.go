package bitmessage

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"time"

	"crypto/sha512"

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

func sendVersion(nodes nodeMap) {
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
		AddrFrom: NetworkAddress{
			services: services,
			ip:       [16]byte{'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xFF', '\xFF', 127, 0, 0, 1},
			port:     portNumber,
		},
		Nonce: 31312830129, // XXX
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
			ip := tcp.IP
			v.AddrRecv = NetworkAddress{
				services: services,
				ip:       [16]byte{'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xFF', '\xFF', ip[0], ip[1], ip[2], ip[3]},
				port:     uint16(tcp.Port),
			}
			p := new(bytes.Buffer)
			if err = binary.Write(p, binary.BigEndian, v.Version); err != nil {
				log.Println("send version error", err.Error())
			}
			if err = binary.Write(p, binary.BigEndian, v.Services); err != nil {
				log.Println("send version error", err.Error())
			}
			// already in addrrecv
			if err = binary.Write(p, binary.BigEndian, v.Timestamp); err != nil {
				log.Println("send version error", err.Error())
			}

			if err = binary.Write(p, binary.BigEndian, v.AddrRecv); err != nil {
				log.Println("send version error", err.Error())
			}
			if err = binary.Write(p, binary.BigEndian, v.AddrFrom); err != nil {
				log.Println("send version error", err.Error())
			}
			if err = binary.Write(p, binary.BigEndian, v.Nonce); err != nil {
				log.Println("send version error", err.Error())
			}
			if err = binary.Write(p, binary.BigEndian, v.UserAgent); err != nil {
				log.Println("send version error", err.Error())
			}
			if err = binary.Write(p, binary.BigEndian, v.StreamNumbers); err != nil {
				log.Println("send version error", err.Error())
			}
			b := p.Bytes()

			data := new(bytes.Buffer)

			c(binary.Write(data, binary.BigEndian, MagicHeader))
			//data := MagicHeader
			c(binary.Write(data, binary.BigEndian, []byte("version\x00\x00\x00\x00\x00")))
			c(binary.Write(data, binary.BigEndian, uint32(len(b))))
			s := sha512.New()
			s.Write(b)
			c(binary.Write(data, binary.BigEndian, s.Sum(nil)[0:4]))
			c(binary.Write(data, binary.BigEndian, b))

			what := data.Bytes()
			log.Printf("PRINTING: magic %q, len %d", what[0:4], len(what[0:4]))
			log.Printf("PRINTING: commnand %q, len %d", what[4:16], len(what[0:16]))
			log.Printf("PRINTING: len %q, len %d", what[16:20], len(what[16:20]))
			log.Printf("PRINTING: checksum %q, len %d", what[20:24], len(what[20:24]))

			// Message
			log.Printf("DATA: version %q, len %d", what[24:28], len(what[24:28]))
			log.Printf("DATA: services %q, len %d", what[28:36], len(what[28:36]))
			log.Printf("DATA: timestamp %q, len %d", what[36:44], len(what[36:44]))
			log.Printf("DATA: addrecv %q, len %d", what[44:70], len(what[44:70]))
			log.Printf("DATA: addfrom %q, len %d", what[70:96], len(what[70:96]))
			log.Printf("DATA: nonce %q, len %d", what[96:104], len(what[96:104]))
			log.Printf("DATA: useragent+streamnumbers %q, len %d", what[105:], len(what[105:]))

			if _, err := node.conn.Write(what); err != nil {
				log.Println("conn write failed", err)
			}

		}

	}
}

func c(err error) {
	if err != nil {
		log.Println("error", err.Error())
	}
}
