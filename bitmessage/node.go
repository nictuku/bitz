package bitmessage

import (
	//	"expvar"
	//	"log"
	//"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	//encVarstring "github.com/spearson78/guardian/encoding/varstring"
)

var _ = time.Now()

// This file implements the main engine for this BitMessage node.

type Node struct {
	cfg *Config

	knownNodes streamNodes

	// Stats. All access must be synchronized because it's often used by other
	// goroutines (UI).
	stats stats

	recvChan chan packet
}

const portNumber = 9090

func (n *Node) Run() {
	n.cfg = openConfig(portNumber)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portNumber))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listener att", listener.Addr())
	n.recvChan = make(chan packet)
	go listen(listener.(*net.TCPListener), n.recvChan)

	log.Println("foo")
	n.boot()
	log.Println("foobar")

	for {
		select {
		case p := <-n.recvChan:
			fmt.Println("recvChan from %v, got: %q", p.raddr, p.b)
		}

	}
}

type packet struct {
	b     []byte
	raddr net.Addr
}

// Read from TCP , writes slice of byte into channel.
func listen(listener *net.TCPListener, recvChan chan packet) {
	log.Println("listennnn")
	for {
		log.Println("accept:")
		//listener.SetDeadline(time.Now().Add(time.Second * 30))
		conn, err := listener.AcceptTCP()
		log.Println("accept result:", conn, err)
		if err != nil {
			log.Println("CABOU")
			log.Fatal("Can't listen to network port:", err)
			return
		}
		log.Println("calling handleconn")

		go handleConn(conn, recvChan)
		// debug.Println("DHT: readResponse error:", err)
	}
}

type parserState struct {
	magicPos      int // if == 4 means all magic bytes have been found and is ready to read data.
	pos           int
	payloadLength int
	command       string
	checksum      uint32
}

func handleConn(conn *net.TCPConn, recvChan chan packet) {
	// TODO performance: move to an arena allocator.

	log.Println("handleconn")
	defer conn.Close()
	b := make([]byte, 512)
	// Payload length contained within the first 20 bites.
	//conn.SetReadDeadline(time.Now().Add(time.Second * 30))

	// XXXX PROBLEM: FIND MESSAGE BOUNDARIES.

	p := parserState{}
	// Use a reading buffer?
	// data := new(bytes.Buffer)

	// Start by reading at least 20 bytes, to find the payload length.
	n, err := io.ReadAtLeast(conn, b, 20)
	log.Println("readfull")
	data := new(bytes.Buffer)
	log.Printf("initial bytes read: %x", b[:n])
	// Find magic bytes.
	for {
		for p.pos = 0; p.pos < n && p.magicPos != 4; p.pos++ {
			if b[p.pos] == MagicHeaderSlice[p.magicPos] {
				p.magicPos += 1
			} else {
				p.magicPos = 0
			}
		}
		if p.magicPos == 4 {
			if len(b) > p.pos {
				// Save the extra bytes that were read unnecessarily.
				log.Printf("saving %x", b[p.pos:n])
				data.Write(b[p.pos:n])
			}
			break
		}
		// Read more.
		n, err = conn.Read(b)
	}
	// Add the magic bytes again, so numeric positions don't change.
	//data.Write(MagicHeaderSlice)

	// XXX
	// log.Fatal should be replaced with either reset state and try again, or close connection.

	log.Printf("reading data, pos=%d, n=%d", p.pos, n)
	//if p.pos < len(b) {
	//	data.Write(b[p.pos:n])
	//}
	_, err = io.CopyN(data, conn, int64(20-n-p.pos)) // Read the whole header, including the checksum.
	if err != nil {
		log.Fatal("copyn ", err)
	}
	log.Println("data", data.Len())
	//return
	cmd := make([]byte, 12)
	_, err = io.ReadFull(data, cmd)
	if err != nil {
		log.Fatal("command ", err, data.String())
	}
	p.command = string(cmd)
	//	if p.command != "version" {
	//		log.Fatalf("unknown command: %v, from %v, rest: %v", p.command, string(cmd), data.String())
	//	}
	log.Println("got command: %v", p.command)
	p.payloadLength = int(readUint32(data))
	log.Printf("PARSING: payload length of %d", p.payloadLength)
	if p.payloadLength > 180000000 { // Using same value from PyBitmessage. The protocol itself doesn't restrict it.
		log.Fatal("too big.")
	}
	p.checksum = readUint32(data)
	log.Printf("PARSING: checksum %x", p.checksum)

	// Pipe directly do disk instead of keeping all in memory?
	b = make([]byte, p.payloadLength)

	conn.SetDeadline(time.Now().Add(time.Minute * 5))

	// Note: reading from conn, not data.
	n, err = io.ReadFull(conn, b)
	if err != nil {
		log.Fatal(err)
	}
	if n == p.payloadLength {
		// Since ReadAtLeast() guaranteed that we read the whole payload, return now.
		log.Printf("finished reading everything. payload: %q", b)
		return
	}
	log.Println("stream ended before we could get payload data")
}

// recvChan <- packet{b[0:n], conn.RemoteAddr()}

func OFFreadFrom(n nodeMap) {
	// multiplex this somehow.
	for _, v := range n {
		if v.conn != nil {
			result, err := ioutil.ReadAll(v.conn)
			if err != nil {
				log.Println("readfrom error", err.Error())
				continue
			}
			fmt.Printf("Received: %q", result)
		}
	}
}

// Things needing implementation.
//
// broadcastToSendDataQueues((0, 'shutdown', self.HOST))
//
// Zero out the list of already contacted nodes every 30 minutes, to give it another chance.
//
// self.receivedgetbiginv = False #Gets set to true once we receive a getbiginv message from our peer. An abusive peer might request it too much so we use this variable to check whether they have already asked for a big inv message.

// #Only one singleListener thread will ever exist. It creates the
// #receiveDataThread and sendDataThread for each incoming connection. Note
// #that it cannot set the stream number because it is not known yet- the
// #other node will have to tell us its stream number in a version message. If
// #we don't care about their stream, we will close the connection (within the
// #recversion function of the recieveData thread)

// #For each stream to which we connect, several outgoingSynSender threads
// #will exist and will collectively create 8 connections with peers.
//
// Random nonce used to detect connections to self.

type stats struct {
	sync.RWMutex
	streamConnectionCount map[int]int
}

// ipPort is a string that can be resolved with net.ResolveTCPAddr("tcp",
// ipPort) and the first part can be parsed by net.ParseIP(). 
type ipPort string
