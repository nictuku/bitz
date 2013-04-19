package bitmessage

// This file implements the main engine for this BitMessage node.

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Node struct {
	cfg *Config

	knownNodes streamNodes

	// Stats. All access must be synchronized because it's often used by other
	// goroutines (UI).
	stats stats

	recvChan chan packet
}

const (
	portNumber = 9090
	// Using same value from PyBitmessage, which was originally added to avoid memory blowups.
	// The protocol itself doesn't restrict it. This should certainly be removed
	maxPayloadLength = 180000000
)

func (n *Node) Run() {
	n.cfg = openConfig(portNumber)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portNumber))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listener att", listener.Addr())
	n.recvChan = make(chan packet)
	go listen(listener.(*net.TCPListener), n.recvChan)
	n.boot()

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
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Fatal("Can't listen to network port:", err)
			return
		}
		go handleConn(conn, recvChan)
	}
}

func handleConn(conn *net.TCPConn, recvChan chan packet) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second * 30))
	command, _, err := readMessage(conn)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("got command: %v", command)
}

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
func readMessage(r io.Reader) (command string, payload []byte, err error) {

	b := make([]byte, 512)
	p := parserState{}

	data := new(bytes.Buffer)

	// The first bytes aren't necessarily the beginning of a message, because
	// the TCP stream can be in an unknown state - in case there is a bug in
	// the network parser for example.
	// Find the beginning of the message, marked by magic bytes.
	var n int
	for {
		// Read at least 20 bytes because it's useless to proceed without
		// knowing the payload length. If the remote server doesn't give the
		// data this will block. In the common case, 'r' is a net.Conn with a
		// deadline set, so it shouldn't be a problem.

		n, err = io.ReadAtLeast(r, b, 20)

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
				data.Write(b[p.pos:n])
			}
			break
		}
	}

	// Read the message header, including the checksum.
	if _, err = io.CopyN(data, r, int64(20-n-p.pos)); err != nil {
		return "", nil, fmt.Errorf("readMessage: error reading header: %v", err.Error())
	}

	if err := parseHeaderFields(&p, data); err != nil {
		return p.command, nil, fmt.Errorf("readMessage: %v", err.Error())
	}

	// TODO performance: depending on the command type, pipe directly do disk
	// instead of keeping all in memory?
	// TODO performance: keep an arena of reusable byte slices.
	b = make([]byte, p.payloadLength)

	// Note: reading from r, not data.
	if n, err = io.ReadFull(r, b); err != nil {
		return p.command, nil, err
	}
	if n != p.payloadLength {
		return p.command, nil, fmt.Errorf("readMessage: stream ended before we could get the payload data")
	}
	if checksum := sha512HashPrefix(b); p.checksum != checksum {
		return p.command, nil, fmt.Errorf("readMessage: checksum mismatch: message advertised %x, calculated %x", p.checksum, checksum)
	}
	return p.command, b, nil
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
	return string(cmd), nil
}

// Things needing implementation.
//
// broadcastToSendDataQueues((0, 'shutdown', self.HOST))
//
// Zero out the list of already contacted nodes every 30 minutes, to give it another chance.
//
// self.receivedgetbiginv = False #Gets set to true once we receive a
// getbiginv message from our peer. An abusive peer might request it too much
// so we use this variable to check whether they have already asked for a big
// inv message.

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
