package bitmessage

// This file implements the main engine for this BitMessage node.

import (
	"bytes"
	"fmt"
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
	log.Println("Listening at", listener.Addr())
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

type peerState struct {
	versionMatch bool
}

func handleConn(conn *net.TCPConn, recvChan chan packet) {
	defer conn.Close()

	p := peerState{}
	for {
		conn.SetReadDeadline(time.Now().Add(time.Second * 30))
		command, payload, err := readMessage(conn)
		if err != nil {
			log.Println("handleConn:", err)
			return
		}
		log.Printf("got command: %v", command)
		switch command {
		case "version":
			if p.versionMatch {
				log.Println("received a 'version' message from a host we already went through a version exchange. Closing the connection.")
				return
			}

			// XXX move readmessage to return a reader?
			version, err := parseVersion(bytes.NewBuffer(payload))
			if err != nil {
				log.Println("parseVersion:", err)
				return
			}
			if version.Version != protocolVersion {
				log.Printf("protocol version not supported: got %d, wanted %d.Closing the connection", version.Version, protocolVersion)
				return
			}
			p.versionMatch = true
			writeVerack(conn)
		}
	}
	// XXX send something to recvChan.
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
