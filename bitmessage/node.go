package bitmessage

// This file implements the main engine for this BitMessage node.

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Node struct {
	cfg        *Config
	knownNodes streamNodes
	// Stats. All access must be synchronized because it's often used by other
	// goroutines (UI).
	stats stats
	resp  responses
}

type responses struct {
	nodesChan chan []extendedNetworkAddress
}

func (n *Node) Run() {
	n.cfg = openConfig(PortNumber)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", PortNumber))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Listening at", listener.Addr())
	n.resp = responses{make(chan []extendedNetworkAddress)}
	go listen(listener.(*net.TCPListener), n.resp)
	go n.bootstrap()

	for {
		select {
		case addrs := <-n.resp.nodesChan:
			log.Printf("nodesChan, got: %d nodes", len(addrs))
		}

	}
}

type packet struct {
	b     []byte
	raddr net.Addr
}

// Read from TCP , writes slice of byte into channel.
func listen(listener *net.TCPListener, resp responses) {
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Fatal("Can't listen to network port:", err)
			return
		}
		go handleConn(conn, resp)
	}
}

type peerState struct {
	established    bool // when 'verack' has been sent and received.
	verackSent     bool
	verackReceived bool
}

func handleConn(conn *net.TCPConn, resp responses) {
	defer conn.Close()

	p := &peerState{}
	for {
		conn.SetReadDeadline(time.Now().Add(connectionTimeout))
		command, payload, err := readMessage(conn)
		if err != nil {
			log.Println("handleConn:", err)
			return
		}
		log.Printf("got command: %v", command)
		switch command {
		case "version":
			err = handleVersion(conn, p, payload)
		case "addr":
			err = handleAddr(conn, p, payload, resp.nodesChan)

		case "verack":
			err = handleVerack(conn, p)
		default:
			log.Println("ignoring unknown command %q", command)
		}
		if err != nil {
			return
		}
	}
}

func handleVersion(conn io.Writer, p *peerState, payload io.Reader) error {
	if p.established {
		return fmt.Errorf("received a 'version' message from a host we already went through a version exchange. Closing the connection.")
	}
	version, err := parseVersion(payload)
	if err != nil {
		return fmt.Errorf("parseVersion: %v", err)
	}
	if version.Version != protocolVersion {
		return fmt.Errorf("protocol version not supported: got %d, wanted %d.Closing the connection", version.Version, protocolVersion)
	}
	if p.verackSent == false {
		writeVerack(conn)
	}
	p.verackSent = true
	if p.verackReceived {
		p.established = true
	}
	return nil
}

func handleVerack(conn io.Writer, p *peerState) error {
	if p.verackReceived {
		return fmt.Errorf("received 'verack' twice from a node. Closing connection")
	}
	p.verackReceived = true
	if p.verackSent {
		p.established = true
	}
	return nil
}

func handleAddr(conn io.Writer, p *peerState, payload io.Reader, respNodes chan []extendedNetworkAddress) error {
	if !p.established {
		return fmt.Errorf("version unknown. Closing connection")
	}
	addrs, err := parseAddr(payload)
	if err != nil {
		return fmt.Errorf("parseAddr error: %v. Closing connection", err)
	}
	log.Println("respNodes starting")
	respNodes <- addrs
	log.Println("respNodes done")
	return nil
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
