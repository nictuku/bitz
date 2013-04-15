package bitmessage

import (
	//	"expvar"
	//	"log"
	//"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
)

// This file implements the main engine for this BitMessage node.

type Node struct {
	cfg *Config

	knownNodes streamNodes

	// Stats. All access must be synchronized because it's often used by other
	// goroutines (UI).
	stats stats
}

const portNumber = 9090

func (n *Node) Run() {
	n.cfg = openConfig(portNumber)

	if n.knownNodes == nil {
		n.knownNodes = make(streamNodes)
	}
	// Add bootstrap nodes to stream 1.
	for _, node := range findBootstrapNodes() {
		if stream, ok := n.knownNodes[1]; !ok {
			stream = make(nodeMap)
			n.knownNodes[1] = stream
		}

		n.knownNodes[1][ipPort(node.String())] = remoteNode{}
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portNumber))
	if err != nil {
		log.Fatal(err)
	}
	recvChan := make(chan packet)
	go listen(listener.(*net.TCPListener), recvChan)

	// Keep trying to connect to nodes.
	// Current bitmessage clients only connect to stream 1.
	nodes := n.knownNodes[1]
	handshake(nodes)

	for {
		select {
		case p := <-recvChan:
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
			continue
		}
		go handleConn(conn, recvChan)
		// debug.Println("DHT: readResponse error:", err)
	}
}

func handleConn(conn *net.TCPConn, recvChan chan packet) {
	// TODO performance: move to an arena allocator.
	b := make([]byte, 0, 1024)
	for {
		n, err := conn.Read(b)
		b = b[0:n]
		if n > 0 && err == nil {
			recvChan <- packet{b, conn.RemoteAddr()}
		}
	}
}

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
