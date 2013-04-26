package bitmessage

// This file implements the main engine for this BitMessage node.

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/pmylund/go-bloom"
	"sync"
)

type Node struct {
	// All members can only be accessed by the main server routine inside
	// Run().
	cfg *Config
	// Stats. All access must be synchronized because it's often used by other
	// goroutines (UI).
	stats stats
	resp  responses
	// connectedNodes are all nodes we have a connection established to, for
	// each stream.
	connectedNodes streamNodes
	// Bloomfilter of unreachable IPs.
	// TODO: Rotate the filters and expire them.
	// TODO: Save it on disk.
	unreachableNodes *bloom.Filter
	// connectedNodes are all nodes we know of for each stream number in
	// addition to the connectedNodes.
	knownNodes streamNodes
	objects    objectsInventory
}

type responses struct {
	addrsChan   chan []extendedNetworkAddress
	addNodeChan chan extendedNetworkAddress
	delNodeChan chan extendedNetworkAddress
	invChan     chan objectsInventory
}

func (n *Node) Run() {
	n.connectedNodes = make(streamNodes)
	n.knownNodes = make(streamNodes)
	n.objects = make(objectsInventory)
	n.unreachableNodes = bloom.New(10000, 0.01)

	n.cfg = openConfig(PortNumber)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", PortNumber))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Listening at", listener.Addr())
	n.resp = responses{
		make(chan []extendedNetworkAddress),
		make(chan extendedNetworkAddress),
		make(chan extendedNetworkAddress),
		make(chan objectsInventory),
	}
	go listen(listener.(*net.TCPListener), n.resp)
	n.bootstrap()
	// TODO: do this less frequently.
	// TODO: add signal handler for saving on exit.
	saveTick := time.Tick(time.Second * 1)
	for {
		select {
		case addrs := <-n.resp.addrsChan:
			log.Printf("nodesChan, got: %d nodes", len(addrs))
			// Only connect to stream one for now.

			needExtra := numNodesForMainStream - n.numStreamNodes(streamOne)
			i := 0
			// This is imprecise because I check the count of nodes using a
			// metric that is only updated after the connection is
			// established, not soon after a handshake goroutine is
			// dispatched. That's fine, we'll just a have a few extra too may
			// nodes.
			log.Println("need extra", needExtra)
			for _, addr := range addrs {
				if addr.Stream != streamOne {
					continue
				}
				if _, ok := n.connectedNodes[streamOne][addr.ipPort()]; ok {
					continue
				}
				if n.unreachableNodes.Test(addr.IP[:]) {
					continue
				}
				node := remoteNode{}
				if i <= needExtra {
					log.Println("handshaking with", addr.ipPort())
					// Nodes for which the connection attempt fail won't even
					// make it to n.knownNodes.
					go handshake(addr.ipPort(), node, n.resp)
					i++
				} else {
					n.addKnownNode(int(addr.Stream), addr.ipPort(), node)
				}
			}

		case addr := <-n.resp.addNodeChan:
			node := remoteNode{lastContacted: time.Now()}
			n.addNode(int(addr.Stream), addr.ipPort(), node)
		case addr := <-n.resp.delNodeChan:
			n.delNode(int(addr.Stream), addr.ipPort())
			n.unreachableNodes.Add(addr.IP[:])
			// XXX if connection counter drops below numNodesforMainStream,
			// get a node from knownNodes and promote it.
		case obj := <-n.resp.invChan:
			n.objects.merge(obj)
		case <-saveTick:
			n.cfg.save(n.connectedNodes)
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
	ipPort         ipPort
}

func handleConn(conn *net.TCPConn, resp responses) {
	defer conn.Close()

	p := &peerState{}
	p.ipPort = ipPort(conn.RemoteAddr().String())
	for {

		conn.SetReadDeadline(time.Now().Add(connectionTimeout))
		command, payload, err := readMessage(conn)
		if err != nil {
			log.Println("handleConn:", err)
			resp.delNodeChan <- p.ipPort.toNetworkAddress()
			return
		}
		log.Printf("got command: %v", command)
		switch command {
		case "version":
			err = handleVersion(conn, p, payload, resp.addNodeChan)
		case "addr":
			err = handleAddr(conn, p, payload, resp.addrsChan)
		case "verack":
			err = handleVerack(conn, p, resp.addNodeChan)
		case "inv":
			err = handleInv(conn, p, payload, resp.invChan)
		default:
			// XXX Used during development.
			log.Fatalf("ignoring unknown command %q", command)
		}
		if err != nil {
			log.Printf("error while processing command %v: %v", command, err)
			resp.delNodeChan <- ipPort(conn.RemoteAddr().String()).toNetworkAddress()
			// Disconnects from node.
			return
		}
	}
}

func handleVersion(conn io.Writer, p *peerState, payload io.Reader, addNode chan extendedNetworkAddress) error {
	if p.established {
		return fmt.Errorf("received a 'version' message from a host we already went through a version exchange. Closing the connection.")
	}
	version, err := parseVersion(payload)
	if err != nil {
		return fmt.Errorf("parseVersion: %v", err)
	}
	if version.Nonce == nonce {
		// Close connection to self.
		// TODO: put on ipPort blacklist.
		return fmt.Errorf("closing loop")
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
		addNode <- p.ipPort.toNetworkAddress()
	}
	return nil
}

func handleVerack(conn io.Writer, p *peerState, addNode chan extendedNetworkAddress) error {
	if p.verackReceived {
		return fmt.Errorf("received 'verack' twice from a node. Closing connection")
	}
	p.verackReceived = true
	if p.verackSent {
		p.established = true
		addNode <- p.ipPort.toNetworkAddress()
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
	respNodes <- addrs
	return nil
}

var once sync.Once

func handleInv(conn io.Writer, p *peerState, payload io.Reader, obj chan objectsInventory) error {
	if !p.established {
		return fmt.Errorf("version unknown. Closing connection")
	}
	invs, err := parseInv(payload)
	if err != nil {
		return fmt.Errorf("parseInv error: %v. Closing connection", err)
	}
	objects := make(objectsInventory)
	for _, inv := range invs {
		objects[inv.Hash] = p.ipPort
		// XXX Used during development.
		once.Do(
			func() {
				writeGetData(conn, []inventoryVector{inv})
			})
	}
	obj <- objects
	return nil
}

// Things needing implementation.
//
// - save the config frequently. be more resilient to BitMessage attacks.
// - Preserve the routing table for longer, don't delete nodes immediately
// - after they disconnect.
//
// from PyBitMessage:
//
// broadcastToSendDataQueues((0, 'shutdown', self.HOST))
//
// Zero out the list of already contacted nodes every 30 minutes, to give it
// another chance.
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
	streamConnectionCount map[int]int
}

// ipPort is a string that can be resolved with net.ResolveTCPAddr("tcp",
// ipPort) and the first part can be parsed by net.ParseIP(). It is illegal to
// create an ipPort that doesn't follow these conditions.
type ipPort string

func (ipPort ipPort) toNetworkAddress() extendedNetworkAddress {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", string(ipPort))
	var rawIp [16]byte
	copy(rawIp[:], tcpAddr.IP)
	addr := extendedNetworkAddress{
		Time:   uint32(time.Now().Unix()),
		Stream: streamOne, // This should change after the version exchange.
		NetworkAddress: NetworkAddress{
			Services: ConnectionServiceNodeNetwork, //
			IP:       rawIp,
			Port:     uint16(tcpAddr.Port),
		},
	}
	return addr
}
