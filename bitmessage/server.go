//  Copyright 2013 Google Inc. All Rights Reserved.
// 
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
// 
//      http://www.apache.org/licenses/LICENSE-2.0
// 
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package bitmessage

// This file implements the main engine for this BitMessage node.

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/pmylund/go-bloom"
)

type Node struct {
	// All members can only be accessed by the main server routine inside
	// Run().
	cfg *Config
	// Stats. All access must be synchronized because it's often used by other
	// goroutines (UI).
	stats stats
	// resp contains channels for receiving parsed data from remote nodes.
	resp responses
	// connectedNodes are all nodes we have a connection established to, for
	// each stream.
	connectedNodes streamNodes
	// Bloomfilter of unreachable IPs.
	// TODO: Rotate the filters and expire them.
	// TODO: Save it on disk.
	unreachableNodes *bloom.Filter
	// knownNodes are all nodes we know of for each stream number in
	// addition to the connectedNodes.
	knownNodes streamNodes
	// objects provides information about which nodes holds each object.
	// XXX this should be renamed to objectLocations or so.
	objects *objStore
}

func (n *Node) Run() {
	n.connectedNodes = make(streamNodes)
	n.knownNodes = make(streamNodes)
	n.unreachableNodes = bloom.New(10000, 0.01)

	var err error
	n.objects, err = createObjStore()
	if err != nil {
		log.Fatalln("Node fatal error:", err)
	}

	n.cfg = openConfig(PortNumber)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", PortNumber))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Listening at", listener.Addr())
	n.resp = newResponses()
	go listen(listener.(*net.TCPListener), n.resp)
	n.bootstrap()
	saveTick := time.Tick(time.Minute * 1)
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
		case i := <-n.resp.invChan:
			n.objects.mergeInventory(i.inv, i.w)
		case msg := <-n.resp.msgChan:
			log.Printf("received message %+q", msg)
			log.Printf("received message content: len=%d, content=%q \n====\n%x", len(msg.Encrypted), msg.Encrypted, msg.Encrypted)
		//	log.Fatalln("done")
		case broadcast := <-n.resp.broadcastChan:
			//log.Printf("received broadcast %+q", broadcast)
			log.Printf("received brodcast content: %v", string(broadcast.Message))
			log.Fatalln("done")
		case <-saveTick:
			n.cfg.save(n.connectedNodes)
		}
	}
}

// responses contains channels that are used by Node to receive data from the
// network goroutines that are parsing the bitmessage protocol messages
// from remote nodes.
type responses struct {
	addrsChan     chan []extendedNetworkAddress
	addNodeChan   chan extendedNetworkAddress
	delNodeChan   chan extendedNetworkAddress
	invChan       chan nodeInv
	msgChan       chan msg
	broadcastChan chan broadcast
}

func newResponses() responses {
	return responses{
		make(chan []extendedNetworkAddress),
		make(chan extendedNetworkAddress),
		make(chan extendedNetworkAddress),
		make(chan nodeInv),
		make(chan msg),
		make(chan broadcast),
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

		conn.SetDeadline(time.Now().Add(connectionTimeout))
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
		case "msg":
			err = handleMsg(conn, p, payload, resp.msgChan)
		case "broadcast":
			err = handleBroadcast(conn, p, payload, resp.broadcastChan)
		default:
			// XXX
			err = fmt.Errorf("ignoring unknown command %q", command)
			log.Println(err.Error())
			err = nil
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

var i = 0

func handleInv(conn io.Writer, p *peerState, payload io.Reader, obj chan nodeInv) error {
	if !p.established {
		return fmt.Errorf("version unknown. Closing connection")
	}
	invs, err := parseInv(payload)
	if err != nil {
		return fmt.Errorf("parseInv error: %v. Closing connection", err)
	}
	nodeObjects := newObjInventory()
	for _, inv := range invs {
		nodeObjects.add(inv.Hash, p.ipPort)
	}
	obj <- nodeInv{conn, *nodeObjects}
	return nil
}

func handleMsg(conn io.Writer, p *peerState, payload io.Reader, msgChan chan msg) error {
	if !p.established {
		return fmt.Errorf("version unknown. Closing connection")
	}
	m, err := parseMsg(payload)
	if err != nil {
		return fmt.Errorf("handleMsg parseMsg error: %v. Closing connection", err)
	}
	msgChan <- m
	return nil
}

func handleBroadcast(conn io.Writer, p *peerState, payload io.Reader, bChan chan broadcast) error {
	if !p.established {
		return fmt.Errorf("version unknown. Closing connection")
	}
	b, err := parseBroadcast(payload)
	if err != nil {
		return fmt.Errorf("handleBroadcast parseBroadcast error: %v. Closing connection", err)
	}
	bChan <- b
	return nil
}

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
		Time:   uint64(time.Now().Unix()),
		Stream: streamOne, // This should change after the version exchange.
		NetworkAddress: NetworkAddress{
			Services: ConnectionServiceNodeNetwork, //
			IP:       rawIp,
			Port:     uint16(tcpAddr.Port),
		},
	}
	return addr
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
//
// if streamNumberAsClaimedByMsg != self.streamNumber:
//   print 'The stream number encoded in this msg (' + str(streamNumberAsClaimedByMsg) + ') message does not match the stream number on which it was received. Ignoring it.'
