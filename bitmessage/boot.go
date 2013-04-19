package bitmessage

import (
	"log"
	"net"
	"strconv"
	"time"
)

// This file implements functions typically performed when the node is
// starting up - be it the inital run for this client or when the process is
// restarted. These functions are run by the main goroutine only and are not
// thread-safe.

func (n *Node) boot() {
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

	// Keep trying to connect to nodes.
	// Current bitmessage clients only connect to stream 1.
	nodes := n.knownNodes[1]
	handshake(nodes, n.recvChan)
}

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

// sendVersion 
func handshake(nodes nodeMap, recvChan chan packet) {
	for ipPort, node := range nodes {
		if !node.lastContacted.IsZero() && time.Since(node.lastContacted) < nodeConnectionRetryPeriod {
			// This node was contacted recently, so wait before the next try.
			continue
		}
		node.lastContacted = time.Now()
		if node.conn == nil {
			var err error
			if node.conn, err = net.Dial("tcp", string(ipPort)); err != nil {
				log.Printf("error connecting to node %v: %v", ipPort, err)
				continue
			}
			go handleConn(node.conn.(*net.TCPConn), recvChan)
		}
		dest := node.conn.RemoteAddr().(*net.TCPAddr)
		go writeVersion(node.conn, dest)
	}
}

// check logs the provided error if it's not nil.
func check(err error) {
	if err != nil {
		log.Fatalln("error", err.Error())
	}
}
