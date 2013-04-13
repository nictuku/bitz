package bitmessage

import (
	"log"
	"net"
	"strconv"
)

// This file implements functions typically performed when the node is
// starting up - be it the inital run for this client or when the process is
// restarted.

var bootstrapNodes = [][]string{
	{"bootstrap8080.bitmessage.org", "8080"},
	{"bootstrap8444.bitmessage.org", "8444"},
}

// findBootStrapNodes uses DNS resolution for finding bootstrap nodes for the
// network. The list of DNS hosts was obtained from the original client source
// in 2013-04-14. TODO: provide our own bootstrap nodes.
func findBootstrapNodes() (nodes []net.TCPAddr) {
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
