package bitmessage

import (
	"net"
	"time"
)

// This file implements functions for operating on list of nodes

// knownNodes are all nodes we know of in each stream number. Only the main
// goroutine can access this.
type streamNodes map[int]nodeMap

// nodeMap ...
type nodeMap map[ipPort]remoteNode

type remoteNode struct {
	conn          net.Conn
	lastContacted time.Time
}
