package bitmessage

import (
	"encoding/gob"
	"io"
)

// This file implements storage for bitmessage objects, which are kept as un-
// typed blobs.

// ipPortSet holds unique ipPorts.
type ipPortSet map[ipPort]bool

// objHash contains the first 4 bytes of the SHA-512 hash of the object.
type objHash [32]byte

func newobjInfo() *objInfo {
	return &objInfo{make(ipPortSet)}
}

type objInfo struct {
	Nodes ipPortSet
}

func (i *objInfo) addNode(addr ipPort) {
	i.Nodes[addr] = true
}

func newObjInventory() objectsInventory {
	return objectsInventory{
		make(map[objHash]*objInfo),
	}
}

// objectsInventory knows which ipPorts know about a particular objHash.
type objectsInventory struct {
	M map[objHash]*objInfo
}

// adds indicates that the provided addr knows about that
// objHash.
func (inv objectsInventory) add(h objHash, addr ipPort) {
	_, ok := inv.M[h]
	if !ok {
		inv.M[h] = newobjInfo()
	}
	inv.M[h].addNode(addr)
}

// merge adds all items from inv2 into inv.
func (inv objectsInventory) merge(inv2 objectsInventory) {
	for h, m := range inv2.M {
		_, ok := inv.M[h]
		if !ok {
			inv.M[h] = m
			continue
		}
		for addr, _ := range m.Nodes {
			inv.M[h].addNode(addr)
		}
	}
}

// save writes the contents of inv in gob format to w.
func (inv objectsInventory) save(w io.Writer) error {
	g := gob.NewEncoder(w)
	return g.Encode(inv)
}

// load decodes the gob object in r and replaces inv with it.
func (inv objectsInventory) load(r io.Reader) error {
	g := gob.NewDecoder(r)
	return g.Decode(&inv)
}
