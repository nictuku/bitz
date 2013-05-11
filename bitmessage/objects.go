package bitmessage

import (
	"encoding/gob"
	"io"
)

// This file implements storage for bitmessage objects, which are kept as un-
// typed blobs.

// ipPortSet holds unique ipPorts.
type ipPortSet map[ipPort]struct{}

// objectHash contains the first 4 bytes of the SHA-512 hash of the object.
type objectHash [32]byte

// objectsInventory is a map that tells which ipPorts know about a particular
// object, keyed by the objectHash.
type objectsInventory map[objectHash]ipPortSet

// adds updates the map to indicate that the provided addr knows about that
// objectHash.
func (inv objectsInventory) add(h objectHash, addr ipPort) {
	_, ok := inv[h]
	if !ok {
		inv[h] = make(ipPortSet)
	}
	inv[h][addr] = struct{}{}
}

// merge adds all items from inv2 into inv. inv2 is not changed.
func (inv objectsInventory) merge(inv2 objectsInventory) {
	// TODO: make it faster.
	for h, m := range inv2 {
		_, ok := inv[h]
		if !ok {
			inv[h] = make(ipPortSet)
		}
		for ipPort, _ := range m {
			inv[h][ipPort] = struct{}{}
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
