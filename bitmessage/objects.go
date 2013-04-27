package bitmessage

import (
	"encoding/gob"
	"io"
)

// Object store.

// TODO: Move to a map of hashes to identifiers instead of ipPort.
// TODO: Move things to disk as necessary (diskv?)
type objectsInventory map[[32]byte]map[ipPort]struct{}

func (inv objectsInventory) add(h [32]byte, addr ipPort) {
	_, ok := inv[h]
	if !ok {
		inv[h] = make(map[ipPort]struct{})
	}
	inv[h][addr] = struct{}{}
}

func (inv objectsInventory) merge(inv2 objectsInventory) {
	// TODO: make it faster.
	for h, m := range inv2 {
		_, ok := inv[h]
		if !ok {
			inv[h] = make(map[ipPort]struct{})
		}
		for ipPort, _ := range m {
			inv[h][ipPort] = struct{}{}
		}
	}
}

func (inv objectsInventory) save(w io.Writer) error {
	g := gob.NewEncoder(w)
	return g.Encode(inv)
}

func (inv objectsInventory) load(r io.Reader) error {
	g := gob.NewDecoder(r)
	return g.Decode(&inv)
}
