package bitmessage

// Object store.

// TODO: Move to a map of hashes to identifiers instead of ipPort.
// TODO: Move things to disk as necessary (diskv?)
type objectsInventory map[[32]byte]ipPort

func (inv objectsInventory) add(h [32]byte, addr ipPort) {
	// TODO: Move to a list of nodes instead of just one.
	inv[h] = addr
}

func (inv objectsInventory) merge(inv2 objectsInventory) {
	// TODO: make it faster.
	for h, ipPort := range inv2 {
		inv[h] = ipPort
	}
}
