package bitmessage

// Object store.

// TODO: Move to a map of hashes to identifiers instead of ipPort.
// TODO: Move things to disk as necessary (diskv?)
type objectsInventory map[[32]byte]map[ipPort]struct{}

func (inv objectsInventory) add(h [32]byte, addr ipPort) {
	// TODO: Move to a list of nodes instead of just one.
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
