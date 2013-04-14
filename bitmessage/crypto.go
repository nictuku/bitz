package bitmessage

import (
	//	"bytes"
	"crypto/sha512"
	//	"encoding/binary"
	//"log"
)

// sha512HashPrefix returns the first 4 bytes of the SHA-512 hash of b. The
// original protocol asks for a uint32, but in the wire that's the same as
// a byte slice of length 4.
func sha512HashPrefix(b []byte) []byte {
	s := sha512.New()
	s.Write(b)
	return s.Sum(nil)[0:4]
}
