package bitmessage

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	//"log"
)

// sha512HashPrefix returns the first 4 bytes of the SHA-512 hash of b.
func sha512HashPrefix(b []byte) (x uint32) {
	s := sha512.New()
	s.Write(b)
	r := bytes.NewBuffer(s.Sum(nil)[0:4])
	binary.Read(r, binary.BigEndian, &x)
	return x
}
