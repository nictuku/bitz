package bitmessage

import (
	"fmt"
	"testing"
)

func TestDoubleHash(t *testing.T) {
	// Values picked from the protocol specification hash examples:
	// https://bitmessage.org/wiki/Protocol_specification
	msg := []byte("hello")
	rcv, err := offProofOfWork(msg)
	if err != nil {
		t.Fatalf("doubleHash error: %v", err.Error())
	}

	if fmt.Sprintf("%x", rcv) != "0592a10584ffabf96539f3d780d776828c67da1ab5b169e9e8aed838aaecc9ed36d49ff1423c55f019e050c66c6324f53588be88894fef4dcffdb74b98e2b200" {
		t.Fatalf("doubleHash mismatch, got %x", rcv)
	}
}

func TestBitmessage(t *testing.T) {
	// Values picked from the protocol specification hash examples:
	// https://bitmessage.org/wiki/Protocol_specification
	msg := []byte("hello")
	rcv, err := Bitmessage(msg)
	if err != nil {
		t.Fatalf("Bitmessage error: %v", err.Error())
	}

	if fmt.Sprintf("%x", rcv) != "79a324faeebcbf9849f310545ed531556882487e" {
		t.Fatalf("Bitmessage mismatch, got %x", rcv)
	}
}
