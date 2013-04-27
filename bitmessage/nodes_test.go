package bitmessage

import (
	"testing"
)

func TestFindBootstrapNodes(t *testing.T) {
	nodes := findBootstrapNodes()
	if len(nodes) == 0 {
		t.Fatal("findBootstrapNodes returned an empty set")
	}
}
