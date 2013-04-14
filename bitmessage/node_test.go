package bitmessage

import (
	"testing"
)

func TestNode(t *testing.T) {
	n := new(Node)
	n.Run()
	t.Log("run finished")
}
