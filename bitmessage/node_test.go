package bitmessage

import (
	"testing"
)

func TestNode(t *testing.T) {
	// Skip this if the -test.short flag is set. This is a placeholder
	// integration test only.
	if testing.Short() {
		return
	}
	n := new(Node)
	n.Run()
	t.Log("run finished")
}
