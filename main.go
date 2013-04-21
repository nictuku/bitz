// This is a stub BitMessage client. More features will be added soon.
package main

import (
	"github.com/nictuku/bitz/bitmessage"
	"log"
)

func main() {

	n := new(bitmessage.Node)
	n.Run()
	log.Println("run finished")
}
