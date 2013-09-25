//  Copyright 2013 Google Inc. All Rights Reserved.
// 
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
// 
//      http://www.apache.org/licenses/LICENSE-2.0
// 
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package bitmessage

import (
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"strings"

	camli "camlistore.org/pkg/client"
)

// This file implements storage for bitmessage objects using camlistore.

// ipPortSet holds unique ipPorts.
type ipPortSet map[ipPort]bool

// objHash contains the first 4 bytes of the SHA-512 hash of the object.
type objHash [32]byte

func newobjInfo() *objInfo {
	return &objInfo{make(ipPortSet)}
}

type objInfo struct {
	Nodes ipPortSet
}

func (i *objInfo) addNode(addr ipPort) {
	i.Nodes[addr] = true
}

func createObjStore() (*objStore, error) {
	db := camli.New("localhost:3179")

	return &objStore{newObjInventory(), db}, nil
}

// objStore persists objects on disk and keeps track of metadata of each
// object.
type objStore struct {
	inv *objectsInventory
	db  *camli.Client
}

func (s *objStore) OffaddObjNode(h objHash, addr ipPort, conn io.Writer) {
	s.inv.add(h, addr)
	if s.shouldRetrieve(h) {
		log.Println("retrieving %x [%v]", h, addr)
		iv := inventoryVector{h}

		writeGetData(conn, []inventoryVector{iv})
	}
}

func (s *objStore) shouldRetrieve(h objHash) bool {
	return strings.HasPrefix(fmt.Sprintf("%x", h), "3")
}

func (s *objStore) mergeInventory(inv2 objectsInventory, conn io.Writer) {
	s.inv.merge(inv2)
	for h, _ := range inv2.M {
		if s.shouldRetrieve(h) {
			log.Printf("==================== retrieving %x", h)
			iv := inventoryVector{h}

			writeGetData(conn, []inventoryVector{iv})
		}
	}
}

// invSource indicates a source that can receive writes requesting for a data.
type nodeInv struct {
	w   io.Writer
	inv objectsInventory
}

func newObjInventory() *objectsInventory {
	return &objectsInventory{make(map[objHash]*objInfo)}
}

// objectsInventory tracks metadata about a particular objHash.
type objectsInventory struct {
	M map[objHash]*objInfo
}

// adds indicates that the provided addr knows about that
// objHash.
func (inv objectsInventory) add(h objHash, addr ipPort) {
	_, ok := inv.M[h]
	if !ok {
		inv.M[h] = newobjInfo()
	}
	inv.M[h].addNode(addr)
}

// merge adds all items from inv2 into inv.
func (inv objectsInventory) merge(inv2 objectsInventory) {
	for h, m := range inv2.M {
		_, ok := inv.M[h]
		if !ok {
			inv.M[h] = m
			continue
		}
		for addr, _ := range m.Nodes {
			inv.add(h, addr)
		}
	}
}

// save writes the contents of inv in gob format to w.
// Used for testing.
func (inv objectsInventory) save(w io.Writer) error {
	g := gob.NewEncoder(w)
	return g.Encode(inv)
}

// load decodes the gob object in r and replaces inv with it.
func (inv objectsInventory) load(r io.Reader) error {
	g := gob.NewDecoder(r)
	return g.Decode(&inv)
}
