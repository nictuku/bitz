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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"time"

	encVarint "github.com/nictuku/guardian/encoding/varint"
	encVarstring "github.com/spearson78/guardian/encoding/varstring"
)

// init initializes package variables and constants.
func init() {
	// Flip the byte order for BitMessage, which is different than BitCoin.
	encVarint.ByteOrder = binary.BigEndian
	buf := new(bytes.Buffer)
	// Don't attract attention to this client just yet, use the vanilla client
	// user agent.
	// encVarstring.WriteVarString(userAgent, "/bitz:1/")
	encVarstring.WriteVarString(buf, "/PyBitmessage:0.2.8/")
	userAgent = buf.Bytes()

	buf = new(bytes.Buffer)
	putVarIntList(buf, []uint64{streamOne})
	streamNumbers = buf.Bytes()

	// TODO: rotate the nonce numbers. A package variable isn't a good place
	// to keep this because it would be racy. Move it to the server.
	err := binary.Read(rand.Reader, binary.LittleEndian, &nonce)
	if err != nil {
		nonce = uint64(time.Now().UnixNano())
	}
}

const (
	protocolVersion = 2
	streamOne       = 1
	// Using same value from PyBitmessage, which was originally added to avoid memory blowups.
	// The protocol itself doesn't restrict it. This should certainly be removed
	maxPayloadLength = 180000000
	id               = "bitz"
	prefix           = "bitmessage"

	nodeConnectionRetryPeriod            = time.Minute * 30
	connectionTimeout                    = time.Second * 10
	numNodesForMainStream                = 15
	maxInventoryEntries                  = 50000
	payloadLengthExtraBytes              = 14000
	averageProofOfWorkNonceTrialsPerByte = 320

	// This is a normal network node.
	ConnectionServiceNodeNetwork = 1
)

var (
	// PortNumber can be safely changed before the call to node.Run().
	PortNumber = 9090

	// Magic value indicating message origin network, and used to seek to next
	// message when stream state is unknown.
	magicHeader      = uint32(0xE9BEB4D9)
	magicHeaderSlice = []byte{0xE9, 0xBE, 0xB4, 0xD9}

	// These values are initialzied by init() and should never be changed
	// after they are written for the first time.
	nonce         uint64                                 // Filled by init().
	services      = uint64(ConnectionServiceNodeNetwork) // Only one bit is used for now.
	streamNumbers = []byte{}                             // Only using stream 1 for now.
	userAgent     = []byte{}                             // Filled by init().

	bootstrapNodes = [][]string{
		// The only node that seems to be up:
		{"217.91.97.196", "8444"},

		// DNS nodes used by PyBitMessage for bootstrapping:
		{"bootstrap8080.bitmessage.org", "8080"},
		{"bootstrap8444.bitmessage.org", "8444"},

		// My test PyBitMessage.
		// {"192.168.11.8", "8444"},
	}
)
