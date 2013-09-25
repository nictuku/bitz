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
	"io"
	"net"
	"time"
)

// When a node creates an outgoing connection, it will immediately advertise
// its version. The remote node will respond with its version. No futher
// communication is possible until both peers have exchanged their version.
func writeVersion(w io.Writer, dest *net.TCPAddr) {
	buf := new(bytes.Buffer)
	putInt32(buf, protocolVersion)
	// bitfield of features to be enabled for this connection.
	// uint64
	putUint64(buf, services)
	// standard UNIX timestamp in seconds
	// int64
	putInt64(buf, time.Now().Unix())
	// The network address of the node receiving this message (not including
	// the time or stream number)
	check(writeNetworkAddress(buf, dest))
	// The network address of the node emitting this message (not including
	// the time or stream number and the ip itself is ignored by the receiver)
	check(writeNetworkAddress(buf, nil))

	// Random nonce used to detect connections to self.
	putUint64(buf, nonce)

	// User Agent (0x00 if string is 0 bytes long).
	// varstring already encoded.
	putBytes(buf, userAgent)

	// The stream numbers that the emitting node is interested in.
	// var_int_list	already encoded.
	putBytes(buf, streamNumbers)

	writeMessage(w, "version", buf.Bytes())
}

// The verack message is sent in reply to version. This message consists of
// only a message header with the command string "verack".
func writeVerack(w io.Writer) {
	writeMessage(w, "verack", []byte{})
}

// Provide information on known nodes of the network. Non-advertised nodes
// should be forgotten after typically 3 hours.
// func writeAddr

// InvMessage allows a node to advertise its knowledge of one or more objects.
// It can be received unsolicited, or in reply to getmessages.
// Maximum payload length: 50000 items.
// func writeInv

// getdata is used in response to an inv message to retrieve the content of a specific object after filtering known elements.
// Payload (maximum payload length: 50000 entries).
//
// Example:
//	b, err := base58.BitcoinEncoding.Encode(inv.Hash[:])
//	if err != nil {
//		log.Println("could not encode base58 %v: %v", inv.Hash, err)
//	}
//	log.Printf("requesting content: BM-%v", string(b))
//	writeGetData(conn, []inventoryVector{inv})

func writeGetData(w io.Writer, invs []inventoryVector) {
	buf := new(bytes.Buffer)
	check(writeInventoryVector(buf, invs))
	writeMessage(w, "getdata", buf.Bytes())
}
