package bitmessage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	encVarint "github.com/nictuku/guardian/encoding/varint"
	"io/ioutil"
	"testing"
)

func init() {
	// Flip the byte order for BitMessage, which is different than BitCoin.
	encVarint.ByteOrder = binary.BigEndian
}

type test struct {
	raw     []byte
	command string
	payload []byte
	err     error
}

var testData = []test{
	{
		// From BitMessage.py logs.
		[]byte("\xe9\xbe\xb4\xd9version\x00\x00\x00\x00\x00\x00\x00\x00g\x9b\xdc\xbda\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00Qqt\x0c\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xc0\xa8\x0b\r#\x82\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x7f\x00\x00\x01 \xfc\x04\xd9\xdcA\xd6\xfd\x96\xd3\x14/PyBitmessage:0.2.8/\x01\x01"),
		"version",
		[]byte("\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00Qqt\x0c\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xc0\xa8\x0b\r#\x82\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x7f\x00\x00\x01 \xfc\x04\xd9\xdcA\xd6\xfd\x96\xd3\x14/PyBitmessage:0.2.8/\x01\x01"),
		nil,
	},
	{
		[]byte("\xe9\xbe\xb4\xd9fake\x00\x00\x00\x00\x00\x00\x00\x00" + // magic + command
			"\x00\x00\x00\x05" + // length
			"\x50\x54\x0b\xc4" + // checksum
			"\x01\x02\x03\x04\x05"), // payload
		"fake",
		[]byte{1, 2, 3, 4, 5},
		nil,
	},
	{
		[]byte("\xe9\xbe\xb4\xd9badcheck\x00\x00\x00\x00" + // magic + command
			"\x00\x00\x00\x05" + // length
			"\x50\x54\x0b\xFF" + // BAD checksum
			"\x01\x02\x03\x04\x05"), // payload
		"badcheck",
		[]byte{}, // resulting payload is empty when checksum is wrong.
		fmt.Errorf("readMessage: checksum mismatch: message advertised 50540bff, calculated 50540bc4"),
	},
}

func TestReadMessages(t *testing.T) {
	for i, tt := range testData {
		x := new(bytes.Buffer)
		x.Write(tt.raw)
		cmd, payload, err := readMessage(x)
		if err != nil && err.Error() != tt.err.Error() {
			t.Fatalf("err wanted:\n%q\n	got:\n%q\n (test %d)", tt.err, err, i)
		}
		if err != nil {
			break
		}
		if cmd != tt.command {
			t.Errorf("version wanted %q got %q (test %d)", tt.command, cmd, i)
		}
		buf, _ := ioutil.ReadAll(payload)
		if !bytes.Equal(buf, tt.payload) {
			t.Errorf("payload wanted %q got %q (test %d)", tt.payload, payload, i)
		}
	}
}

// TestWriteAndRead first writes a payload+command, transforming that to a raw
// bitmessage Message, then reads it back using the network parse, and
// verifies that the result matches the original.
func TestWriteAndRead(t *testing.T) {
	for i, tt := range testData {
		b := new(bytes.Buffer)
		writeMessage(b, tt.command, tt.payload)
		cmd, payload, err := readMessage(b)
		if err != nil && err.Error() != tt.err.Error() {
			t.Errorf("err wanted:\n%q\n, got:\n%q\n (test %d)", tt.err, err, i)
		}
		if cmd != tt.command {
			t.Errorf("version wanted %q got %q (test %d)", tt.command, cmd, i)
		}
		buf, _ := ioutil.ReadAll(payload)
		if !bytes.Equal(buf, tt.payload) {
			t.Errorf("payload wanted %q got %q (test %d)", tt.payload, payload, i)
		}
	}
}

func TestVarIntDecode(t *testing.T) {
	// This was obtained by debugging a PyBitMessage message. Only the first 4
	// bytes are relevant. The problem I had was with endianess if the varint
	// decoding library (bitcoin and bitmessage use different endianess.)
	count, x, err := encVarint.ReadVarInt(bytes.NewBuffer([]byte("\xfd\x10y\xc2\xeb\xbf\x12\xe0k:")))
	if err != nil {
		t.Errorf("got err: %v", err.Error())
	}
	if count != 4217 {
		t.Errorf("wanted 4217, got %d (%d)", count, x)
	}
}
