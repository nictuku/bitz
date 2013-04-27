package bitmessage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	encVarint "github.com/nictuku/guardian/encoding/varint"
	"io/ioutil"
	"reflect"
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
		// From a pcap capture.
		[]byte{0xe9, 0xbe, 0xb4, 0xd9, 0x6d, 0x73, 0x67, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x2d, 0x18, 0xe5, 0x51, 0x30,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x6b, 0x2a,
			0x51, 0x7a, 0x4c, 0xc7, 0x01, 0x1f, 0x54, 0x9c,
			0x27, 0x5e, 0x23, 0x96, 0x2c, 0x61, 0x09, 0xc0,
			0xfb, 0xdb, 0x45, 0x4b, 0x7d, 0x63, 0xe9, 0x77,
			0xa0, 0x3b, 0xaa, 0x8a, 0x67, 0x34, 0x8a, 0xa4,
			0x9c, 0x09, 0xa1, 0xc7, 0xcb},
		"msg",
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x6b, 0x2a,
			0x51, 0x7a, 0x4c, 0xc7, 0x01, 0x1f, 0x54, 0x9c,
			0x27, 0x5e, 0x23, 0x96, 0x2c, 0x61, 0x09, 0xc0,
			0xfb, 0xdb, 0x45, 0x4b, 0x7d, 0x63, 0xe9, 0x77,
			0xa0, 0x3b, 0xaa, 0x8a, 0x67, 0x34, 0x8a, 0xa4,
			0x9c, 0x09, 0xa1, 0xc7, 0xcb},
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
			t.Errorf("payload wanted %q got %q (test %d)", tt.payload, buf, i)
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

func TestParseMsg(t *testing.T) {
	// TODO: Add test for bad POW, when that's done.
	buf := bytes.NewBuffer([]byte{
		0xe9, 0xbe, 0xb4, 0xd9, 0x6d, 0x73, 0x67, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x2d, 0x18, 0xe5, 0x51, 0x30,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x6b, 0x2a,
		0x51, 0x7a, 0x4c, 0xc7, 0x01, 0x1f, 0x54, 0x9c,
		0x27, 0x5e, 0x23, 0x96, 0x2c, 0x61, 0x09, 0xc0,
		0xfb, 0xdb, 0x45, 0x4b, 0x7d, 0x63, 0xe9, 0x77,
		0xa0, 0x3b, 0xaa, 0x8a, 0x67, 0x34, 0x8a, 0xa4,
		0x9c, 0x09, 0xa1, 0xc7, 0xcb,
	})
	want := msg{
		PowNonce:     [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x6b, 0x2a},
		Time:         1366969543,
		StreamNumber: 1,
		Encrypted: []byte{
			0x1f, 0x54, 0x9c, 0x27, 0x5e, 0x23, 0x96, 0x2c,
			0x61, 0x09, 0xc0, 0xfb, 0xdb, 0x45, 0x4b, 0x7d,
			0x63, 0xe9, 0x77, 0xa0, 0x3b, 0xaa, 0x8a, 0x67,
			0x34, 0x8a, 0xa4, 0x9c, 0x09, 0xa1, 0xc7, 0xcb,
		},
	}
	cmd, b, err := readMessage(buf)
	if err != nil {
		t.Fatalf("parseMSG error: %v", err.Error())
	}
	if cmd != "msg" {
		t.Fatalf("msg error: %v", err.Error())
	}
	m, err := parseMsg(b)
	if !reflect.DeepEqual(m, want) {
		t.Errorf("got %+q, wanted %+q", m, want)
	}
}

func TestPow(t *testing.T) {
	want := msg{
		PowNonce:     [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x6b, 0x2a},
		Time:         1366969543,
		StreamNumber: 1,
		Encrypted: []byte{
			0x1f, 0x54, 0x9c, 0x27, 0x5e, 0x23, 0x96, 0x2c,
			0x61, 0x09, 0xc0, 0xfb, 0xdb, 0x45, 0x4b, 0x7d,
			0x63, 0xe9, 0x77, 0xa0, 0x3b, 0xaa, 0x8a, 0x67,
			0x34, 0x8a, 0xa4, 0x9c, 0x09, 0xa1, 0xc7, 0xcb,
		},
	}
	buf := new(bytes.Buffer)
	writeMsg(buf, want)
	nonce, err := ProofOfWork(buf.Bytes()[8:])
	if err != nil {
		t.Fatalf("ProofOfWork: %v", err)
	}
	if !bytes.Equal(nonce[:], want.PowNonce[:]) {
		t.Fatalf("ProofOfWork produced unexpected result: wanted %x, got %x", want.PowNonce, nonce)
	}
}
