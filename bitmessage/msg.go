// Package bitmessage implements the BitMessage protocol.
package bitmessage

// The description of most data types was based on the protocol definition,
// licensed under "Creative Commons Attribution 3.0" and available at
// https://bitmessage.org/wiki/Protocol_specification.

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"

	"code.google.com/p/go.crypto/ripemd160"
	encVarint "github.com/nictuku/guardian/encoding/varint"
	encVarstring "github.com/spearson78/guardian/encoding/varstring"
)

func init() {
	// Flip the byte order for BitMessage, which is different than BitCoin.
	encVarint.ByteOrder = binary.BigEndian

	n2to64 = new(big.Int)
	if _, err := fmt.Sscan("18446744073709551617", n2to64); err != nil {
		log.Panicf("error scanning math.Big value n2to64:", err)
	}
	initialTrial = new(big.Int)
	if _, err := fmt.Sscan("99999999999999999999", initialTrial); err != nil {
		log.Panicf("error scanning math.Big value initialTrial:", err)
	}
}

func writeMessage(w io.Writer, command string, payload []byte) {
	// TODO performance: pre-allocate byte slices, share between instances.
	buf := new(bytes.Buffer)

	// Magic value indicating message origin network, and used to seek to
	// next message when stream state is unknown.
	putUint32(buf, magicHeader)
	// ASCII string identifying the packet content, NULL padded (non-NULL
	// padding results in packet rejected).
	putBytes(buf, []byte(nullPadCommand(command)))
	// Length of payload in number of bytes
	putUint32(buf, uint32(len(payload)))
	// First 4 bytes of sha512(payload).
	putUint32(buf, sha512HashPrefix(payload))
	// The actual data, a message or an object
	putBytes(buf, payload)

	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Println("writeMessage write failed: ", err)
	}
}

type parserState struct {
	magicPos      int // if == 4 means all magic bytes have been found and is ready to read data.
	pos           int
	payloadLength int
	command       string
	checksum      uint32
}

// readMessage parses a BitMessage message in the protocol-defined format and
// outputs the name of the command in the message, plus the payload content.
// It verifies that the content matches the checksum in the message header and
// throws an error otherwise.
func readMessage(r io.Reader) (command string, buf io.Reader, err error) {
	b := make([]byte, 20)
	p := parserState{}

	data := new(bytes.Buffer)

	// The first bytes aren't necessarily the beginning of a message, because
	// the TCP stream can be in an unknown state - in case there is a bug in
	// the network parser for example.
	// Find the beginning of the message, marked by magic bytes.

	for {
		var n int
		// Read at least 20 bytes because it's useless to proceed without
		// knowing the payload length. If the remote server doesn't give the
		// data this will block. In the common case, 'r' is a net.Conn with a
		// deadline set, so it shouldn't be a problem.

		n, err = io.ReadAtLeast(r, b, 20)
		for p.pos = 0; p.pos < n && p.magicPos != 4; p.pos++ {
			if b[p.pos] == magicHeaderSlice[p.magicPos] {
				p.magicPos += 1
			} else {
				p.magicPos = 0
			}
		}
		if p.magicPos == 4 {
			if len(b) > p.pos {
				// Save the extra bytes that were read unnecessarily.
				data.Write(b[p.pos:n])
			}
			break
		}
	}
	// Read the message header, including the checksum. The header's length is 20 bytes at least.
	missingData := 20 - data.Len()
	if _, err = io.CopyN(data, r, int64(missingData)); err != nil {
		return "", nil, fmt.Errorf("readMessage: error reading header: %v", err.Error())
	}
	if err := parseHeaderFields(&p, data); err != nil {
		return p.command, nil, fmt.Errorf("readMessage: %v", err.Error())
	}
	// TODO performance: depending on the command type, pipe directly do disk
	// instead of keeping all in memory?
	//
	// TODO performance: keep an arena of reusable byte slices.

	// There might be still some bytes left in 'data'. Calculate how much we
	// still have to read now.
	missingData = p.payloadLength - data.Len()
	// Copy the remaining bytes from reader to 'data'.
	if _, err := io.CopyN(data, r, int64(missingData)); err != nil && err != io.EOF {
		return p.command, nil, err
	}
	if data.Len() != p.payloadLength {
		return p.command, nil, fmt.Errorf("readMessage: stream ended before we could get the payload data, wanted length %d, got %d", p.payloadLength, data.Len())
	}
	if checksum := sha512HashPrefix(data.Bytes()); p.checksum != checksum {
		return p.command, nil, fmt.Errorf("readMessage: checksum mismatch: message advertised %x, calculated %x", p.checksum, checksum)
	}
	return p.command, data, nil
}

func parseHeaderFields(p *parserState, data io.Reader) (err error) {
	if p.command, err = parseCommand(data); err != nil {
		return fmt.Errorf("headerFields: %v", err.Error())
	}
	p.payloadLength = int(readUint32(data))
	if p.payloadLength > maxPayloadLength {
		return fmt.Errorf("headerFields: advertised payload length too large, aborting.")
	}
	p.checksum = readUint32(data)
	return nil
}

func parseCommand(r io.Reader) (command string, err error) {
	cmd := make([]byte, 12)
	if _, err = io.ReadFull(r, cmd); err != nil {
		return "", fmt.Errorf("parseCommand error: %v", err.Error())
	}
	cmd = bytes.TrimRight(cmd, "\x00")
	return string(cmd), nil
}

// networkAddress produces a wire format Network Address packet. If addr is
// nil, assumes that it's about this node itself.
func writeNetworkAddress(w io.Writer, addr *net.TCPAddr) (err error) {

	// Network addresses are prefixed with a timestamp in a few cases, but not
	// in others (e.g: version message).

	buf := new(bytes.Buffer)
	putUint64(buf, uint64(ConnectionServiceNodeNetwork)) // + other bits.
	if addr == nil {
		// Data refers to this node. Fill the IP address with a loopback address, but set
		// a meaningful TCP port.
		putBytes(buf, net.IPv6loopback)
		putUint16(buf, uint16(PortNumber))
		_, err = w.Write(buf.Bytes())
		return err
	}
	putBytes(buf, addr.IP.To16())
	putUint16(buf, uint16(addr.Port))
	_, err = w.Write(buf.Bytes())
	return err
}

type NetworkAddress struct {
	Services uint64 // Same service(s) listed in version

	// IPv6 Address, or IPv6-mapped IPv4 address:
	//00 00 00 00 00 00 00 00 00 00 FF FF, followed by the IPv4 bytes.
	IP   [16]byte
	Port uint16 // portNumber.
}

func (addr NetworkAddress) ipPort() ipPort {
	ip := parseIP(addr.IP)
	return ipPort(fmt.Sprintf("%v:%d", ip.String(), addr.Port))
}

type extendedNetworkAddress struct {
	// Last received message from this node.
	Time uint64
	// Stream number for this node.
	Stream uint32
	NetworkAddress
}

func parseAddr(r io.Reader) ([]extendedNetworkAddress, error) {
	return readNetworkAddressList(r)
}

func parseIP(ip [16]byte) net.IP {
	return net.IP(ip[0:len(ip)])
}

// InventoryVectors are used for notifying other nodes about objects they
// have or data which is being requested. Two rounds of SHA-512 are used,
// resulting in a 64 byte hash. Only the first 32 bytes are used; the later 32
// bytes are ignored.
type inventoryVector struct {
	Hash [32]byte
}

func writeInventoryVector(w io.Writer, invs []inventoryVector) (err error) {
	if len(invs) > maxInventoryEntries {
		return fmt.Errorf("Asked to write %d inventory vectors for getdata, but the maximum is %d. Ignoring.", len(invs), maxInventoryEntries)
	}
	buf := new(bytes.Buffer)
	encVarint.WriteVarInt(buf, uint64(len(invs)))
	if err = binary.Write(buf, binary.BigEndian, invs); err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

func parseInv(r io.Reader) ([]inventoryVector, error) {
	count, _, err := encVarint.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	ivs := make([]inventoryVector, count)
	err = binary.Read(r, binary.BigEndian, ivs)
	return ivs, err
}

// Use varint and varstring from:
// https://github.com/spearson78/guardian/tree/master/encoding
type varint []byte
type varstring []byte

type UnencryptedMessageData struct {
	// Message format version.
	msgVersion varint
	// Sender's address version number. This is needed in order to calculate
	// the sender's address to show in the UI, and also to allow for forwards
	// compatible changes to the public-key data included below.
	addressVersion varint
	// Sender's stream number.
	streamNumber varint
	// A bitfield of optional behaviors and features that can be expected from
	// the node with this pubkey included in this msg message (the sender's
	// pubkey).
	behavior uint32
	// The ECC public key used for signing (uncompressed format; normally
	// prepended with \x04).
	publicSigningKey [64]byte
	// The ECC public key used for encryption (uncompressed format; normally
	// prepended with \x04 ).
	publicEncryptionKey [64]byte
	// The ripe hash of the public key of the receiver of the message.
	destinationRipe [20]byte
	// Message encoding type.
	encoding varint
	// Message length.
	messageLength varint
	// The message.
	message []byte
	// Length of the acknowledgement data
	ackLength varint
	// The acknowledgement data to be transmitted. This takes the form of a
	// Bitmessage protocol message, like another msg message. The POW therein
	// must already be completed.
	ackData []byte
	// Length of the signature.
	sigLength varint
	// The ECDSA signature which covers everything from the msg_version to the
	// ack_data.
	singnature []byte
}

const (
	// Any data with this number may be ignored. The sending node might simply
	// be sharing its public key with you.
	EncodingIgnore = iota
	// UTF-8. No 'Subject' or 'Body' sections. Useful for simple strings of
	// data, like URIs or magnet links.
	EncodingTrivial
	// UTF-8. Uses 'Subject' and 'Body' sections. No MIME is used.
	// messageToTransmit = 'Subject:' + subject + '\n' + 'Body:' + message
	EncodingSimple
	// Further values for the message encodings can be decided upon by the
	// community. Any MIME or MIME-like encoding format, should they be used,
	// should make use of Bitmessage's 8-bit bytes.
	// As of 2013-04-14, no other types have been standardized.
)

const (
	// Pubkey bitfield features. As of 2013-04-14, only the following is in
	// the protocol:
	// If true, the receiving node does send acknowledgements (rather than
	// dropping them). Note that this is the least significant bit.
	pubKeyDoesAck = 31
)

// binaryVersionMessage is the initial section of a Version message that can be
// decoded directly by the encoding/binary package functions.
type binaryVersionMessage struct {
	// Identifies protocol version being used by the node.
	Version int32
	// bitfield of features to be enabled for this connection.
	Services uint64
	// standard UNIX timestamp in seconds
	Timestamp int64
	// The network address of the node receiving this message (not including
	// the time or stream number)
	AddrRecv NetworkAddress
	// The network address of the node emitting this message (not including
	// the time or stream number and the ip itself is ignored by the receiver)
	AddrFrom NetworkAddress
	// Random nonce used to detect connections to self.
	Nonce uint64
	// Extra fields that can't be parsed by the binary reader:
	// varstring: User Agent (0x00 if string is 0 bytes long)
	// list of varint: The stream numbers that the emitting node is interested in.
}

// When a node creates an outgoing connection, it will immediately advertise
// its version. The remote node will respond with its version. No futher
// communication is possible until both peers have exchanged their version.
type versionMessage struct {
	binaryVersionMessage
	userAgent     string
	streamNumbers []uint64
}

func parseVersion(r io.Reader) (versionMessage, error) {
	v := &binaryVersionMessage{}
	check(binary.Read(r, binary.BigEndian, v))
	fmt.Println("version", v.Version)
	fmt.Println("addr recv", parseIP(v.AddrRecv.IP))

	userAgent, _, _ := encVarstring.ReadVarString(r)
	streams := readVarIntList(r)
	version := versionMessage{*v, userAgent, streams}
	return version, nil
}

// Objects:
// Any object is also a message. The difference is, that an object should be
// shared with the whole stream, while a normal message is just for direct
// client to client communication. A client should advertise objects that are
// not older than 2 days. To create an object, the Proof Of Work has to be
// done.

// When a node has the hash of a public key (from an address) but not the
// public key itself, it must send out a request for the public key.
type GetPubKey struct {
	powNonce       uint64   // Random nonce used for the Proof Of Work
	time           uint64   // The time that this message was generated and broadcast.
	addressVersion varint   // The address' version.
	streamNumber   varint   // The address' stream number
	pubKeyHash     [20]byte // The ripemd hash of the public key
}

// A public key.
type PubKey struct {
	powNonce       uint64 // Random nonce used for the Proof Of Work
	time           uint64 // The time that this message was generated and broadcast.
	addressVersion varint // The address' version.
	streamNumber   varint // The address' stream number
	behavior       uint32 // A bitfield of optional behaviors and features that can be expected from the node receiving the message.
	// The ECC public key used for signing (uncompressed format; normally
	// prepended with \x04).
	publicSigningKey [64]byte
	// The ECC public key used for encryption (uncompressed format; normally
	// prepended with \x04 ).
	publicEncryptionKey [64]byte
}

// Used for person-to-person messages.
type msg struct {
	PowNonce     [8]byte // Random nonce used for the Proof Of Work
	Time         uint64  // The time that this message was generated and broadcast. V1 used uint32.
	StreamNumber uint64  // varint, the address' stream number
	Encrypted    []byte  // Encrypted data. See also: UnencryptedMessageData
}

func writeMsg(w io.Writer, m msg) error {
	// TODO performance: pre-allocate byte slices, share between instances.
	buf := new(bytes.Buffer)
	putBytes(buf, m.PowNonce[:])
	putUint32(buf, uint32(m.Time)) // XXX moving to uint64 soon.
	encVarint.WriteVarInt(buf, m.StreamNumber)
	putBytes(buf, m.Encrypted)
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Println("writeMessage write failed: ", err)
	}
	return nil
}

func parseMsg(r io.Reader) (m msg, err error) {
	m.PowNonce = readBytes8(r)
	// TODO:
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, r); err != nil {
		return m, err
	}
	r = buf
	if err := checkProofOfWork(buf.Bytes(), m.PowNonce); err != nil {
		return m, err
	}
	// TODO: Soon moving to uint32 in the wire.
	m.Time = uint64(readUint32(r))
	m.StreamNumber, _, err = encVarint.ReadVarInt(r)
	if err != nil {
		return m, fmt.Errorf("parseMsg reading Stream Number: %v\n", err)
	}
	buf = new(bytes.Buffer)
	if n, err := io.Copy(buf, r); err != nil {
		return m, err
	} else if n == 0 {
		return m, fmt.Errorf("parseMsg Encrypted content empty")
	}
	m.Encrypted = buf.Bytes()
	return m, nil
}

type broadcast struct {
	// Random nonce used for the Proof Of Work
	PowNonce [8]byte
	// The time that this message was generated and broadcast.
	Time uint64 // XXX still writing uint32, moving to 64 in v2.
	// The version number of this broadcast protocol message.
	BroadcastVersion uint64
	// Sender's address version number. This is needed in order to calculate
	// the sender's address to show in the UI, and also to allow for forwards
	// compatible changes to the public-key data included below.
	AddressVersion uint64
	// Sender's stream number.
	StreamNumber uint64
	// A bitfield of optional behaviors and features that can be expected from
	// the node with this pubkey included in this msg message (the sender's
	// pubkey).
	Behavior uint32 // => retired in new version.

	// The ECC public key used for signing (uncompressed format; normally
	// prepended with \x04).
	PublicSigningKey [64]byte
	// The ECC public key used for encryption (uncompressed format; normally
	// prepended with \x04 ).
	PublicEncryptionKey [64]byte
	// The sender's address hash. This is included so that nodes can more
	// cheaply detect whether this is a broadcast message for which they are
	// listening, although it must be verified with the public key above.
	AddressHash [20]byte
	// Message encoding type.
	Encoding uint64
	// Message length.
	MessageLength uint64
	// The message.
	Message []byte
	// Length of the signature.
	SigLength uint64
	// The ECDSA signature which covers everything from the msg_version to the
	// ack_data.
	Signature []byte
}

func parseBroadcast(r io.Reader) (b broadcast, err error) {
	b.PowNonce = readBytes8(r)
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, r); err != nil {
		return b, err
	}
	r = buf
	if err := checkProofOfWork(buf.Bytes(), b.PowNonce); err != nil {
		return b, err
	}
	// TODO: Soon moving to uint32 in the wire.
	b.Time = uint64(readUint32(r))
	b.BroadcastVersion, _, err = encVarint.ReadVarInt(r)
	if err != nil {
		return b, fmt.Errorf("parseBroadcast reading broadcast version: %v\n", err)
	}
	if b.BroadcastVersion != 1 {
		return b, fmt.Errorf("I do not yet support Broadcasts of version %d", b.BroadcastVersion)
	}
	b.AddressVersion, _, err = encVarint.ReadVarInt(r)
	if err != nil {
		return b, fmt.Errorf("parseBroadcast reading address version: %v\n", err)
	}
	b.StreamNumber, _, err = encVarint.ReadVarInt(r)
	if err != nil {
		return b, fmt.Errorf("parseBroadcast reading Stream Number: %v\n", err)
	}
	b.Behavior = readUint32(r)
	if b.Behavior != 1 {
		log.Printf("warning: parseBroadcast unknown behavior mask: %x\n", b.Behavior)
	}
	if err = binary.Read(r, binary.BigEndian, &b.PublicSigningKey); err != nil {
		return b, fmt.Errorf("parseBroadcast PublicSigningKey err: %v\n", err)
	}
	if err = binary.Read(r, binary.BigEndian, &b.PublicEncryptionKey); err != nil {
		return b, fmt.Errorf("parseBroadcast PublicEncryptionKey err: %v\n", err)
	}
	if err = binary.Read(r, binary.BigEndian, &b.AddressHash); err != nil {
		return b, fmt.Errorf("parseBroadcast AddressHash err: %v\n", err)
	}
	// PyBitMessage just writes '\x02'.
	b.Encoding, _, err = encVarint.ReadVarInt(r)
	if err != nil {
		return b, fmt.Errorf("parseBroadcast reading encoding: %v\n", err)
	}
	if b.MessageLength, _, err = encVarint.ReadVarInt(r); err != nil {
		return b, fmt.Errorf("parseBroadcast reading message length: %v\n", err)
	}
	b.Message = make([]byte, b.MessageLength)
	if _, err = r.Read(b.Message); err != nil {
		return b, fmt.Errorf("parseBroadcast reading message: %v\n", err)
	}
	if b.SigLength, _, err = encVarint.ReadVarInt(r); err != nil {
		return b, fmt.Errorf("parseBroadcast reading siglength: %v\n", err)
	}
	b.Signature = make([]byte, b.SigLength)
	if _, err = r.Read(b.Message); err != nil {
		return b, fmt.Errorf("parseBroadcast reading signature: %v\n", err)
	}
	return b, nil
}

func nullPadCommand(command string) string {
	return command + strings.Repeat("\x00", 12-len(command))
}

// These helper functions aren't strictly needed because I could just call
// binary.Write() directly, but they serve as documentation and help ensure
// I'm writing the correct type expected by the protocol.

func putBytes(w io.Writer, b []byte) {
	check(binary.Write(w, binary.BigEndian, b))
}

func putInt32(w io.Writer, i int32) {
	check(binary.Write(w, binary.BigEndian, i))
}

func putInt64(w io.Writer, i int64) {
	check(binary.Write(w, binary.BigEndian, i))
}

func putUint16(w io.Writer, u uint16) {
	check(binary.Write(w, binary.BigEndian, u))
}

func putUint32(w io.Writer, u uint32) {
	check(binary.Write(w, binary.BigEndian, u))
}

func putUint64(w io.Writer, u uint64) {
	check(binary.Write(w, binary.BigEndian, u))
}

func putVarIntList(w io.Writer, x []uint64) {
	if _, err := encVarint.WriteVarInt(w, uint64(len(x))); err != nil {
		log.Println("putVarIntList lenght:", err.Error())

	}
	for _, v := range x {
		if _, err := encVarint.WriteVarInt(w, uint64(v)); err != nil {
			log.Println("putVarIntList:", err.Error())
		}
	}
}

func readInt32(r io.Reader) (x int32) {
	check(binary.Read(r, binary.BigEndian, &x))
	return x
}

func readUint32(r io.Reader) (x uint32) {
	check(binary.Read(r, binary.BigEndian, &x))
	return x
}

func readUint64(r io.Reader) (x uint64) {
	check(binary.Read(r, binary.BigEndian, &x))
	return x
}

func readBytes8(r io.Reader) (x [8]byte) {
	check(binary.Read(r, binary.BigEndian, &x))
	return x
}

// XXX return errors too
func readVarIntList(r io.Reader) []uint64 {
	length, _, err := encVarint.ReadVarInt(r)
	if err != nil {
		log.Println(err)
		return nil
	}
	x := make([]uint64, length)
	for i := range x {
		if x[i], _, err = encVarint.ReadVarInt(r); err != nil {
			log.Println(err)
			return nil
		}
	}
	return x
}

func readNetworkAddressList(r io.Reader) ([]extendedNetworkAddress, error) {
	length, _, err := encVarint.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	log.Println("entries", length)
	addrs := make([]extendedNetworkAddress, length)
	for i := range addrs {
		addr := extendedNetworkAddress{}
		if err := binary.Read(r, binary.BigEndian, &addr); err != nil {
			return nil, err
		}
		addrs[i] = addr
	}
	return addrs, nil
}

func doubleHash(msg []byte) ([]byte, error) {
	for i := 0; i < 2; i++ {
		h := sha512.New()
		h.Write(msg)
		msg = h.Sum(nil)
	}
	return msg, nil
}

// sha512HashPrefix returns the first 4 bytes of the SHA-512 hash of b.
func sha512HashPrefix(b []byte) (x uint32) {
	s := sha512.New()
	s.Write(b)
	r := bytes.NewBuffer(s.Sum(nil)[0:4])
	binary.Read(r, binary.BigEndian, &x)
	return x
}

// These values are filled in by init. They can't be represented using uint64.
var n2to64 *big.Int       // 18446744073709551616
var initialTrial *big.Int // 99999999999999999999

// ProofOfWork goes through several iterations to find a nonce number that,
// when hashed with the payload data, produces a certain target result. The
// only way to find such a nonce is by bruteforce. The goal is to ensure that
// each participant of the network can only send a limited number of messages
// per hour, since they need computational power to do so. See the wikipedia
// article for Hashcash, that inspired Bitcoin's mechanism and Bitmessage's.
// The BitMessage implementation is documented at
// https://bitmessage.org/wiki/Proof_of_work. Note that the difficulty of the
// calculation is proportional to the size of the payload.
func ProofOfWork(data []byte, initialNonce []byte) (nonceByte [8]byte, err error) {
	if len(data) == 0 {
		return nonceByte, fmt.Errorf("ProofOfWork received empty data.")
	}
	target := new(big.Int).Div(n2to64, big.NewInt(int64((len(data)+payloadLengthExtraBytes+8)*averageProofOfWorkNonceTrialsPerByte)))
	if target.Cmp(new(big.Int)) == 0 { // target == 0
		return nonceByte, fmt.Errorf("error calculating target")
	}
	// Copies initialTrial to trialValue.
	trialValue := new(big.Int).Set(initialTrial)

	initialHash := sha512.New()
	initialHash.Write(data)

	nonce := big.NewInt(1)
	if initialNonce != nil {
		// Used for testing.
		nonce.SetBytes(initialNonce[:8])
	}
	var (
		one = big.NewInt(1)
		b   = make([]byte, 8)
		h   []byte
	)
	// while trialValue > target:
	for trialValue.Cmp(target) == 1 {
		// 8 byte slice of nonce.Bytes() prefixed with zeroes. Avoid an extra
		// allocation by reusing the slice. Since the nonce always increases,
		// the prefix bytes are guaranteed to be zero.
		b = append(b[0:8-len(nonce.Bytes())], nonce.Bytes()...)
		h, err = doubleHash(append(b, initialHash.Sum(nil)...))
		trialValue.SetBytes(h[0:8])
		nonce.Add(nonce, one)
	}
	copy(nonceByte[:], b)
	return nonceByte, nil
}

func checkProofOfWork(data []byte, nonce [8]byte) error {
	// From: https://bitmessage.org/wiki/Proof_of_work
	initialHash := sha512.New()
	initialHash.Write(data)

	h, err := doubleHash(append(nonce[:], initialHash.Sum(nil)...))
	if err != nil {
		return err
	}

	POWValue := new(big.Int).SetBytes(h[0:8])
	target := new(big.Int).Div(n2to64, big.NewInt(int64((len(data)+payloadLengthExtraBytes)*averageProofOfWorkNonceTrialsPerByte)))
	// POWValue >= target:
	if POWValue.Cmp(target) != 1 {
		return nil
	}
	return fmt.Errorf("checkProofOfWork did not pass")
}

// Bitmessage produces a hash for the provided message using a SHA-512 in the
// first round and a RIPEMD-160 in the second.
func Bitmessage(msg []byte) ([]byte, error) {
	s := sha512.New()
	s.Write(msg)

	r := ripemd160.New()
	r.Write(s.Sum(nil))
	return r.Sum(nil), nil
}
