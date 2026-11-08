package main

import "encoding/binary"

// Wire format (one UDP datagram, kept <= maxDatagram to survive overlay MTU):
//
//	type u8 | reqid u64 | sender node id [32] | body
const (
	tPing  byte = 1
	tPong  byte = 2
	tStore byte = 3
	tAck   byte = 4
	tGet   byte = 5
	tData  byte = 6
	tHas   byte = 7 // body as GET; answered with tHasR
	tHasR  byte = 8 // body: status u8 (0 held, 1 not held)
	tOnion byte = 9 // fixed-size onion packet, see onion.go

	hdrLen      = 1 + 8 + 32
	maxDatagram = 1400
)

type Hash = [32]byte

type msg struct {
	typ  byte
	id   uint64
	from Hash
	body []byte
}

func (m msg) marshal() []byte {
	b := make([]byte, 0, hdrLen+len(m.body))
	b = append(b, m.typ)
	b = binary.BigEndian.AppendUint64(b, m.id)
	b = append(b, m.from[:]...)
	return append(b, m.body...)
}

func unmarshal(b []byte) (msg, bool) {
	if len(b) < hdrLen {
		return msg{}, false
	}
	m := msg{typ: b[0], id: binary.BigEndian.Uint64(b[1:9]), body: b[hdrLen:]}
	copy(m.from[:], b[9:hdrLen])
	return m, true
}

// rd is a sticky-error reader.
type rd struct {
	b   []byte
	bad bool
}

func (r *rd) take(n int) []byte {
	if r.bad || len(r.b) < n {
		r.bad = true
		return make([]byte, n)
	}
	x := r.b[:n]
	r.b = r.b[n:]
	return x
}
func (r *rd) u8() byte    { return r.take(1)[0] }
func (r *rd) u16() uint16 { return binary.BigEndian.Uint16(r.take(2)) }
func (r *rd) u32() uint32 { return binary.BigEndian.Uint32(r.take(4)) }
func (r *rd) hash() (h Hash) {
	copy(h[:], r.take(32))
	return
}
func (r *rd) proof() []Hash {
	n := int(r.u8())
	p := make([]Hash, 0, n)
	for i := 0; i < n; i++ {
		p = append(p, r.hash())
	}
	return p
}

func putProof(b []byte, p []Hash) []byte {
	b = append(b, byte(len(p)))
	for _, h := range p {
		b = append(b, h[:]...)
	}
	return b
}

// STORE body: root | leaf u32 | nleaves u32 | dlen u16 | data | proof
func encStore(root Hash, leaf, n uint32, data []byte, proof []Hash) []byte {
	b := append([]byte{}, root[:]...)
	b = binary.BigEndian.AppendUint32(b, leaf)
	b = binary.BigEndian.AppendUint32(b, n)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	b = append(b, data...)
	return putProof(b, proof)
}

// GET body: root | leaf u32
func encGet(root Hash, leaf uint32) []byte {
	b := append([]byte{}, root[:]...)
	return binary.BigEndian.AppendUint32(b, leaf)
}

// DATA body: status u8 (0 found, 1 miss) | [nleaves u32 | dlen u16 | data | proof]
func encData(found bool, n uint32, data []byte, proof []Hash) []byte {
	if !found {
		return []byte{1}
	}
	b := []byte{0}
	b = binary.BigEndian.AppendUint32(b, n)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	b = append(b, data...)
	return putProof(b, proof)
}
