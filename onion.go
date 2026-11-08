package main

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// Onion packets, Sphinx-style. Every packet is exactly maxDatagram bytes, on
// every hop, whatever it carries:
//
//	hdr(41, link level) | e(32) | gamma(16) | beta(165) | delta(1146)
//
// e      one-shot X25519 public key for this hop (fresh per hop, per packet)
// beta   routing info, stream-encrypted in layers; each hop peels one record
//
//	off the front and re-pads the back with stream output (the "filler"
//	the sender precomputes so the next hop's MAC still verifies)
//
// gamma  MAC over e||beta
// delta  payload, wrapped in a wide-block cipher (LIONESS) per hop so that any
//
//	modification turns the whole payload to garbage (no tagging attacks)
//
// A relay learns only its predecessor and its successor. Replies travel in
// single-use reply blocks (SURBs) prepared by the requester.
const (
	onionR   = 55 // record: type(1) addr(6) e_next(32) gamma_next(16)
	onionH   = 3  // hops on every path: 2 relays + destination
	onionB   = onionR * onionH
	onionHdr = 32 + 16 + onionB
	onionD   = maxDatagram - hdrLen - onionHdr
	surbLen  = 6 + onionHdr + 16
	zeroLen  = 8 // integrity prefix inside the payload

	recRelay     = 1
	recDeliver   = 2
	recSurb      = 3
	recRelayLink = 5 // like recRelay, but the next hop is an attached client named by a link id, not an address

	kReq   = 1
	kReply = 2
	kDummy = 3
	kPost  = 4 // request without a reply block
)

type hop struct {
	pub  [32]byte
	addr netip.AddrPort // where the previous hop sends to reach this one
	link *[6]byte       // or: the previous hop holds a link with this id (attached clients behind NAT)
}

type hopKeys struct {
	mac, rho [32]byte
	pi       [4][32]byte
}

type onionHeader struct {
	e     [32]byte
	gamma [16]byte
	beta  [onionB]byte
}

func deriveHop(shared []byte) hopKeys {
	var k hopKeys
	r := hkdf.New(sha256.New, shared, nil, []byte("da/onion/v1"))
	io.ReadFull(r, k.mac[:])
	io.ReadFull(r, k.rho[:])
	for i := range k.pi {
		io.ReadFull(r, k.pi[i][:])
	}
	return k
}

func keysFromKs(ks []byte) hopKeys {
	return deriveHop(append([]byte("surb"), ks...))
}

func streamXOR(key []byte, b []byte) {
	c, _ := chacha20.NewUnauthenticatedCipher(key, make([]byte, 12))
	c.XORKeyStream(b, b)
}

func rhoStream(k *[32]byte, n int) []byte {
	b := make([]byte, n)
	streamXOR(k[:], b)
	return b
}

func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func macOf(k *[32]byte, e, beta []byte) (g [16]byte) {
	h := hmac.New(sha256.New, k[:])
	h.Write(e)
	h.Write(beta)
	copy(g[:], h.Sum(nil))
	return
}

// LIONESS wide-block cipher: 4 rounds of stream cipher / keyed hash.
func piEnc(k *hopKeys, m []byte) {
	L, R := m[:32], m[32:]
	var t [32]byte
	step := func(key *[32]byte) { // R ^= S(L ^ K)
		copy(t[:], L)
		xorInto(t[:], key[:])
		streamXOR(t[:], R)
	}
	hash := func(key *[32]byte) { // L ^= H_K(R)
		h, _ := blake2b.New256(key[:])
		h.Write(R)
		xorInto(L, h.Sum(nil))
	}
	step(&k.pi[0])
	hash(&k.pi[1])
	step(&k.pi[2])
	hash(&k.pi[3])
}

func piDec(k *hopKeys, m []byte) {
	L, R := m[:32], m[32:]
	var t [32]byte
	step := func(key *[32]byte) {
		copy(t[:], L)
		xorInto(t[:], key[:])
		streamXOR(t[:], R)
	}
	hash := func(key *[32]byte) {
		h, _ := blake2b.New256(key[:])
		h.Write(R)
		xorInto(L, h.Sum(nil))
	}
	hash(&k.pi[3])
	step(&k.pi[2])
	hash(&k.pi[1])
	step(&k.pi[0])
}

// wrapPayload applies the per-hop layers, last hop first (forward packets), or
// removes them again at the owner of a reply block.
func wrapPayload(keys []hopKeys, m []byte) {
	for j := len(keys) - 1; j >= 0; j-- {
		piEnc(&keys[j], m)
	}
}

func putAddr(b []byte, a netip.AddrPort) {
	ip := a.Addr().As4()
	copy(b, ip[:])
	binary.BigEndian.PutUint16(b[4:], a.Port())
}

func getAddr(b []byte) netip.AddrPort {
	var ip [4]byte
	copy(ip[:], b)
	return netip.AddrPortFrom(netip.AddrFrom4(ip), binary.BigEndian.Uint16(b[4:]))
}

// buildHeader makes the header for a path of exactly onionH hops. last is the
// record the final hop will read. It returns the header, to be sent to
// path[0], and the per-hop keys (kept by the sender for reply blocks).
func buildHeader(path []hop, last []byte) (onionHeader, []hopKeys, error) {
	var h onionHeader
	if len(path) != onionH || len(last) > onionR {
		return h, nil, errors.New("bad path")
	}
	curve := ecdh.X25519()
	eph := make([][32]byte, onionH)
	keys := make([]hopKeys, onionH)
	rho := make([][]byte, onionH)
	for j := range path {
		x, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return h, nil, err
		}
		copy(eph[j][:], x.PublicKey().Bytes())
		Y, err := curve.NewPublicKey(path[j].pub[:])
		if err != nil {
			return h, nil, err
		}
		s, err := x.ECDH(Y)
		if err != nil {
			return h, nil, err
		}
		keys[j] = deriveHop(s)
		rho[j] = rhoStream(&keys[j].rho, onionB+onionR)
	}
	// filler: what the first H-1 hops will append to beta as they peel
	var phi []byte
	for i := 0; i < onionH-1; i++ {
		ext := append(append([]byte{}, phi...), make([]byte, onionR)...)
		xorInto(ext, rho[i][onionB-len(phi):onionB+onionR])
		phi = ext
	}
	beta := make([]byte, onionB)
	copy(beta, last)
	xorInto(beta[:onionR], rho[onionH-1][:onionR])
	copy(beta[onionR:], phi)
	gamma := macOf(&keys[onionH-1].mac, eph[onionH-1][:], beta)
	for i := onionH - 2; i >= 0; i-- {
		nb := make([]byte, onionB)
		if l := path[i+1].link; l != nil {
			nb[0] = recRelayLink
			copy(nb[1:7], l[:])
		} else {
			nb[0] = recRelay
			putAddr(nb[1:7], path[i+1].addr)
		}
		copy(nb[7:39], eph[i+1][:])
		copy(nb[39:55], gamma[:])
		copy(nb[onionR:], beta[:onionB-onionR])
		xorInto(nb, rho[i][:onionB])
		beta = nb
		gamma = macOf(&keys[i].mac, eph[i][:], beta)
	}
	h.e, h.gamma = eph[0], gamma
	copy(h.beta[:], beta)
	return h, keys, nil
}

type peeled struct {
	rec  [onionR]byte
	next onionHeader // valid when rec[0] == recRelay
	keys hopKeys
	tag  [16]byte // replay tag
}

func peelHeader(priv *ecdh.PrivateKey, h onionHeader) (p peeled, err error) {
	Y, err := ecdh.X25519().NewPublicKey(h.e[:])
	if err != nil {
		return p, err
	}
	s, err := priv.ECDH(Y)
	if err != nil {
		return p, err
	}
	p.keys = deriveHop(s)
	want := macOf(&p.keys.mac, h.e[:], h.beta[:])
	if !hmac.Equal(want[:], h.gamma[:]) {
		return p, errors.New("bad mac")
	}
	ext := append(append([]byte{}, h.beta[:]...), make([]byte, onionR)...)
	xorInto(ext, rhoStream(&p.keys.rho, onionB+onionR))
	copy(p.rec[:], ext[:onionR])
	copy(p.next.beta[:], ext[onionR:])
	copy(p.next.e[:], p.rec[7:39])
	copy(p.next.gamma[:], p.rec[39:55])
	sum := sha256.Sum256(s)
	copy(p.tag[:], sum[:16])
	return p, nil
}

func encodeOnion(h onionHeader, delta []byte) []byte {
	b := make([]byte, 0, onionHdr+len(delta))
	b = append(b, h.e[:]...)
	b = append(b, h.gamma[:]...)
	b = append(b, h.beta[:]...)
	return append(b, delta...)
}

func decodeOnion(b []byte) (h onionHeader, delta []byte, ok bool) {
	if len(b) != onionHdr+onionD {
		return h, nil, false
	}
	copy(h.e[:], b[:32])
	copy(h.gamma[:], b[32:48])
	copy(h.beta[:], b[48:onionHdr])
	return h, append([]byte(nil), b[onionHdr:]...), true
}

// surb: a single-use reply block. The holder of one can send exactly one
// message back to its creator without learning who or where that is.
type surb struct {
	first netip.AddrPort
	hdr   onionHeader
	ks    [16]byte // payload key shared with the responder
}

func (s surb) encode() []byte {
	b := make([]byte, 6, surbLen)
	putAddr(b, s.first)
	b = append(b, s.hdr.e[:]...)
	b = append(b, s.hdr.gamma[:]...)
	b = append(b, s.hdr.beta[:]...)
	return append(b, s.ks[:]...)
}

func decodeSurb(b []byte) (s surb, ok bool) {
	if len(b) < surbLen {
		return s, false
	}
	s.first = getAddr(b)
	copy(s.hdr.e[:], b[6:38])
	copy(s.hdr.gamma[:], b[38:54])
	copy(s.hdr.beta[:], b[54:54+onionB])
	copy(s.ks[:], b[54+onionB:surbLen])
	return s, true
}
