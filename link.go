package main

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Authenticated links.
//
// Every datagram between two nodes travels inside a session. A session is set
// up by a SIGMA-style handshake: both sides contribute a fresh X25519 key,
// both sign the transcript with their long-term Ed25519 identity, and the
// session keys come from the ephemeral Diffie-Hellman only. So
//
//   - the sender id of every message is proven (nobody can speak as another node),
//   - an initiator that knows who it dials (id learned from gossip) aborts if
//     the peer at that address is somebody else (pinning),
//   - recorded traffic stays unreadable even if an identity key leaks later
//     (forward secrecy; sessions are re-keyed every LinkLife),
//   - modified, replayed or forged datagrams are dropped before any parsing.
//
// Datagram kinds (first byte):
//
//	hs1  idxI(4) | eI(32)
//	hs2  idxI(4) | idxR(4) | eR(32) | AEAD{ ikR(32) | sigR(64) }
//	hs3  idxR(4) | AEAD{ ikI(32) | sigI(64) }
//	data idx(4) | counter(8) | AEAD(msg)
//
// The responder can already derive the keys at hs2 but only learns (and
// authenticates) the initiator at hs3. The initiator repeats hs3 in front of
// its data until the first packet comes back, so a lost hs3 costs nothing.
const (
	kHs1  byte = 0xA1
	kHs2  byte = 0xA2
	kHs3  byte = 0xA3
	kData byte = 0xA4

	linkOverhead = 1 + 4 + 8 + 16 // kind, receiver index, counter, tag
	maxPlain     = maxDatagram - linkOverhead

	hsTries   = 6
	hsRetry   = 250 * time.Millisecond
	maxPendIn = 512
	maxQueue  = 16
)

type window struct {
	max  uint64
	bits uint64
}

func (w *window) fresh(c uint64) bool {
	if c > w.max {
		return true
	}
	d := w.max - c
	return d < 64 && w.bits&(1<<d) == 0
}

func (w *window) mark(c uint64) {
	if c > w.max {
		s := c - w.max
		if s >= 64 {
			w.bits = 0
		} else {
			w.bits <<= s
		}
		w.max = c
		w.bits |= 1
		return
	}
	w.bits |= 1 << (w.max - c)
}

type session struct {
	idx, peerIdx uint32
	peer         Hash
	ik           [32]byte
	addr         netip.AddrPort
	send, recv   cipher.AEAD
	ctr          uint64
	win          window
	born, last   time.Time
	initiator    bool
	confirmed    bool   // initiator: heard from the peer on this session
	hs3          []byte // initiator: repeated until confirmed
}

type hsOut struct {
	eph    *ecdh.PrivateKey
	idx    uint32
	addr   netip.AddrPort
	expect *Hash
	queue  [][]byte
	born   time.Time
}

type hsIn struct {
	t1         []byte
	k3         []byte
	send, recv cipher.AEAD
	peerIdx    uint32
	addr       netip.AddrPort
	born       time.Time
}

type linkState struct {
	mu     sync.Mutex
	byIdx  map[uint32]*session
	byAddr map[netip.AddrPort]*session
	out    map[netip.AddrPort]*hsOut
	outIdx map[uint32]*hsOut
	in     map[uint32]*hsIn
	pins   map[netip.AddrPort]pin

	opened, rejected, forged, replayed int64 // counters for status/tests
}

type pin struct {
	id Hash
	at time.Time
}

func newLinkState() *linkState {
	return &linkState{byIdx: map[uint32]*session{}, byAddr: map[netip.AddrPort]*session{}, out: map[netip.AddrPort]*hsOut{},
		outIdx: map[uint32]*hsOut{}, in: map[uint32]*hsIn{}, pins: map[netip.AddrPort]pin{}}
}

func u32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func (l *linkState) freshIdx() uint32 { // caller holds mu
	for {
		i := u32()
		if i == 0 {
			continue
		}
		if _, a := l.byIdx[i]; a {
			continue
		}
		if _, b := l.outIdx[i]; b {
			continue
		}
		if _, c := l.in[i]; c {
			continue
		}
		return i
	}
}

func (n *Node) linkLife() time.Duration {
	if n.cfg.LinkLife > 0 {
		return n.cfg.LinkLife
	}
	return 2 * time.Minute
}

// pinAddr records which id we expect to find at an address (learned from a
// peer's gossip). A handshake with anybody else is aborted.
func (n *Node) pinAddr(a netip.AddrPort, id Hash) {
	n.lk.mu.Lock()
	if len(n.lk.pins) < 4096 {
		n.lk.pins[a] = pin{id, time.Now()}
	}
	n.lk.mu.Unlock()
}

func hsKeys(dh, t1 []byte) (k2, k3, kIR, kRI []byte) {
	r := hkdf.New(sha256.New, dh, t1, []byte("da/link/v1"))
	k2, k3, kIR, kRI = make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)
	io.ReadFull(r, k2)
	io.ReadFull(r, k3)
	io.ReadFull(r, kIR)
	io.ReadFull(r, kRI)
	return
}

func aeadOf(k []byte) cipher.AEAD {
	a, _ := chacha20poly1305.New(k)
	return a
}

func transcript(eI, eR []byte, idxI, idxR uint32) []byte {
	h := sha256.New()
	h.Write([]byte("da/link/t1"))
	h.Write(eI)
	h.Write(eR)
	var b [8]byte
	binary.BigEndian.PutUint32(b[:], idxI)
	binary.BigEndian.PutUint32(b[4:], idxR)
	h.Write(b[:])
	return h.Sum(nil)
}

func sigMsg(role string, t1 []byte, ids ...[]byte) []byte {
	m := append([]byte("da/link/"+role), t1...)
	for _, i := range ids {
		m = append(m, i...)
	}
	return m
}

var zeroNonce = make([]byte, chacha20poly1305.NonceSize)

// raw writes one datagram.
func (n *Node) raw(to netip.AddrPort, b []byte) {
	if n.cfg.NATFilter {
		n.outMu.Lock()
		n.out[to] = time.Now()
		n.outMu.Unlock()
	}
	if c := n.conn.Load(); c != nil {
		c.WriteToUDPAddrPort(b, to)
	}
}

// linkSend sends one plaintext message to addr, through a session. Without a
// session the message is queued and a handshake is started.
func (n *Node) linkSend(to netip.AddrPort, plain []byte) {
	l := n.lk
	l.mu.Lock()
	s := l.byAddr[to]
	life := n.linkLife()
	if s != nil {
		age := time.Since(s.born)
		if age > 2*life {
			s = nil
		} else if age > life && s.initiator {
			n.startLocked(to, nil, nil) // re-key in the background, keep using the old session meanwhile
		}
	}
	if s == nil {
		n.startLocked(to, plain, nil)
		l.mu.Unlock()
		return
	}
	pkt := n.sealLocked(s, plain)
	var hs3 []byte
	if s.initiator && !s.confirmed {
		hs3 = s.hs3
	}
	l.mu.Unlock()
	if hs3 != nil {
		n.raw(to, hs3)
	}
	n.raw(to, pkt)
}

func (n *Node) sealLocked(s *session, plain []byte) []byte {
	s.ctr++
	hdr := make([]byte, 13, 13+len(plain)+16)
	hdr[0] = kData
	binary.BigEndian.PutUint32(hdr[1:], s.peerIdx)
	binary.BigEndian.PutUint64(hdr[5:], s.ctr)
	var nonce [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], s.ctr)
	return s.send.Seal(hdr, nonce[:], plain, hdr)
}

// startLocked begins a handshake towards addr unless one is running; plain, if
// any, is queued behind it. l.mu is held.
func (n *Node) startLocked(to netip.AddrPort, plain []byte, expect *Hash) {
	l := n.lk
	if h := l.out[to]; h != nil {
		if plain != nil && len(h.queue) < maxQueue {
			h.queue = append(h.queue, plain)
		}
		return
	}
	if expect == nil {
		if p, ok := l.pins[to]; ok && time.Since(p.at) < time.Minute {
			e := p.id
			expect = &e
		} else if s := l.byAddr[to]; s != nil {
			e := s.peer
			expect = &e
		}
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	h := &hsOut{eph: eph, idx: l.freshIdx(), addr: to, expect: expect, born: time.Now()}
	if plain != nil {
		h.queue = [][]byte{plain}
	}
	l.out[to] = h
	l.outIdx[h.idx] = h
	go n.hsRetry(h)
}

func (n *Node) hsRetry(h *hsOut) {
	pkt := make([]byte, 0, 37)
	pkt = append(pkt, kHs1)
	pkt = binary.BigEndian.AppendUint32(pkt, h.idx)
	pkt = append(pkt, h.eph.PublicKey().Bytes()...)
	for i := 0; i < hsTries; i++ {
		n.lk.mu.Lock()
		alive := n.lk.out[h.addr] == h
		n.lk.mu.Unlock()
		if !alive {
			return
		}
		n.raw(h.addr, pkt)
		select {
		case <-time.After(hsRetry):
		case <-n.done:
			return
		}
	}
	n.lk.mu.Lock()
	if n.lk.out[h.addr] == h {
		delete(n.lk.out, h.addr)
		delete(n.lk.outIdx, h.idx)
		n.lk.rejected++
	}
	n.lk.mu.Unlock()
}

// linkRecv processes one datagram. It returns a plaintext message with the
// authenticated identity of its sender, or ok=false when the datagram was a
// handshake step or not acceptable.
func (n *Node) linkRecv(b []byte, src netip.AddrPort) (plain []byte, from Hash, ik [32]byte, ok bool) {
	if len(b) < 1 {
		return
	}
	switch b[0] {
	case kData:
		return n.recvData(b, src)
	case kHs1:
		n.recvHs1(b, src)
	case kHs2:
		n.recvHs2(b, src)
	case kHs3:
		n.recvHs3(b, src)
	}
	return
}

func (n *Node) recvData(b []byte, src netip.AddrPort) (plain []byte, from Hash, ik [32]byte, ok bool) {
	if len(b) < 13+16 {
		return
	}
	idx := binary.BigEndian.Uint32(b[1:5])
	ctr := binary.BigEndian.Uint64(b[5:13])
	l := n.lk
	l.mu.Lock()
	s := l.byIdx[idx]
	if s == nil {
		l.forged++
		l.mu.Unlock()
		return
	}
	if !s.win.fresh(ctr) {
		l.replayed++
		l.mu.Unlock()
		return
	}
	aead := s.recv
	l.mu.Unlock()
	var nonce [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	pt, err := aead.Open(nil, nonce[:], b[13:], b[:13])
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.forged++
		return
	}
	if !s.win.fresh(ctr) {
		l.replayed++
		return
	}
	s.win.mark(ctr)
	s.last = time.Now()
	s.confirmed = true
	if s.addr != src { // roaming: only an authentic, fresh packet may move the session
		if l.byAddr[s.addr] == s {
			delete(l.byAddr, s.addr)
		}
		s.addr = src
		l.byAddr[src] = s
	}
	return pt, s.peer, s.ik, true
}

func (n *Node) recvHs1(b []byte, src netip.AddrPort) {
	if n.cfg.Attached || len(b) != 37 { // attached and hidden nodes never accept inbound links
		return
	}
	idxI := binary.BigEndian.Uint32(b[1:5])
	eI := b[5:37]
	l := n.lk
	l.mu.Lock()
	if len(l.in) >= maxPendIn {
		l.mu.Unlock()
		return
	}
	idxR := l.freshIdx()
	l.mu.Unlock()
	pubI, err := ecdh.X25519().NewPublicKey(eI)
	if err != nil {
		return
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	dh, err := eph.ECDH(pubI)
	if err != nil {
		return
	}
	eR := eph.PublicKey().Bytes()
	t1 := transcript(eI, eR, idxI, idxR)
	k2, k3, kIR, kRI := hsKeys(dh, t1)
	sig := ed25519.Sign(n.sk, sigMsg("R", t1, n.pub[:]))
	pl := append(append([]byte{}, n.pub[:]...), sig...)
	out := []byte{kHs2}
	out = binary.BigEndian.AppendUint32(out, idxI)
	out = binary.BigEndian.AppendUint32(out, idxR)
	out = append(out, eR...)
	out = aeadOf(k2).Seal(out, zeroNonce, pl, t1)
	l.mu.Lock()
	l.in[idxR] = &hsIn{t1: t1, k3: k3, send: aeadOf(kRI), recv: aeadOf(kIR), peerIdx: idxI, addr: src, born: time.Now()}
	l.mu.Unlock()
	n.raw(src, out)
}

func (n *Node) recvHs2(b []byte, src netip.AddrPort) {
	if len(b) != 1+4+4+32+96+16 {
		return
	}
	idxI, idxR := binary.BigEndian.Uint32(b[1:5]), binary.BigEndian.Uint32(b[5:9])
	eR := b[9:41]
	l := n.lk
	l.mu.Lock()
	h := l.outIdx[idxI]
	if h == nil || h.addr != src {
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()
	pubR, err := ecdh.X25519().NewPublicKey(eR)
	if err != nil {
		return
	}
	dh, err := h.eph.ECDH(pubR)
	if err != nil {
		return
	}
	t1 := transcript(h.eph.PublicKey().Bytes(), eR, idxI, idxR)
	k2, k3, kIR, kRI := hsKeys(dh, t1)
	pl, err := aeadOf(k2).Open(nil, zeroNonce, b[41:], t1)
	if err != nil {
		return
	}
	var ikR [32]byte
	copy(ikR[:], pl[:32])
	idR := idOf(ikR[:])
	if !ed25519.Verify(ikR[:], sigMsg("R", t1, ikR[:]), pl[32:]) || (h.expect != nil && *h.expect != idR) || idR == n.id {
		l.mu.Lock()
		if l.out[h.addr] == h {
			delete(l.out, h.addr)
			delete(l.outIdx, h.idx)
		}
		l.rejected++
		l.mu.Unlock()
		return
	}
	sig := ed25519.Sign(n.sk, sigMsg("I", t1, n.pub[:], ikR[:]))
	hs3 := []byte{kHs3}
	hs3 = binary.BigEndian.AppendUint32(hs3, idxR)
	hs3 = aeadOf(k3).Seal(hs3, zeroNonce, append(append([]byte{}, n.pub[:]...), sig...), t1)
	l.mu.Lock()
	if l.out[h.addr] != h { // finished by an earlier copy of hs2
		l.mu.Unlock()
		return
	}
	delete(l.out, h.addr)
	delete(l.outIdx, h.idx)
	s := &session{idx: idxI, peerIdx: idxR, peer: idR, ik: ikR, addr: src, send: aeadOf(kIR), recv: aeadOf(kRI),
		born: time.Now(), last: time.Now(), initiator: true, hs3: hs3}
	l.byIdx[s.idx] = s
	l.byAddr[src] = s
	l.opened++
	var pkts [][]byte
	for _, q := range h.queue {
		pkts = append(pkts, n.sealLocked(s, q))
	}
	l.mu.Unlock()
	n.raw(src, hs3)
	for _, p := range pkts {
		n.raw(src, p)
	}
}

func (n *Node) recvHs3(b []byte, src netip.AddrPort) {
	if len(b) != 1+4+96+16 {
		return
	}
	idxR := binary.BigEndian.Uint32(b[1:5])
	l := n.lk
	l.mu.Lock()
	h := l.in[idxR]
	l.mu.Unlock()
	if h == nil {
		return
	}
	pl, err := aeadOf(h.k3).Open(nil, zeroNonce, b[5:], h.t1)
	if err != nil {
		return
	}
	var ikI [32]byte
	copy(ikI[:], pl[:32])
	if !ed25519.Verify(ikI[:], sigMsg("I", h.t1, ikI[:], n.pub[:]), pl[32:]) || idOf(ikI[:]) == n.id {
		l.mu.Lock()
		l.rejected++
		l.mu.Unlock()
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.in[idxR] != h {
		return
	}
	delete(l.in, idxR)
	s := &session{idx: idxR, peerIdx: h.peerIdx, peer: idOf(ikI[:]), ik: ikI, addr: src, send: h.send, recv: h.recv,
		born: time.Now(), last: time.Now()}
	l.byIdx[s.idx] = s
	if old := l.byAddr[src]; old == nil || old.born.Before(s.born) {
		l.byAddr[src] = s
	}
	l.opened++
}

// pruneLinks drops idle and expired sessions and stale handshake state.
func (n *Node) pruneLinks() {
	l := n.lk
	now := time.Now()
	life := n.linkLife()
	l.mu.Lock()
	defer l.mu.Unlock()
	for idx, s := range l.byIdx {
		if now.Sub(s.last) > 90*time.Second || now.Sub(s.born) > 3*life {
			delete(l.byIdx, idx)
			if l.byAddr[s.addr] == s {
				delete(l.byAddr, s.addr)
			}
		}
	}
	for a, s := range l.byAddr {
		if l.byIdx[s.idx] != s {
			delete(l.byAddr, a)
		}
	}
	for i, h := range l.in {
		if now.Sub(h.born) > 10*time.Second {
			delete(l.in, i)
		}
	}
	for a, p := range l.pins {
		if now.Sub(p.at) > time.Minute {
			delete(l.pins, a)
		}
	}
}

// sessionCount reports the live sessions, for tests and status.
func (n *Node) sessionCount() int {
	n.lk.mu.Lock()
	defer n.lk.mu.Unlock()
	return len(n.lk.byIdx)
}

func (n *Node) linkStat(i int) int64 {
	n.lk.mu.Lock()
	defer n.lk.mu.Unlock()
	return [4]int64{n.lk.opened, n.lk.rejected, n.lk.forged, n.lk.replayed}[i]
}

func (n *Node) okeyCount() int {
	n.okMu.Lock()
	defer n.okMu.Unlock()
	return len(n.okeys)
}
