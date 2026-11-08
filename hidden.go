package main

import (
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	mrand "math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Hidden holders, in the style of Tor hidden services, built from the same
// onion packets:
//
//	hidden node H   picks introduction points (IPs) among its guards, hands each a
//	                stock of single-use reply blocks, and publishes a signed
//	                descriptor {keys, IPs} to directory nodes, all over onion routes
//	client C        fetches the descriptor, picks a rendezvous point (RP) from it,
//	                gives the RP a reply block under a random cookie, then sends an
//	                end-to-end encrypted INTRODUCE {RP, cookie, request} to an IP
//	IP              forwards the INTRODUCE into one of H's reply blocks
//	H               decrypts, serves the request, sends the encrypted answer to the
//	                RP over an onion route
//	RP              pushes it into C's reply block
//
// Nobody on the path learns both ends: IPs and RPs know neither C nor H's
// address, directories only see a signed blob.
const (
	tHsReg       byte = 10
	tHsIntro     byte = 11
	tHsIntroFwd  byte = 12
	tHsRpSetup   byte = 13
	tHsRpDeliver byte = 14
	tHsRpReply   byte = 15
	tHsPutDesc   byte = 16
	tHsGetDesc   byte = 17
	tHsDesc      byte = 18

	hsIntros   = 3  // introduction points per service
	hsPool     = 48 // reply blocks kept at each IP
	hsMaxQueue = 128
	descTTL    = 15 * time.Minute
)

type introRef struct {
	pub  [32]byte
	addr netip.AddrPort
}

func (r introRef) id() Hash { return idOf(r.pub[:]) }

// service is the long-term identity of a hidden node. It is deliberately
// unrelated to the node's relay key, so publishing it links to nothing.
type service struct {
	ed     ed25519.PrivateKey
	edPub  [32]byte
	enc    *ecdh.PrivateKey
	encPub [32]byte
	sid    Hash
	intros []introRef
}

func sidOf(edPub []byte) Hash {
	h := sha256.New()
	h.Write([]byte("da/sid/v1"))
	h.Write(edPub)
	var o Hash
	h.Sum(o[:0])
	return o
}

func loadService(dir string) (*service, error) {
	s := &service{}
	var seed []byte
	var encRaw []byte
	if dir != "" {
		seed, _ = os.ReadFile(filepath.Join(dir, "service.key"))
		encRaw, _ = os.ReadFile(filepath.Join(dir, "service.enc"))
	}
	fresh := false
	if len(seed) != ed25519.SeedSize || len(encRaw) != 32 {
		seed = make([]byte, ed25519.SeedSize)
		rand.Read(seed)
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		encRaw = k.Bytes()
		fresh = true
	}
	s.ed = ed25519.NewKeyFromSeed(seed)
	copy(s.edPub[:], s.ed.Public().(ed25519.PublicKey))
	k, err := ecdh.X25519().NewPrivateKey(encRaw)
	if err != nil {
		return nil, err
	}
	s.enc = k
	copy(s.encPub[:], k.PublicKey().Bytes())
	s.sid = sidOf(s.edPub[:])
	if fresh && dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "service.key"), seed, 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "service.enc"), encRaw, 0o600); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ---- wire helpers --------------------------------------------------------------

func lp(b []byte) []byte { // length-prefixed
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

func (r *rd) lp() []byte { return append([]byte(nil), r.take(int(r.u16()))...) }

// ---- descriptor ----------------------------------------------------------------

type descriptor struct {
	edPub, encPub [32]byte
	ts            int64
	intros        []introRef
	raw           []byte
}

func (s *service) descriptor() []byte {
	b := append([]byte{}, s.edPub[:]...)
	b = append(b, s.encPub[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(time.Now().Unix()))
	b = append(b, byte(len(s.intros)))
	for _, in := range s.intros {
		b = append(b, in.pub[:]...)
		b = append(b, make([]byte, 6)...)
		putAddr(b[len(b)-6:], in.addr)
	}
	h := sha256.Sum256(append([]byte("da/desc/v1"), b...))
	return append(b, ed25519.Sign(s.ed, h[:])...)
}

func parseDescriptor(raw []byte) (*descriptor, error) {
	if len(raw) < 32+32+8+1+ed25519.SignatureSize {
		return nil, errors.New("short descriptor")
	}
	body, sig := raw[:len(raw)-ed25519.SignatureSize], raw[len(raw)-ed25519.SignatureSize:]
	d := &descriptor{raw: raw}
	copy(d.edPub[:], body[:32])
	h := sha256.Sum256(append([]byte("da/desc/v1"), body...))
	if !ed25519.Verify(d.edPub[:], h[:], sig) {
		return nil, errors.New("bad descriptor signature")
	}
	copy(d.encPub[:], body[32:64])
	d.ts = int64(binary.BigEndian.Uint64(body[64:72]))
	cnt := int(body[72])
	r := &rd{b: body[73:]}
	for i := 0; i < cnt; i++ {
		var in introRef
		copy(in.pub[:], r.take(32))
		in.addr = getAddr(r.take(6))
		d.intros = append(d.intros, in)
	}
	if r.bad {
		return nil, errors.New("bad descriptor")
	}
	if age := time.Since(time.Unix(d.ts, 0)); age > descTTL || age < -time.Minute {
		return nil, errors.New("stale descriptor")
	}
	return d, nil
}

func (d *descriptor) sid() Hash { return sidOf(d.edPub[:]) }

// ---- per-node tables for the roles every node can play -------------------------

type queuedSurb struct {
	sb  surb
	exp time.Time
}

type rpEntry struct {
	sb  surb
	exp time.Time
}

type descEntry struct {
	d   *descriptor
	exp time.Time
}

type hsState struct {
	intro map[Hash][]queuedSurb // IP role: reply blocks registered by hidden services
	rp    map[[16]byte]rpEntry  // RP role
	descs map[Hash]descEntry    // directory role
	cache map[Hash]descEntry    // client side
}

func newHsState() hsState {
	return hsState{intro: map[Hash][]queuedSurb{}, rp: map[[16]byte]rpEntry{}, descs: map[Hash]descEntry{}, cache: map[Hash]descEntry{}}
}

func (n *Node) pruneHidden() {
	now := time.Now()
	n.hsMu.Lock()
	defer n.hsMu.Unlock()
	for sid, q := range n.hs.intro {
		keep := q[:0]
		for _, x := range q {
			if now.Before(x.exp) {
				keep = append(keep, x)
			}
		}
		if len(keep) == 0 {
			delete(n.hs.intro, sid)
		} else {
			n.hs.intro[sid] = keep
		}
	}
	for c, e := range n.hs.rp {
		if now.After(e.exp) {
			delete(n.hs.rp, c)
		}
	}
	for s, e := range n.hs.descs {
		if now.After(e.exp) {
			delete(n.hs.descs, s)
		}
	}
	for s, e := range n.hs.cache {
		if now.After(e.exp) {
			delete(n.hs.cache, s)
		}
	}
}

// hiddenServe handles the control messages of the hidden-service roles. It is
// reached only through onion packets, so none of these learn a sender.
func (n *Node) hiddenServe(typ byte, body []byte) (byte, []byte, bool) {
	r := &rd{b: body}
	now := time.Now()
	switch typ {
	case tHsReg: // IP role: edpub | ts | sig | count | surbs
		edPub := r.take(32)
		ts := int64(binary.BigEndian.Uint64(r.take(8)))
		sig := r.take(64)
		cnt := int(r.u8())
		raw := r.b
		if r.bad || cnt > 4 || len(raw) < cnt*surbLen {
			return 0, nil, false
		}
		raw = raw[:cnt*surbLen]
		h := sha256.Sum256(append(binary.BigEndian.AppendUint64([]byte("da/reg/v1"), uint64(ts)), raw...))
		if !ed25519.Verify(edPub, h[:], sig) || absDur(time.Since(time.Unix(ts, 0))) > 5*time.Minute {
			return 0, nil, false
		}
		sid := sidOf(edPub)
		n.hsMu.Lock()
		defer n.hsMu.Unlock()
		if _, ok := n.hs.intro[sid]; !ok && len(n.hs.intro) >= 4096 {
			return 0, nil, false
		}
		for i := 0; i < cnt; i++ {
			sb, ok := decodeSurb(raw[i*surbLen:])
			if ok && len(n.hs.intro[sid]) < hsMaxQueue {
				n.hs.intro[sid] = append(n.hs.intro[sid], queuedSurb{sb, now.Add(100 * time.Second)})
			}
		}
	case tHsIntro: // IP role: sid | len blob
		sid := r.hash()
		blob := r.lp()
		if r.bad {
			return 0, nil, false
		}
		n.hsMu.Lock()
		var sb surb
		found := false
		q := n.hs.intro[sid]
		for len(q) > 0 && !found {
			x := q[0]
			q = q[1:]
			if now.Before(x.exp) {
				sb, found = x.sb, true
			}
		}
		n.hs.intro[sid] = q
		n.hsMu.Unlock()
		if found {
			n.sendReply(sb, tHsIntroFwd, lp(blob))
		}
	case tHsRpSetup: // RP role: cookie | surb
		var cookie [16]byte
		copy(cookie[:], r.take(16))
		sb, ok := decodeSurb(r.take(surbLen))
		if r.bad || !ok {
			return 0, nil, false
		}
		n.hsMu.Lock()
		defer n.hsMu.Unlock()
		if len(n.hs.rp) < 8192 {
			n.hs.rp[cookie] = rpEntry{sb, now.Add(2 * time.Minute)}
		}
	case tHsRpDeliver: // RP role: cookie | len ct
		var cookie [16]byte
		copy(cookie[:], r.take(16))
		ct := r.lp()
		if r.bad {
			return 0, nil, false
		}
		n.hsMu.Lock()
		e, ok := n.hs.rp[cookie]
		delete(n.hs.rp, cookie)
		n.hsMu.Unlock()
		if ok {
			n.sendReply(e.sb, tHsRpReply, lp(ct))
		}
	case tHsPutDesc: // directory role
		raw := r.lp()
		d, err := parseDescriptor(raw)
		if r.bad || err != nil {
			return 0, nil, false
		}
		n.hsMu.Lock()
		defer n.hsMu.Unlock()
		old, had := n.hs.descs[d.sid()]
		if (had && old.d.ts > d.ts) || (!had && len(n.hs.descs) >= 4096) {
			return 0, nil, false
		}
		n.hs.descs[d.sid()] = descEntry{d, now.Add(descTTL)}
	case tHsGetDesc:
		sid := r.hash()
		n.hsMu.Lock()
		e, ok := n.hs.descs[sid]
		n.hsMu.Unlock()
		if !ok || r.bad {
			return tHsDesc, lp(nil), true
		}
		return tHsDesc, lp(e.d.raw), true
	}
	return 0, nil, false
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// ---- hidden node ---------------------------------------------------------------

func (n *Node) hsLoop() {
	select {
	case <-time.After(3 * time.Second):
	case <-n.done:
		return
	}
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	var last time.Time
	for {
		n.hsTick(&last)
		select {
		case <-t.C:
		case <-n.done:
			return
		}
	}
}

func (n *Node) hsTick(lastPub *time.Time) {
	s := n.svc
	live := map[Hash]peer{}
	for _, p := range n.peerList() {
		if p.hasPub {
			live[p.id] = p
		}
	}
	keep := s.intros[:0]
	have := map[Hash]bool{}
	for _, in := range s.intros {
		if p, ok := live[in.id()]; ok {
			in.addr = p.addr
			keep = append(keep, in)
			have[in.id()] = true
		}
	}
	s.intros = keep
	var pool []peer
	for id, p := range live {
		if !have[id] {
			pool = append(pool, p)
		}
	}
	sort.Slice(pool, func(i, j int) bool { return mrand.Intn(2) == 0 })
	for _, p := range pool {
		if len(s.intros) >= hsIntros {
			break
		}
		s.intros = append(s.intros, introRef{p.pub, p.addr})
		*lastPub = time.Time{} // descriptor changed
	}
	for _, in := range s.intros {
		n.hsTopUp(in)
	}
	if len(s.intros) > 0 && time.Since(*lastPub) > 20*time.Second {
		n.hsPublish()
		*lastPub = time.Now()
	}
}

func (n *Node) hsPoolSize(ip Hash) int {
	n.smu.Lock()
	defer n.smu.Unlock()
	c := 0
	for _, e := range n.surbs {
		if e.fn != nil && e.tag == ip {
			c++
		}
	}
	return c
}

func (n *Node) hsTopUp(in introRef) {
	for tries := 0; n.hsPoolSize(in.id()) < hsPool && tries < hsPool; tries++ {
		if err := n.hsReg(in, 3); err != nil {
			return
		}
	}
}

// hsReg gives an introduction point a few reply blocks that lead back to us.
func (n *Node) hsReg(in introRef, count int) error {
	id := in.id()
	fwd, ok := n.pickFwd(id)
	if !ok {
		return errNoRoute
	}
	var blocks []byte
	for i := 0; i < count; i++ {
		back, ok := n.pickBack(id)
		if !ok {
			return errNoRoute
		}
		e := &surbEntry{tag: id, fn: func(typ byte, body []byte) {
			if typ == tHsIntroFwd {
				n.hsOnIntro(in, body)
			}
		}}
		sb, _, err := n.newSurb(back, e)
		if err != nil {
			return err
		}
		blocks = append(blocks, sb.encode()...)
	}
	ts := time.Now().Unix()
	h := sha256.Sum256(append(binary.BigEndian.AppendUint64([]byte("da/reg/v1"), uint64(ts)), blocks...))
	b := append([]byte{}, n.svc.edPub[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(ts))
	b = append(b, ed25519.Sign(n.svc.ed, h[:])...)
	b = append(b, byte(count))
	b = append(b, blocks...)
	return n.sendPost(fwd, tHsReg, b)
}

// hsPublish sends the signed descriptor to the directory nodes closest to our
// service id, and to our introduction points.
func (n *Node) hsPublish() {
	desc := lp(n.svc.descriptor())
	sent := map[Hash]bool{}
	targets := n.closestPeers(n.svc.sid, 5)
	for _, in := range n.svc.intros {
		targets = append(targets, in.id())
	}
	for _, id := range targets {
		if sent[id] {
			continue
		}
		sent[id] = true
		if fwd, ok := n.pickFwd(id); ok {
			n.sendPost(fwd, tHsPutDesc, desc)
		}
	}
}

func (n *Node) closestPeers(key Hash, k int) []Hash {
	ps := n.peerList()
	sort.Slice(ps, func(i, j int) bool {
		for b := 0; b < 32; b++ {
			x, y := ps[i].id[b]^key[b], ps[j].id[b]^key[b]
			if x != y {
				return x < y
			}
		}
		return false
	})
	var out []Hash
	for _, p := range ps {
		if p.hasPub && len(out) < k {
			out = append(out, p.id)
		}
	}
	return out
}

func hsAEAD(shared []byte) cipher.AEAD {
	k := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte("da/hs/v1")), k)
	a, _ := chacha20poly1305.New(k)
	return a
}

var nonce0, nonce1 = make([]byte, 12), append(make([]byte, 11), 1)

// hsOnIntro runs at the hidden node when an introduction arrives through one of
// its reply blocks.
func (n *Node) hsOnIntro(ip introRef, body []byte) {
	r := &rd{b: body}
	blob := r.lp()
	if r.bad || len(blob) < 32+16 {
		return
	}
	go n.hsTopUp(ip) // one block was used up
	ce, err := ecdh.X25519().NewPublicKey(blob[:32])
	if err != nil {
		return
	}
	shared, err := n.svc.enc.ECDH(ce)
	if err != nil {
		return
	}
	aead := hsAEAD(shared)
	pt, err := aead.Open(nil, nonce0, blob[32:], nil)
	if err != nil || len(pt) < 32+16+1 {
		return
	}
	rpID := idOf(pt[:32])
	cookie, typ, req := pt[32:48], pt[48], pt[49:]
	if typ != tStore && typ != tGet {
		return
	}
	rt, rb, ok := n.serve(typ, req)
	if !ok {
		return
	}
	ct := aead.Seal(nil, nonce1, append([]byte{rt}, rb...), nil)
	fwd, ok := n.pickFwd(rpID)
	if !ok {
		return
	}
	n.sendPost(fwd, tHsRpDeliver, append(append([]byte{}, cookie...), lp(ct)...))
}

// ---- client --------------------------------------------------------------------

func (n *Node) descriptorFor(ctx context.Context, sid Hash) (*descriptor, error) {
	n.hsMu.Lock()
	if e, ok := n.hs.cache[sid]; ok && time.Now().Before(e.exp) {
		n.hsMu.Unlock()
		return e.d, nil
	}
	n.hsMu.Unlock()
	cands := n.closestPeers(sid, 5)
	for _, p := range n.peerList() { // directories seen from other vantage points
		if len(cands) >= 10 {
			break
		}
		cands = append(cands, p.id)
	}
	seen := map[Hash]bool{}
	var best *descriptor
	for _, id := range cands {
		if seen[id] || ctx.Err() != nil {
			continue
		}
		seen[id] = true
		m, err := n.onionCall(ctx, id, tHsGetDesc, append([]byte{}, sid[:]...), time.Second, 2)
		if err != nil || m.typ != tHsDesc {
			continue
		}
		rr := &rd{b: m.body}
		raw := rr.lp()
		if rr.bad || len(raw) == 0 {
			continue
		}
		d, err := parseDescriptor(raw)
		if err != nil || d.sid() != sid {
			continue
		}
		if best == nil || d.ts > best.ts {
			best = d
		}
		break // first valid answer is enough; a newer one is picked up on the next refresh
	}
	if best == nil {
		return nil, errors.New("hidden service descriptor not found")
	}
	n.hsMu.Lock()
	n.hs.cache[sid] = descEntry{best, time.Now().Add(60 * time.Second)}
	n.hsMu.Unlock()
	return best, nil
}

// hiddenCall performs request/response with a hidden holder via rendezvous.
func (n *Node) hiddenCall(ctx context.Context, sid Hash, typ byte, body []byte, timeout time.Duration, tries int) (msg, error) {
	d, err := n.descriptorFor(ctx, sid)
	if err != nil {
		return msg{}, err
	}
	// intro points we can reach ourselves (we need them as direct peers)
	var usable []introRef
	n.mu.RLock()
	for _, in := range d.intros {
		if p := n.peers[in.id()]; p != nil && p.hasPub {
			usable = append(usable, in)
		}
	}
	n.mu.RUnlock()
	if len(usable) == 0 {
		return msg{}, errNoRoute
	}
	for t := 0; t < tries; t++ {
		ip := usable[mrand.Intn(len(usable))]
		rp := usable[mrand.Intn(len(usable))]
		if len(usable) > 1 {
			for rp == ip {
				rp = usable[mrand.Intn(len(usable))]
			}
		}
		var cookie [16]byte
		rand.Read(cookie[:])
		ce, _ := ecdh.X25519().GenerateKey(rand.Reader)
		hpub, err := ecdh.X25519().NewPublicKey(d.encPub[:])
		if err != nil {
			return msg{}, err
		}
		shared, err := ce.ECDH(hpub)
		if err != nil {
			return msg{}, err
		}
		aead := hsAEAD(shared)

		// 1. rendezvous point learns a reply block under our cookie
		e := &surbEntry{ch: make(chan reply, 1)}
		back, ok1 := n.pickBack(rp.id())
		fwdRP, ok2 := n.pickFwd(rp.id())
		fwdIP, ok3 := n.pickFwd(ip.id())
		if !ok1 || !ok2 || !ok3 {
			return msg{}, errNoRoute
		}
		sb, sid2, err := n.newSurb(back, e)
		if err != nil {
			return msg{}, err
		}
		if err := n.sendPost(fwdRP, tHsRpSetup, append(cookie[:], sb.encode()...)); err != nil {
			n.dropSurb(sid2)
			return msg{}, err
		}
		time.Sleep(2*n.cfg.OnionDelay + 40*time.Millisecond) // let the setup get there first

		// 2. introduce ourselves, end-to-end encrypted to the hidden node
		pt := append(append(append([]byte{}, rp.pub[:]...), cookie[:]...), typ)
		pt = append(pt, body...)
		blob := append(append([]byte{}, ce.PublicKey().Bytes()...), aead.Seal(nil, nonce0, pt, nil)...)
		msgBody := append(append([]byte{}, sid[:]...), lp(blob)...)
		if err := n.sendPost(fwdIP, tHsIntro, msgBody); err != nil {
			n.dropSurb(sid2)
			return msg{}, err
		}

		// 3. the answer comes back through the rendezvous point
		select {
		case rep := <-e.ch:
			rr := &rd{b: rep.body}
			ct := rr.lp()
			if rep.typ != tHsRpReply || rr.bad {
				continue
			}
			plain, err := aead.Open(nil, nonce1, ct, nil)
			if err != nil || len(plain) < 1 {
				continue
			}
			return msg{typ: plain[0], body: plain[1:]}, nil
		case <-time.After(timeout):
			n.dropSurb(sid2)
		case <-ctx.Done():
			n.dropSurb(sid2)
			return msg{}, ctx.Err()
		}
	}
	return msg{}, errors.New("hidden call timed out")
}

func (n *Node) hexSid() string {
	if n.svc == nil {
		return ""
	}
	return hex.EncodeToString(n.svc.sid[:])
}

type ctxKey int

const hiddenOnlyKey ctxKey = 1

// hiddenOnly makes shard fetches skip ordinary holders (to prove that hidden
// replicas alone are enough).
func hiddenOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, hiddenOnlyKey, true)
}

func isHiddenOnly(ctx context.Context) bool { v, _ := ctx.Value(hiddenOnlyKey).(bool); return v }
