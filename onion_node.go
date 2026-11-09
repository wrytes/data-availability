package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	mrand "math/rand"
	"net/netip"
	"time"
)

var errNoRoute = errors.New("no onion route")

// surbEntry is what the creator of a reply block keeps: the per-hop keys to
// undo the layers, and where to hand the result.
type surbEntry struct {
	keys []hopKeys
	ks   [16]byte
	ch   chan reply
	fn   func(typ byte, body []byte) // for unsolicited deliveries (hidden services)
	exp  time.Time
	tag  Hash // which introduction point a hidden node registered this block with
}

type reply struct {
	typ  byte
	body []byte
}

// ---- receiving ---------------------------------------------------------------

func (n *Node) handleOnion(m msg, src netip.AddrPort) {
	h, delta, ok := decodeOnion(m.body)
	if !ok {
		n.dropped.Add(1)
		return
	}
	pl, err := n.peelAny(h)
	if err != nil || n.replayed(pl.tag) {
		n.dropped.Add(1)
		return
	}
	piDec(&pl.keys, delta)
	switch pl.rec[0] {
	case recRelay, recRelayLink:
		var next netip.AddrPort
		if pl.rec[0] == recRelayLink { // an attached client: find it by its link
			var id [6]byte
			copy(id[:], pl.rec[1:7])
			a, ok := n.linkAddr(id)
			if !ok {
				n.dropped.Add(1)
				return
			}
			next = a
		} else {
			next = getAddr(pl.rec[1:7])
		}
		n.relayed.Add(1)
		pkt := encodeOnion(pl.next, delta)
		go func() {
			if d := n.cfg.OnionDelay; d > 0 { // random delay breaks timing correlation
				select {
				case <-time.After(time.Duration(mrand.Int63n(int64(d)))):
				case <-n.done:
					return
				}
			}
			n.send(next, msg{typ: tOnion, body: pkt})
		}()
	case recDeliver:
		n.delivered.Add(1)
		n.onionRequest(delta, src)
	case recSurb:
		n.delivered.Add(1)
		n.onionReply(binary.BigEndian.Uint64(pl.rec[1:9]), delta)
	default:
		n.dropped.Add(1)
	}
}

func (n *Node) replayed(tag [16]byte) bool {
	n.smu.Lock()
	defer n.smu.Unlock()
	if _, ok := n.seen[tag]; ok {
		return true
	}
	if len(n.seen) < 1<<20 {
		n.seen[tag] = time.Now()
	}
	return false
}

// onionRequest runs at the destination: it sees the request and a reply block,
// never the requester. prev is the last relay, not the requester.
func (n *Node) onionRequest(delta []byte, prev netip.AddrPort) {
	for _, z := range delta[:zeroLen] {
		if z != 0 {
			n.dropped.Add(1)
			return
		}
	}
	switch delta[zeroLen] {
	case kReq:
		sb, ok := decodeSurb(delta[zeroLen+1:])
		if !ok {
			return
		}
		typ, body := delta[zeroLen+1+surbLen], delta[zeroLen+2+surbLen:]
		if n.hook != nil {
			n.hook(prev, typ, true)
		}
		rt, rb, ok := n.anonServe(typ, body)
		if ok {
			n.sendReply(sb, rt, rb)
		}
	case kPost:
		typ, body := delta[zeroLen+1], delta[zeroLen+2:]
		if n.hook != nil {
			n.hook(prev, typ, true)
		}
		n.anonServe(typ, body)
	case kDummy:
	}
}

// anonServe handles requests that arrive without a sender. Only storage
// requests (and, with hidden services, their control messages) are accepted.
func (n *Node) anonServe(typ byte, body []byte) (byte, []byte, bool) {
	switch typ {
	case tStore, tGet:
		if typ == tGet {
			n.getOnion.Add(1)
		}
		return n.serve(typ, body)
	}
	return n.hiddenServe(typ, body)
}

func (n *Node) sendReply(sb surb, typ byte, body []byte) {
	if 1+len(body) > onionD-zeroLen-1 {
		return
	}
	m := make([]byte, onionD)
	m[zeroLen] = kReply
	m[zeroLen+1] = typ
	copy(m[zeroLen+2:], body)
	ks := keysFromKs(sb.ks[:])
	piEnc(&ks, m)
	n.send(sb.first, msg{typ: tOnion, body: encodeOnion(sb.hdr, m)})
}

// onionReply runs at the creator of a reply block.
func (n *Node) onionReply(id uint64, delta []byte) {
	n.smu.Lock()
	e := n.surbs[id]
	delete(n.surbs, id)
	n.smu.Unlock()
	if e == nil {
		n.dropped.Add(1)
		return
	}
	wrapPayload(e.keys, delta) // undo the layers the hops removed
	ks := keysFromKs(e.ks[:])
	piDec(&ks, delta)
	for _, z := range delta[:zeroLen] {
		if z != 0 {
			n.dropped.Add(1)
			return
		}
	}
	if delta[zeroLen] != kReply {
		return
	}
	typ, body := delta[zeroLen+1], delta[zeroLen+2:]
	if e.fn != nil {
		go e.fn(typ, body)
		return
	}
	select {
	case e.ch <- reply{typ, body}:
	default:
	}
}

// ---- path selection ------------------------------------------------------------

// pickFwd draws [relay, relay, dest] such that each consecutive pair can talk,
// using the neighbour lists peers gossip. Addresses are always the ones the
// *previous* hop uses.
func (n *Node) pickFwd(dest Hash) ([]hop, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	now := time.Now()
	dkey, ok := n.okOfLocked(dest, now)
	if !ok {
		return nil, false
	}
	type cand struct{ r0, r1 *peer }
	var cs []cand
	for _, r0 := range n.peers {
		if r0.id == dest || !r0.live(now) {
			continue
		}
		for id1 := range r0.nbrs {
			r1 := n.peers[id1]
			if r1 == nil || !r1.live(now) || id1 == dest || id1 == r0.id {
				continue
			}
			if nb, ok := r1.nbrs[dest]; ok && nb.okExp.After(now) {
				cs = append(cs, cand{r0, r1})
			}
		}
	}
	if len(cs) == 0 {
		return nil, false
	}
	c := cs[mrand.Intn(len(cs))]
	return []hop{
		{pub: c.r0.ok, addr: c.r0.addr},
		{pub: c.r1.ok, addr: c.r0.nbrs[c.r1.id].addr},
		{pub: dkey, addr: c.r1.nbrs[dest].addr},
	}, true
}

// live: we hold a key certificate that has not expired.
func (p *peer) live(now time.Time) bool { return p.hasPub && p.okExp.After(now) }

// okOfLocked is the current onion key of a node: first-hand if it is our
// peer, else from a neighbour list (still verified against the node's own signature).
func (n *Node) okOfLocked(id Hash, now time.Time) ([32]byte, bool) {
	if p := n.peers[id]; p != nil && p.live(now) {
		return p.ok, true
	}
	for _, p := range n.peers {
		if nb, ok := p.nbrs[id]; ok && nb.okExp.After(now) {
			return nb.ok, true
		}
	}
	return [32]byte{}, false
}

// pickBack draws a return path [relay, relay, me] that the destination can
// enter: the first relay must be a neighbour of dest, and the second must know
// how to reach us (by the address it sees us at, or, for attached clients
// behind NAT, by the link we keep open to it).
func (n *Node) pickBack(dest Hash) ([]hop, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	now := time.Now()
	type cand struct {
		r0, r1 *peer
		a0     netip.AddrPort
	}
	var cs []cand
	add := func(r0 *peer, a0 netip.AddrPort) {
		for id1 := range r0.nbrs {
			r1 := n.peers[id1]
			if r1 == nil || !r1.live(now) || id1 == dest || id1 == r0.id || (!n.cfg.Attached && !r1.me.IsValid()) {
				continue
			}
			cs = append(cs, cand{r0, r1, a0})
		}
	}
	if d := n.peers[dest]; d != nil {
		for id0, a0 := range d.nbrs { // precise: first relay as the destination itself sees it
			if r0 := n.peers[id0]; r0 != nil && r0.live(now) && id0 != dest {
				add(r0, a0.addr)
			}
		}
	} else { // destination is not our direct peer: use relays that list it as a neighbour
		for _, r0 := range n.peers {
			if _, ok := r0.nbrs[dest]; ok && r0.live(now) && r0.id != dest {
				add(r0, r0.addr)
			}
		}
	}
	if len(cs) == 0 {
		return nil, false
	}
	c := cs[mrand.Intn(len(cs))]
	mine, _ := n.myOnionKey()
	last := hop{pub: mine, addr: c.r1.me}
	if n.cfg.Attached {
		l := n.linkFor(c.r1.addr)
		last = hop{pub: mine, link: &l}
	}
	return []hop{
		{pub: c.r0.ok, addr: c.a0},
		{pub: c.r1.ok, addr: c.r0.nbrs[c.r1.id].addr},
		last,
	}, true
}

// ---- sending -------------------------------------------------------------------

// newSurb builds a reply block along path and registers it.
func (n *Node) newSurb(path []hop, e *surbEntry) (surb, uint64, error) {
	var id uint64
	for id == 0 {
		id = mrand.Uint64()
	}
	last := make([]byte, onionR)
	last[0] = recSurb
	binary.BigEndian.PutUint64(last[1:9], id)
	hdr, keys, err := buildHeader(path, last)
	if err != nil {
		return surb{}, 0, err
	}
	sb := surb{first: path[0].addr, hdr: hdr}
	rand.Read(sb.ks[:])
	e.keys, e.ks, e.exp = keys, sb.ks, time.Now().Add(2*time.Minute)
	n.smu.Lock()
	n.surbs[id] = e
	n.smu.Unlock()
	return sb, id, nil
}

// sendReq sends an anonymous request carrying a reply block. The caller has
// already registered the reply block.
func (n *Node) sendReq(path []hop, sb surb, typ byte, body []byte) error {
	if zeroLen+2+surbLen+len(body) > onionD {
		return errors.New("request too large for one onion packet")
	}
	hdr, keys, err := buildHeader(path, []byte{recDeliver})
	if err != nil {
		return err
	}
	m := make([]byte, onionD)
	m[zeroLen] = kReq
	copy(m[zeroLen+1:], sb.encode())
	m[zeroLen+1+surbLen] = typ
	copy(m[zeroLen+2+surbLen:], body)
	wrapPayload(keys, m)
	n.send(path[0].addr, msg{typ: tOnion, body: encodeOnion(hdr, m)})
	return nil
}

// sendPost sends an anonymous request that expects no answer.
func (n *Node) sendPost(path []hop, typ byte, body []byte) error {
	if zeroLen+2+len(body) > onionD {
		return errors.New("post too large for one onion packet")
	}
	hdr, keys, err := buildHeader(path, []byte{recDeliver})
	if err != nil {
		return err
	}
	m := make([]byte, onionD)
	m[zeroLen] = kPost
	m[zeroLen+1] = typ
	copy(m[zeroLen+2:], body)
	wrapPayload(keys, m)
	n.send(path[0].addr, msg{typ: tOnion, body: encodeOnion(hdr, m)})
	return nil
}

func (n *Node) dropSurb(id uint64) {
	n.smu.Lock()
	delete(n.surbs, id)
	n.smu.Unlock()
}

// onionCall is call() over a fresh random route per attempt. dest only sees
// the last relay and a reply block.
func (n *Node) onionCall(ctx context.Context, dest Hash, typ byte, body []byte, timeout time.Duration, tries int) (msg, error) {
	for t := 0; t < tries; t++ {
		fwd, ok1 := n.pickFwd(dest)
		back, ok2 := n.pickBack(dest)
		if !ok1 || !ok2 {
			return msg{}, errNoRoute
		}
		e := &surbEntry{ch: make(chan reply, 1)}
		sb, id, err := n.newSurb(back, e)
		if err != nil {
			return msg{}, err
		}
		if err := n.sendReq(fwd, sb, typ, body); err != nil {
			n.dropSurb(id)
			return msg{}, err
		}
		select {
		case r := <-e.ch:
			return msg{typ: r.typ, body: r.body}, nil
		case <-time.After(timeout):
			n.dropSurb(id)
		case <-ctx.Done():
			n.dropSurb(id)
			return msg{}, ctx.Err()
		}
	}
	return msg{}, errors.New("timeout")
}

// rpc is how client operations talk to a holder: over onion routes when
// enabled (falling back to direct unless Onion == 2), directly otherwise.
func (n *Node) rpc(ctx context.Context, h target, typ byte, body []byte, timeout time.Duration, tries int) (msg, error) {
	if n.cfg.Onion > 0 {
		m, err := n.onionCall(ctx, h.id, typ, body, timeout*4+n.cfg.OnionDelay*4, tries)
		if err == nil || n.cfg.Onion >= 2 || !errors.Is(err, errNoRoute) {
			return m, err
		}
	}
	return n.call(ctx, h.addr, typ, body, timeout, tries)
}

// coverLoop sends dummy onion packets so that real traffic is not the only
// traffic.
func (n *Node) coverLoop() {
	for {
		wait := time.Duration(mrand.ExpFloat64() / n.cfg.Cover * float64(time.Second))
		select {
		case <-time.After(wait):
		case <-n.done:
			return
		}
		ps := n.peerList()
		if len(ps) == 0 {
			continue
		}
		fwd, ok := n.pickFwd(ps[mrand.Intn(len(ps))].id)
		if !ok {
			continue
		}
		hdr, keys, err := buildHeader(fwd, []byte{recDeliver})
		if err != nil {
			continue
		}
		m := make([]byte, onionD)
		m[zeroLen] = kDummy
		wrapPayload(keys, m)
		n.send(fwd[0].addr, msg{typ: tOnion, body: encodeOnion(hdr, m)})
	}
}

func (n *Node) pruneOnion() {
	n.pruneHidden()
	now := time.Now()
	n.smu.Lock()
	defer n.smu.Unlock()
	for t, ts := range n.seen {
		if now.Sub(ts) > 10*time.Minute {
			delete(n.seen, t)
		}
	}
	for id, e := range n.surbs {
		if now.After(e.exp) {
			delete(n.surbs, id)
		}
	}
	n.linkMu.Lock()
	for id, l := range n.links {
		if now.Sub(l.seen) > 30*time.Second {
			delete(n.links, id)
		}
	}
	n.linkMu.Unlock()
	n.outMu.Lock()
	for a, t := range n.out {
		if now.Sub(t) > time.Minute {
			delete(n.out, a)
		}
	}
	n.outMu.Unlock()
}
