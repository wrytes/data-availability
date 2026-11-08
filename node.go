package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Port        int
	HTTP        string
	Discover    []string // host or host:port; resolved via DNS (swarm: tasks.<svc>)
	Replication int
	MaxBytes    int64
	Loss        float64       // simulated inbound packet loss, 0..1
	DataDir     string        // empty = in-memory only
	NodeName    string        // stable per-replica subdirectory under DataDir
	RepairEvery time.Duration // 0 disables repair

	Onion      int           // 0 direct, 1 onion routes for client requests (direct if no route), 2 onion only
	OnionDelay time.Duration // max random delay a relay adds per hop
	Cover      float64       // dummy onion packets per second
}

// nbr is what a peer told us about one of its own peers: the key and the
// address *that peer* uses to reach it. This is the reachability graph that
// onion paths are drawn from (consecutive hops must be able to talk).
type nbr struct {
	pub  [32]byte
	addr netip.AddrPort
	seen time.Time
}

type peer struct {
	id     Hash
	addr   netip.AddrPort
	seen   time.Time
	pub    [32]byte
	hasPub bool
	me     netip.AddrPort // how this peer sees us
	nbrs   map[Hash]nbr
}

// idOf binds a node id to its onion key, so a key cannot be claimed for a
// foreign id.
func idOf(pub []byte) Hash {
	h := sha256.New()
	h.Write([]byte("da/node/v1"))
	h.Write(pub)
	var o Hash
	h.Sum(o[:0])
	return o
}

type Node struct {
	cfg  Config
	id   Hash
	priv *ecdh.PrivateKey
	pub  [32]byte
	conn *net.UDPConn

	mu    sync.RWMutex
	peers map[Hash]*peer
	tried map[netip.AddrPort]time.Time
	pend  map[uint64]chan msg

	store *shardStore

	smu   sync.Mutex
	surbs map[uint64]*surbEntry
	seen  map[[16]byte]time.Time
	hook  func(from netip.AddrPort, typ byte, viaOnion bool) // tests: observe who talks to a server

	relayed, delivered, dropped atomic.Int64
	getDirect, getOnion         atomic.Int64

	repMu    sync.Mutex
	cool     map[Hash]time.Time
	cursor   map[Hash]int // repair loop only
	pushed   atomic.Int64
	rebuilds atomic.Int64

	done chan struct{}
	once sync.Once
}

func NewNode(cfg Config) (*Node, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: cfg.Port})
	if err != nil {
		return nil, err
	}
	dir := ""
	if cfg.DataDir != "" {
		name := cfg.NodeName
		if name == "" {
			name = "node"
		}
		dir = filepath.Join(cfg.DataDir, name)
	}
	st, err := openStore(dir)
	if err != nil {
		c.Close()
		return nil, err
	}
	n := &Node{cfg: cfg, conn: c, peers: map[Hash]*peer{}, tried: map[netip.AddrPort]time.Time{},
		pend: map[uint64]chan msg{}, store: st, cool: map[Hash]time.Time{}, cursor: map[Hash]int{}, done: make(chan struct{}),
		surbs: map[uint64]*surbEntry{}, seen: map[[16]byte]time.Time{}}
	if err := n.loadKey(dir); err != nil {
		c.Close()
		return nil, err
	}
	if cnt, b := st.stats(); cnt > 0 {
		log.Printf("restored %d shards (%d bytes) from %s", cnt, b, dir)
	}
	go n.recvLoop()
	go n.maintainLoop()
	if cfg.RepairEvery > 0 {
		go n.repairLoop()
	}
	if cfg.Cover > 0 {
		go n.coverLoop()
	}
	return n, nil
}

// loadKey keeps the node key (and so its id) stable across restarts, so
// placement stays valid.
func (n *Node) loadKey(dir string) error {
	curve := ecdh.X25519()
	if dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, "node.key")); err == nil && len(b) == 32 {
			k, err := curve.NewPrivateKey(b)
			if err != nil {
				return err
			}
			n.setKey(k)
			return nil
		}
	}
	k, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	n.setKey(k)
	if dir != "" {
		return os.WriteFile(filepath.Join(dir, "node.key"), k.Bytes(), 0o600)
	}
	return nil
}

func (n *Node) setKey(k *ecdh.PrivateKey) {
	n.priv = k
	copy(n.pub[:], k.PublicKey().Bytes())
	n.id = idOf(n.pub[:])
}

func (n *Node) Close() { n.once.Do(func() { close(n.done); n.conn.Close() }) }

func (n *Node) send(to netip.AddrPort, m msg) {
	m.from = n.id
	b := m.marshal()
	if len(b) > maxDatagram {
		return
	}
	n.conn.WriteToUDPAddrPort(b, to)
}

func (n *Node) recvLoop() {
	buf := make([]byte, 2048)
	for {
		l, src, err := n.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-n.done:
				return
			default:
				continue
			}
		}
		if n.cfg.Loss > 0 && mrand.Float64() < n.cfg.Loss {
			continue
		}
		m, ok := unmarshal(append([]byte(nil), buf[:l]...))
		if !ok || m.from == n.id {
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if m.typ != tOnion {
			n.upsert(m.from, src)
		}
		go n.handle(m, src)
	}
}

func (n *Node) upsert(id Hash, a netip.AddrPort) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if p, ok := n.peers[id]; ok {
		p.addr, p.seen = a, time.Now()
		return
	}
	n.peers[id] = &peer{id: id, addr: a, seen: time.Now(), nbrs: map[Hash]nbr{}}
}

func (n *Node) handle(m msg, src netip.AddrPort) {
	switch m.typ {
	case tPing:
		pub := m.body
		if len(pub) < 32 || idOf(pub[:32]) != m.from {
			return
		}
		n.setPub(m.from, pub[:32])
		b := append([]byte{}, n.pub[:]...)
		b = append(b, make([]byte, 6)...)
		putAddr(b[32:], src)
		n.send(src, msg{typ: tPong, id: m.id, body: append(b, n.gossipBody()...)})
	case tPong:
		r := &rd{b: m.body}
		pub := r.take(32)
		me := getAddr(r.take(6))
		if r.bad || idOf(pub) != m.from {
			return
		}
		n.setPub(m.from, pub)
		n.learn(m.from, me, r.b)
		n.deliver(m)
	case tAck, tData, tHasR:
		n.deliver(m)
	case tStore, tGet, tHas:
		if n.hook != nil {
			n.hook(src, m.typ, false)
		}
		if m.typ == tGet {
			n.getDirect.Add(1)
		}
		if rt, rb, ok := n.serve(m.typ, m.body); ok {
			n.send(src, msg{typ: rt, id: m.id, body: rb})
		}
	case tOnion:
		n.handleOnion(m, src)
	}
}

// serve executes a storage request and returns the reply. It is shared by the
// direct path and the onion path, so a request is handled identically whether
// or not it knows who is asking.
func (n *Node) serve(typ byte, body []byte) (byte, []byte, bool) {
	r := &rd{b: body}
	switch typ {
	case tStore:
		root, leaf, cnt := r.hash(), r.u32(), r.u32()
		data := append([]byte(nil), r.take(int(r.u16()))...)
		proof := r.proof()
		return tAck, []byte{n.putLocal(root, leaf, cnt, data, proof, r.bad)}, true
	case tGet:
		root, leaf := r.hash(), r.u32()
		if r.bad {
			return 0, nil, false
		}
		s, ok := n.store.get(root, leaf)
		return tData, encData(ok, s.n, s.data, s.proof), true
	case tHas:
		root, leaf := r.hash(), r.u32()
		if r.bad {
			return 0, nil, false
		}
		st := byte(1)
		if n.store.has(root, leaf) {
			st = 0
		}
		return tHasR, []byte{st}, true
	}
	return 0, nil, false
}

func (n *Node) setPub(id Hash, pub []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if p, ok := n.peers[id]; ok {
		copy(p.pub[:], pub)
		p.hasPub = true
	}
}

// putLocal returns 0 ok, 1 invalid, 2 full, 3 io error.
func (n *Node) putLocal(root Hash, leaf, cnt uint32, data []byte, proof []Hash, bad bool) byte {
	if bad || len(data) == 0 || !verifyShard(root, leaf, cnt, data, proof) {
		return 1
	}
	return n.store.put(root, leaf, cnt, data, proof, n.cfg.MaxBytes)
}

func (n *Node) deliver(m msg) {
	n.mu.Lock()
	ch := n.pend[m.id]
	n.mu.Unlock()
	if ch != nil {
		select {
		case ch <- m:
		default:
		}
	}
}

func (n *Node) call(ctx context.Context, to netip.AddrPort, typ byte, body []byte, timeout time.Duration, tries int) (msg, error) {
	var id uint64
	for id == 0 {
		v, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<63))
		id = v.Uint64()
	}
	ch := make(chan msg, 1)
	n.mu.Lock()
	n.pend[id] = ch
	n.mu.Unlock()
	defer func() { n.mu.Lock(); delete(n.pend, id); n.mu.Unlock() }()
	for t := 0; t < tries; t++ {
		n.send(to, msg{typ: typ, id: id, body: body})
		select {
		case m := <-ch:
			return m, nil
		case <-time.After(timeout):
		case <-ctx.Done():
			return msg{}, ctx.Err()
		}
	}
	return msg{}, errors.New("timeout")
}

// ---- discovery -------------------------------------------------------------

func (n *Node) gossipBody() []byte {
	n.mu.RLock()
	ps := make([]*peer, 0, len(n.peers))
	for _, p := range n.peers {
		if p.hasPub {
			ps = append(ps, p)
		}
	}
	mrand.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
	if len(ps) > 12 {
		ps = ps[:12]
	}
	b := []byte{byte(len(ps))}
	for _, p := range ps {
		b = append(b, p.pub[:]...)
		b = append(b, make([]byte, 6)...)
		putAddr(b[len(b)-6:], p.addr)
	}
	n.mu.RUnlock()
	return b
}

func (n *Node) sendPing(to netip.AddrPort) {
	n.send(to, msg{typ: tPing, id: mrand.Uint64(), body: append([]byte{}, n.pub[:]...)})
}

// learn records what a peer reports about its own peers (key + the address it
// uses), and pings unknown addresses; they only become peers once they answer
// directly, so unreachable cross-subnet addresses never enter the table.
func (n *Node) learn(from Hash, me netip.AddrPort, body []byte) {
	n.mu.Lock()
	if p, ok := n.peers[from]; ok {
		p.me = me
	}
	n.mu.Unlock()
	r := &rd{b: body}
	cnt := int(r.u8())
	for i := 0; i < cnt; i++ {
		pub := append([]byte(nil), r.take(32)...)
		ap := getAddr(r.take(6))
		if r.bad {
			return
		}
		id := idOf(pub)
		if id == n.id {
			continue
		}
		n.mu.Lock()
		if p, ok := n.peers[from]; ok {
			var rec nbr
			copy(rec.pub[:], pub)
			rec.addr, rec.seen = ap, time.Now()
			p.nbrs[id] = rec
		}
		t, seen := n.tried[ap]
		known := false
		for _, p := range n.peers {
			if p.addr == ap {
				known = true
				break
			}
		}
		if !known && (!seen || time.Since(t) > 10*time.Second) {
			n.tried[ap] = time.Now()
			n.mu.Unlock()
			n.sendPing(ap)
			continue
		}
		n.mu.Unlock()
	}
}

func (n *Node) resolve() []netip.AddrPort {
	var out []netip.AddrPort
	for _, d := range n.cfg.Discover {
		host, port := d, n.cfg.Port
		if h, p, err := net.SplitHostPort(d); err == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}
		ips, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, s := range ips {
			if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
				out = append(out, netip.AddrPortFrom(a, uint16(port)))
			}
		}
	}
	return out
}

func (n *Node) maintainLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		n.mu.Lock()
		for id, p := range n.peers {
			if time.Since(p.seen) > 12*time.Second {
				delete(n.peers, id)
			}
		}
		for _, p := range n.peers {
			for id, nb := range p.nbrs {
				if time.Since(nb.seen) > 30*time.Second {
					delete(p.nbrs, id)
				}
			}
		}
		for a, ts := range n.tried {
			if time.Since(ts) > time.Minute {
				delete(n.tried, a)
			}
		}
		n.mu.Unlock()
		n.pruneOnion()

		for _, a := range n.resolve() {
			n.sendPing(a)
		}
		ps := n.peerList()
		mrand.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
		for i := 0; i < len(ps) && i < 4; i++ {
			n.sendPing(ps[i].addr)
		}
		select {
		case <-t.C:
		case <-n.done:
			return
		}
	}
}

func (n *Node) peerList() []peer {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]peer, 0, len(n.peers))
	for _, p := range n.peers {
		c := *p
		c.nbrs = nil // never share the map outside the lock
		out = append(out, c)
	}
	return out
}

// ---- placement (Kademlia-style XOR metric) ---------------------------------

type target struct {
	id   Hash
	addr netip.AddrPort
	self bool
}

func (n *Node) holders(key Hash, r int) []target {
	ts := []target{{id: n.id, self: true}}
	for _, p := range n.peerList() {
		ts = append(ts, target{id: p.id, addr: p.addr})
	}
	sort.Slice(ts, func(i, j int) bool {
		for b := 0; b < 32; b++ {
			x, y := ts[i].id[b]^key[b], ts[j].id[b]^key[b]
			if x != y {
				return x < y
			}
		}
		return false
	})
	if len(ts) > r {
		ts = ts[:r]
	}
	return ts
}

func parseDiscover(s string) (out []string) {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return
}
