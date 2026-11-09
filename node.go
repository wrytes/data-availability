package main

import (
	"context"
	"crypto/ed25519"
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
	Hidden     bool          // hidden holder: never listed, ignores direct requests, reachable only via rendezvous
	Attached   bool          // behind NAT: only dials out to a few guards, keeps those links alive, is never listed
	Guards     int           // how many guards an attached node keeps (default 3)
	NATFilter  bool          // test/demo: drop inbound packets from addresses we have not sent to (stateful NAT/firewall)

	LinkLife     time.Duration // sessions are re-keyed after this long (default 2m)
	OnionKeyLife time.Duration // onion keys live this long, rotate at half of it, and are deleted shortly after (default 10m)
}

// nbr is what a peer told us about one of its own peers: the key and the
// address *that peer* uses to reach it. This is the reachability graph that
// onion paths are drawn from (consecutive hops must be able to talk).
type nbr struct {
	pub   [32]byte // identity key
	addr  netip.AddrPort
	seen  time.Time
	ok    [32]byte // onion key, from a certificate signed by pub
	okExp time.Time
	cert  []byte
}

type peer struct {
	id     Hash
	addr   netip.AddrPort
	seen   time.Time
	pub    [32]byte // identity key, proven by the link handshake
	hasPub bool     // we hold a valid onion key certificate for it
	ok     [32]byte // its current onion key
	okExp  time.Time
	cert   []byte
	me     netip.AddrPort // how this peer sees us
	nbrs   map[Hash]nbr
}

// idOf binds a node id to its identity key, so a key cannot be claimed for a
// foreign id.
func idOf(pub []byte) Hash {
	h := sha256.New()
	h.Write([]byte("da/node/v1"))
	h.Write(pub)
	var o Hash
	h.Sum(o[:0])
	return o
}

type linkEntry struct {
	addr  netip.AddrPort
	seen  time.Time
	owner Hash // only the authenticated node that created a link id may move it
}

type Node struct {
	cfg  Config
	id   Hash
	sk   ed25519.PrivateKey // identity
	pub  [32]byte           // identity public key
	conn atomic.Pointer[net.UDPConn]
	lk   *linkState

	okMu  sync.Mutex
	okeys []*okey // live onion keys, oldest first

	mu    sync.RWMutex
	peers map[Hash]*peer
	tried map[netip.AddrPort]time.Time
	pend  map[uint64]chan msg

	store *shardStore

	linkMu     sync.Mutex
	links      map[[6]byte]linkEntry // guard side: attached clients by link id
	linkSecret [16]byte
	outMu      sync.Mutex
	out        map[netip.AddrPort]time.Time // NATFilter: who we have sent to
	natDropped atomic.Int64

	hsMu    sync.Mutex
	hs      hsState
	svc     *service // set on hidden nodes
	private map[Hash]bool

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
	if cfg.Hidden {
		cfg.Attached = true
	}
	if cfg.Attached {
		if cfg.Guards <= 0 {
			cfg.Guards = 3
		}
		if cfg.Onion < 2 {
			cfg.Onion = 2 // an attached node has no direct path to anyone but its guards
		}
	}
	n := &Node{cfg: cfg, lk: newLinkState(), links: map[[6]byte]linkEntry{}, out: map[netip.AddrPort]time.Time{}, peers: map[Hash]*peer{}, tried: map[netip.AddrPort]time.Time{},
		pend: map[uint64]chan msg{}, store: st, cool: map[Hash]time.Time{}, cursor: map[Hash]int{}, done: make(chan struct{}),
		hs: newHsState(), private: map[Hash]bool{}, surbs: map[uint64]*surbEntry{}, seen: map[[16]byte]time.Time{}}
	n.conn.Store(c)
	rand.Read(n.linkSecret[:])
	if err := n.loadKey(dir); err != nil {
		c.Close()
		return nil, err
	}
	n.rotateKeys()
	if cnt, b := st.stats(); cnt > 0 {
		log.Printf("restored %d shards (%d bytes) from %s", cnt, b, dir)
	}
	go n.recvLoop(c)
	go n.maintainLoop()
	if cfg.RepairEvery > 0 {
		go n.repairLoop()
	}
	if cfg.Cover > 0 {
		go n.coverLoop()
	}
	if cfg.Hidden {
		svc, err := loadService(dir)
		if err != nil {
			c.Close()
			return nil, err
		}
		n.svc = svc
		go n.hsLoop()
	}
	return n, nil
}

// loadKey keeps the identity key (and so the node id) stable across restarts,
// so placement stays valid. Onion keys are never stored: they are meant to be lost.
func (n *Node) loadKey(dir string) error {
	if dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, "node.key")); err == nil && len(b) == ed25519.SeedSize {
			n.setKey(ed25519.NewKeyFromSeed(b))
			return nil
		}
	}
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	n.setKey(k)
	if dir != "" {
		return os.WriteFile(filepath.Join(dir, "node.key"), k.Seed(), 0o600)
	}
	return nil
}

func (n *Node) setKey(k ed25519.PrivateKey) {
	n.sk = k
	copy(n.pub[:], k.Public().(ed25519.PublicKey))
	n.id = idOf(n.pub[:])
}

func (n *Node) Close() {
	n.once.Do(func() {
		close(n.done)
		if c := n.conn.Load(); c != nil {
			c.Close()
		}
	})
}

// rebind moves the node to a new UDP port, as a NAT does when it drops and
// recreates a mapping. Used by tests.
func (n *Node) rebind() error {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return err
	}
	old := n.conn.Swap(c)
	go n.recvLoop(c)
	if old != nil {
		old.Close()
	}
	return nil
}

// linkFor is the id under which we ask a guard to remember our current address.
// It is stable per guard, so reply blocks stay valid when our NAT mapping moves.
func (n *Node) linkFor(guard netip.AddrPort) (id [6]byte) {
	h := sha256.Sum256(append(n.linkSecret[:], guard.String()...))
	copy(id[:], h[:6])
	return
}

func (n *Node) linkAddr(id [6]byte) (netip.AddrPort, bool) {
	n.linkMu.Lock()
	defer n.linkMu.Unlock()
	l, ok := n.links[id]
	return l.addr, ok
}

func (n *Node) send(to netip.AddrPort, m msg) {
	b := m.marshal()
	if len(b) > maxPlain {
		return
	}
	n.linkSend(to, b)
}

func (n *Node) recvLoop(c *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		l, src, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n.cfg.Loss > 0 && mrand.Float64() < n.cfg.Loss {
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if n.cfg.NATFilter { // a stateful NAT only lets replies from addresses we contacted
			n.outMu.Lock()
			t, ok := n.out[src]
			n.outMu.Unlock()
			if !ok || time.Since(t) > 30*time.Second {
				n.natDropped.Add(1)
				continue
			}
		}
		plain, from, ik, ok := n.linkRecv(buf[:l], src)
		if !ok {
			continue
		}
		m, ok := unmarshal(plain)
		if !ok || from == n.id {
			continue
		}
		m.from, m.ik = from, ik
		if m.typ == tPing && len(m.body) >= 1 && m.body[0]&1 != 0 {
			n.markPrivate(m.from)                     // attached/hidden node: answer so it learns its address, never list it
			if m.body[0]&2 != 0 && len(m.body) >= 7 { // and remember where its link currently points
				var id [6]byte
				copy(id[:], m.body[1:7])
				n.linkMu.Lock()
				if e, had := n.links[id]; (!had || e.owner == m.from || time.Since(e.seen) > 30*time.Second) && len(n.links) < 8192 {
					n.links[id] = linkEntry{src, time.Now(), m.from}
				}
				n.linkMu.Unlock()
			}
		} else if m.typ != tOnion && !n.isPrivate(m.from) {
			n.upsert(m.from, src)
		}
		go n.handle(m, src)
	}
}

func (n *Node) markPrivate(id Hash) {
	n.mu.Lock()
	n.private[id] = true
	delete(n.peers, id)
	n.mu.Unlock()
}

func (n *Node) isPrivate(id Hash) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.private[id]
}

func (n *Node) upsert(id Hash, a netip.AddrPort) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if p, ok := n.peers[id]; ok {
		p.addr, p.seen = a, time.Now()
		return
	}
	if n.cfg.Attached && len(n.peers) >= n.cfg.Guards {
		return // an attached node keeps a handful of guards and nobody else
	}
	n.peers[id] = &peer{id: id, addr: a, seen: time.Now(), nbrs: map[Hash]nbr{}}
}

func (n *Node) handle(m msg, src netip.AddrPort) {
	if (n.cfg.Hidden || n.cfg.Attached) && (m.typ == tPing || m.typ == tStore || m.typ == tGet || m.typ == tHas) {
		return // a hidden node never answers on the open network
	}
	switch m.typ {
	case tPing:
		_, cert := n.myOnionKey()
		b := make([]byte, 6, 6+len(cert))
		putAddr(b, src)
		b = append(b, cert...)
		n.send(src, msg{typ: tPong, id: m.id, body: append(b, n.gossipBody()...)})
	case tPong:
		r := &rd{b: m.body}
		me := getAddr(r.take(6))
		cert := append([]byte(nil), r.take(certLen)...)
		if r.bad {
			return
		}
		if !n.setPeerKey(m.from, m.ik, cert) {
			return
		}
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

// setPeerKey records a peer's onion key certificate, after checking that its
// identity (proven by the link) signed it.
func (n *Node) setPeerKey(id Hash, ik [32]byte, cert []byte) bool {
	ok, exp, valid := verifyCert(ik, cert)
	if !valid || !exp.After(time.Now()) {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if p, exists := n.peers[id]; exists {
		p.pub, p.ok, p.okExp, p.cert, p.hasPub = ik, ok, exp, cert, true
	}
	return true
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

// gossipMax entries of ik(32)+addr(6)+cert(100) must fit a PONG next to its own certificate.
const gossipMax = 8

func (n *Node) gossipBody() []byte {
	n.mu.RLock()
	ps := make([]*peer, 0, len(n.peers))
	for _, p := range n.peers {
		if p.hasPub && p.okExp.After(time.Now()) {
			ps = append(ps, p)
		}
	}
	mrand.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
	if len(ps) > gossipMax {
		ps = ps[:gossipMax]
	}
	b := []byte{byte(len(ps))}
	for _, p := range ps {
		b = append(b, p.pub[:]...)
		b = append(b, make([]byte, 6)...)
		putAddr(b[len(b)-6:], p.addr)
		b = append(b, p.cert...) // the peer's own signed onion key: relayed, never re-signed
	}
	n.mu.RUnlock()
	return b
}

func (n *Node) sendPing(to netip.AddrPort) {
	body := []byte{0}
	if n.cfg.Attached {
		l := n.linkFor(to)
		body = append([]byte{1 | 2}, l[:]...) // private: do not list or gossip me; keep a link for me
	}
	n.send(to, msg{typ: tPing, id: mrand.Uint64(), body: body})
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
		var ik [32]byte
		copy(ik[:], r.take(32))
		ap := getAddr(r.take(6))
		cert := append([]byte(nil), r.take(certLen)...)
		if r.bad {
			return
		}
		id := idOf(ik[:])
		if id == n.id {
			continue
		}
		okey, exp, valid := verifyCert(ik, cert) // the neighbour's own signature, so the reporting peer cannot swap keys
		if !valid || !exp.After(time.Now()) {
			continue
		}
		n.mu.Lock()
		if p, ok := n.peers[from]; ok {
			rec := nbr{pub: ik, addr: ap, seen: time.Now(), ok: okey, okExp: exp, cert: cert}
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
		if !known && !n.cfg.Attached && (!seen || time.Since(t) > 10*time.Second) {
			n.tried[ap] = time.Now()
			n.mu.Unlock()
			n.pinAddr(ap, id) // the handshake must find exactly this node there
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
		n.rotateKeys()
		n.pruneLinks()

		ps := n.peerList()
		if !n.cfg.Attached {
			for _, a := range n.resolve() {
				n.sendPing(a)
			}
		} else if need := n.cfg.Guards - len(ps); need > 0 { // attached: contact only as many candidates as guards missing
			cands := n.resolve()
			mrand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
			for i := 0; i < len(cands) && i < need; i++ {
				n.sendPing(cands[i])
			}
		}
		mrand.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
		for i := 0; i < len(ps) && (i < 4 || n.cfg.Attached); i++ { // keepalives hold the NAT mapping open
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
	var ts []target
	if !n.cfg.Attached { // an attached node stores nothing and is not a holder
		ts = append(ts, target{id: n.id, self: true})
	}
	seen := map[Hash]bool{}
	for _, p := range n.peerList() {
		ts = append(ts, target{id: p.id, addr: p.addr})
		seen[p.id] = true
	}
	if n.cfg.Attached { // placement still has to see the whole public network: take it from the guards' gossip
		n.mu.RLock()
		for _, p := range n.peers {
			for id, nb := range p.nbrs {
				if !seen[id] && id != n.id {
					seen[id] = true
					ts = append(ts, target{id: id, addr: nb.addr})
				}
			}
		}
		n.mu.RUnlock()
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
