package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
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
}

type peer struct {
	id   Hash
	addr netip.AddrPort
	seen time.Time
}

type Node struct {
	cfg  Config
	id   Hash
	conn *net.UDPConn

	mu    sync.RWMutex
	peers map[Hash]*peer
	tried map[netip.AddrPort]time.Time
	pend  map[uint64]chan msg

	store *shardStore

	repMu    sync.Mutex
	cool     map[Hash]time.Time
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
		pend: map[uint64]chan msg{}, store: st, cool: map[Hash]time.Time{}, done: make(chan struct{})}
	if err := n.loadID(dir); err != nil {
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
	return n, nil
}

// loadID keeps the node ID stable across restarts, so placement stays valid.
func (n *Node) loadID(dir string) error {
	if dir == "" {
		_, err := rand.Read(n.id[:])
		return err
	}
	p := filepath.Join(dir, "node.id")
	if b, err := os.ReadFile(p); err == nil {
		if len(b) == 32 {
			copy(n.id[:], b)
			return nil
		}
	}
	if _, err := rand.Read(n.id[:]); err != nil {
		return err
	}
	return os.WriteFile(p, n.id[:], 0o600)
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
		n.upsert(m.from, src)
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
	n.peers[id] = &peer{id, a, time.Now()}
}

func (n *Node) handle(m msg, src netip.AddrPort) {
	switch m.typ {
	case tPing:
		n.send(src, msg{typ: tPong, id: m.id, body: n.gossipBody()})
	case tPong:
		n.learn(m.body)
		n.deliver(m)
	case tAck, tData, tHasR:
		n.deliver(m)
	case tStore:
		r := &rd{b: m.body}
		root, leaf, cnt := r.hash(), r.u32(), r.u32()
		data := append([]byte(nil), r.take(int(r.u16()))...)
		proof := r.proof()
		status := n.putLocal(root, leaf, cnt, data, proof, r.bad)
		n.send(src, msg{typ: tAck, id: m.id, body: []byte{status}})
	case tGet:
		r := &rd{b: m.body}
		root, leaf := r.hash(), r.u32()
		if r.bad {
			return
		}
		s, ok := n.store.get(root, leaf)
		n.send(src, msg{typ: tData, id: m.id, body: encData(ok, s.n, s.data, s.proof)})
	case tHas:
		r := &rd{b: m.body}
		root, leaf := r.hash(), r.u32()
		if r.bad {
			return
		}
		st := byte(1)
		if n.store.has(root, leaf) {
			st = 0
		}
		n.send(src, msg{typ: tHasR, id: m.id, body: []byte{st}})
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
		ps = append(ps, p)
	}
	n.mu.RUnlock()
	mrand.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
	if len(ps) > 12 {
		ps = ps[:12]
	}
	b := []byte{byte(len(ps))}
	for _, p := range ps {
		a := p.addr.Addr().As4()
		b = append(b, a[:]...)
		b = binary.BigEndian.AppendUint16(b, p.addr.Port())
	}
	return b
}

// learn pings gossiped addresses; they only become peers once they answer
// directly (so unreachable cross-subnet addresses never enter the table).
func (n *Node) learn(body []byte) {
	r := &rd{b: body}
	cnt := int(r.u8())
	for i := 0; i < cnt; i++ {
		var a [4]byte
		copy(a[:], r.take(4))
		port := r.u16()
		if r.bad {
			return
		}
		ap := netip.AddrPortFrom(netip.AddrFrom4(a), port)
		n.mu.Lock()
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
			n.send(ap, msg{typ: tPing, id: mrand.Uint64()})
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
		for a, ts := range n.tried {
			if time.Since(ts) > time.Minute {
				delete(n.tried, a)
			}
		}
		n.mu.Unlock()

		for _, a := range n.resolve() {
			n.send(a, msg{typ: tPing, id: mrand.Uint64()})
		}
		ps := n.peerList()
		mrand.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
		for i := 0; i < len(ps) && i < 4; i++ {
			n.send(ps[i].addr, msg{typ: tPing, id: mrand.Uint64()})
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
		out = append(out, *p)
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
