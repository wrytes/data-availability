package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"
)

func newAt(t *testing.T, port int, disc []string, mod func(*Config)) *Node {
	cfg := Config{Port: port, Discover: disc, Replication: 2, MaxBytes: 1 << 24}
	if mod != nil {
		mod(&cfg)
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func local(port int) netip.AddrPort { return netip.MustParseAddrPort("127.0.0.1:" + itoa(port)) }

func itoa(i int) string {
	return string(rune('0'+i/10000%10)) + string(rune('0'+i/1000%10)) + string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}

// Links are authenticated and encrypted: the sender id is proven, forged,
// modified and replayed datagrams are dropped, and a handshake with an
// unexpected identity is refused.
func TestLinkAuth(t *testing.T) {
	a := newAt(t, 17100, nil, nil)
	b := newAt(t, 17101, []string{"127.0.0.1:17100"}, nil)
	c := newAt(t, 17102, nil, nil)
	defer closeAll([]*Node{a, b, c})
	time.Sleep(4 * time.Second)

	// 1. the session proves who is who
	if len(b.peerList()) != 1 || b.peerList()[0].id != a.id {
		t.Fatal("b does not see a as its peer")
	}
	a.lk.mu.Lock()
	sa := a.lk.byAddr[local(17101)]
	a.lk.mu.Unlock()
	if sa == nil || sa.peer != b.id {
		t.Fatal("a has no session proving b's identity")
	}

	// 2. a genuine datagram is accepted once; replays and bit flips are not
	plain := msg{typ: tAck, id: 7}.marshal()
	a.lk.mu.Lock()
	good := a.sealLocked(sa, plain)
	flip := a.sealLocked(sa, plain)
	a.lk.mu.Unlock()
	if _, from, _, ok := b.linkRecv(good, local(17100)); !ok || from != a.id {
		t.Fatal("genuine datagram rejected")
	}
	if _, _, _, ok := b.linkRecv(good, local(17100)); ok {
		t.Fatal("replayed datagram accepted")
	}
	flip[len(flip)-1] ^= 1
	if _, _, _, ok := b.linkRecv(flip, local(17100)); ok {
		t.Fatal("modified datagram accepted")
	}
	if b.linkStat(3) == 0 || b.linkStat(2) == 0 {
		t.Fatalf("replay/forgery counters not bumped: %d/%d", b.linkStat(3), b.linkStat(2))
	}

	// 3. a stranger cannot speak as a: plaintext messages and made-up sessions are ignored
	var heard bool
	b.hook = func(netip.AddrPort, byte, bool) { heard = true }
	raw, _ := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 17101})
	defer raw.Close()
	raw.Write(msg{typ: tHas, id: 1, body: encGet(Hash{1}, 0)}.marshal())
	fake := append([]byte{kData, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9}, make([]byte, 40)...)
	rand.Read(fake[13:])
	raw.Write(fake)
	time.Sleep(300 * time.Millisecond)
	if heard {
		t.Fatal("an unauthenticated datagram reached the request handler")
	}

	// 4. pinning: a expects b at c's address; the handshake must fail
	a.pinAddr(local(17102), b.id)
	before := a.linkStat(1)
	a.send(local(17102), msg{typ: tPing, id: 1, body: []byte{0}})
	time.Sleep(2 * time.Second)
	a.lk.mu.Lock()
	imposter := a.lk.byAddr[local(17102)]
	a.lk.mu.Unlock()
	if imposter != nil || a.linkStat(1) == before {
		t.Fatal("a accepted c while expecting b")
	}
}

// Sessions are re-keyed on a timer without interrupting traffic.
func TestLinkRekey(t *testing.T) {
	mod := func(c *Config) { c.LinkLife = time.Second }
	a := newAt(t, 17110, nil, mod)
	b := newAt(t, 17111, []string{"127.0.0.1:17110"}, mod)
	defer closeAll([]*Node{a, b})
	time.Sleep(3 * time.Second)
	ctx := context.Background()
	fail := 0
	for i := 0; i < 24; i++ {
		var peer netip.AddrPort
		if ps := b.peerList(); len(ps) > 0 {
			peer = ps[0].addr
		} else {
			peer = local(17110)
		}
		if _, err := b.call(ctx, peer, tPing, []byte{0}, 300*time.Millisecond, 3); err != nil {
			fail++
		}
		time.Sleep(250 * time.Millisecond)
	}
	if fail > 0 {
		t.Fatalf("%d calls failed across re-keying", fail)
	}
	if b.linkStat(0) < 3 {
		t.Fatalf("expected several handshakes over 6s with a 1s lifetime, got %d", b.linkStat(0))
	}
}

// Relays peel with short-lived onion keys that are deleted after rotation, so
// a packet recorded today cannot be opened tomorrow, not even by its relay.
func TestOnionForwardSecrecy(t *testing.T) {
	mod := func(c *Config) {
		c.Onion, c.OnionDelay, c.OnionKeyLife = 1, 5*time.Millisecond, 4*time.Second
	}
	var ns []*Node
	for i := 0; i < 6; i++ {
		var d []string
		if i > 0 {
			d = []string{"127.0.0.1:17120"}
		}
		ns = append(ns, newAt(t, 17120+i, d, mod))
	}
	defer closeAll(ns)
	time.Sleep(8 * time.Second)
	ctx := context.Background()

	pt := make([]byte, 20_000)
	rand.Read(pt)
	res, err := ns[0].Put(ctx, pt)
	if err != nil {
		t.Fatal(err)
	}

	// record a packet addressed to relay 3's current key
	k, _ := ns[3].myOnionKey()
	ad := local(17123)
	hdr, _, err := buildHeader([]hop{{pub: k, addr: ad}, {pub: k, addr: ad}, {pub: k, addr: ad}}, []byte{recDeliver})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ns[3].peelAny(hdr); err != nil {
		t.Fatalf("a live key must open it: %v", err)
	}

	time.Sleep(12 * time.Second) // key life 4s + grace 2s, with maintenance ticks

	if _, err := ns[3].peelAny(hdr); err == nil {
		t.Fatal("the recorded packet can still be opened after the key should be gone")
	}
	if c := ns[3].okeyCount(); c > 3 {
		t.Fatalf("%d onion keys retained", c)
	}
	// and the network keeps working on the new keys
	got, err := ns[5].Get(ctx, res.Manifest)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("get after rotation: %v", err)
	}
}
