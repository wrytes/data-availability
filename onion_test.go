package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type tnode struct {
	priv *ecdh.PrivateKey
	hop  hop
}

func mkHops(t *testing.T, n int) []tnode {
	var out []tnode
	for i := 0; i < n; i++ {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var h hop
		copy(h.pub[:], k.PublicKey().Bytes())
		h.addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), uint16(7000+i))
		out = append(out, tnode{k, h})
	}
	return out
}

func hopsOf(ns []tnode) []hop {
	var h []hop
	for _, n := range ns {
		h = append(h, n.hop)
	}
	return h
}

func TestOnionSizes(t *testing.T) {
	if hdrLen+onionHdr+onionD != maxPlain {
		t.Fatal("onion packet is not exactly one max datagram")
	}
	// the biggest request (STORE with a depth-16 proof) and reply (DATA) must fit
	store := encStore(Hash{}, 0, 65000, make([]byte, shardSize), make([]Hash, 16))
	if zeroLen+2+surbLen+len(store) > onionD {
		t.Fatalf("STORE needs %d, onion carries %d", zeroLen+2+surbLen+len(store), onionD)
	}
	data := encData(true, 65000, make([]byte, shardSize), make([]Hash, 16))
	if zeroLen+2+len(data) > onionD {
		t.Fatalf("DATA needs %d, onion carries %d", zeroLen+2+len(data), onionD)
	}
}

// peel runs one hop's processing the way handleOnion does.
func peel(t *testing.T, n tnode, h onionHeader, delta []byte) (peeled, []byte) {
	pl, err := peelHeader(n.priv, h)
	if err != nil {
		t.Fatalf("peel: %v", err)
	}
	piDec(&pl.keys, delta)
	return pl, delta
}

func TestOnionForwardAndReply(t *testing.T) {
	fw := mkHops(t, 3)
	hdr, keys, err := buildHeader(hopsOf(fw), []byte{recDeliver})
	if err != nil {
		t.Fatal(err)
	}
	msgBody := bytes.Repeat([]byte("secret request "), 20)
	m := make([]byte, onionD)
	copy(m[zeroLen+1:], msgBody)
	plain := append([]byte(nil), m...)
	wrapPayload(keys, m)

	var seen [][]byte
	h, delta := hdr, m
	for i := 0; i < 3; i++ {
		pkt := encodeOnion(h, delta)
		if len(pkt) != onionHdr+onionD {
			t.Fatalf("hop %d: packet size %d", i, len(pkt))
		}
		for _, s := range seen { // consecutive packets share no content
			if bytes.Equal(s[:48], pkt[:48]) || bytes.Equal(s[onionHdr:onionHdr+64], pkt[onionHdr:onionHdr+64]) {
				t.Fatal("packets are linkable between hops")
			}
		}
		seen = append(seen, pkt)
		var pl peeled
		pl, delta = peel(t, fw[i], h, append([]byte(nil), delta...))
		if i < 2 {
			if pl.rec[0] != recRelay || getAddr(pl.rec[1:7]) != fw[i+1].hop.addr {
				t.Fatalf("hop %d: wrong next hop", i)
			}
			h = pl.next
		} else if pl.rec[0] != recDeliver {
			t.Fatal("last hop must deliver")
		}
	}
	if !bytes.Equal(delta, plain) {
		t.Fatal("payload corrupted on the way")
	}

	// reply block: me <- r0 <- r1 <- r2 <- responder
	back := mkHops(t, 3)
	id := uint64(42)
	last := make([]byte, onionR)
	last[0] = recSurb
	last[8] = byte(id)
	sh, skeys, err := buildHeader(hopsOf(back), last)
	if err != nil {
		t.Fatal(err)
	}
	var ks [16]byte
	rand.Read(ks[:])
	sb, ok := decodeSurb(surb{back[0].hop.addr, sh, ks}.encode())
	if !ok {
		t.Fatal("surb encoding")
	}
	resp := make([]byte, onionD)
	copy(resp[zeroLen+1:], []byte("the reply"))
	rk := keysFromKs(sb.ks[:])
	piEnc(&rk, resp)
	h, delta = sb.hdr, resp
	for i := 0; i < 3; i++ {
		var pl peeled
		pl, delta = peel(t, back[i], h, append([]byte(nil), delta...))
		h = pl.next
		if i == 2 && (pl.rec[0] != recSurb || pl.rec[8] != byte(id)) {
			t.Fatal("reply block must end with the surb id")
		}
	}
	wrapPayload(skeys, delta)
	ok2 := keysFromKs(ks[:])
	piDec(&ok2, delta)
	if !bytes.Equal(delta[zeroLen+1:zeroLen+1+9], []byte("the reply")) || !bytes.Equal(delta[:zeroLen], make([]byte, zeroLen)) {
		t.Fatal("reply did not survive the reply block")
	}
}

func TestOnionTamper(t *testing.T) {
	fw := mkHops(t, 3)
	hdr, keys, _ := buildHeader(hopsOf(fw), []byte{recDeliver})
	m := make([]byte, onionD)
	wrapPayload(keys, m)
	for _, off := range []int{0, 40, 100, 200} { // e, gamma, beta
		pkt := encodeOnion(hdr, m)
		pkt[off] ^= 1
		h, _, _ := decodeOnion(pkt)
		if _, err := peelHeader(fw[0].priv, h); err == nil {
			t.Fatalf("flipped header byte %d accepted", off)
		}
	}
	// a flipped payload bit turns the whole payload to noise (wide-block cipher)
	d := append([]byte(nil), m...)
	d[500] ^= 1
	h, d := hdr, d
	for i := 0; i < 3; i++ {
		var pl peeled
		pl, d = peel(t, fw[i], h, d)
		h = pl.next
	}
	if bytes.Equal(d[:zeroLen], make([]byte, zeroLen)) {
		t.Fatal("tampered payload still passes the integrity prefix")
	}
	// wrong key
	other := mkHops(t, 1)[0]
	if _, err := peelHeader(other.priv, hdr); err == nil {
		t.Fatal("foreign key peeled a layer")
	}
}

func TestOnionReplay(t *testing.T) {
	n, err := NewNode(Config{Port: 17900, Replication: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	var tag [16]byte
	rand.Read(tag[:])
	if n.replayed(tag) || !n.replayed(tag) {
		t.Fatal("replay cache")
	}
}

// Real nodes, real UDP: requests travel through two relays and the holder never
// sees the requester.
func TestOnionEndToEnd(t *testing.T) {
	ns, _ := clusterWait(t, 8, opts{onion: 2, delay: 5 * time.Millisecond}, 10*time.Second)
	defer closeAll(ns)
	requester := uint16(17000 + 0)

	var mu sync.Mutex
	viaOnion, fromRequester, direct := 0, 0, 0
	for _, n := range ns {
		n.hook = func(from netip.AddrPort, typ byte, onion bool) {
			mu.Lock()
			defer mu.Unlock()
			if onion {
				viaOnion++
			} else if typ != tHas {
				direct++
			}
			if from.Port() == requester {
				fromRequester++
			}
		}
	}
	ctx := context.Background()
	pt := make([]byte, 40_000)
	rand.Read(pt)
	res, err := ns[0].Put(ctx, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ns[0].Get(ctx, res.Manifest)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("get over onion: %v", err)
	}
	a, _ := ns[0].Audit(ctx, res.Manifest, 12)
	if !a.Recoverable {
		t.Fatalf("audit %+v", a)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("served over onion: %d, directly: %d, requests whose observed source was the requester: %d", viaOnion, direct, fromRequester)
	if viaOnion == 0 {
		t.Fatal("nothing went through onion routes")
	}
	if direct != 0 || fromRequester != 0 {
		t.Fatalf("holders saw the requester: direct=%d fromRequester=%d", direct, fromRequester)
	}
	var relayed int64
	for _, n := range ns {
		relayed += n.relayed.Load()
	}
	if relayed == 0 {
		t.Fatal("no relaying happened")
	}
}
