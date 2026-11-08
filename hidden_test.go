package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestHiddenHolder(t *testing.T) {
	ns, _ := cluster(t, 8, opts{onion: 1, delay: 5 * time.Millisecond})
	defer closeAll(ns)

	// the hidden node only knows four guards; nothing else in the network is told about it
	h, err := NewNode(Config{Port: 17020, Replication: 2, MaxBytes: 1 << 28, Hidden: true, OnionDelay: 5 * time.Millisecond,
		DataDir: t.TempDir(), NodeName: "h",
		Discover: []string{"127.0.0.1:17001", "127.0.0.1:17002", "127.0.0.1:17003", "127.0.0.1:17004"}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	time.Sleep(16 * time.Second) // guards, introduction points, descriptor

	ctx := context.Background()
	sid := h.svc.sid

	// 1. nobody lists or gossips the hidden node
	for i, n := range ns {
		for _, p := range n.peerList() {
			if p.id == h.id || p.addr.Port() == 17020 {
				t.Fatalf("node %d lists the hidden node", i)
			}
		}
	}
	// 2. it does not answer on the open network
	probe := netip.MustParseAddrPort("127.0.0.1:17020")
	if _, err := ns[5].call(ctx, probe, tGet, encGet(Hash{}, 0), 300*time.Millisecond, 2); err == nil {
		t.Fatal("hidden node answered a direct request")
	}
	if _, err := ns[5].call(ctx, probe, tPing, append([]byte{}, ns[5].pub[:]...), 300*time.Millisecond, 2); err == nil {
		t.Fatal("hidden node answered a ping")
	}

	// 3. store through rendezvous
	pt := make([]byte, 20_000)
	rand.Read(pt)
	res, err := ns[0].PutReaderHidden(ctx, bytes.NewReader(pt), []Hash{sid})
	if err != nil {
		t.Fatal(err)
	}
	k := res.Manifest.Segs[0].K
	held, _ := h.store.stats()
	t.Logf("shards=%d hidden replica acks=%d held by the hidden node=%d", res.Shards, res.HiddenAck, held)
	if res.HiddenAck < k || held != res.HiddenAck {
		t.Fatalf("hidden replicas incomplete: %d acks (need >= %d), %d held", res.HiddenAck, k, held)
	}

	// 4. a different client reads it back from the hidden node alone
	got, err := ns[6].Get(hiddenOnly(ctx), res.Manifest)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("hidden-only get: %v", err)
	}
	a, _ := ns[7].Audit(hiddenOnly(ctx), res.Manifest, 10)
	if !a.Recoverable || a.Available != a.Samples {
		t.Fatalf("hidden audit %+v", a)
	}

	// 5. still invisible afterwards
	for i, n := range ns {
		if n.isPrivate(h.id) {
			continue // guards know it is private, which is the point
		}
		for _, p := range n.peerList() {
			if p.id == h.id {
				t.Fatalf("node %d lists the hidden node after use", i)
			}
		}
	}
	for i, n := range ns {
		for _, p := range n.peerList() {
			if p.id == h.id {
				t.Fatal(fmt.Sprint("node ", i, " lists it"))
			}
		}
	}
}
