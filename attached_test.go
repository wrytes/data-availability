package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"
)

// An attached client behind a stateful NAT: it only dials out to three guards,
// nobody lists it, unsolicited packets never reach it, and it still stores and
// reads data on the public network, also after its NAT mapping moves.
func TestAttachedBehindNAT(t *testing.T) {
	ns, _ := clusterWait(t, 6, opts{onion: 1, delay: 5 * time.Millisecond}, 9*time.Second)
	defer closeAll(ns)

	a, err := NewNode(Config{Port: 17030, Replication: 2, MaxBytes: 1 << 20, Attached: true, NATFilter: true, Guards: 3,
		OnionDelay: 5 * time.Millisecond,
		Discover:   []string{"127.0.0.1:17001", "127.0.0.1:17002", "127.0.0.1:17003", "127.0.0.1:17004"}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	time.Sleep(12 * time.Second)
	ctx := context.Background()

	// 1. exactly three guards, and nobody lists the attached node
	if got := len(a.peerList()); got != 3 {
		t.Fatalf("attached node has %d guards, want 3", got)
	}
	for i, n := range ns {
		for _, p := range n.peerList() {
			if p.id == a.id {
				t.Fatalf("node %d lists the attached node", i)
			}
		}
	}
	links := 0
	for _, n := range ns {
		links += n.linkCount()
	}
	if links != 3 {
		t.Fatalf("guards hold %d links, want 3", links)
	}

	// 2. the NAT drops unsolicited traffic from non-guards
	before := a.natDropped.Load()
	addr := netip.MustParseAddrPort("127.0.0.1:17030")
	if _, err := ns[5].call(ctx, addr, tPing, append([]byte{}, ns[5].pub[:]...), 300*time.Millisecond, 2); err == nil {
		t.Fatal("an unsolicited ping got through the NAT")
	}
	if a.natDropped.Load() == before {
		t.Fatal("the NAT filter did not see the unsolicited ping")
	}

	// 3. it works as a client using only its guards
	dropped := a.natDropped.Load()
	pt := make([]byte, 30_000)
	rand.Read(pt)
	res, err := a.Put(ctx, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Get(ctx, res.Manifest)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("get behind NAT: %v", err)
	}
	if au, _ := a.Audit(ctx, res.Manifest, 10); !au.Recoverable {
		t.Fatalf("audit %+v", au)
	}
	if d := a.natDropped.Load() - dropped; d != 0 {
		t.Fatalf("%d legitimate packets came from addresses the client never contacted", d)
	}
	// and an unattached node can read what it stored
	if got, err := ns[0].Get(ctx, res.Manifest); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("public node cannot read it: %v", err)
	}

	// 4. the NAT mapping moves; link ids keep reply blocks valid
	if err := a.rebind(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second) // keepalives re-register the link at each guard
	got, err = a.Get(ctx, res.Manifest)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("get after the NAT mapping moved: %v", err)
	}
}
