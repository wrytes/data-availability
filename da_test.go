package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestSealOpen(t *testing.T) {
	m := make([]byte, 32)
	rand.Read(m)
	pt := []byte("hello layered world")
	ct, _ := seal(m, pt, 0)
	got, err := open(m, ct, 0)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 1
	if _, err := open(m, ct, 0); err == nil {
		t.Fatal("tamper not detected")
	}
}

func TestMerkle(t *testing.T) {
	for _, n := range []int{2, 3, 7, 64, 1001} {
		ls := make([]Hash, n)
		ds := make([][]byte, n)
		for i := range ls {
			ds[i] = []byte(fmt.Sprint("d", i))
			ls[i] = leafHash(uint32(i), ds[i])
		}
		lv := buildTree(ls)
		root := lv[len(lv)-1][0]
		for i := 0; i < n; i++ {
			if !verifyShard(root, uint32(i), uint32(n), ds[i], proofFor(lv, i)) {
				t.Fatalf("n=%d i=%d", n, i)
			}
		}
		if verifyShard(root, 0, uint32(n), []byte("x"), proofFor(lv, 0)) {
			t.Fatal("bad shard accepted")
		}
	}
}

type opts struct {
	loss   float64
	data   bool
	repair time.Duration
}

func mk(t *testing.T, i int, o opts, dirs []string) *Node {
	d := []string{}
	if i > 0 {
		d = []string{"127.0.0.1:17000"}
	}
	cfg := Config{Port: 17000 + i, Discover: d, Replication: 2, MaxBytes: 1 << 28, Loss: o.loss, RepairEvery: o.repair}
	if o.data {
		cfg.DataDir, cfg.NodeName = dirs[i], "n"
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func cluster(t *testing.T, cnt int, o opts) ([]*Node, []string) {
	var dirs []string
	for i := 0; i < cnt; i++ {
		dirs = append(dirs, t.TempDir())
	}
	var ns []*Node
	for i := 0; i < cnt; i++ {
		ns = append(ns, mk(t, i, o, dirs))
	}
	time.Sleep(6 * time.Second)
	return ns, dirs
}

func closeAll(ns []*Node) {
	for _, n := range ns {
		n.Close()
	}
}

func TestEndToEnd(t *testing.T) {
	ns, _ := cluster(t, 10, opts{loss: 0.1}) // 10% packet loss
	defer closeAll(ns)
	ctx := context.Background()
	for _, size := range []int{10, 200_000, 1_500_000} { // 1.5MB => >256 shards => GF16 path
		pt := make([]byte, size)
		rand.Read(pt)
		res, err := ns[0].Put(ctx, pt)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		got, err := ns[5].Get(ctx, res.Manifest)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("size %d get: %v", size, err)
		}
		a, _ := ns[3].Audit(ctx, res.Manifest, 20)
		t.Logf("size=%d shards=%d audit=%+v", size, res.Shards, a)
	}
	// kill 4 of 10 nodes (some shard replicas die); data must survive via the >50% rule
	pt := make([]byte, 100_000)
	rand.Read(pt)
	res, _ := ns[0].Put(ctx, pt)
	for _, n := range ns[6:] {
		n.Close()
	}
	time.Sleep(14 * time.Second) // let dead peers expire
	got, err := ns[1].Get(ctx, res.Manifest)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("after failures: %v", err)
	}
}

func TestSegments(t *testing.T) {
	old := segSize
	segSize = 100_000 // 3.5 segments, exercises the streaming path without huge files
	defer func() { segSize = old }()
	ns, _ := cluster(t, 6, opts{})
	defer closeAll(ns)
	ctx := context.Background()
	for _, size := range []int{0, 99_999, 100_000, 350_000} {
		pt := make([]byte, size)
		rand.Read(pt)
		res, err := ns[0].Put(ctx, pt)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		want := (size + segSize - 1) / segSize
		if want == 0 {
			want = 1
		}
		if res.Segments != want {
			t.Fatalf("size %d: %d segments, want %d", size, res.Segments, want)
		}
		got, err := ns[3].Get(ctx, res.Manifest)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("size %d get: %v", size, err)
		}
		a, _ := ns[2].Audit(ctx, res.Manifest, 10)
		if !a.Recoverable || a.Available != a.Samples {
			t.Fatalf("audit %+v", a)
		}
		if size == 350_000 { // segments are bound to their position
			mf := res.Manifest
			mf.Segs = append([]Seg{mf.Segs[1], mf.Segs[0]}, mf.Segs[2:]...)
			if _, err := ns[3].Get(ctx, mf); err == nil {
				t.Fatal("reordered segments accepted")
			}
		}
	}
}

func TestPersistence(t *testing.T) {
	dirs := []string{t.TempDir()}
	o := opts{data: true}
	n := mk(t, 0, o, dirs)
	ctx := context.Background()
	pt := make([]byte, 50_000)
	rand.Read(pt)
	res, err := n.Put(ctx, pt) // alone in the network: every shard lands locally
	if err != nil {
		t.Fatal(err)
	}
	id := n.id
	shards, _ := n.store.stats()
	n.Close()
	time.Sleep(200 * time.Millisecond)

	n2 := mk(t, 0, o, dirs)
	defer n2.Close()
	if n2.id != id {
		t.Fatal("node id changed across restart")
	}
	if s2, _ := n2.store.stats(); s2 != shards || shards == 0 {
		t.Fatalf("restored %d shards, had %d", s2, shards)
	}
	got, err := n2.Get(ctx, res.Manifest)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("get after restart: %v", err)
	}
}

// lostShards counts shards of a segment that no live node holds any more.
func lostShards(live []*Node, root Hash, total int) (lost, thin int) {
	for i := 0; i < total; i++ {
		c := 0
		for _, n := range live {
			if n.store.has(root, uint32(i)) {
				c++
			}
		}
		if c == 0 {
			lost++
		}
		if c < 2 {
			thin++
		}
	}
	return
}

func TestRepair(t *testing.T) {
	ns, _ := cluster(t, 8, opts{data: true, repair: 2 * time.Second})
	defer closeAll(ns)
	ctx := context.Background()
	pt := make([]byte, 60_000)
	rand.Read(pt)
	res, err := ns[0].Put(ctx, pt)
	if err != nil {
		t.Fatal(err)
	}
	sg := res.Manifest.Segs[0]
	var root Hash
	rb, _ := hex.DecodeString(sg.Root)
	copy(root[:], rb)
	total := 2 * sg.K

	closeAll(ns[5:]) // three of eight nodes die
	live := ns[:5]
	lost0, thin0 := lostShards(live, root, total)
	t.Logf("after failure: %d shards have no copy, %d have < 2 copies (of %d)", lost0, thin0, total)

	deadline := time.Now().Add(90 * time.Second)
	for {
		lost, thin := lostShards(live, root, total)
		if lost == 0 && thin == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("repair incomplete: %d lost, %d thin", lost, thin)
		}
		time.Sleep(2 * time.Second)
	}
	var rebuilds, pushed int64
	for _, n := range live {
		rebuilds += n.rebuilds.Load()
		pushed += n.pushed.Load()
	}
	t.Logf("repaired: %d erasure rebuilds, %d copies pushed", rebuilds, pushed)
	if lost0 > 0 && rebuilds == 0 {
		t.Fatal("shards were lost entirely but nothing was rebuilt from the erasure code")
	}
	got, err := ns[1].Get(ctx, res.Manifest)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("get after repair: %v", err)
	}
}
