package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestSealOpen(t *testing.T) {
	m := make([]byte, 32)
	rand.Read(m)
	pt := []byte("hello layered world")
	ct, _ := seal(m, pt)
	got, err := open(m, ct)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 1
	if _, err := open(m, ct); err == nil {
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

func cluster(t *testing.T, cnt int, loss float64) []*Node {
	var ns []*Node
	for i := 0; i < cnt; i++ {
		d := []string{}
		if i > 0 {
			d = []string{fmt.Sprintf("127.0.0.1:%d", 17000)}
		}
		n, err := NewNode(Config{Port: 17000 + i, Discover: d, Replication: 2, MaxBytes: 1 << 28, Loss: loss})
		if err != nil {
			t.Fatal(err)
		}
		ns = append(ns, n)
	}
	time.Sleep(6 * time.Second)
	return ns
}

func TestEndToEnd(t *testing.T) {
	ns := cluster(t, 10, 0.1) // 10% packet loss
	defer func() {
		for _, n := range ns {
			n.Close()
		}
	}()
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
