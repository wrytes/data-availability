package main

import (
	"context"
	"fmt"
	"log"
	mrand "math/rand"
	"sort"
	"time"

	"github.com/klauspost/reedsolomon"
)

// Repair runs on every node, using only what the node itself holds:
//
//  1. Re-replication / rebalancing. For sampled shards it holds, it asks the
//     current closest holders (HAS) and pushes the shard to any that lack it.
//     This restores the replication factor after a node dies and moves shards
//     to newly joined nodes that are now closer.
//  2. Loss detection + erasure rebuild. For sampled leaves of a root it holds
//     anything of, if no holder has the shard at all, it fetches any K shards
//     of that root, Reed-Solomon reconstructs everything, checks the result
//     against the Merkle root, and pushes every missing shard to its holders.
//     K = total/2 follows from the fixed rate-1/2 code, and the repairer never
//     needs the decryption key (shards are ciphertext).

const (
	sampleHeld   = 64 // held shards checked per root per sweep, scanned with a rotating cursor
	sampleRandom = 12
	rebuildGap   = 20 * time.Second
)

func (n *Node) has(ctx context.Context, h target, root Hash, leaf uint32) (has, known bool) {
	if h.self {
		return n.store.has(root, leaf), true
	}
	m, err := n.call(ctx, h.addr, tHas, encGet(root, leaf), 300*time.Millisecond, 2)
	if err != nil || len(m.body) == 0 {
		return false, false
	}
	return m.body[0] == 0, true
}

func (n *Node) push(ctx context.Context, h target, root Hash, leaf, total uint32, data []byte, proof []Hash) bool {
	if h.self {
		return n.putLocal(root, leaf, total, data, proof, false) == 0
	}
	m, err := n.call(ctx, h.addr, tStore, encStore(root, leaf, total, data, proof), 500*time.Millisecond, 3)
	return err == nil && len(m.body) > 0 && m.body[0] == 0
}

func (n *Node) repairCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	go func() {
		select {
		case <-n.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (n *Node) repairLoop() {
	select {
	case <-time.After(n.cfg.RepairEvery):
	case <-n.done:
		return
	}
	t := time.NewTicker(n.cfg.RepairEvery)
	defer t.Stop()
	for {
		n.repairSweep()
		select {
		case <-t.C:
		case <-n.done:
			return
		}
	}
}

func (n *Node) repairSweep() {
	ctx, cancel := n.repairCtx()
	defer cancel()
	for root, ri := range n.store.roots() {
		if ctx.Err() != nil {
			return
		}
		if ri.n < 4 || ri.n%2 != 0 || ri.n > maxLeaves {
			continue
		}
		// an upload may still be in flight: leave young roots alone
		if time.Since(ri.newest) < 3*n.cfg.RepairEvery {
			continue
		}
		sample := map[uint32]bool{}
		held := append([]uint32(nil), ri.leaves...)
		sort.Slice(held, func(i, j int) bool { return held[i] < held[j] })
		start := n.cursor[root] % len(held) // full coverage in len/sampleHeld sweeps, no coupon-collector tail
		for i := 0; i < len(held) && i < sampleHeld; i++ {
			sample[held[(start+i)%len(held)]] = true
		}
		n.cursor[root] = start + sampleHeld
		for i := 0; i < sampleRandom; i++ {
			sample[uint32(mrand.Intn(int(ri.n)))] = true
		}
		var missing []uint32
		for leaf := range sample {
			if ctx.Err() != nil {
				return
			}
			mine, iHold := n.store.get(root, leaf)
			anyHas, unknown := iHold, false
			var lacking []target
			for _, h := range n.holders(shardKey(root, leaf), n.cfg.Replication) {
				has, known := n.has(ctx, h, root, leaf)
				switch {
				case !known:
					unknown = true
				case has:
					anyHas = true
				case !h.self:
					lacking = append(lacking, h)
				}
			}
			if iHold {
				for _, h := range lacking {
					if n.push(ctx, h, root, leaf, ri.n, mine.data, mine.proof) {
						n.pushed.Add(1)
					}
				}
			} else if !anyHas && !unknown {
				missing = append(missing, leaf)
			}
		}
		if len(missing) > 0 {
			n.tryRebuild(ctx, root, int(ri.n), missing)
		}
	}
}

func (n *Node) tryRebuild(ctx context.Context, root Hash, total int, missing []uint32) {
	if !n.repMu.TryLock() {
		return
	}
	defer n.repMu.Unlock()
	if time.Since(n.cool[root]) < rebuildGap {
		return
	}
	n.cool[root] = time.Now()
	// jitter so that several guardians of the same root do not all rebuild
	select {
	case <-time.After(time.Duration(mrand.Intn(1500)) * time.Millisecond):
	case <-ctx.Done():
		return
	}
	still := false
	for _, leaf := range missing {
		anyHas := false
		for _, h := range n.holders(shardKey(root, leaf), n.cfg.Replication) {
			if has, _ := n.has(ctx, h, root, leaf); has {
				anyHas = true
			}
		}
		if !anyHas {
			still = true
			break
		}
	}
	if !still {
		return
	}
	pushed, err := n.rebuild(ctx, root, total)
	if err != nil {
		log.Printf("repair root=%x: %v", root[:4], err)
		return
	}
	n.rebuilds.Add(1)
	log.Printf("repair root=%x: %d lost shards seen, rebuilt from erasure code, restored %d copies", root[:4], len(missing), pushed)
}

// rebuild fetches any K shards, reconstructs all of them, verifies against the
// root and pushes every copy that a current holder lacks.
func (n *Node) rebuild(ctx context.Context, root Hash, total int) (int, error) {
	k := total / 2
	got, err := n.gather(ctx, root, total, k)
	if err != nil {
		return 0, err
	}
	enc, err := reedsolomon.New(k, k)
	if err != nil {
		return 0, err
	}
	if err := enc.Reconstruct(got); err != nil {
		return 0, err
	}
	leaves := make([]Hash, total)
	for i, s := range got {
		leaves[i] = leafHash(uint32(i), s)
	}
	levels := buildTree(leaves)
	if levels[len(levels)-1][0] != root {
		return 0, fmt.Errorf("reconstruction does not match root (bad encoding?)")
	}
	pushed := 0
	var mu = make(chan struct{}, 1)
	parallel(ctx, total, 32, func(i int) {
		var proof []Hash
		for _, h := range n.holders(shardKey(root, uint32(i)), n.cfg.Replication) {
			if has, known := n.has(ctx, h, root, uint32(i)); known && !has {
				if proof == nil {
					proof = proofFor(levels, i)
				}
				if n.push(ctx, h, root, uint32(i), uint32(total), got[i], proof) {
					mu <- struct{}{}
					pushed++
					<-mu
					n.pushed.Add(1)
				}
			}
		}
	})
	return pushed, nil
}
