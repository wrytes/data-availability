package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	shardSize = 640 // multiple of 64 (GF16 codec); keeps datagrams < MTU with a depth-16 proof
	maxLeaves = 65536
)

// Manifest is the retrieval capability: it names the commitment and holds the
// secret. Whoever holds it can fetch and decrypt; nodes never see the key.
type Manifest struct {
	V      int      `json:"v"`
	Root   string   `json:"root"`
	K      int      `json:"k"` // data shards
	M      int      `json:"m"` // parity shards (any K of K+M recover)
	Shard  int      `json:"shard"`
	CtLen  int      `json:"ctlen"`
	Key    string   `json:"key"`
	Layers []string `json:"layers"`
}

type PutResult struct {
	Manifest  Manifest `json:"manifest"`
	Shards    int      `json:"shards"`
	Acked     int      `json:"shards_acked"`
	Replicas  int      `json:"replica_acks"`
	PlainSize int      `json:"plain_size"`
	Stored    int      `json:"stored_bytes_network"`
}

func parallel(ctx context.Context, n, workers int, f func(i int)) {
	ch := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				f(i)
			}
		}()
	}
loop:
	for i := 0; i < n; i++ {
		select {
		case ch <- i:
		case <-ctx.Done():
			break loop
		}
	}
	close(ch)
	wg.Wait()
}

func (n *Node) Put(ctx context.Context, pt []byte) (*PutResult, error) {
	master := make([]byte, 32)
	rand.Read(master)
	ct, err := seal(master, pt)
	if err != nil {
		return nil, err
	}
	k := (len(ct) + shardSize - 1) / shardSize
	if k < 2 {
		k = 2
	}
	if 2*k > maxLeaves {
		return nil, fmt.Errorf("too large: max ~%d bytes", (maxLeaves/2)*shardSize)
	}
	total := 2 * k
	shards := make([][]byte, total)
	padded := make([]byte, k*shardSize)
	copy(padded, ct)
	for i := 0; i < k; i++ {
		shards[i] = padded[i*shardSize : (i+1)*shardSize]
	}
	for i := k; i < total; i++ {
		shards[i] = make([]byte, shardSize)
	}
	enc, err := reedsolomon.New(k, k)
	if err != nil {
		return nil, err
	}
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	leaves := make([]Hash, total)
	for i, s := range shards {
		leaves[i] = leafHash(uint32(i), s)
	}
	levels := buildTree(leaves)
	root := levels[len(levels)-1][0]

	var acked, replicas int64
	acks := make([]int32, total)
	parallel(ctx, total, 64, func(i int) {
		proof := proofFor(levels, i)
		for _, h := range n.holders(shardKey(root, uint32(i)), n.cfg.Replication) {
			ok := false
			if h.self {
				ok = n.putLocal(root, uint32(i), uint32(total), shards[i], proof, false) == 0
			} else if m, err := n.call(ctx, h.addr, tStore, encStore(root, uint32(i), uint32(total), shards[i], proof), 500*time.Millisecond, 4); err == nil {
				ok = len(m.body) > 0 && m.body[0] == 0
			}
			if ok {
				atomic.AddInt32(&acks[i], 1)
				atomic.AddInt64(&replicas, 1)
			}
		}
		if acks[i] > 0 {
			atomic.AddInt64(&acked, 1)
		}
	})
	res := &PutResult{
		Manifest: Manifest{V: 1, Root: hex.EncodeToString(root[:]), K: k, M: k, Shard: shardSize, CtLen: len(ct),
			Key: hex.EncodeToString(master), Layers: layerNames()},
		Shards: total, Acked: int(acked), Replicas: int(replicas), PlainSize: len(pt), Stored: int(replicas) * shardSize,
	}
	if int(acked) < k+(total-k)/2 { // not enough margin to be useful
		return res, fmt.Errorf("only %d/%d shards acknowledged (need >= %d)", acked, total, k+(total-k)/2)
	}
	return res, nil
}

// fetchShard asks the closest holders (replication + spares) until one returns
// a shard that verifies against the commitment.
func (n *Node) fetchShard(ctx context.Context, root Hash, total, i int) ([]byte, bool) {
	key := shardKey(root, uint32(i))
	for _, h := range n.holders(key, n.cfg.Replication+3) {
		if ctx.Err() != nil {
			return nil, false
		}
		if h.self {
			n.smu.RLock()
			s, ok := n.store[key]
			n.smu.RUnlock()
			if ok {
				return s.data, true
			}
			continue
		}
		m, err := n.call(ctx, h.addr, tGet, encGet(root, uint32(i)), 400*time.Millisecond, 2)
		if err != nil || len(m.body) == 0 || m.body[0] != 0 {
			continue
		}
		r := &rd{b: m.body[1:]}
		cnt := r.u32()
		data := r.take(int(r.u16()))
		proof := r.proof()
		if !r.bad && int(cnt) == total && verifyShard(root, uint32(i), cnt, data, proof) {
			return data, true
		}
	}
	return nil, false
}

func parseRoot(mf Manifest) (Hash, error) {
	var root Hash
	b, err := hex.DecodeString(mf.Root)
	if err != nil || len(b) != 32 || mf.K < 2 || mf.M != mf.K || mf.Shard != shardSize {
		return root, errors.New("bad manifest")
	}
	copy(root[:], b)
	return root, nil
}

func (n *Node) Get(ctx context.Context, mf Manifest) ([]byte, error) {
	root, err := parseRoot(mf)
	if err != nil {
		return nil, err
	}
	master, err := hex.DecodeString(mf.Key)
	if err != nil {
		return nil, err
	}
	total := mf.K + mf.M
	got := make([][]byte, total)
	var have int32
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	order := mrand.Perm(total)
	parallel(cctx, total, 48, func(j int) {
		if cctx.Err() != nil {
			return
		}
		i := order[j]
		if d, ok := n.fetchShard(cctx, root, total, i); ok {
			got[i] = d
			if int(atomic.AddInt32(&have, 1)) >= mf.K {
				cancel() // probabilistic: any K of 2K is enough
			}
		}
	})
	if int(have) < mf.K {
		return nil, fmt.Errorf("unavailable: only %d/%d shards retrievable (need %d)", have, total, mf.K)
	}
	enc, err := reedsolomon.New(mf.K, mf.M)
	if err != nil {
		return nil, err
	}
	if err := enc.ReconstructData(got); err != nil {
		return nil, err
	}
	ct := make([]byte, 0, mf.K*mf.Shard)
	for i := 0; i < mf.K; i++ {
		ct = append(ct, got[i]...)
	}
	if mf.CtLen > len(ct) {
		return nil, errors.New("bad manifest length")
	}
	return open(master, ct[:mf.CtLen])
}

type AuditResult struct {
	Samples     int     `json:"samples"`
	Available   int     `json:"available"`
	Fraction    float64 `json:"fraction_available"`
	Recoverable bool    `json:"recoverable_by_sampling"`
	FalseAccept float64 `json:"p_unrecoverable_given_all_samples_ok"`
	Needed      int     `json:"shards_needed"`
	TotalShards int     `json:"shards_total"`
}

// Audit is data-availability sampling: fetch s random shards and verify each
// against the Merkle root. Data is unrecoverable only if >50% of shards are
// withheld, so s clean samples bound that probability by 2^-s.
func (n *Node) Audit(ctx context.Context, mf Manifest, s int) (*AuditResult, error) {
	root, err := parseRoot(mf)
	if err != nil {
		return nil, err
	}
	total := mf.K + mf.M
	if s > total {
		s = total
	}
	idx := mrand.Perm(total)[:s]
	var ok int32
	parallel(ctx, s, 32, func(j int) {
		if _, good := n.fetchShard(ctx, root, total, idx[j]); good {
			atomic.AddInt32(&ok, 1)
		}
	})
	frac := float64(ok) / float64(s)
	r := &AuditResult{Samples: s, Available: int(ok), Fraction: frac, Needed: mf.K, TotalShards: total}
	r.Recoverable = frac > 0.5
	if int(ok) == s {
		r.FalseAccept = math.Pow(0.5, float64(s))
	} else {
		r.FalseAccept = 1
	}
	return r, nil
}
