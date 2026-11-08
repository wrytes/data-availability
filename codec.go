package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	shardSize = 256 // multiple of 64 (GF16 codec); a STORE plus a reply block must fit one onion packet
	maxLeaves = 65536
)

// segSize is the plaintext size of one segment. Each segment is its own
// Reed-Solomon codeword with its own Merkle root, which lifts the 65 536-shard
// limit of a single codeword: files of any size are streamed segment by segment.
// 8 MiB minus 64 KiB (+96 B of cipher overhead) is ~65 000 shards at 256 B, just under the limit.
var segSize = 8<<20 - 64<<10

// Seg is one independently coded and committed piece of the file.
type Seg struct {
	Root  string `json:"root"`
	K     int    `json:"k"` // data shards; K parity shards follow (any K of 2K recover)
	CtLen int    `json:"ctlen"`
}

// Manifest is the retrieval capability: it names the commitments and holds the
// secret. Whoever holds it can fetch and decrypt; nodes never see the key.
type Manifest struct {
	V        int      `json:"v"`
	Key      string   `json:"key"`
	Layers   []string `json:"layers"`
	Shard    int      `json:"shard"`
	PlainLen int64    `json:"plainlen"`
	Segs     []Seg    `json:"segs"`
}

type PutResult struct {
	Manifest  Manifest `json:"manifest"`
	Segments  int      `json:"segments"`
	Shards    int      `json:"shards"`
	Acked     int      `json:"shards_acked"`
	Replicas  int      `json:"replica_acks"`
	PlainSize int64    `json:"plain_size"`
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
	return n.PutReader(ctx, bytes.NewReader(pt))
}

// PutReader streams r in segSize pieces; memory use is bounded by one segment.
func (n *Node) PutReader(ctx context.Context, r io.Reader) (*PutResult, error) {
	master := make([]byte, 32)
	rand.Read(master)
	res := &PutResult{Manifest: Manifest{V: 2, Key: hex.EncodeToString(master), Layers: layerNames(), Shard: shardSize}}
	buf := make([]byte, segSize)
	for idx := uint32(0); ; idx++ {
		l, err := io.ReadFull(r, buf)
		last := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !last {
			return res, err
		}
		if l == 0 && idx > 0 { // file size was an exact multiple of segSize
			break
		}
		sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		seg, st, perr := n.putSegment(sctx, master, idx, buf[:l])
		cancel()
		res.Shards += st.shards
		res.Acked += st.acked
		res.Replicas += st.replicas
		res.Stored += st.replicas * shardSize
		if perr != nil {
			return res, fmt.Errorf("segment %d: %w", idx, perr)
		}
		res.Manifest.Segs = append(res.Manifest.Segs, seg)
		res.PlainSize += int64(l)
		if last {
			break
		}
	}
	res.Manifest.PlainLen = res.PlainSize
	res.Segments = len(res.Manifest.Segs)
	return res, nil
}

type putStats struct{ shards, acked, replicas int }

func (n *Node) putSegment(ctx context.Context, master []byte, idx uint32, pt []byte) (Seg, putStats, error) {
	var st putStats
	ct, err := seal(master, pt, idx)
	if err != nil {
		return Seg{}, st, err
	}
	k := (len(ct) + shardSize - 1) / shardSize
	if k < 2 {
		k = 2
	}
	if 2*k > maxLeaves {
		return Seg{}, st, errors.New("segment too large")
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
		return Seg{}, st, err
	}
	if err := enc.Encode(shards); err != nil {
		return Seg{}, st, err
	}
	leaves := make([]Hash, total)
	for i, s := range shards {
		leaves[i] = leafHash(uint32(i), s)
	}
	levels := buildTree(leaves)
	root := levels[len(levels)-1][0]

	var acked, replicas int64
	parallel(ctx, total, 64, func(i int) {
		proof := proofFor(levels, i)
		got := false
		for _, h := range n.holders(shardKey(root, uint32(i)), n.cfg.Replication) {
			ok := false
			if h.self {
				ok = n.putLocal(root, uint32(i), uint32(total), shards[i], proof, false) == 0
			} else if m, err := n.rpc(ctx, h, tStore, encStore(root, uint32(i), uint32(total), shards[i], proof), 500*time.Millisecond, 4); err == nil {
				ok = len(m.body) > 0 && m.body[0] == 0
			}
			if ok {
				got = true
				atomic.AddInt64(&replicas, 1)
			}
		}
		if got {
			atomic.AddInt64(&acked, 1)
		}
	})
	st = putStats{total, int(acked), int(replicas)}
	seg := Seg{Root: hex.EncodeToString(root[:]), K: k, CtLen: len(ct)}
	if need := k + (total-k)/2; int(acked) < need { // not enough margin to be useful
		return seg, st, fmt.Errorf("only %d/%d shards acknowledged (need >= %d)", acked, total, need)
	}
	return seg, st, nil
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
			if s, ok := n.store.get(root, uint32(i)); ok {
				return s.data, true
			}
			continue
		}
		m, err := n.rpc(ctx, h, tGet, encGet(root, uint32(i)), 400*time.Millisecond, 2)
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

// gather fetches random shards until k verified ones are in hand (any K of 2K
// is enough, which is what makes loss on the way harmless).
func (n *Node) gather(ctx context.Context, root Hash, total, k int) ([][]byte, error) {
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
			if int(atomic.AddInt32(&have, 1)) >= k {
				cancel()
			}
		}
	})
	if int(have) < k {
		return nil, fmt.Errorf("unavailable: only %d/%d shards retrievable (need %d)", have, total, k)
	}
	return got, nil
}

func (mf Manifest) check() ([]Hash, error) {
	if mf.V != 2 || mf.Shard != shardSize || len(mf.Segs) == 0 {
		return nil, errors.New("bad manifest")
	}
	roots := make([]Hash, len(mf.Segs))
	for i, s := range mf.Segs {
		b, err := hex.DecodeString(s.Root)
		if err != nil || len(b) != 32 || s.K < 2 || 2*s.K > maxLeaves || s.CtLen < 0 || s.CtLen > s.K*shardSize {
			return nil, fmt.Errorf("bad manifest: segment %d", i)
		}
		copy(roots[i][:], b)
	}
	return roots, nil
}

// GetTo streams the file to w one segment at a time.
func (n *Node) GetTo(ctx context.Context, mf Manifest, w io.Writer) error {
	roots, err := mf.check()
	if err != nil {
		return err
	}
	master, err := hex.DecodeString(mf.Key)
	if err != nil {
		return err
	}
	var written int64
	for i, sg := range mf.Segs {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		pt, err := n.getSegment(sctx, master, uint32(i), roots[i], sg)
		cancel()
		if err != nil {
			return fmt.Errorf("segment %d/%d: %w", i+1, len(mf.Segs), err)
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
		written += int64(len(pt))
	}
	if written != mf.PlainLen {
		return errors.New("length mismatch: manifest does not match data")
	}
	return nil
}

func (n *Node) getSegment(ctx context.Context, master []byte, idx uint32, root Hash, sg Seg) ([]byte, error) {
	got, err := n.gather(ctx, root, 2*sg.K, sg.K)
	if err != nil {
		return nil, err
	}
	enc, err := reedsolomon.New(sg.K, sg.K)
	if err != nil {
		return nil, err
	}
	if err := enc.ReconstructData(got); err != nil {
		return nil, err
	}
	ct := make([]byte, 0, sg.K*shardSize)
	for i := 0; i < sg.K; i++ {
		ct = append(ct, got[i]...)
	}
	return open(master, ct[:sg.CtLen], idx)
}

func (n *Node) Get(ctx context.Context, mf Manifest) ([]byte, error) {
	var b bytes.Buffer
	if err := n.GetTo(ctx, mf, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type AuditResult struct {
	Segments    int     `json:"segments"`
	Samples     int     `json:"samples"`
	Available   int     `json:"available"`
	Fraction    float64 `json:"fraction_available"` // worst segment
	Recoverable bool    `json:"recoverable_by_sampling"`
	FalseAccept float64 `json:"p_unrecoverable_given_all_samples_ok"`
	Needed      int     `json:"shards_needed"`
	TotalShards int     `json:"shards_total"`
}

// Audit is data availability sampling: per segment, fetch s random shards and
// verify each against that segment's Merkle root. A segment is unrecoverable
// only if >50% of its shards are withheld, so s clean samples bound that by
// 2^-s; a union bound over all segments gives the figure for the whole file.
// (Independent segments mean every segment must be sampled; coding across
// segments, 2D, would let far fewer samples cover the whole file.)
func (n *Node) Audit(ctx context.Context, mf Manifest, s int) (*AuditResult, error) {
	roots, err := mf.check()
	if err != nil {
		return nil, err
	}
	r := &AuditResult{Segments: len(mf.Segs), Fraction: 1, Recoverable: true}
	allClean := true
	for si, sg := range mf.Segs {
		total := 2 * sg.K
		ss := s
		if ss > total {
			ss = total
		}
		sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		idx := mrand.Perm(total)[:ss]
		var ok int32
		parallel(sctx, ss, 32, func(j int) {
			if _, good := n.fetchShard(sctx, roots[si], total, idx[j]); good {
				atomic.AddInt32(&ok, 1)
			}
		})
		cancel()
		frac := float64(ok) / float64(ss)
		r.Samples += ss
		r.Available += int(ok)
		r.Needed += sg.K
		r.TotalShards += total
		r.Fraction = math.Min(r.Fraction, frac)
		if frac <= 0.5 {
			r.Recoverable = false
		}
		if int(ok) != ss {
			allClean = false
		}
	}
	r.FalseAccept = 1
	if allClean {
		per := s
		r.FalseAccept = math.Min(1, float64(len(mf.Segs))*math.Pow(0.5, float64(per)))
	}
	return r, nil
}
