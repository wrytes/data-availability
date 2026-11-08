package main

import (
	"crypto/sha256"
	"encoding/binary"
)

// Binary Merkle tree over shards. Leaves are domain-separated and bound to
// their index, so a shard cannot be replayed at another position.
// An odd node at any level is paired with itself.

func leafHash(i uint32, data []byte) Hash {
	h := sha256.New()
	var b [5]byte
	binary.BigEndian.PutUint32(b[1:], i)
	h.Write(b[:])
	h.Write(data)
	var o Hash
	h.Sum(o[:0])
	return o
}

func nodeHash(l, r Hash) Hash {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l[:])
	h.Write(r[:])
	var o Hash
	h.Sum(o[:0])
	return o
}

func depth(n uint32) int {
	d := 0
	for m := n; m > 1; m = (m + 1) / 2 {
		d++
	}
	return d
}

func buildTree(leaves []Hash) [][]Hash {
	levels := [][]Hash{leaves}
	for cur := leaves; len(cur) > 1; {
		next := make([]Hash, (len(cur)+1)/2)
		for i := range next {
			l, r := cur[2*i], cur[2*i]
			if 2*i+1 < len(cur) {
				r = cur[2*i+1]
			}
			next[i] = nodeHash(l, r)
		}
		levels = append(levels, next)
		cur = next
	}
	return levels
}

func proofFor(levels [][]Hash, idx int) []Hash {
	var p []Hash
	for _, lv := range levels[:len(levels)-1] {
		s := idx ^ 1
		if s >= len(lv) {
			s = idx
		}
		p = append(p, lv[s])
		idx >>= 1
	}
	return p
}

func verifyShard(root Hash, idx, n uint32, data []byte, proof []Hash) bool {
	if idx >= n || len(proof) != depth(n) {
		return false
	}
	cur := leafHash(idx, data)
	for _, s := range proof {
		if idx&1 == 0 {
			cur = nodeHash(cur, s)
		} else {
			cur = nodeHash(s, cur)
		}
		idx >>= 1
	}
	return cur == root
}

func shardKey(root Hash, leaf uint32) Hash {
	h := sha256.New()
	h.Write(root[:])
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], leaf)
	h.Write(b[:])
	var o Hash
	h.Sum(o[:0])
	return o
}
