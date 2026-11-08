package main

import (
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type stored struct {
	n     uint32
	data  []byte
	proof []Hash
}

type meta struct {
	root Hash
	leaf uint32
	n    uint32
	size int
	at   time.Time // when this node stored it (load time after a restart)
}

// shardStore keeps shards on disk (one file per shard, written to a temp file
// and renamed, so a crash never leaves a half-written shard) with an in-memory
// index. With dir == "" it is purely in-memory.
type shardStore struct {
	dir   string
	mu    sync.RWMutex
	idx   map[Hash]meta
	mem   map[Hash]stored
	bytes int64
}

func decodeStore(b []byte) (root Hash, leaf, n uint32, data []byte, proof []Hash, ok bool) {
	r := &rd{b: b}
	root, leaf, n = r.hash(), r.u32(), r.u32()
	data = r.take(int(r.u16()))
	proof = r.proof()
	return root, leaf, n, data, proof, !r.bad
}

func openStore(dir string) (*shardStore, error) {
	s := &shardStore{dir: dir, idx: map[Hash]meta{}, mem: map[Hash]stored{}}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".tmp") { // interrupted write
			os.Remove(p)
			return nil
		}
		if !strings.HasSuffix(p, ".shard") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		root, leaf, cnt, data, proof, ok := decodeStore(b)
		k := shardKey(root, leaf)
		if !ok || !verifyShard(root, leaf, cnt, data, proof) || p != s.path(k) {
			os.Remove(p) // corrupt or misplaced: drop, repair will restore it
			return nil
		}
		s.idx[k] = meta{root, leaf, cnt, len(data), time.Now()}
		s.bytes += int64(len(data))
		return nil
	})
	return s, err
}

func (s *shardStore) path(k Hash) string {
	h := hex.EncodeToString(k[:])
	return filepath.Join(s.dir, h[:2], h+".shard")
}

// put returns 0 ok, 2 full, 3 io error. The caller has verified the proof.
func (s *shardStore) put(root Hash, leaf, cnt uint32, data []byte, proof []Hash, max int64) byte {
	k := shardKey(root, leaf)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.idx[k]; ok {
		return 0
	}
	if s.bytes+int64(len(data)) > max {
		return 2
	}
	if s.dir == "" {
		s.mem[k] = stored{cnt, data, proof}
	} else {
		p := s.path(k)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return 3
		}
		if err := os.WriteFile(p+".tmp", encStore(root, leaf, cnt, data, proof), 0o644); err != nil {
			return 3
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			return 3
		}
	}
	s.idx[k] = meta{root, leaf, cnt, len(data), time.Now()}
	s.bytes += int64(len(data))
	return 0
}

func (s *shardStore) has(root Hash, leaf uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.idx[shardKey(root, leaf)]
	return ok
}

func (s *shardStore) get(root Hash, leaf uint32) (stored, bool) {
	k := shardKey(root, leaf)
	s.mu.RLock()
	_, ok := s.idx[k]
	m, inMem := s.mem[k]
	s.mu.RUnlock()
	if !ok {
		return stored{}, false
	}
	if inMem || s.dir == "" {
		return m, true
	}
	b, err := os.ReadFile(s.path(k))
	if err != nil {
		return stored{}, false
	}
	_, _, cnt, data, proof, good := decodeStore(b)
	if !good {
		return stored{}, false
	}
	return stored{cnt, data, proof}, true
}

func (s *shardStore) stats() (shards int, bytes int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.idx), s.bytes
}

type rootInfo struct {
	n      uint32
	leaves []uint32
	newest time.Time
}

func (s *shardStore) roots() map[Hash]*rootInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[Hash]*rootInfo{}
	for _, m := range s.idx {
		ri := out[m.root]
		if ri == nil {
			ri = &rootInfo{n: m.n}
			out[m.root] = ri
		}
		ri.leaves = append(ri.leaves, m.leaf)
		if m.at.After(ri.newest) {
			ri.newest = m.at
		}
	}
	return out
}
