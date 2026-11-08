package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"
)

const maxBody = 24 << 20

func (n *Node) status() map[string]any {
	ps := n.peerList()
	pl := make([]map[string]string, 0, len(ps))
	for _, p := range ps {
		pl = append(pl, map[string]string{"id": hex.EncodeToString(p.id[:4]), "addr": p.addr.String()})
	}
	n.smu.RLock()
	defer n.smu.RUnlock()
	return map[string]any{"id": hex.EncodeToString(n.id[:4]), "peers": len(ps), "peer_list": pl,
		"shards": len(n.store), "bytes": n.bytes, "replication": n.cfg.Replication, "loss": n.cfg.Loss}
}

func (n *Node) serveHTTP() error {
	mux := http.NewServeMux()
	wj := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { wj(w, 200, n.status()) })
	mux.HandleFunc("POST /put", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			wj(w, 413, map[string]string{"error": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		res, err := n.Put(ctx, body)
		if err != nil {
			wj(w, 502, map[string]any{"error": err.Error(), "result": res})
			return
		}
		wj(w, 200, res)
	})
	manifest := func(w http.ResponseWriter, r *http.Request) (Manifest, bool) {
		var mf Manifest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&mf); err != nil {
			wj(w, 400, map[string]string{"error": "bad manifest json"})
			return mf, false
		}
		return mf, true
	}
	mux.HandleFunc("POST /get", func(w http.ResponseWriter, r *http.Request) {
		mf, ok := manifest(w, r)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		b, err := n.Get(ctx, mf)
		if err != nil {
			wj(w, 502, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("content-type", "application/octet-stream")
		w.Write(b)
	})
	mux.HandleFunc("POST /audit", func(w http.ResponseWriter, r *http.Request) {
		mf, ok := manifest(w, r)
		if !ok {
			return
		}
		s, _ := strconv.Atoi(r.URL.Query().Get("samples"))
		if s <= 0 {
			s = 30
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		res, err := n.Audit(ctx, mf, s)
		if err != nil {
			wj(w, 400, map[string]string{"error": err.Error()})
			return
		}
		wj(w, 200, res)
	})
	return (&http.Server{Addr: n.cfg.HTTP, Handler: mux, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe()
}
