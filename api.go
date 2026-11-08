package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type lazyWriter struct {
	w       http.ResponseWriter
	started bool
}

func (l *lazyWriter) Write(b []byte) (int, error) { l.started = true; return l.w.Write(b) }

const maxFile = int64(8) << 30 // sanity cap per upload; storage is bounded by node capacity

func (n *Node) status() map[string]any {
	ps := n.peerList()
	pl := make([]map[string]string, 0, len(ps))
	for _, p := range ps {
		pl = append(pl, map[string]string{"id": hex.EncodeToString(p.id[:4]), "addr": p.addr.String()})
	}
	shards, bytes := n.store.stats()
	roots := map[string]int{}
	for r, ri := range n.store.roots() {
		roots[hex.EncodeToString(r[:4])] = len(ri.leaves)
	}
	return map[string]any{"id": hex.EncodeToString(n.id[:4]), "peers": len(ps), "peer_list": pl,
		"shards": shards, "bytes": bytes, "replication": n.cfg.Replication, "loss": n.cfg.Loss,
		"persistent": n.cfg.DataDir != "", "hidden": n.cfg.Hidden, "sid": n.hexSid(), "onion": n.cfg.Onion, "onion_relayed": n.relayed.Load(), "onion_delivered": n.delivered.Load(), "onion_dropped": n.dropped.Load(), "get_direct": n.getDirect.Load(), "get_onion": n.getOnion.Load(), "roots": roots, "repair_pushed": n.pushed.Load(), "repair_rebuilds": n.rebuilds.Load()}
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
		var hid []Hash
		for _, s := range strings.Split(r.URL.Query().Get("hidden"), ",") {
			if b, err := hex.DecodeString(strings.TrimSpace(s)); err == nil && len(b) == 32 {
				var h Hash
				copy(h[:], b)
				hid = append(hid, h)
			}
		}
		res, err := n.PutReaderHidden(r.Context(), http.MaxBytesReader(w, r.Body, maxFile), hid)
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
		w.Header().Set("content-type", "application/octet-stream")
		sw := &lazyWriter{w: w}
		ctx := r.Context()
		if r.URL.Query().Get("via") == "hidden" {
			ctx = hiddenOnly(ctx)
		}
		if err := n.GetTo(ctx, mf, sw); err != nil {
			if !sw.started { // nothing sent yet: report properly
				w.Header().Set("content-type", "application/json")
				wj(w, 502, map[string]string{"error": err.Error()})
				return
			}
			panic(http.ErrAbortHandler) // mid-stream failure: cut the connection so the client sees an error
		}
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
		res, err := n.Audit(r.Context(), mf, s)
		if err != nil {
			wj(w, 400, map[string]string{"error": err.Error()})
			return
		}
		wj(w, 200, res)
	})
	return (&http.Server{Addr: n.cfg.HTTP, Handler: mux, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe()
}
