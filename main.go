// da: a tiny trust-minimized data availability node.
//
//	da node                      run a node (UDP shard transport + local HTTP API)
//	da put   < file              encrypt, erasure-code, commit, distribute; prints result JSON
//	da get   '<manifest json>'   fetch >=50% of shards, verify, decode, decrypt -> stdout
//	da audit '<manifest json>' [samples]   data availability sampling
//	da status                    node / peer info
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	cmd := "node"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd == "node" {
		port, _ := strconv.Atoi(env("PORT", "7000"))
		rep, _ := strconv.Atoi(env("REPLICATION", "2"))
		mb, _ := strconv.ParseInt(env("MAX_BYTES", "268435456"), 10, 64)
		loss, _ := strconv.ParseFloat(env("LOSS", "0"), 64)
		n, err := NewNode(Config{Port: port, HTTP: env("HTTP", ":8080"), Discover: parseDiscover(env("DISCOVER", "")),
			Replication: rep, MaxBytes: mb, Loss: loss})
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("node %x udp :%d http %s discover=%v", n.id[:4], port, n.cfg.HTTP, n.cfg.Discover)
		log.Fatal(n.serveHTTP())
	}
	base := env("API", "http://127.0.0.1:8080")
	var resp *http.Response
	var err error
	switch cmd {
	case "status":
		resp, err = http.Get(base + "/status")
	case "put":
		resp, err = http.Post(base+"/put", "application/octet-stream", os.Stdin)
	case "get", "audit":
		if len(os.Args) < 3 {
			log.Fatal("manifest json required")
		}
		var mf Manifest
		raw := []byte(os.Args[2])
		if json.Unmarshal(raw, &mf) != nil { // allow {"manifest":{...}} (full put result) too
			log.Fatal("bad manifest json")
		}
		if mf.Root == "" {
			var pr PutResult
			json.Unmarshal(raw, &pr)
			raw, _ = json.Marshal(pr.Manifest)
		}
		u := base + "/" + cmd
		if cmd == "audit" && len(os.Args) > 3 {
			u += "?samples=" + os.Args[3]
		}
		resp, err = http.Post(u, "application/json", bytes.NewReader(raw))
	default:
		fmt.Fprintln(os.Stderr, "usage: da node|put|get|audit|status")
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
	if resp.StatusCode >= 300 {
		os.Exit(1)
	}
}
