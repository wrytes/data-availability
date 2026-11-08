# da — trust-minimized data availability node (Go, UDP)

    scripts/demo.sh up       # build image, deploy stack (2 regions + bridges), wait for gossip
    scripts/demo.sh demo     # put -> get -> audit -> kill region-b -> get again
    docker service scale da_node-a=20
    scripts/demo.sh down

Client (run inside any node; bridge nodes see both regions):

    docker exec -i $(docker ps -qf name=da_bridge|head -1) da put < file     # -> JSON incl. manifest (holds the key!)
    docker exec -i <bridge> da get   '<manifest json>' > out
    docker exec -i <bridge> da audit '<manifest json>' 30
    docker exec -i <bridge> da status

## Pipeline
1. **Cascade encryption** (crypt.go): AES-256-GCM -> XChaCha20-Poly1305 -> ChaCha20-Poly1305. Each layer key is HKDF-derived
   with a different hash (SHA-256 / SHA3-256 / BLAKE2b) from a random per-file master secret that never leaves the manifest.
2. **One Reed-Solomon codeword per file**, rate 1/2 (K data + K parity, 640 B shards): *any* 50% of shards recover the file.
3. **Merkle root** over shards is the commitment; every shard travels with its proof and is verified by storer and fetcher.
4. **Placement**: shard key = H(root, index); the `REPLICATION` closest nodes by XOR distance hold it.
5. **UDP** request/response with retries; peers discovered via swarm DNS (`tasks.<svc>`) + gossip, and only admitted after answering directly.
6. **Audit** = data availability sampling: s random shards verified against the root; if >50% were withheld each sample fails w.p. >= 1/2, so s clean samples bound that by 2^-s.

`LOSS=0.2` env drops 20% of inbound datagrams to watch the probabilistic retrieval cope.

## Findings / insights
- **Layers**: stacking ciphers is cheap here (AEAD, ~40 B overhead per layer) and protects against a break of one primitive,
  but only if keys are independent (they are). It does *not* add security against a key leak, nor hide size.
- **Per-stripe RS breaks sampling.** First instinct is to encode every 10 KB stripe separately; then an adversary hides 11/20
  shards of ONE stripe (0.2% of the file) and random sampling almost never notices. A single file-wide codeword (GF(2^16)
  Leopard, up to 65 536 shards ≈ 21 MB) makes the 50% threshold global. Larger files need 2D coding (as in danksharding/Celestia).
- **Merkle vs KZG**: Merkle proofs cost log2(n)·32 B per shard (≤ 512 B) which fits a UDP datagram, but they cannot prove the
  encoding itself is valid; a malicious *uploader* can commit garbage parity. KZG/FRI (or fraud proofs) would close that.
- **UDP**: datagrams are capped at 1400 B (overlay MTU 1450). Loss is tolerable *because* only K of 2K shards are needed, so retrieval
  needs retries only on the holder level, not reliable transport.

## Known gaps (prototype)
- Storage is in-memory; no repair/re-replication when holders die; no stake/slashing or proof-of-storage challenges (audit is a sampler, not an incentive).
- Node IDs are free (Sybil), packets are unauthenticated (spoofable source), the HTTP API has no auth, so keep it unpublished.
- Placement uses each node's own peer view; views differ slightly, so fetches probe `REPLICATION+3` closest nodes.
