# da — trust-minimized data availability node (Go, UDP)

    scripts/demo.sh up       # build image, deploy stack (2 regions + bridges), wait for gossip
    scripts/demo.sh demo     # put -> get -> audit
    scripts/demo.sh big      # 40 MB file = 3 segments
    scripts/demo.sh repair   # kill region B, watch copies get rebuilt, then drop more nodes
    scripts/demo.sh persist  # restart every node, data comes back from disk
    docker service scale da_node-a=20
    scripts/demo.sh down

Client (run inside any node; bridge nodes see both regions):

    docker exec -i $(docker ps -qf name=da_bridge|head -1) da put < file     # -> JSON incl. manifest (holds the key!)
    docker exec -i <bridge> da get   '<manifest json>' > out      # or `-` to read the manifest from stdin
    docker exec -i <bridge> da audit - 30 < manifest.json         # 30 samples per segment
    docker exec -i <bridge> da status

## Pipeline
1. **Cascade encryption** (crypt.go): AES-256-GCM -> XChaCha20-Poly1305 -> ChaCha20-Poly1305. Each layer key is HKDF-derived
   with a different hash (SHA-256 / SHA3-256 / BLAKE2b) from a random per-file master secret that never leaves the manifest.
2. **Segments**: the file streams through in 16 MiB segments (no size limit; memory is bounded by one segment). Each segment is one
   Reed-Solomon codeword, rate 1/2 (K data + K parity, 640 B shards): *any* 50% of its shards recover it. A segment's ciphertext is
   bound to its index (AEAD associated data), so segments cannot be reordered.
3. **Merkle root** per segment is the commitment; the manifest lists the roots. Every shard travels with its proof and is verified by storer and fetcher.
4. **Placement**: shard key = H(root, index); the `REPLICATION` closest nodes by XOR distance hold it.
5. **UDP** request/response with retries; peers discovered via swarm DNS (`tasks.<svc>`) + gossip, and only admitted after answering directly.
6. **Audit** = data availability sampling: per segment, s random shards verified against its root; if >50% were withheld each sample fails w.p. >= 1/2, so s clean samples bound that by 2^-s (times the number of segments for the whole file).
7. **Persistence**: with `DATA_DIR` set, each shard is a file (temp file + rename), the node ID is stored too, and everything is reloaded and re-verified on start. Corrupt files are dropped and repaired like any other loss.
8. **Repair** (every `REPAIR_INTERVAL` s, on every node, using only what it holds):
   - *re-replication / rebalancing*: for shards it holds it asks the current closest holders (`HAS`) and pushes the shard to any that lack it.
   - *erasure rebuild*: for sampled leaves of a root it holds, if no holder has the shard at all, it fetches any K shards, Reed-Solomon reconstructs all of them, checks the result against the Merkle root, and pushes every missing copy. K = total/2 is implied by the fixed rate, and no key is needed because shards are ciphertext.

`LOSS=0.2` env drops 20% of inbound datagrams to watch the probabilistic retrieval cope.

## Findings / insights
- **Layers**: stacking ciphers is cheap here (AEAD, ~40 B overhead per layer) and protects against a break of one primitive,
  but only if keys are independent (they are). It does *not* add security against a key leak, nor hide size.
- **Small stripes break sampling; big segments fix it, but not for free.** Encoding every 10 KB stripe separately lets an adversary hide
  11/20 shards of ONE stripe (0.2% of the file) and random sampling almost never notices. One codeword per segment (GF(2^16)
  Leopard, up to 65 536 shards ≈ 21 MB) makes the 50% threshold global *within* a segment. Files are split into segments, so an audit now
  has to sample every segment (cost grows with file size). Coding across segments (2D, as in danksharding/Celestia) would let a fixed
  number of samples cover the whole file; that is the next step.
- **Compression** does not help here: ciphertext is incompressible, and compress-then-encrypt leaks size patterns. If wanted, do it before `put`.
- **Merkle vs KZG**: Merkle proofs cost log2(n)·32 B per shard (≤ 512 B) which fits a UDP datagram, but they cannot prove the
  encoding itself is valid; a malicious *uploader* can commit garbage parity. KZG/FRI (or fraud proofs) would close that.
- **UDP**: datagrams are capped at 1400 B (overlay MTU 1450). Loss is tolerable *because* only K of 2K shards are needed, so retrieval
  needs retries only on the holder level, not reliable transport.

## Known gaps (prototype)
- No garbage collection: after nodes return or the network rebalances, surplus copies stay on disk (the repair demo shows copies > 2x after a full restart).
- Repair is uncoordinated: guardians of a root use jitter + a cooldown instead of leader election, and detection is by sampling, so tiny losses may take several sweeps. A rebuild needs K shards reachable at once; if fewer survive, the data is gone.
- Shards are not fsynced (a power cut can lose the newest ones; repair then restores them if copies exist elsewhere), and there is one file per shard.
- No stake/slashing or proof-of-storage challenges (audit is a sampler, not an incentive).
- Node IDs are free (Sybil), packets are unauthenticated (spoofable source), the HTTP API has no auth, so keep it unpublished.
- Placement uses each node's own peer view; views differ slightly, so fetches probe `REPLICATION+3` closest nodes.
