# da — trust-minimized data availability node (Go, UDP)

    scripts/demo.sh up       # build image, deploy stack (2 regions + bridges), wait for gossip
    scripts/demo.sh demo     # put -> get -> audit
    scripts/demo.sh big      # 40 MB file = 5 segments
    scripts/demo.sh repair   # kill region B, watch copies get rebuilt, then drop more nodes
    scripts/demo.sh persist  # restart every node, data comes back from disk
    scripts/demo.sh onion    # same traffic over onion routes: holders never see the requester
    scripts/demo.sh hidden   # store on, and read back from, a holder nobody can see
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
2. **Segments**: the file streams through in ~8 MiB segments (no size limit; memory is bounded by one segment). Each segment is one
   Reed-Solomon codeword, rate 1/2 (K data + K parity, 256 B shards): *any* 50% of its shards recover it. A segment's ciphertext is
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

## Onion routing (`ONION=1`)
Client requests (`STORE` and `GET` for put/get/audit/rebuild) can travel over a fresh random route per attempt: two relays, then the holder.

- **Packets** (`onion.go`): Sphinx-style, exactly one max-size datagram at every hop whatever they carry. Per hop an ephemeral X25519 key,
  layered routing info with a precomputed filler so the MAC still verifies after each peel, and a LIONESS wide-block cipher on the payload so
  a modified byte turns the whole payload to noise. Consecutive packets of one route share no bytes.
- **Replies** use single-use reply blocks (SURBs) the requester ships inside the request. The holder answers into the block; it never learns who or where.
- **Who sees what:** relay 1 sees the requester's address but only an opaque packet; relay 2 sees neither end; the holder sees the request and a relay.
  The unit test asserts that no holder ever observes the requester as the source of a served request.
- **Paths** are drawn from the reachability graph nodes gossip (each peer reports its own peers' keys and the addresses *it* uses), so consecutive hops can really
  talk, which matters across the two overlay regions. Node ids are `H(onion public key)`, so a key cannot be claimed for another id.
- **Timing:** relays add a random delay (`ONION_DELAY_MS`), and `COVER_RATE` sends dummy packets. Replays are rejected by a tag cache.
- **Shard size is 256 B** because a STORE (shard + a depth-16 Merkle proof) and a reply block must fit in one packet.
- Not hidden: the requester from its *first* relay, and traffic volume from an observer of the whole network (needs real mixing and a lot of cover traffic). No forward secrecy:
  relay keys are long-lived. Repair traffic between nodes stays direct.

## Hidden holders (`HIDDEN=1`)
A hidden node stores shards that only people holding its service id can reach. It is built from the same onion packets, in the style of Tor hidden services:

1. The node has a service identity (Ed25519 + an X25519 key, unrelated to its relay key) and talks only to its guards (`DISCOVER`). It pings them with a *private* flag, so they answer
   but never list or gossip it. It ignores direct requests and pings.
2. It picks 3 **introduction points** among its guards and keeps a stock of single-use reply blocks (leading back to it) at each. It publishes a signed **descriptor**
   {keys, introduction points} to the directory nodes closest to its service id, over onion routes.
3. A client fetches the descriptor, gives a **rendezvous point** one of its own reply blocks under a random cookie, and sends an end-to-end encrypted `INTRODUCE`
   {rendezvous point, cookie, request} to an introduction point, which pushes it into one of the node's reply blocks.
4. The node decrypts, serves the request, and sends the encrypted answer to the rendezvous point, which pushes it into the client's reply block.

The introduction point knows neither side's address; the rendezvous point knows neither side and cannot read the answer; directories only hold a signed blob.
`da put <service id>` stores every shard there too (listed in the manifest), `da get - hidden < manifest.json` reads from hidden holders only.
Limits: hidden replicas are not repaired, a client can only use introduction points it has as direct peers, directories are found by "closest in my view" (clients also try other peers),
and one request costs about three onion round trips, so this suits modest data volumes.

## Attached nodes behind NAT (`ATTACHED=1`)

A node with no reachable port dials out to a few public guards (`GUARDS`, default 3) and never appears in peer tables or gossip.
- Each PING to a guard carries a 6-byte link id (`sha256(linkSecret||guardAddr)[:6]`); the guard maps id -> current source address.
- Keepalive pings every 2s hold the router's NAT row open and refresh the guard's mapping, so a changed external port heals itself.
- Reply blocks end in a link record (`recRelayLink`): the last relay delivers by link id, never by address.
- `NAT_FILTER=1` simulates a restrictive NAT (drops inbound from addresses not sent to within 30s); `rebind()` simulates a mapping change.
- `HIDDEN=1` implies `ATTACHED=1`; onion is forced to at least 2 relays.
- Demo: `scripts/demo.sh edge`. Test: `TestAttachedBehindNAT`.

Limits: NAT is simulated, not real; no hole punching; source addresses are spoofable (no link-level auth); networks that block UDP still need a TCP/TLS fallback.

## Link authentication and forward secrecy

**Links.** Every datagram travels inside a session (`link.go`). A 3-message SIGMA-style handshake mixes fresh X25519 keys (session keys come
from these alone) and signs the transcript with each node's Ed25519 identity (`node.key` is the seed; id = sha256 of the public key).
- The sender of a message is the identity that authenticated the session: no spoofed sender ids, no forged or modified datagrams
  (ChaCha20-Poly1305), replays dropped (64-wide window per session).
- Pinning: an id learned from gossip is expected at that address; a different identity aborts the handshake.
- Sessions re-key every `LINK_LIFE_S` (120). Sessions follow a peer across address changes (NAT rebind), but only on an authentic fresh packet.
- Attached/hidden nodes never accept inbound handshakes, so a scan cannot even tell they exist.
- A link id at a guard can only be moved by the node that created it.
- Cost: 29 B per datagram (the sender id field, 32 B, is gone, so onion payloads are 3 B larger than before).

**Onion forward secrecy.** Relays no longer peel with a long-term key. They use X25519 onion keys, new every `ONION_KEY_LIFE_S`/2 (600/2),
signed by the node identity (certificate `key|expiry|sig`, gossiped as is, so a middleman cannot swap a relay's key), kept for the key life
plus half again, then deleted. A recorded packet cannot be opened later, not even by the relay it passed.

Limits: forward secrecy is per key epoch (minutes), not per circuit as in Tor; a relay compromised *during* an epoch exposes that epoch's traffic.
Handshake floods cost CPU (state is capped at 512, no cookie/puzzle yet). Pinning needs an id; bootstrap addresses from DNS are trusted on first contact.
Tests: `TestLinkAuth`, `TestLinkRekey`, `TestOnionForwardSecrecy`. `node.key` from older versions is read as an Ed25519 seed, so those nodes get new ids.

## Findings / insights
- **Layers**: stacking ciphers is cheap here (AEAD, ~40 B overhead per layer) and protects against a break of one primitive,
  but only if keys are independent (they are). It does *not* add security against a key leak, nor hide size.
- **Small stripes break sampling; big segments fix it, but not for free.** Encoding every 10 KB stripe separately lets an adversary hide
  11/20 shards of ONE stripe (0.2% of the file) and random sampling almost never notices. One codeword per segment (GF(2^16)
  Leopard, up to 65 536 shards of 256 B ≈ 8 MiB of data + 8 MiB parity) makes the 50% threshold global *within* a segment. Files are split into segments, so an audit now
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
- Node IDs are free (Sybil), the HTTP API has no auth, so keep it unpublished. Links are authenticated, but a node still cannot tell an honest relay from a hostile one.
- Placement uses each node's own peer view; views differ slightly, so fetches probe `REPLICATION+3` closest nodes.
