# Trust-Minimized Data Availability & Storage

**Core idea:** separate *storing* data from *proving it's available*, and make the proof cheap enough that anyone can verify it without trusting anyone.

## 1. Encode the data

- Split blobs into chunks and apply erasure coding (Reed-Solomon), so any ~50% of the shards can reconstruct the whole.
- Commit to the encoding with KZG or FRI-style polynomial commitments, so a bad encoding can be proven wrong (fraud or validity proofs) rather than trusted.

## 2. Verify availability by sampling

- Light clients randomly sample small pieces and check them against the commitment. If enough independent samples succeed, the full data is available with overwhelming probability (Data Availability Sampling, as in Celestia and Ethereum's danksharding).
- Sampling scales: more verifiers means more security, and no one needs the full data.

## 3. Distribute storage without a gatekeeper

- Assign shards using a DHT (Kademlia-style) or verifiable random assignment, so no party chooses who stores what.
- Use a permissionless node set with staking, so there's no committee to capture.

## 4. Prove ongoing storage

- Periodic challenges: nodes must answer randomly selected, unpredictable challenges (proofs of retrievability or proofs of replication) using on-chain randomness from a VRF or a beacon like drand.
- Reward valid proofs, slash failures. Also pay for retrieval, since storing without serving is a known attack.

## 5. Keep it unbiased

- **Randomness:** use unbiasable sources (threshold BLS beacons, VDFs) for challenges and shard assignment.
- **Anti-Sybil:** stake plus bandwidth/storage-backed identity, with caps per operator or per region and geographic and ASN diversity incentives.
- **Neutral ordering:** no privileged sequencer. Use encrypted mempools, fair-ordering rules, or multiple independent proposers so inclusion can't be censored.
- **Open verification:** anyone can run a sampler, and fraud proofs are permissionless.

## 6. Economics

- Pricing via an open fee market, with fees paid for a defined retention window.
- Long-term storage funded through an endowment or pay-up-front model, since "store forever" can't be paid for per-block.
- Penalties must exceed the gains from lying or deleting.

## Main trade-offs

- **Honest-minority assumption:** sampling needs at least one honest light node connected to enough peers (and in some designs a reasonably synchronous network).
- **Availability is not permanence:** DA layers guarantee data was published and retrievable for a window, not forever. Long-term storage needs a separate incentive layer (Filecoin/Arweave-style).
- **Bias creeps back via stake concentration and hardware costs.** Keep node requirements low and use stake caps or reputation-weighted limits.
- **Trusted setup:** KZG needs one (mitigated by large ceremonies); FRI/STARK-based commitments avoid it at the cost of larger proofs.

## Reference stack

Erasure coding + KZG/FRI commitments + DAS light clients + Kademlia networking + staked storage nodes with VRF-driven challenges + a threshold randomness beacon + slashing on-chain.

## Open question

Target use case determines design choices: rollup DA layer, archival storage, or general-purpose blob storage.
