# CargoClear — Autonomous Maritime Letter of Credit & Cold-Chain Customs Escrow

A pure GenLayer Intelligent Contract (no frontend). An importer locks native GEN against a
shipment; an accredited **Carrier Authority** attests the Electronic Bill of Lading with an
**Ed25519 signature verified inside the contract**; funds then move in two tranches only when
**2 of 3 independent feeds** (carrier manifest, port customs, cold-chain AIS mirror) agree on
what happened to the container. Settlement is integer basis points, with cold-chain and
demurrage haircuts, and every wei is accounted for.

| | |
|---|---|
| **Network** | GenLayer Studio Next, chain `61997` (`https://studio-next.genlayer.com/api`) |
| **Contract** | [`0x985a9931Cd8BD8c0fd6cA37274D57e8f4235f34C`](https://explorer-studio-next.genlayer.com/address/0x985a9931Cd8BD8c0fd6cA37274D57e8f4235f34C) — deployed from the source at commit `329d90a`; the robustness polish on `main` (safe `fetch_source`, O(1) summary) has **not** been redeployed |
| **Deployed source SHA-256** | `2eab01f7a0c19a03bd58a48cc8b11355c10a3d31e9238bf5877f6d597afa6bd5` (byte-identical to what `genlayer code` returns for the address; see `git show 329d90a:contracts/cargo_clear.py`) |
| **Runner** | `py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng` (GenVM v0.3.0-rc7 line) |
| **Feed commit (immutable pin)** | `41ae8738942b8e938036325e78b600ff6ec0df51` |
| **Linter** | `genvm-lint check` and `genvm-lint typecheck`: 0 errors, 0 warnings |
| **Tests** | 2139 pytest tests (2085 direct-mode + 54 mutation runs), all passing |
| **Authoritative record** | [`deployments/studio-next.json`](deployments/studio-next.json) |

## Design

* **Zero floats.** Temperatures are integer tenths of °C (`-180` = −18.0 °C), shares are basis
  points, money is wei. Views return only `int/str/bool/list/dict` (so `gen_call` can encode
  them) and the feed parser rejects every float spelling (`1.0`, `1e2`, `-0.0`, `NaN`,
  `Infinity`) plus duplicate keys, booleans-as-ints, extra/missing keys and oversized bodies.
* **In-contract Ed25519 (RFC 8032).** `carrier_authority_pubkey` is fixed at deployment (and must
  be a canonical, non-small-order point). `verify_bill_of_lading(lc_id, bol_record_id, sig)`
  rebuilds the message from the stored L/C terms:
  `bol_record_id|lc_id|container_id|exporter_address|cargo_spec_hash|max_temp_tenths_c|latest_arrival_ts`
  and verifies it with pure integer arithmetic (Shamir's trick, canonical encodings only,
  `S < L`). A bad signature reverts `ERR_INVALID_BOL_ATTESTATION` before any fetch or write.
  One BoL id can back only one L/C.
* **48-hour bilateral handshake.** `open_letter_of_credit` → `PENDING_EXPORTER_ACCEPTANCE`. The
  named exporter may `accept_lc_terms` / `reject_lc_terms` (the deadline itself is still inside
  the window). If rejected, or still unaccepted after 48 h, the importer calls
  `cancel_unaccepted_lc` and reclaims 100 % of principal.
* **3-host independence, pinned.** Feed URLs must be on `raw.githubusercontent.com`,
  `cdn.jsdelivr.net` and `raw.githack.com` (one each, in that order), inside
  `moltaphet/CargoClear`, under `deployments/mock_feeds/{a,b,c}/`, at the **same 40-hex commit
  SHA**. No queries, fragments, ports, userinfo, traversal or encodings.
* **Two tranches.**
  * `STAGE_1_DEPARTURE` — 2000 BPS (20 %): ≥ 2 feeds confirm departure for the same
    `bol_record_id` / `container_id` with `0 < departure_ts <= latest_arrival_ts`.
  * `STAGE_2_CUSTOMS_CLEARED` — 8000 BPS (80 %), by bucket (shares of the whole L/C):

    | bucket | condition | exporter | importer |
    |---|---|---|---|
    | 0 `CLEAN_DELIVERY` | `peak <= max`, `arrival <= latest` | 8000 | 0 |
    | 1 `LATE_DEMURRAGE` | clean temp, `latest < arrival <= latest + 7 d` | 6000 | 2000 |
    | 2 `MINOR_THERMAL_DRIFT` | `max < peak <= max + 30` | 4000 | 4000 |
    | 3 `SPOILED_OR_REJECTED` | `peak > max + 30`, or arrival > 7 d late, or customs rejected | 0 | 8000 |

    Lateness and drift combine to the **worse** bucket. Rounding dust (the sum of floors) goes to
    the exporter on bucket 0 and to the importer on every haircut bucket, so
    `exporter_claimable + importer_rebate + unreleased + withdrawn == total_deposited` always.
* **Fault-tolerant `_aggregate`.** Consensus payload is exactly
  `{"verdict","stage","bucket","source_count","manifest_hash","event_ts"}`.
  `verdict 1` = ≥ 2 sources agree on `(stage, bucket, manifest_hash)`; `verdict 0` = ≥ 2 sources
  attest `CUSTOMS_REJECTED` / `VOYAGE_ABORTED` (Stage 2 → bucket 3; a corroborated abort before
  Stage 1 refunds everything still in escrow); everything else — fewer than 2 responders,
  `1 CONFIRMED + 2× 404`, `1 CONFIRMED + 404 + OUTAGE`, conflicting positives, future timestamps
  (`> now + 3600`) — is `verdict 2 QUORUM_FAILURE`: **retryable and it mutates nothing** except a
  diagnostic counter. A 404 or an outage can never produce a rejection. Validators re-fetch and
  require exact equality of all six fields (exact key set, int/str types).
* **Liveness.** `reclaim_expired_lc`: if nobody settles within `latest_arrival + 7 d + 30 d`,
  the importer recovers whatever is still in escrow.
* **Payouts** are pull-pattern (`claim_funds`), checks-effects-interactions, restored if the
  transfer cannot be enqueued. No owner, no pause, no upgrade, no fee.

Beyond the spec: Stage 2 requires Stage 1; settlement requires a verified BoL; only L/C parties
may trigger settlement; the clock is `gl.message.raw["datetime"]` (the transaction time),
captured outside the non-deterministic block.

## Live proof on Studio Next (all transactions finalized, `MAJORITY_AGREE`)

Wallets (fresh, created for this project): importer `0xA6110B6Be420EF177A4B49830ed83a3a25098CB1`
(`cargoclear-importer`), exporter `0xaCb60E9E3162b84Db79D92b703db09D4a29C3039`
(`cargoclear-exporter`). Both were funded by the Studio Next faucet (it credited; the local-CLI
fallback was not needed). L/C principal: `50000000000000003` wei (0.05 GEN + 3 wei, deliberately
not divisible by 5).

| # | Step | Result | Tx |
|---|---|---|---|
| 1 | deploy | `FINISHED_WITH_RETURN` | [`0x318a037a…fe3f`](https://explorer-studio-next.genlayer.com/tx/0x318a037a44b0f8f2f10ac56254db8a1b0bc161ff6ee6106c10ff14618d54fe3f) |
| 2 | `open_letter_of_credit` → `LC-1` | `LC-1` | [`0x7569cdd9…d623`](https://explorer-studio-next.genlayer.com/tx/0x7569cdd9d07264c1cd72c7adcdb1d05a1e4e271faee64ab7f7550978d8d3d623) |
| 3 | `accept_lc_terms` (exporter) | `ACTIVE` | [`0x88c8fa5c…df6c`](https://explorer-studio-next.genlayer.com/tx/0x88c8fa5ca7ea917a95885a09ac27a54d1a2feab72b4fea7594919132b7c1df6c) |
| 4 | **`verify_bill_of_lading` — FORGED signature** | `FINISHED_WITH_ERROR`: `ERR_INVALID_BOL_ATTESTATION signature does not verify`; state unchanged, `bol_verified == false` | [`0x99a0d1f4…14e4`](https://explorer-studio-next.genlayer.com/tx/0x99a0d1f40896a3c3bbcd545590c005c54a95cfc54e9ac67fc1645c0e87ed14e4) |
| 5 | `verify_bill_of_lading` — genuine Carrier Authority signature | `BOL-CC-20261009-0001` | [`0x8cfa8cd7…8e4d`](https://explorer-studio-next.genlayer.com/tx/0x8cfa8cd78785daf956263ea4f97990c11540f68aaa12595714cb9e9c9a2f8e4d) |
| 6 | `settle_shipment_stage(1)` | `verdict 1, bucket 0, source_count 3` → exporter 20 % | [`0x11913fa9…e6a3`](https://explorer-studio-next.genlayer.com/tx/0x11913fa9a495612bcf4f175368c208ac953e0bc2dd0f9a8097ac16a53500e6a3) |
| 7 | `settle_shipment_stage(2)` | `verdict 1, bucket 2, source_count 2` (the AIS mirror dissented) | [`0x9a571443…4b63`](https://explorer-studio-next.genlayer.com/tx/0x9a57144310efd9f34b97cb3a1f3c52147d2b668386cb292352c7352ca0fd4b63) |
| 8 | `claim_funds` (exporter) | `30000000000000001` | [`0x56196dc4…86c1`](https://explorer-studio-next.genlayer.com/tx/0x56196dc4008b0c17527e570d7d047a352c6debdb154101725d1e0324403d86c1) |
| 9 | `claim_funds` (importer) | `20000000000000002` | [`0xbf261983…8469`](https://explorer-studio-next.genlayer.com/tx/0xbf2619837817fd5516c6d4eecdc843c965f5c47561a49f5abcc896e08a708469) |

The forged signature in step 4 is a well-formed Ed25519 signature by a *different* key over the
correct canonical message, i.e. the realistic forgery. Stage 2 settled **bucket 2** (−16.0 °C vs
the −18.0 °C limit = +2.0 °C): exporter 20 % + 40 % + 1 wei = `30000000000000001`, importer
40 % + 1 wei dust = `20000000000000002`; the two sum to the principal exactly.

Live `gen_call` readbacks (full output in `deployments/studio-next.json`):

```text
get_lc_state("LC-1")         state COMPLETED, final_bucket 2, stage1_sources 3, stage2_sources 2,
                             unreleased_escrow 0, exporter_claimable 30000000000000001,
                             importer_rebate 20000000000000002, total_deposited 50000000000000003
get_protocol_summary()       lc_count 1, stage_1_bps 2000, stage_2_bps 8000,
                             carrier_authority_pubkey <Carrier Authority Ed25519 key>
get_feed_sources("LC-1")     3 distinct hosts, repository github.com/moltaphet/CargoClear,
                             commit 41ae8738942b8e938036325e78b600ff6ec0df51
verify_solvency_invariant()  solvent true, per_lc_conserved true  (before claims: owed ==
                             exporter 30000000000000001 + importer 20000000000000002 == deposit)
```

## Trust Model, Demo Scope & Known Limitations

**Trust model.** Funds move only on (a) a valid Ed25519 attestation by the Carrier Authority key
fixed at deployment and (b) a 2-of-3 agreement between three feed operators. Anyone who controls
the Carrier key can attest any Bill of Lading, and any two colluding feed operators can decide a
bucket. CargoClear minimises trust; it does not remove it.

* **Local demo keys & CDN fixtures.** In this testnet demonstration the Carrier Authority
  Ed25519 key is generated locally in `.secrets/carrier_ed25519.seed` (git-ignored) by the same
  operator who runs the importer and exporter wallets, and the three "independent" feeds are
  static fixtures that live in this single repository, pinned by commit SHA and served through
  three CDNs. The CDNs are independent hosts; the *publisher* is not. A production deployment needs
  a real accredited authority key and feeds published by genuinely separate parties.
* **Immutable constructor authority.** `carrier_authority_pubkey` is set in the constructor and
  there is no setter, rotation or admin path. Replacing or revoking the authority means deploying
  a new contract; open letters of credit on the old contract keep their original authority.
* **Post-grace exporter reclaim risk.** If the feeds stay unreachable (or never reach quorum),
  nothing is settled and the importer may call `reclaim_expired_lc` once
  `latest_arrival_ts + 7 days (grace) + 30 days (settlement window)` — 37 days after the
  contractual arrival time — has passed. It returns everything still in escrow to the importer, so
  an exporter whose cargo arrived but whose feeds are down for that long loses the unsettled
  tranches. Exporters should watch their feeds and settle well inside the window. Funds already
  released by Stage 1 stay with the exporter.
* **Importer feed selection.** The importer chooses the three feed URLs when opening the L/C. The
  contract constrains them (three fixed operator hosts, this repository, one shared 40-hex commit
  SHA, `deployments/mock_feeds/{a,b,c}/`), but the *content* at that commit is the importer's
  choice. **Exporters must inspect the pinned commit SHA and the three files (`get_feed_sources`)
  during the 48-hour acceptance handshake**, and should reject the L/C if they do not accept what
  those files say.
* **Read cost.** `get_protocol_summary` is O(1): it is served from counters (`state_counts`,
  `total_unreleased`) updated on every transition, so it does not grow with the number of
  letters of credit. `verify_solvency_invariant` is deliberately an independent from-scratch
  audit and therefore scales **linearly** with the number of L/Cs; call it sparingly on a
  protocol with very many letters.
* **Malformed fetches are outages.** `fetch_source` reads status/body defensively (object or
  mapping, missing attribute, wrong type): anything unexpected is an `OUTAGE` that cannot vote, so
  an RPC outlier yields a retryable `QUORUM_FAILURE` instead of reverting the transaction.

### Payouts on Studio Next (observed, not a contract fault)

`claim_funds` debits the ledger and emits the payout with `emit_transfer(..., on="finalized")`.
The transactions finalize and the emitted message (correct recipient and amount) is recorded in
each tx's `messages`, but **Studio Next did not credit the recipient EOA in the ~10 minutes
observed**; a minimal test contract using `emit_transfer` on both `accepted` and `finalized`
behaved the same way. So the readbacks after claims show the ledger drained
(`total_withdrawn == total_deposited`) while the contract's native balance still holds the
principal. The accounting and the emitted messages are verified; actual EOA crediting is
something this Studio deployment does not currently perform.

## Repository

```text
contracts/cargo_clear.py          the Intelligent Contract
deployments/mock_feeds/{a,b,c}/   commit-pinned maritime / customs / cold-chain fixtures
deployments/studio-next.json      authoritative deployment, tx hashes and live readbacks
deployments/cargo_clear_abi.json  contract schema as returned by Studio Next
scripts/deploy_and_verify.py      autonomous deploy + forged-BoL proof + live settlement
scripts/verify_feeds.py           HTTP 200 + byte parity on all three CDN hosts
scripts/make_fixtures.py          regenerates the fixtures
tests/                            test_ed25519_bol, test_aggregate_quorum,
                                  test_settlement_math, test_contract_flows (+ mutation harness)
```

## Run it

```bash
uv venv --python 3.12 && uv pip install --prerelease=allow -r requirements-dev.txt
export GENVM_VERSION=v0.6.0-rc7      # the bundle that ships runner 5jycge…; tests set it by default
.venv/bin/python -m pytest -q        # 2139 tests; add -m "not mutation" to skip the ~5 min mutation run
.venv/bin/genvm-lint check contracts/cargo_clear.py
.venv/bin/genvm-lint typecheck contracts/cargo_clear.py
python scripts/verify_feeds.py 41ae8738942b8e938036325e78b600ff6ec0df51
.venv/bin/python scripts/deploy_and_verify.py      # needs .secrets/ (git-ignored) or creates fresh keys
```

Direct-mode tests must not be run with `pytest -s` (the SDK reads the message from stdin).

### What the tests cover

* **`test_ed25519_bol.py`** — RFC 8032 vectors; 60 random keys/messages cross-checked against
  OpenSSL via `cryptography`; every signature byte flipped; malleable `S ≥ L`; non-canonical and
  off-curve points; small-order keys rejected at deployment; the forged-BoL path (no state change,
  no fetch); all seven message fields individually altered; replay across L/Cs and BoL ids.
* **`test_aggregate_quorum.py`** — all **216** per-source state combinations × 2 stages against
  an independent oracle, on the pure aggregate **and** end-to-end through the contract (648
  oracle tests); `1 confirmed + 2× 404`, `1 + 404 + outage`; 31 malformed feed bodies × 2;
  float-literal smuggling; future-timestamp boundary; validator key-set / type / equality.
* **`test_settlement_math.py`** — every bucket boundary (±1 tenth, ±1 second, the 7-day grace);
  exact BPS; conservation for 60+ principals × 4 buckets; dust direction; payouts drain exactly
  what is owed; AST proof of no floats / no `/` / no `float`; views survive calldata round-trip.
* **`test_contract_flows.py`** — full lifecycle, 48 h boundaries, 34 feed-pinning attacks,
  authorization, replay, expiry, double claims, failed-transfer rollback, and **54 mutants**
  (changed constants, flipped comparisons, deleted checks, removed signature verification…) that
  the suite must kill; all 54 are killed.

Test-environment note: GenVM's direct-mode harness does not re-inject the transaction datetime
after load, so tests move the clock by updating both the VM and `genlayer.message.raw["datetime"]`.
