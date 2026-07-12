# Longfellow fixture provenance

Every fixture in this directory is a data dump computed by the reference implementation
`google/longfellow-zk` in its own build environment (the `longfellow-ref` Docker image over a local
clone), outside this repository. The development harnesses that produce the dumps live in the
untracked local `tempdocs/longfellow-anchors/`; no reference code is committed here.

## Upstream pin

- Repository: https://github.com/google/longfellow-zk (Apache-2.0)
- Commit: `d8ad8f65187c7c364a3c2181ad484bcab03f0ec2` (`v0.9-90-gd8ad8f6`, 2026-05-29) — 90 commits
  past the latest release tag `v0.9` (fe83ec6, 2026-03-31), and also the upstream `main` HEAD as of
  2026-07-09.
- ZkSpec identity of the pinned mdoc bundle (upstream `lib/circuits/mdoc/zk_spec.cc`, `kZkSpecs[0]`):
  system `longfellow-libzk-v1`, version 7, num_attributes 1, block_enc_hash 4151, block_enc_sig 4096,
  circuit_hash `8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121`. The v7 circuits
  were produced upstream on 2026-01-09 (the sibling `circuits/README.md` says 2026-01-12; both dates
  appear upstream) and shipped in release v0.8.6. Version 7 parameters: Ligero inverse rate 7 with
  132 opened columns, 40 SHA-256 blocks of MSO capacity (max hashed COSE1 input 40*64-9 = 2551 bytes,
  max tagged MSO 2533 bytes net of the 18-byte COSE prefix); up to 4 attributes are disclosed per
  proof (one circuit per attribute count).
- ZkSpec identity of the pinned four-attribute bundle (`kZkSpecs[3]`): system `longfellow-libzk-v1`,
  version 7, num_attributes 4, block_enc_hash 4415, block_enc_sig 4096, circuit_hash
  `5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460`. The signature circuit is
  byte-identical across the version-7 attribute counts (structural id `2845210a…` in both circuit
  anchors); only the hash circuit grows (ninputs 99,830, npub_in 3,304, subfield_boundary 99,824).

## Circuit identity chain (verified 2026-07-09)

The `kZkSpecs` `circuit_hash` is the SHA-256 of the canonical 2026-01-09 zstd compression of the
circuit. zstd output is not byte-reproducible across builds, so that hash works as a registry key,
not as a reproducible artifact hash: upstream's own in-tree blob
`lib/circuits/mdoc/circuits/8d079211…` hashes to `9016d173d8a579a104591b85826798bfbb03eafa7b376ad1
8c5344eab3a92769`, not to its own filename. No public artifact hashes to `8d079211…`.

The stable identity is the decompressed RAW circuit stream, and the chain was verified with all
three sources agreeing byte-for-byte (98,932,952 bytes, SHA-256
`332e3a96826a5f1a7a745dc9acac82e4a38051ee435877f95cdba71493354835`):

1. `mdoc-circuit-raw.gz` here (gzip-recompressed for the C# reader), asserted on every read by
   `LongfellowCircuitReaderTests`;
2. the decompression of upstream's canonical in-tree blob `circuits/8d079211…` at the pinned commit;
3. the decompression of the locally regenerated blob `mdoc-circuit-compressed.zst`
   (SHA-256 `7d0f80a7…`; differs from both at the zstd byte level, identical raw content).

Proof envelopes carry the registry-key hash only as a circuit-lookup identifier; the Fiat-Shamir
transcript binds the structural circuit ids inside the raw stream (`sig_id`/`hash_id` in
`mdoc-circuit-anchor-output.txt`).

The four-attribute bundle's identity chain follows the same shape. Upstream ships no in-tree
`kZkSpecs[3]` blob at the pinned checkout, so the chain has two sources, compared byte-for-byte
on 2026-07-09; both decompress to the same raw stream (114,608,684 bytes, SHA-256
`5a282c3f77d35a32ec5af028ece8c2c8cab612f4aa1d178f7607984dd5787010`):

1. `mdoc-circuit-raw-4attr.gz` here — the decompression of the blob `generate_circuit(&kZkSpecs[3])`
   emits at the pinned `google/longfellow-zk` commit `d8ad8f65187c7c364a3c2181ad484bcab03f0ec2`
   (the local zstd wrapper hashes to `2ab6f881…`, not the registry key, as expected);
2. the decompression of the `5aebdaaa…` registry artifact committed by an independent
   implementation of the format, taken at that implementation's commit
   `4f3d1b3fc6818901f8e532b20daa3e9faf6d3b57` (2026-05-04); the artifact's own zstd wrapper
   hashes to `3a979b6e6a7df8e9404b2293d60c3277d3ba2a1846baa82e5fad75cbe3bbc76b`.

The second-source artifact is not committed here (no foreign content enters this repository), so
the default suite re-verifies source 1 only; the comparison is reproducible by refetching the
artifact named by the `5aebdaaa…` registry key at the commit above and checking the two hashes.

## Fixture inventory

| File | Conformance step | Contents |
|------|------------------|----------|
| `commit-anchor-output.txt` | C.2 | Ligero commitment ground truth (LigeroParam derivations, deterministic commit leaves/roots) |
| `transcript-anchor-output.txt` | — | Fiat-Shamir transcript oracle (v6/v7 key+bytes init, element absorbs, ofscalar draws) |
| `prove-anchor-output.txt` | C.4 | Ligero prove flow ground truth (deterministic nw=8 tuple, q16/q32) |
| `serialize-anchor-output.txt` | C.6 | Ligero proof byte serialization through the real reference serializer |
| `sc-anchor-output.txt` | C.7 | zk sumcheck-segment ground truth (small GF(2^128) circuit, every FS challenge) |
| `zk-anchor-output.txt` | C.8 | Full ZkProof envelope ground truth over the small circuit |
| `mdoc-circuit-anchor-output.txt` | C.10 | Circuit-artifact import ground truth: ZkSpec identity, both circuits' shapes and 32-byte structural ids, `raw_rawsha` |
| `mdoc-circuit-compressed.zst` | C.10 | Locally regenerated zstd blob (identity input for `computed_circuit_hash`) |
| `mdoc-circuit-raw.gz` | C.10 | THE circuit fixture: raw serialized dual-circuit stream, canonical content (see chain above) |
| `mdoc-circuit-hash-witness.gz` | C.10 | GF(2^128) hash-circuit witness column for mdoc_tests[0] with age_over_18 |
| `fp256-rs-anchor-output.txt` | C.12 | Fp256 Reed-Solomon codewords + kRootX/kRootY ground truth |
| `mdoc-zk-anchor-output.txt` | crown | Google's real reference mdoc ZkProof: version 7 envelope (359,924 bytes), 117-byte SessionTranscript, hash/sig public-input templates, over mdoc_tests[0] |
| `mdoc-circuit-anchor-4attr-output.txt` | W2.5b | kZkSpecs[3] import ground truth: ZkSpec identity, both circuits' shapes and ids, `raw_rawsha` |
| `mdoc-circuit-raw-4attr.gz` | W2.5b | The four-attribute circuit fixture: raw serialized dual-circuit stream (see the four-attribute chain above) |
| `mdoc-circuit-hash-witness-4attr.gz` | W2.5b | GF(2^128) hash-circuit witness column for mdoc_tests[3] with the four org.iso.18013.5.1 attributes |
| `mdoc-zk-anchor-4attr-output.txt` | W2.5b | The reference's real four-attribute mdoc ZkProof: kZkSpecs[3] envelope (364,804 bytes) over mdoc_tests[3] (family_name, birth_date, height, issue_date), templates + transcript + attribute list |

The 26 mdoc credentials in `../Mdoc/mdoc-00..25.cbor` (+ `index.tsv`) are byte-exact exports of
upstream `lib/circuits/mdoc/mdoc_examples.h` `mdoc_tests[]` at the same pinned commit.

## Re-pin tripwires

An upstream release newer than `v0.9`, a `kZkSpecs` table change (new circuit version or changed
hashes), or a normative `docs/specs` change that alters transcript or wire bytes each trigger
re-verification of these fixtures against the new upstream state before any claim of conformance to
it. `LongfellowUpstreamPinTests` asserts the ZkSpec identity recorded in
`mdoc-circuit-anchor-output.txt` against the pin documented here, so a fixture regeneration from a
different upstream state fails the suite rather than drifting silently.
