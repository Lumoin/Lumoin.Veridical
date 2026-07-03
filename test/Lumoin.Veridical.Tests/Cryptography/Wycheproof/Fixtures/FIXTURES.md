# Wycheproof ECDSA secp256r1 fixtures

## Source

| Property | Value |
|----------|-------|
| Upstream project | [C2SP/wycheproof](https://github.com/C2SP/wycheproof) |
| Directory | `testvectors_v1/` |
| Fetch date | 2026-07-03 (both files fetched from `main`) |
| Most recent upstream commit touching the ASN.1 file at fetch time | `878e5366008753df2064d40c49f8e2f50f9c6af7` |
| License | Apache License 2.0 |
| Schema version | v1 (results are `valid` or `invalid` only; no `acceptable`) |

## Files

### `ecdsa_secp256r1_sha256_p1363_test.json`

IEEE P1363 (raw `r‖s`) encoded ECDSA signatures over secp256r1 with SHA-256.
262 test vectors distributed across 112 test groups; each group carries its own public key.

| Property | Value |
|----------|-------|
| SHA-256 | `c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986` |

### `ecdsa_secp256r1_sha256_test.json`

ASN.1/DER encoded ECDSA signatures over secp256r1 with SHA-256.
484 test vectors distributed across 113 test groups; each group carries its own public key.

| Property | Value |
|----------|-------|
| SHA-256 | `182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332` |

## Regeneration

```sh
curl -sLO https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json
curl -sLO https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ecdsa_secp256r1_sha256_test.json
```

After fetching, recompute and re-pin the SHA-256 hashes in this file and in the
`WycheproofEcdsaP1363Tests` integrity test constants.

## Notes

The ASN.1 file is driven through a strict test-side DER decoder in
`WycheproofEcdsaAsn1Tests`. The library deliberately ships no ASN.1/DER parsing
surface — signatures cross its API as fixed-width `r, s` spans — so a caller
consuming DER-encoded signatures owns the DER decode. The strict harness decoder
pins that contract, and the gate is fail-closed: a lenient decoder would let a
BER-encoded signature decode and verify, and the vector's `invalid` expectation
would then fail the test loudly.
