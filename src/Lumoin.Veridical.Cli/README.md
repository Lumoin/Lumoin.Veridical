# veridical

A command-line and [Model Context Protocol](https://modelcontextprotocol.io) (MCP)
tool for [Lumoin.Veridical](https://github.com/lumoin/Veridical).

## Install

```
dotnet tool install --global Lumoin.Veridical.Cli
```

## Commands

```
veridical info                 Print platform and scalar-backend information.
veridical hash <input>         BLAKE3-256 hash of UTF-8 text (or --hex bytes).
veridical hash <hex> --hex     BLAKE3-256 hash of a hex-encoded byte string.
veridical selftest             Run known-answer conformance vectors; exit non-zero on failure.
veridical prove <request>      Prove a supply-chain predicate bundle from local data; artifact JSON to stdout.
veridical verify <artifact>    Verify a proof artifact and report the statement it proves; exit non-zero if it does not.
veridical longfellow-jwt-prove <token> --issuer-key-x <hex> --issuer-key-y <hex> --attribute id=value --seed <text> [--blocks 7|9]
                               Prove a presentation token (issuerJws~keyBindingJws) against the issuer key; proof as hex to stdout.
veridical longfellow-jwt-verify <proof> --presentation <file> --issuer-key-x <hex> --issuer-key-y <hex> --attribute id=value --seed <text> [--blocks 7|9]
                               Verify a Longfellow JWT proof and report the statement it proves; exit non-zero if it does not.
veridical bbs-keygen --secret-key-file <path> [--ciphersuite sha256|shake256] [--key-material-file <path>] [--key-info <text>]
                               Generate a BBS key pair; the secret key goes to the named file, the public key (hex) to stdout.
veridical bbs-sign <messages> --secret-key-file <path> --public-key <hex> [--header <text>] [--hex]
                               Sign the messages (one per line); signature as hex to stdout.
veridical bbs-verify <signature> --messages-file <path> --public-key <hex> [--header <text>] [--hex]
                               Verify a BBS signature; exit non-zero if it does not verify.
veridical bbs-proof-generate <signature> --messages-file <path> --public-key <hex> --disclose 0,2 [--header <text>] [--presentation-header <text>]
                               Derive a selective-disclosure proof; proof as hex to stdout.
veridical bbs-proof-verify <proof> --disclosed-messages-file <path> --public-key <hex> [--header <text>] [--presentation-header <text>]
                               Verify a selective-disclosure proof against the disclosed index=message lines; exit non-zero if it does not.
veridical secdsa-split-sign --pin-key-file <path> --hardware-key-file <path> --message-hash <hex>
                               Split-sign a message hash from the two key scalars; r || s as hex.
veridical secdsa-public-key --pin-key-file <path> --hardware-key-file <path>
                               Derive the compressed public key of the two key scalars.
veridical secdsa-verify --public-key <hex> --message-hash <hex> --signature <hex>
                               Verify a SECDSA signature; exit non-zero if it does not verify.
veridical secdsa-recover-nonce-point / secdsa-verify-full
                               Recover the nonce point R from a signature; verify with R and s.
veridical secdsa-dl-prove / secdsa-dl-verify
                               Prove and verify discrete-logarithm equality over generator and public-key pairs.
veridical secdsa-blinding-prove / secdsa-blinding-verify
                               Prove and verify the blind-signing evidence relation.
veridical secdsa-control-prove / secdsa-control-verify
                               Prove and verify the control evidence relation bound to a record context.
veridical secdsa-ecdh-mac-derive-key / -sign / -verify / -split-sign
                               ECDH-MAC: derive the MAC key to a file, sign, verify, and sign from three key shares.
veridical secdsa-split-sign-prepare --pin-key-file <path> --message-hash <hex> --output <path>
                               Split sign, prepare: write the blinded representative e' to a new file for the key holder's raw ECDSA sign.
veridical secdsa-split-sign-complete --pin-key-file <path> --message-hash <hex> --public-key <hex> --raw-signature-file <path>
                               Split sign, complete: mask the key holder's r || s0 and print r || s only if it verifies under the public key.
veridical secdsa-ecdh-mac-prepare --peer-public-key <hex>
                               ECDH-MAC, prepare: validate the verifier's ephemeral point and print it for the key holder.
veridical secdsa-ecdh-mac-apply-key-share --key-share-file <path> --point <hex>
                               Split ECDH-MAC wallet or WSCA step: multiply a point by a key share.
veridical secdsa-ecdh-mac-complete-sign / -complete-verify --shared-secret-file <path> ...
                               ECDH-MAC, complete: derive the key from the key holder's shared secret and MAC or verify.
veridical secdsa-ecdh-mac-verify-mac --mac-key-file <path> --message <hex> --mac <hex>
                               Verify an ECDH-MAC under a key the key holder derived itself.
veridical secdsa-result-prove --public-key <hex> --message-hash <hex> --signature <hex>
                               Signature-result conformity, prover side: print the record (R, G'', Q_U'', proof).
veridical secdsa-result-check --public-key <hex> --message-hash <hex> --record <hex>
                               Signature-result conformity, verifier side; exit non-zero on a compromise alarm.
veridical secdsa-ecies-encrypt --recipient-public-key <hex> --plaintext-file <path> [--aad <hex>]
                               ECIES encryption (X9.63 over SHA-256, AES-256-GCM); print E || T || C.
veridical secdsa-ecies-decrypt --private-key-file <path> --ciphertext <hex> [--aad <hex>] --output <path>
                               ECIES decryption; the plaintext goes to a new file, only if the tag verifies.
veridical secdsa-ecies-prepare-decryption --ciphertext <hex>
                               ECIES decryption, prepare: validate E and print it for the key holder.
veridical secdsa-ecies-agree --private-key-file <path> --point <hex> --output <path>
                               The key holder's raw agreement Z_AB in software; Z_AB goes to a new file.
veridical secdsa-ecies-complete-decryption --shared-secret-file <path> --ciphertext <hex> [--aad <hex>] --output <path>
                               ECIES decryption, complete: derive the key from Z_AB and decrypt into a new file.
veridical secdsa-proof-challenge --signing-key-file <path> --generators <hex> --public-keys <hex> [--aad <hex>] [--additional-secret-data-file <path>]
                               Transferable proof, challenge: print JSON with the signed challenge and the ECIES ciphertext.
veridical secdsa-proof-respond-prepare --challenge <hex> --generators <hex> --public-keys <hex> [--aad <hex>] --challenger-public-key <hex>
                               Transferable proof, response prepare: verify the challenge and print E for the key holder.
veridical secdsa-proof-respond-complete --shared-secret-file <path> --challenge <hex> --ciphertext <hex> --generators <hex> --public-keys <hex> [--aad <hex>] --signing-key-file <path> --challenger-public-key <hex> [--additional-secret-data-output <path>]
                               Transferable proof, response complete: verify the challenge signature, then print the signed response; no output if any check fails.
veridical secdsa-proof-verify --challenge <hex> --response <hex> --generators <hex> --public-keys <hex> [--aad <hex>] --challenger-public-key <hex> --prover-public-key <hex>
                               Transferable proof, verification by a third party; exit non-zero when rejected.
veridical analysis-basefold-leakage [--variables n] [--samples n] [--significance p] [--hiding]
                               Run the BaseFold leakage experiments against the plain or hiding commitment provider.
veridical analysis-welch-t <first> <second> [--significance p]
veridical analysis-ks <first> <second> [--significance p]
veridical analysis-chi-squared <observed> <comparison> [--expected] [--significance p]
                               Statistical tests over files of numbers, one per line.
```

For `prove`, `verify`, `longfellow-jwt-prove` and `longfellow-jwt-verify`, the file argument may be `-` to read from standard input.

`selftest` runs deterministic known-answer vectors — a BLAKE3 test vector, field
arithmetic (multiply, invert), and the batch multiply checked against the
single-element path across lane-group boundaries. It is the same code used as the
native-AOT conformance check in CI, so it validates that the AOT-compiled build
computes correct results on each target (including the SIMD paths on ARM).

## Predicate proofs

`prove` and `verify` cover a supply-chain predicate bundle: an ordered conjunction of
*at-least* / *at-most* fixed-point claims (for example, a battery-passport bundle —
recycled content at or above a minimum **and** carbon footprint at or below a cap),
proven over Spartan-over-Ligero — a transparent (hash-based) proof system with no
trusted setup and no key material to distribute. The measured quantities are witness
inputs and are not written into the artifact's JSON fields — but the wired proof path
is **sound and binding, not witness-hiding**: the embedded Ligero openings reveal
committed-matrix columns in cleartext, and for the wired circuit sizes those columns
determine the full witness — including the measured quantities — by interpolation.
Treat the artifact as disclosing the measured values to whoever receives it. What the
proof adds is integrity — the recipient can check that the claims verifiably hold and
that the statement was not altered — with one static binary and no PKI. A hiding
(masked) configuration is a possible future upgrade, not what ships here.

- **`prove`** reads a request that carries the statement parameters and the measured
  quantities, and writes a proof artifact. Send the artifact only to parties allowed
  to learn the measured values (see the disclosure note above).
- **`verify`** needs only the artifact — no private data, no PKI, no platform change.
  It rebuilds the statement circuit from the artifact's claim descriptors, reconstructs
  the public instance from the revealed public inputs (no witness), and checks the
  proof. It then prints the described statement.

A regulatory bound is either a **constant** baked into the circuit or a **public input**
the artifact reveals. Either way the bound is bound to the proof: changing a constant
in the descriptor, a revealed public input, or the commitment parameters causes
verification to fail. The proof attests that the *described* statement is satisfiable —
`verify` prints that statement so an operator confirms it is the compliance claim they
require.

Every claim carries a `kind` discriminator. A **`range`** claim compares a measured
quantity against a bound (`atLeast` / `atMost`); the bundle's range claims are proven
together over Spartan-over-Ligero. A **`memberOf`** claim states that a measured
quantity is one of a public list of `allowedValues`; each is proven by its own
LogUp-over-Ligero lookup argument, whose proofs travel in the artifact's
`lookupProofs`. The same disclosure note applies to both kinds.

The commitment parameters (curve, query count, lookup query count, inverse rate,
digest size) are pinned to one wired set that both verbs enforce, so an artifact
cannot silently weaken them. The lookup query count is higher than the range one: the
lookup argument opens three independently forgeable columns, so its 128-bit target
carries a union-bound surcharge (65 columns instead of 64 at rate 1/16).

### Example

A request proving recycled content ≥ 30.0%, carbon footprint ≤ 12.50, and a material
code drawn from an allowed list, over private measurements of 32.5%, 11.20 and 7:

```json
{
  "format": "veridical-supply-chain-predicate-request/3",
  "curve": "bls12-381",
  "transcriptDomain": "veridical.supplychain.batterypassport.v1",
  "queryCount": 64,
  "lookupQueryCount": 65,
  "inverseRate": 16,
  "digestBytes": 32,
  "claims": [
    { "name": "recycled_content", "kind": "range", "direction": "atLeast", "fractionalDigits": 1, "inclusiveMaximum": "100.0", "bound": "constant", "boundValue": "30.0", "measured": "32.5" },
    { "name": "carbon_footprint", "kind": "range", "direction": "atMost", "fractionalDigits": 2, "inclusiveMaximum": "100.00", "bound": "constant", "boundValue": "12.50", "measured": "11.20" },
    { "name": "material_code", "kind": "memberOf", "fractionalDigits": 0, "inclusiveMaximum": "9999", "allowedValues": ["3", "7", "42", "1001"], "measured": "7" }
  ]
}
```

```
veridical prove request.json > artifact.json
veridical verify artifact.json
# VALID: proves recycled_content >= 30.0 (constant); carbon_footprint <= 12.50 (constant); material_code in {3, 7, 42, 1001} (4 allowed value(s))
```

The artifact and request JSON are serialized by `Lumoin.Veridical.Json`, an AOT-safe
(source-generated) reference serializer that consumers can reuse.

## Longfellow JWT proofs

`longfellow-jwt-prove` and `longfellow-jwt-verify` drive the Longfellow zero-knowledge proof of a
restricted `issuerJws~keyBindingJws` presentation token (JWT+KB, ECDSA P-256): the proof shows the
issuer signed a token that discloses the stated `id=value` attributes and that the key-binding
signature is valid, without revealing the rest of the token. The issuer key is the verifier's
out-of-band trust anchor, given as the 32-byte `--issuer-key-x` and `--issuer-key-y` hex
coordinates. Repeat `--attribute` for each disclosed attribute; `--seed` is the public session
text both parties must use; `--blocks` is the SHA-256 block capacity of the issuer signing input
(7 or 9). The token is the prover's private witness: it is read only from the named file or
standard input, never from an argument, and never echoed. The proof is lowercase hex and carries
no witness. `longfellow-jwt-verify` needs only the proof and the presentation's key-binding JWS
(a whole token is accepted; the part after the last `~` is used).

The tool is the composition root for the cryptography: SHA-256 for the Merkle, leaf and
transcript hashes, single-block AES-256 for the transcript permutation, and the operating
system random generator for the prover's randomness. The library selects none of them.

## BBS signatures

The `bbs-*` commands drive BBS signatures over BLS12-381 with the `sha256` or `shake256`
ciphersuite: key generation, signing, verification, and selective-disclosure proofs. Messages are
UTF-8 text lines in a file (hex byte strings with `--hex`). The secret key is never taken from an
argument and never printed: `bbs-keygen` writes it to the file named by `--secret-key-file`
(created exclusively, readable by its owner only, refusing to overwrite) and prints only the
public key; `bbs-sign` reads it from a file. `--key-material-file` supplies key material instead of
drawing it from the operating system random generator. A proof discloses only the messages at the
`--disclose` indices; the verifier passes them as `index=message` lines with ascending indices.
Signatures and proofs are lowercase hex.

## SECDSA

The `secdsa-*` commands map one-to-one onto the library's SECDSA primitives over P-256: split
signing, verification, nonce-point recovery, discrete-logarithm-equality proofs, the blinding and
control evidence relations, and ECDH-MAC key derivation, signing, verification and split signing.
Points, hashes, challenges and proofs are hex. Every secret scalar (key shares, witnesses, ephemeral
private keys) is read only from a file named by a `--...-file` option, never from an argument, and
is never echoed; `secdsa-ecdh-mac-derive-key` writes the derived MAC key to the file named by
`--output`, created exclusively. Signing is deterministic (RFC 6979 nonces).

The phase commands let the key that does the raw work live outside the process, in an HSM, a TPM or
a KMS, with the caller moving the data between the steps (a file, a pipe, another machine). For
split signing, `secdsa-split-sign-prepare` writes the blinded representative `e'` to a new file;
the key holder raw-ECDSA-signs it; `secdsa-split-sign-complete` reads the key holder's `r || s0`
from a file, masks it, and prints the signature only if it verifies under the supplied composite
public key, so a faulty or substituted key holder yields an error and no signature. `e'` and `s0`
are kept out of standard output and read only from files, because either one next to the public
message hash or the finished signature reveals the PIN key. The two-party key-share split runs the
same two commands once per party. For ECDH-MAC, `secdsa-ecdh-mac-prepare` validates the verifier's
ephemeral point, the key holder returns the 32-byte shared secret `Z_AB` (or the derived key), and
`secdsa-ecdh-mac-complete-sign` or `-complete-verify` derives `K` with HKDF-SHA-256 and MACs or
compares in constant time; `secdsa-ecdh-mac-verify-mac` verifies under a key the key holder derived
itself, and `secdsa-ecdh-mac-apply-key-share` is the wallet and WSCA step of the split form. The
commands derive the key with HKDF-SHA-256 as the paper's ECDH-MAC algorithms specify; a MAC under a
key an HSM derived with another function (the X9.63 derivation a PKCS#11 `CKD_SHA256_KDF` applies)
verifies only through `secdsa-ecdh-mac-verify-mac` with that key, because the verifier must use the
same derivation.

The signature-result, ECIES and transferable-proof commands cover Annex F Algorithm 41 and Annex A.4
and A.5 (Algorithms 18, 19 and 22 to 24). `secdsa-result-prove` and `secdsa-result-check` prove and
check that a signature result is consistent with the user key; a compromise alarm exits non-zero.
`secdsa-ecies-*` encrypts with X9.63 over SHA-256 and the platform's AES-256-GCM (96-bit IV, 128-bit
tag); the ciphertext is `E || T || C` in hex, plaintexts and shared secrets move only through files, and
a failed tag writes no file. The decrypt phases mirror the key holder hand-off: `prepare-decryption`
validates `E`, `agree` computes `Z_AB` in software for tests, and `complete-decryption` finishes from a
shared secret an HSM returned. The `secdsa-proof-*` commands issue a challenge with the seed encrypted
towards `E`, answer it in two phases around the key holder (step 11, the repeated decryption, is part
of `respond-complete`), and verify it as a third party. Both signatures are ECDSA over P-256 with
SHA-256 and the layout is the library's provisional length-prefixed profile; neither is an
interoperability format. The seed derivation is HKDF-SHA-256 with the derivation byte array as its info
string, which bounds the additional authenticated data to what one HKDF info accepts.

## Analysis

The `analysis-*` commands run the library's analysis experiments and print a plain-text report.
`analysis-basefold-leakage` runs the byte-statistics, classifier and commitment-recoverability
experiments against the plain BaseFold commitment provider, or with `--hiding` the salted one; a
detected leak is a finding in the report, not a failure, so the command exits zero whenever the
experiments ran. `analysis-welch-t`, `analysis-ks` and `analysis-chi-squared` apply Welch's t-test,
the two-sample Kolmogorov-Smirnov test and the chi-squared homogeneity (or, with `--expected`,
goodness-of-fit) test to files of numbers. The timing-leakage harness takes delegates to the
operation under test and has no file-driven form, so it has no command.

## MCP server

Run as an MCP stdio server:

```
veridical -mcp
```

Exposed tools: `Info`, `Hash`, `SelfTest`, `Prove`, `Verify`, `LongfellowJwtProve`, `LongfellowJwtVerify`, `BbsKeyGenerate`, `BbsSign`,
`BbsVerify`, `BbsProofGenerate`, `BbsProofVerify`, and one `Secdsa...` tool per `secdsa-*` command, and `AnalysisBaseFoldLeakage`, `AnalysisWelchT`,
`AnalysisKolmogorovSmirnov` and `AnalysisChiSquared`. Secrets and bulk inputs go through file paths, not
tool arguments. The packaged
`.mcp/server.json` lets MCP-aware clients discover and launch the server.
