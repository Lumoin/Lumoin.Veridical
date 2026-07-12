using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym;

/// <summary>
/// A single BlindSignWithNym / FinalizeBlindSignWithNym test vector,
/// per <see cref="PseudonymDraftRevision.Identifier"/> Section
/// 12.x.4. Because <see cref="NymSecret"/> is a draft defect (see its
/// doc), this family is NOT usable end-to-end as a byte-equality
/// KAT — it is retained to byte-anchor the <see cref="TraceB"/> /
/// <see cref="TraceDomain"/> intermediates that
/// BlindSignWithNym/B_calculate/FinalizeBlindSign transitively
/// exercise. All byte-typed fields are lowercase hex strings; tests
/// decode them via System.Convert.FromHexString(string) at
/// consumption time so the byte arrays land in pool-rented buffers
/// inside the operation under test.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the draft's sub-section title.</param>
/// <param name="DraftSection">The <see cref="PseudonymDraftRevision.Identifier"/> Appendix section the vector comes from (e.g. "12.1.4.1").</param>
/// <param name="SignerSecretKey">Hex of the signer's 32-byte secret key. Both the SHA-256 and the SHAKE-256 sub-section families in this draft print the SAME literal secretKey/publicKey bytes (verified against the raw draft text, not a transcription error) — unlike the core BBS and blind-BBS appendices, which use distinct per-suite key material.</param>
/// <param name="SignerPublicKey">Hex of the signer's 96-byte public key. See <see cref="SignerSecretKey"/> for the cross-suite key-reuse note.</param>
/// <param name="Header">Hex of the header bytes the signer bound into the signature.</param>
/// <param name="Messages">Hex of each signer-known message, in signing order. Empty list for the no-signer-messages case; empty strings denote empty messages.</param>
/// <param name="CommittedMessages">Hex of each prover-committed message, in commitment order. Empty list for the no-committed-messages case.</param>
/// <param name="CommitmentWithProof">Hex of the commitment-with-proof octets from the paired <see cref="NymCommitVector"/> this signature vector reuses as its BlindSignWithNym input.</param>
/// <param name="SignerNymEntropy">Hex of the 32-byte canonical big-endian signer_nym_entropy scalar the signer freshly samples and folds in via <c>nym_secret = prover_nym + signer_nym_entropy mod r</c>. Printed directly by the draft (not a defective field).</param>
/// <param name="ProverBlind">Hex of the 32-byte canonical big-endian secret_prover_blind scalar from the paired commitment vector.</param>
/// <param name="ProverNym">Hex of the 32-byte canonical big-endian prover_nym scalar from the paired commitment vector. See <see cref="NymCommitVector.ProverNym"/> for the recovery provenance (this is the same suite-independent value).</param>
/// <param name="NymSecret">
/// Hex of the 32-byte canonical big-endian nym_secret scalar folded
/// in as an extra message scalar during
/// FinalizeBlindSign/FinalizeBlindSignWithNym. The draft prints this
/// field as the literal string "undefined" in every vector (the same
/// confirmed defect as <see cref="NymCommitVector.ProverNym"/>). The
/// value transcribed here is <c>ProverNym + SignerNymEntropy mod r</c>
/// (suite-independent, shared by every vector in both suites) and was
/// cross-checked to reproduce both suites' printed pseudonym octets
/// exactly; see <see cref="NymCommitVector.ProverNym"/> and
/// W2.4-NYM-VECTORS.md for the full three-way recovery proof.
/// </param>
/// <param name="TraceB">Hex of the 48-byte canonical compressed G1 trace point B that B_calculate computes. The draft prints this field with a stray trailing non-hex character 's' in §12.1.4.1 (SHA-256 suite) — a confirmed draft typo (every other B-bearing field in the same vector family is clean hex); the value recorded here is the clean 48-byte hex with the stray 's' stripped.</param>
/// <param name="TraceDomain">Hex of the 32-byte canonical big-endian trace scalar domain, computed before B per this draft's semantics (settles blind-defect D5 byte-for-byte).</param>
/// <param name="Signature">Hex of the 80-byte blind-with-nym signature octets FinalizeBlindSignWithNym produces.</param>
internal sealed record NymSignatureVector(
    string Id,
    string Description,
    string DraftSection,
    string SignerSecretKey,
    string SignerPublicKey,
    string Header,
    IReadOnlyList<string> Messages,
    IReadOnlyList<string> CommittedMessages,
    string CommitmentWithProof,
    string SignerNymEntropy,
    string ProverBlind,
    string ProverNym,
    string NymSecret,
    string TraceB,
    string TraceDomain,
    string Signature);
