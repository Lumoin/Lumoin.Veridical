using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym;

/// <summary>
/// A single ProofGenWithNym / ProofVerifyWithNym test vector, per
/// <see cref="PseudonymDraftRevision.Identifier"/> Section 12.x.5.
/// Usable in BOTH directions: ProofVerifyWithNym needs only printed
/// values (public key, proof, headers, context_id, pseudonym,
/// disclosed messages + indexes), and ProofGenWithNym is byte-
/// reproducible too — the draft prints e_tilde/r1_tilde/r3_tilde as
/// the literal "undefined", but the seeded mock-random-scalars stream
/// yields them deterministically at draw positions 2-4 (between the
/// printed r_1/r_2 and the printed m~ block), and the undisclosed
/// message contents come from the §12.x.4.4 signing chain.
/// All byte-typed fields are lowercase hex strings; tests decode them
/// via System.Convert.FromHexString(string) at consumption time so
/// the byte arrays land in pool-rented buffers inside the operation
/// under test.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable, DATA-accurate description of the vector's actual disclosure pattern. For §12.x.5.4/.5/.7 this deliberately differs from the draft's printed sub-section title, which is a copy-paste duplicate of §12.x.5.1's title in all three cases; the disclosed-index sets below are authoritative (see W2.4-NYM-VECTORS.md's title/data mismatch note).</param>
/// <param name="DraftSection">The <see cref="PseudonymDraftRevision.Identifier"/> Appendix section the vector comes from (e.g. "12.1.5.1").</param>
/// <param name="SignerPublicKey">Hex of the signer's 96-byte public key.</param>
/// <param name="Signature">Hex of the 80-byte blind-with-nym signature the proof is constructed against; equals the suite's §12.x.4.4 signature vector byte-for-byte (the chaining the proof tests assert before reusing that vector's message lists).</param>
/// <param name="CommitmentWithProof">Hex of the commitment-with-proof octets from the signing chain that produced <see cref="Signature"/>.</param>
/// <param name="ProverBlind">Hex of the 32-byte canonical big-endian secret_prover_blind scalar from the same signing chain.</param>
/// <param name="Header">Hex of the header bytes the signer bound into <see cref="Signature"/>.</param>
/// <param name="PresentationHeader">Hex of the presentation-header bytes the Prover binds into this proof.</param>
/// <param name="SignerNymEntropy">Hex of the 32-byte canonical big-endian signer_nym_entropy scalar the signer sampled during BlindSignWithNym for this signing chain. Printed directly by the draft.</param>
/// <param name="ProverNym">Hex of the 32-byte canonical big-endian prover_nym scalar for this signing chain. See <see cref="NymCommitVector.ProverNym"/> for the recovery provenance (this is the same suite-independent value).</param>
/// <param name="NymSecret">Hex of the 32-byte canonical big-endian nym_secret scalar for this signing chain (<c>ProverNym + SignerNymEntropy mod r</c>). See <see cref="NymSignatureVector.NymSecret"/> for the recovery provenance.</param>
/// <param name="ContextId">Hex of the verifier-supplied context_id octets that hash_to_curve_g1 turns into the per-verifier generator OP for pseudonym calculation.</param>
/// <param name="Pseudonym">Hex of the 48-byte canonical compressed G1 pseudonym point (<c>[nym_secret]OP</c>) this proof is bound to.</param>
/// <param name="SignerMessageCount">The signer-known message count the Verifier receives as an explicit input, printed by the draft as the trace "L". Distinct from the nym-vector length N (1 for every published vector), which is what <c>combined_header = header || I2OSP(N, 8)</c> binds.</param>
/// <param name="DisclosedMessageIndexes">The indices (into the L-length signer-message vector) of disclosed signer messages, strictly ascending. The upstream fixture prints these as the keys of the <c>revealedMessages</c> map.</param>
/// <param name="DisclosedMessages">Hex of each disclosed signer message, in the same order as <see cref="DisclosedMessageIndexes"/>.</param>
/// <param name="DisclosedCommittedMessageIndexes">The indices (into the prover's committed-message vector) of disclosed committed messages, strictly ascending. The upstream fixture prints these as the keys of the <c>revealedCommittedMessages</c> map.</param>
/// <param name="DisclosedCommittedMessages">Hex of each disclosed committed message, in the same order as <see cref="DisclosedCommittedMessageIndexes"/>.</param>
/// <param name="MockedScalarSeed">Hex of the seed fed into <c>mocked_calculate_random_scalars</c> to reproduce <see cref="TraceR1"/>/<see cref="TraceR2"/>/<see cref="TraceMTildeScalars"/> deterministically. Set to the canonical IETF pi-prefix seed (the same value for both ciphersuites; recorded per-vector to keep the case self-contained).</param>
/// <param name="MockedScalarDst">Hex of <c>core_api_id || "PROOF_MOCK_RANDOM_SCALARS_DST_"</c>. Built on the CORE (non-pseudonym) interface api_id. Recorded per-vector to keep the case self-contained even though the value is fixed per ciphersuite.</param>
/// <param name="TraceR1">Hex of the 32-byte canonical big-endian trace scalar r_1. Printed directly by the draft for every vector (unlike e_tilde/r1_tilde/r3_tilde, which print as "undefined" and are deliberately omitted from this record).</param>
/// <param name="TraceR2">Hex of the 32-byte canonical big-endian trace scalar r_2. Printed directly by the draft for every vector.</param>
/// <param name="TraceMTildeScalars">Hex of each 32-byte canonical big-endian m~ trace scalar (mocked-random-scalars trace), one per undisclosed message across both classes, in draw order. Printed directly by the draft for every vector.</param>
/// <param name="TraceDomain">Hex of the 32-byte canonical big-endian trace scalar domain for this signing chain.</param>
/// <param name="TraceChallenge">Hex of the 32-byte canonical big-endian Fiat-Shamir challenge scalar, also the trailing 32 bytes of <see cref="Proof"/>.</param>
/// <param name="Proof">Hex of the full proof octets; the VerifyProof input (returns true for every vector in this family — the published appendix carries no negative pseudonym-proof vectors).</param>
internal sealed record NymProofVector(
    string Id,
    string Description,
    string DraftSection,
    string SignerPublicKey,
    string Signature,
    string CommitmentWithProof,
    string ProverBlind,
    string Header,
    string PresentationHeader,
    string SignerNymEntropy,
    string ProverNym,
    string NymSecret,
    string ContextId,
    string Pseudonym,
    int SignerMessageCount,
    IReadOnlyList<int> DisclosedMessageIndexes,
    IReadOnlyList<string> DisclosedMessages,
    IReadOnlyList<int> DisclosedCommittedMessageIndexes,
    IReadOnlyList<string> DisclosedCommittedMessages,
    string MockedScalarSeed,
    string MockedScalarDst,
    string TraceR1,
    string TraceR2,
    IReadOnlyList<string> TraceMTildeScalars,
    string TraceDomain,
    string TraceChallenge,
    string Proof);
