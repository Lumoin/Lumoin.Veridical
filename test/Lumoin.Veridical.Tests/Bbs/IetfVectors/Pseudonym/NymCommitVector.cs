using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Pseudonym;

/// <summary>
/// A single CommitWithNym test vector, per
/// <see cref="PseudonymDraftRevision.Identifier"/> Section 12.x.3.
/// CommitWithNym reuses the blind-BBS CoreCommit machinery but
/// appends the prover's fresh <see cref="ProverNym"/> scalar as an
/// implicit extra committed value, so <see cref="MTildes"/> carries
/// one more entry than <see cref="CommittedMessages"/> (the trailing
/// entry blinds <see cref="ProverNym"/>, not a committed message).
/// All byte-typed fields are lowercase hex strings; tests decode them
/// via System.Convert.FromHexString(string) at consumption time so
/// the byte arrays land in pool-rented buffers inside the operation
/// under test.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the draft's sub-section title.</param>
/// <param name="DraftSection">The <see cref="PseudonymDraftRevision.Identifier"/> Appendix section the vector comes from (e.g. "12.1.3.1").</param>
/// <param name="CommittedMessages">Hex of each prover-committed message, in commitment order. Empty list for the no-committed-messages case.</param>
/// <param name="MockedScalarSeed">Hex of the seed fed into <c>mocked_calculate_random_scalars</c> to reproduce <see cref="ProverBlind"/>/<see cref="STilde"/>/<see cref="MTildes"/> deterministically. Set to the canonical IETF pi-prefix seed (the same value for both ciphersuites; recorded per-vector to keep the case self-contained).</param>
/// <param name="MockedScalarDst">Hex of <c>core_api_id || "COMMIT_MOCK_RANDOM_SCALARS_DST_"</c>. Built on the CORE (non-pseudonym) interface api_id. Recorded per-vector to keep the case self-contained even though the value is fixed per ciphersuite.</param>
/// <param name="ProverNym">
/// Hex of the 32-byte canonical big-endian prover_nym scalar
/// CommitWithNym samples fresh per commitment. The draft prints this
/// field as the literal string "undefined" in every vector (a
/// confirmed draft defect — see the inventory in W2.4-NYM-VECTORS.md).
/// The value transcribed here is suite-independent (shared by every
/// vector in both suites, since prover_nym is not ciphersuite-bound)
/// and was recovered from the draft co-author's tooling repository
/// (github.com/Wind4Greg/grotto-bbs-signatures, commit
/// ae45ce7130c0ecf863ec63dfc76c4d9859f98c7e,
/// pseudonym_test/fixture_data/**/nymCommit001.json), then verified
/// against this draft revision three independent ways: (a)
/// prover_nym + signer_nym_entropy mod r == nym_secret using this
/// draft's own printed signer_nym_entropy; (b) this draft's
/// commitment octets (see <see cref="CommitmentWithProof"/>) are
/// byte-identical to the fixture commitment that binds exactly this
/// prover_nym + <see cref="ProverBlind"/> pair; (c) the recovered
/// nym_secret paired with this draft's printed context_id reproduces
/// both suites' printed pseudonym octets exactly (discrete-log
/// uniqueness pins the value). See W2.4-NYM-VECTORS.md for the full
/// three-way proof.
/// </param>
/// <param name="ProverBlind">Hex of the 32-byte canonical big-endian secret_prover_blind scalar CoreCommit produces.</param>
/// <param name="STilde">Hex of the 32-byte canonical big-endian s~ trace scalar (mocked-random-scalars trace, first output after secret_prover_blind).</param>
/// <param name="MTildes">Hex of each 32-byte canonical big-endian m~ trace scalar (mocked-random-scalars trace): one per entry of <see cref="CommittedMessages"/>, in the same order, plus one trailing entry that blinds <see cref="ProverNym"/>.</param>
/// <param name="CommitmentWithProof">Hex of the commitment-with-proof octets CommitWithNym produces; both the expected output (byte-equality target) and the deserialize_and_validate_commit input (returns true for every vector in this family — the published appendix carries no negative commitment vectors).</param>
internal sealed record NymCommitVector(
    string Id,
    string Description,
    string DraftSection,
    IReadOnlyList<string> CommittedMessages,
    string MockedScalarSeed,
    string MockedScalarDst,
    string ProverNym,
    string ProverBlind,
    string STilde,
    IReadOnlyList<string> MTildes,
    string CommitmentWithProof);
