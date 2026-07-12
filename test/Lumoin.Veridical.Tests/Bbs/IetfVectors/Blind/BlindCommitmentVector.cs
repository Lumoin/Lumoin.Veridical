using Lumoin.Veridical.Bbs;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Bbs.IetfVectors.Blind;

/// <summary>
/// A single blind-BBS commitment test vector for CoreCommit and
/// CoreCommitVerify / deserialize_and_validate_commit, covering the
/// prover-side commitment-with-proof construction that a Committer
/// sends to the Signer before blind issuance. Transcribed from
/// <see cref="BlindDraftRevision.CommitmentVectorSourceRevision"/>
/// (still valid under <see cref="BlindDraftRevision.Identifier"/>;
/// CoreCommit is textually unchanged between the two revisions). All
/// byte-typed fields are lowercase hex strings; tests decode them via
/// System.Convert.FromHexString(string) at consumption time so the
/// byte arrays land in pool-rented buffers inside the operation under
/// test.
/// </summary>
/// <param name="Id">A stable identifier for the vector — short, kebab-case, ciphersuite-prefixed.</param>
/// <param name="Description">Human-readable description copied from the upstream fixture's <c>caseName</c>.</param>
/// <param name="DraftSection">The <see cref="BlindDraftRevision.CommitmentVectorSourceRevision"/> Appendix section the vector comes from (e.g. "9.1.3.1").</param>
/// <param name="CommittedMessages">Hex of each prover-committed message, in commitment order. Empty list for the no-committed-messages case.</param>
/// <param name="MockedScalarSeed">Hex of the seed fed into <c>mocked_calculate_random_scalars</c> to reproduce <see cref="ProverBlind"/>/<see cref="STilde"/>/<see cref="MTildes"/> deterministically. Set to the canonical IETF pi-prefix seed (the same value for both ciphersuites; recorded per-vector to keep the case self-contained).</param>
/// <param name="MockedScalarDst">Hex of <c>core_api_id || "COMMIT_MOCK_RANDOM_SCALARS_DST_"</c>. Built on the CORE (non-blind) interface api_id, not the "BLIND_"-prefixed one. Recorded per-vector to keep the case self-contained even though the value is fixed per ciphersuite.</param>
/// <param name="ProverBlind">Hex of the 32-byte canonical big-endian secret_prover_blind scalar CoreCommit produces.</param>
/// <param name="STilde">Hex of the 32-byte canonical big-endian s~ trace scalar (mocked-random-scalars trace, first output after secret_prover_blind).</param>
/// <param name="MTildes">Hex of each 32-byte canonical big-endian m~_i trace scalar (mocked-random-scalars trace), one per committed message, in the same order as <see cref="CommittedMessages"/>.</param>
/// <param name="CommitmentWithProof">Hex of the commitment-with-proof octets (<c>C || s^ || m^_1 || ... || m^_M || challenge</c>) CoreCommit produces; both the expected CoreCommit output (byte-equality target) and the CoreCommitVerify / deserialize_and_validate_commit input (returns true for every vector in this family — the published appendix carries no negative commitment vectors).</param>
internal sealed record BlindCommitmentVector(
    string Id,
    string Description,
    string DraftSection,
    IReadOnlyList<string> CommittedMessages,
    string MockedScalarSeed,
    string MockedScalarDst,
    string ProverBlind,
    string STilde,
    IReadOnlyList<string> MTildes,
    string CommitmentWithProof);
