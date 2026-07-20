using System.Collections.Generic;

namespace Lumoin.Veridical.Json;

/// <summary>
/// The public, transferable record of a supply-chain predicate proof: everything a
/// counterparty needs to rebuild the statement and check the proof with one static
/// binary, but not the plaintext measured quantities themselves — those are the
/// private witness and are not written into the artifact. A verifier rebuilds the
/// identical statement circuit from <see cref="Claims"/>, reconstructs the instance
/// from <see cref="PublicInputs"/>, and checks <see cref="Proof"/> against it under
/// the shared transcript and commitment parameters.
/// </summary>
/// <remarks>
/// The proof attests that the described statement is satisfiable by some hidden
/// witness. It does not, by itself, assert that the description is the compliance
/// claim a reader requires — a verifier therefore presents the described statement
/// so an operator confirms it is the intended one. Serialized to JSON by
/// <see cref="VeridicalPredicateProofJson"/>.
/// </remarks>
public sealed record PredicateProofArtifact
{
    /// <summary>The artifact format identifier and version.</summary>
    public required string Format { get; init; }

    /// <summary>The curve the proof is over, as a lowercase identifier (for example <c>bls12-381</c>).</summary>
    public required string Curve { get; init; }

    /// <summary>The Fiat-Shamir transcript domain label the prover and verifier must share.</summary>
    public required string TranscriptDomain { get; init; }

    /// <summary>The Ligero opened-column query count the proof was produced under.</summary>
    public required int QueryCount { get; init; }

    /// <summary>The Merkle digest size in bytes the Ligero commitment used.</summary>
    public required int DigestBytes { get; init; }

    /// <summary>The ordered claims whose conjunction the proof attests. Carries no measured values.</summary>
    public required IReadOnlyList<PredicateProofClaim> Claims { get; init; }

    /// <summary>The revealed public inputs as Base64 of the canonical big-endian scalars, in public-input declaration order; empty when every bound is a constant.</summary>
    public required string PublicInputs { get; init; }

    /// <summary>The Ligero-backed Spartan proof, Base64-encoded.</summary>
    public required string Proof { get; init; }
}
