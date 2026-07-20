using System.Collections.Generic;

namespace Lumoin.Veridical.Json;

/// <summary>
/// A request to prove a supply-chain predicate bundle: the statement parameters plus
/// the private measured quantities. This is prover-local input — it is read from
/// local data (a file, or an MCP argument) and never leaves the prover; the proof it
/// yields is a <see cref="PredicateProofArtifact"/>, which carries no measured
/// values. Serialized to JSON by <see cref="VeridicalPredicateProofJson"/>.
/// </summary>
public sealed record PredicateProofRequest
{
    /// <summary>The request format identifier and version.</summary>
    public required string Format { get; init; }

    /// <summary>The curve to prove over, as a lowercase identifier (for example <c>bls12-381</c>).</summary>
    public required string Curve { get; init; }

    /// <summary>The Fiat-Shamir transcript domain label to bind the proof to.</summary>
    public required string TranscriptDomain { get; init; }

    /// <summary>The Ligero opened-column query count to prove under.</summary>
    public required int QueryCount { get; init; }

    /// <summary>The Merkle digest size in bytes for the Ligero commitment.</summary>
    public required int DigestBytes { get; init; }

    /// <summary>The ordered claims whose conjunction to prove, each carrying its private measured quantity.</summary>
    public required IReadOnlyList<PredicateProofRequestClaim> Claims { get; init; }
}
