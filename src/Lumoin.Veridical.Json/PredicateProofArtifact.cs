using System.Collections.Generic;

namespace Lumoin.Veridical.Json;

/// <summary>
/// The public, transferable record of a supply-chain predicate proof: everything a
/// counterparty needs to rebuild the statement and check the proof with one static
/// binary. A verifier rebuilds the identical statement circuit from
/// <see cref="Claims"/>, reconstructs the instance from <see cref="PublicInputs"/>,
/// and checks <see cref="Proof"/> against it under the shared transcript and
/// commitment parameters.
/// </summary>
/// <remarks>
/// The measured quantities are not written into the artifact's JSON fields, but the
/// proof path is binding, not witness-hiding: the openings inside <see cref="Proof"/>
/// reveal committed data in cleartext, and for the wired circuit sizes they determine
/// the full witness — including the measured quantities — by interpolation. Treat the
/// artifact as disclosing the measured values to its recipient; the proof adds
/// integrity, not confidentiality. The proof also does not, by itself, assert that
/// the description is the compliance claim a reader requires — a verifier therefore
/// presents the described statement so an operator confirms it is the intended one.
/// Serialized to JSON by <see cref="VeridicalPredicateProofJson"/>.
/// </remarks>
public sealed record PredicateProofArtifact
{
    /// <summary>The artifact format identifier and version.</summary>
    public required string Format { get; init; }

    /// <summary>The curve the proof is over, as a lowercase identifier (for example <c>bls12-381</c>).</summary>
    public required string Curve { get; init; }

    /// <summary>The Fiat-Shamir transcript domain label the prover and verifier must share.</summary>
    public required string TranscriptDomain { get; init; }

    /// <summary>The Ligero opened-column query count the range-claim proof was produced under.</summary>
    public required int QueryCount { get; init; }

    /// <summary>The Ligero opened-column query count each <c>memberOf</c> claim's lookup proof was produced under. Higher than <see cref="QueryCount"/>: the lookup path opens three independently forgeable columns, so its target carries a union-bound surcharge.</summary>
    public required int LookupQueryCount { get; init; }

    /// <summary>The Ligero inverse code rate <c>c</c> (code rate <c>ρ = 1/c</c>) the proof was produced under.</summary>
    public required int InverseRate { get; init; }

    /// <summary>The Merkle digest size in bytes the Ligero commitment used.</summary>
    public required int DigestBytes { get; init; }

    /// <summary>The ordered claims whose conjunction the proof attests. Carries no measured values.</summary>
    public required IReadOnlyList<PredicateProofClaim> Claims { get; init; }

    /// <summary>The revealed public inputs as Base64 of the canonical big-endian scalars, in public-input declaration order; empty when every bound is a constant or no <c>range</c> claim exists.</summary>
    public required string PublicInputs { get; init; }

    /// <summary>The Ligero-backed Spartan proof over the <c>range</c> claims, Base64-encoded; empty when the bundle carries no <c>range</c> claim.</summary>
    public required string Proof { get; init; }

    /// <summary>The LogUp-over-Ligero lookup proofs, Base64-encoded, one per <c>memberOf</c> claim in claim order; empty when the bundle carries none.</summary>
    public required IReadOnlyList<string> LookupProofs { get; init; }
}
