using System.Collections.Generic;

namespace Lumoin.Veridical.Json;

/// <summary>
/// One claim in a predicate-proof <em>request</em>: the same statement parameters as
/// a <see cref="PredicateProofClaim"/> plus the private <see cref="Measured"/>
/// quantity the prover proves against. A request is prover-local input; unlike the
/// artifact it produces, it carries the measured value, which never leaves the
/// prover.
/// </summary>
public sealed record PredicateProofRequestClaim
{
    /// <summary>The claim's name — its identity within the bundle and the label under which its circuit auxiliaries are derived.</summary>
    public required string Name { get; init; }

    /// <summary>The predicate kind: <c>range</c> (a fixed-point comparison) or <c>memberOf</c> (set membership in <see cref="AllowedValues"/>).</summary>
    public required string Kind { get; init; }

    /// <summary>The comparison direction for a <c>range</c> claim: <c>atLeast</c> (a floor) or <c>atMost</c> (a ceiling). Absent for <c>memberOf</c>.</summary>
    public string? Direction { get; init; }

    /// <summary>The number of base-10 fractional digits the claim's fixed-point domain preserves.</summary>
    public required int FractionalDigits { get; init; }

    /// <summary>The inclusive decimal maximum of the claim's fixed-point domain, as an invariant-culture decimal string.</summary>
    public required string InclusiveMaximum { get; init; }

    /// <summary>How a <c>range</c> claim's bound is carried: <c>constant</c> (baked into the circuit) or <c>public</c> (a revealed public input). Absent for <c>memberOf</c>.</summary>
    public string? Bound { get; init; }

    /// <summary>A <c>range</c> claim's bound value — the regulatory floor or cap — as an invariant-culture decimal string. Absent for <c>memberOf</c>.</summary>
    public string? BoundValue { get; init; }

    /// <summary>A <c>memberOf</c> claim's allowed values, as invariant-culture decimal strings inside the claim's fixed-point domain. Absent for <c>range</c>.</summary>
    public IReadOnlyList<string>? AllowedValues { get; init; }

    /// <summary>The measured quantity to prove against the predicate, as an invariant-culture decimal string. This value is not written into the produced artifact's JSON fields, but the artifact's proof bytes must be treated as disclosing it (see <see cref="PredicateProofArtifact"/>).</summary>
    public required string Measured { get; init; }
}
