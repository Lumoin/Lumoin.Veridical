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

    /// <summary>The comparison direction: <c>atLeast</c> (a floor) or <c>atMost</c> (a ceiling).</summary>
    public required string Direction { get; init; }

    /// <summary>The number of base-10 fractional digits the comparison domain preserves.</summary>
    public required int FractionalDigits { get; init; }

    /// <summary>The inclusive decimal maximum of the comparison domain, as an invariant-culture decimal string.</summary>
    public required string InclusiveMaximum { get; init; }

    /// <summary>How the bound is carried: <c>constant</c> (baked into the circuit) or <c>public</c> (a revealed public input).</summary>
    public required string Bound { get; init; }

    /// <summary>The bound's decimal value — the regulatory floor or cap — as an invariant-culture decimal string. Required for both bound kinds.</summary>
    public required string BoundValue { get; init; }

    /// <summary>The private measured quantity to prove against the bound, as an invariant-culture decimal string. This value stays local to the prover and never appears in the produced artifact.</summary>
    public required string Measured { get; init; }
}
