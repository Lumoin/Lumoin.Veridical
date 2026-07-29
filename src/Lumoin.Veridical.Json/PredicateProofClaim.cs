namespace Lumoin.Veridical.Json;

/// <summary>
/// One claim in a supply-chain predicate-proof artifact: a named quantity compared
/// against a public bound inside a fixed-point comparison domain. This carries only
/// the circuit-determining parameters a verifier needs to rebuild the statement —
/// never a measured value, which stays private to the prover.
/// </summary>
/// <remarks>
/// A verifier reconstructs the identical statement circuit from these fields, so
/// they are part of what the proof is bound to: for a constant bound the value is
/// baked into the circuit, and for a public bound the encoded value travels in the
/// artifact's public inputs — either way a mismatch fails verification.
/// </remarks>
public sealed record PredicateProofClaim
{
    /// <summary>The claim's name — its identity within the bundle and the label under which its circuit auxiliaries are derived.</summary>
    public required string Name { get; init; }

    /// <summary>The comparison direction: <c>atLeast</c> (a floor, such as recycled content) or <c>atMost</c> (a ceiling, such as a carbon cap).</summary>
    public required string Direction { get; init; }

    /// <summary>The number of base-10 fractional digits the comparison domain preserves.</summary>
    public required int FractionalDigits { get; init; }

    /// <summary>The inclusive decimal maximum of the comparison domain, as an invariant-culture decimal string.</summary>
    public required string InclusiveMaximum { get; init; }

    /// <summary>How the bound is carried: <c>constant</c> (baked into the circuit) or <c>public</c> (a revealed public input).</summary>
    public required string Bound { get; init; }

    /// <summary>The bound's decimal value for a constant bound, as an invariant-culture decimal string. Absent for a public bound, whose value travels in the artifact's public inputs.</summary>
    public string? Value { get; init; }
}
