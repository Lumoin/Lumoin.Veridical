using System.Collections.Generic;

namespace Lumoin.Veridical.Json;

/// <summary>
/// One claim in a supply-chain predicate-proof artifact: a named quantity compared
/// against a public bound, or proven to be a member of a public allowed-value set,
/// inside a fixed-point domain. This carries only the statement-determining
/// parameters a verifier needs to rebuild the claim — never a measured value.
/// </summary>
/// <remarks>
/// A verifier reconstructs the identical statement from these fields, so they are
/// part of what the proof is bound to: for a <c>range</c> claim the bound is baked
/// into the circuit or travels in the public inputs, and for a <c>memberOf</c> claim
/// the allowed values determine the lookup table the proof's transcript absorbed —
/// either way a mismatch fails verification.
/// </remarks>
public sealed record PredicateProofClaim
{
    /// <summary>The claim's name — its identity within the bundle and the label under which its circuit auxiliaries are derived.</summary>
    public required string Name { get; init; }

    /// <summary>The predicate kind: <c>range</c> (a fixed-point comparison) or <c>memberOf</c> (set membership in <see cref="AllowedValues"/>).</summary>
    public required string Kind { get; init; }

    /// <summary>The comparison direction for a <c>range</c> claim: <c>atLeast</c> (a floor, such as recycled content) or <c>atMost</c> (a ceiling, such as a carbon cap). Absent for <c>memberOf</c>.</summary>
    public string? Direction { get; init; }

    /// <summary>The number of base-10 fractional digits the claim's fixed-point domain preserves.</summary>
    public required int FractionalDigits { get; init; }

    /// <summary>The inclusive decimal maximum of the claim's fixed-point domain, as an invariant-culture decimal string.</summary>
    public required string InclusiveMaximum { get; init; }

    /// <summary>How a <c>range</c> claim's bound is carried: <c>constant</c> (baked into the circuit) or <c>public</c> (a revealed public input). Absent for <c>memberOf</c>.</summary>
    public string? Bound { get; init; }

    /// <summary>A <c>range</c> claim's constant bound value, as an invariant-culture decimal string. Absent for a public bound (whose value travels in the artifact's public inputs) and for <c>memberOf</c>.</summary>
    public string? Value { get; init; }

    /// <summary>A <c>memberOf</c> claim's allowed values, as invariant-culture decimal strings inside the claim's fixed-point domain. Absent for <c>range</c>.</summary>
    public IReadOnlyList<string>? AllowedValues { get; init; }
}
