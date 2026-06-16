using System.Text;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A per-call label that names what is being absorbed or squeezed. Two
/// otherwise-identical absorbs with different operation labels produce
/// different transcript states.
/// </summary>
/// <param name="Value">The label string, typically a hierarchical protocol identifier such as <c>"witness.commitment"</c>, <c>"sumcheck.round.3.challenge"</c>, <c>"hyrax.opening.proof"</c>.</param>
/// <remarks>
/// <para>
/// The operation label is the second line of defence against
/// transcript-confusion attacks (the first is the <see cref="FiatShamirDomainLabel"/>).
/// Inside a single protocol, two values of different kinds — a scalar
/// commitment versus a polynomial commitment, say — should never collide
/// in the hash input, even if their byte representations happen to
/// agree. The labels make the hash input distinguishable by what the
/// bytes represent, not just by what they are.
/// </para>
/// <para>
/// Distinct from <see cref="FiatShamirDomainLabel"/> on purpose: the
/// API surface should refuse to accept an operation label where a
/// domain label is expected, and vice versa. Two semantic types
/// over the same string payload gives the compiler that guarantee.
/// </para>
/// </remarks>
public readonly record struct FiatShamirOperationLabel(string Value)
{
    /// <summary>
    /// Returns the UTF-8 encoding of <see cref="Value"/>. Allocates a
    /// fresh array per access; callers absorbing many values in a
    /// hot loop should cache the result.
    /// </summary>
    public byte[] Bytes => Encoding.UTF8.GetBytes(Value);
}