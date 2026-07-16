using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// A public bound for a supply-chain comparison, as either a compile-time
/// constant baked into the circuit or a public-input variable supplied at
/// verification. Both carry the <see cref="FixedPointDomain"/> the comparison
/// happens in and the decimal value; a public-input bound additionally names the
/// variable that carries it. Parameterising the bound this way lets one predicate
/// serve a fixed regulatory value (tamper-evident, bound into the circuit id) or a
/// reusable threshold the verifier chooses, without changing the predicate.
/// </summary>
/// <remarks>
/// A constant bound is validated in-domain at construction — it must encode
/// exactly and lie within the domain maximum — so the circuit needs no range check
/// on it. A public-input bound cannot be checked at construction, so the predicate
/// range-checks the variable in-circuit into the field-safe width <c>[0, 2^Bits)</c>
/// instead; that keeps the difference from wrapping, though (unlike a constant) it
/// is not clamped to the exact domain maximum. For a public-input bound the caller
/// must bind the declared variable to <see cref="Encode"/> in the instance — the
/// value here is what the auxiliaries are computed against.
/// </remarks>
public readonly record struct FixedPointBound
{
    /// <summary>The domain — scale and field-safe width — the bound and the measured value are compared in.</summary>
    public FixedPointDomain Domain { get; }

    /// <summary>The bound's decimal value.</summary>
    public decimal Value { get; }

    /// <summary>The public-input variable carrying the bound, or <see langword="null"/> when the bound is a baked constant.</summary>
    public R1csVariableIndex? PublicInputVariable { get; }


    private FixedPointBound(FixedPointDomain domain, decimal value, R1csVariableIndex? publicInputVariable)
    {
        Domain = domain;
        Value = value;
        PublicInputVariable = publicInputVariable;
    }


    /// <summary>
    /// A bound baked into the circuit as a constant. The value is validated
    /// in-domain now (encoded exactly and within the domain maximum), so the
    /// circuit needs no range check on it.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="value"/> is negative or outside <paramref name="domain"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="value"/> cannot be encoded exactly at the domain's scale.</exception>
    public static FixedPointBound Constant(FixedPointDomain domain, decimal value)
    {
        _ = domain.Encode(value);

        return new FixedPointBound(domain, value, publicInputVariable: null);
    }


    /// <summary>
    /// A bound carried by a public-input variable the caller has declared. The
    /// value is validated in-domain now; the predicate additionally range-checks
    /// the variable in-circuit, since a public input is not known at
    /// circuit-build time.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="value"/> is negative or outside <paramref name="domain"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="value"/> cannot be encoded exactly at the domain's scale.</exception>
    public static FixedPointBound PublicInput(FixedPointDomain domain, decimal value, R1csVariableIndex variable)
    {
        _ = domain.Encode(value);

        return new FixedPointBound(domain, value, variable);
    }


    /// <summary>Whether the bound is carried by a public-input variable rather than baked as a constant.</summary>
    public bool IsPublicInput => PublicInputVariable.HasValue;


    /// <summary>The bound's encoding at the domain's scale.</summary>
    public BigInteger Encode() => Domain.Encode(Value);
}
