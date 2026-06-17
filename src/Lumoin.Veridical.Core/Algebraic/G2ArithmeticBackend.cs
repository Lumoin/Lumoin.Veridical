using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A bundle of one curve's G2 (the twist-curve group over the quadratic extension
/// field) operations as delegates, plus the curve identity and a hardware-
/// acceleration capability flag. It is the composition seam for G2 backends, used
/// only by the pairing-friendly curves (BLS12-381, BN254).
/// </summary>
/// <remarks>
/// <para>
/// This mirrors <see cref="ScalarArithmeticBackend"/> and
/// <see cref="G1ArithmeticBackend"/>: a sealed delegate-bundle with an identity and
/// a capability flag. It composes, rather than replaces, the convention of passing
/// individual group delegates into protocol methods.
/// </para>
/// <para>
/// All operations are required: every shipped G2 backend supplies the group law
/// (<see cref="Add"/>, <see cref="Negate"/>, <see cref="ScalarMultiply"/>) and the
/// membership predicates (<see cref="IsOnCurve"/>,
/// <see cref="IsInPrimeOrderSubgroup"/>). The prime-order-subgroup check is
/// security-relevant on G2 because the twist curve has a large cofactor, so a
/// conforming backend is expected to provide it.
/// </para>
/// </remarks>
public sealed class G2ArithmeticBackend: IDisposable
{
    private IDisposable? ownedResource;


    /// <summary>The curve whose G2 group these operations are over.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>Adds two G2 points.</summary>
    public G2AddDelegate Add { get; }

    /// <summary>Negates a G2 point.</summary>
    public G2NegateDelegate Negate { get; }

    /// <summary>Multiplies a G2 point by a scalar.</summary>
    public G2ScalarMultiplyDelegate ScalarMultiply { get; }

    /// <summary>Tests whether bytes decode to a point on the twist curve.</summary>
    public G2IsOnCurveDelegate IsOnCurve { get; }

    /// <summary>Tests whether a point lies in the G2 prime-order subgroup.</summary>
    public G2IsInPrimeOrderSubgroupDelegate IsInPrimeOrderSubgroup { get; }

    /// <summary>Whether the bundled operations use host SIMD or other hardware acceleration. A hint for wiring and telemetry, not a behavioural contract.</summary>
    public bool IsHardwareAccelerated { get; }


    /// <summary>Bundles a curve's G2 operations.</summary>
    /// <param name="curve">The curve identity.</param>
    /// <param name="add">Add backend.</param>
    /// <param name="negate">Negate backend.</param>
    /// <param name="scalarMultiply">Scalar-multiply backend.</param>
    /// <param name="isOnCurve">On-curve predicate.</param>
    /// <param name="isInPrimeOrderSubgroup">Prime-order-subgroup predicate.</param>
    /// <param name="isHardwareAccelerated">Whether the bundled operations use hardware acceleration.</param>
    /// <param name="ownedResource">An optional resource the bundle disposes when disposed; <see langword="null"/> when the caller retains ownership.</param>
    /// <exception cref="ArgumentNullException">When any non-optional delegate is <see langword="null"/>.</exception>
    public G2ArithmeticBackend(
        CurveParameterSet curve,
        G2AddDelegate add,
        G2NegateDelegate negate,
        G2ScalarMultiplyDelegate scalarMultiply,
        G2IsOnCurveDelegate isOnCurve,
        G2IsInPrimeOrderSubgroupDelegate isInPrimeOrderSubgroup,
        bool isHardwareAccelerated = false,
        IDisposable? ownedResource = null)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(negate);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(isOnCurve);
        ArgumentNullException.ThrowIfNull(isInPrimeOrderSubgroup);

        Curve = curve;
        Add = add;
        Negate = negate;
        ScalarMultiply = scalarMultiply;
        IsOnCurve = isOnCurve;
        IsInPrimeOrderSubgroup = isInPrimeOrderSubgroup;
        IsHardwareAccelerated = isHardwareAccelerated;
        this.ownedResource = ownedResource;
    }


    /// <summary>Disposes the resource the bundle owns, if any. Idempotent.</summary>
    public void Dispose()
    {
        ownedResource?.Dispose();
        ownedResource = null;
    }
}
