using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A bundle of one curve's G1 (the base-field elliptic-curve group) operations as
/// delegates, plus the curve identity and a hardware-acceleration capability flag.
/// It is the composition seam for G1 backends: an application assembles one backend
/// at startup and passes the bundle's delegates into the protocol code, which
/// continues to accept individual delegates.
/// </summary>
/// <remarks>
/// <para>
/// This mirrors <see cref="ScalarArithmeticBackend"/>: a sealed delegate-bundle with
/// an identity and capability flags. It composes, rather than replaces, the
/// convention of passing individual group delegates into protocol methods, so a
/// heterogeneous backend (for example an accelerated multi-scalar multiplication
/// over portable single-operation arithmetic) is assembled once and surfaced through
/// one object.
/// </para>
/// <para>
/// The four core operations (<see cref="Add"/>, <see cref="Negate"/>,
/// <see cref="ScalarMultiply"/>, <see cref="MultiScalarMultiply"/>) are present on
/// every shipped curve. <see cref="IsOnCurve"/> and
/// <see cref="IsInPrimeOrderSubgroup"/> are nullable because not every curve's
/// backend supplies membership predicates (the P-256 reference, for instance, omits
/// them).
/// </para>
/// <para>
/// Hash-to-curve is deliberately absent from the bundle: this bundle is the
/// ciphersuite-agnostic group law, whereas hash-to-curve is a ciphersuite-keyed map
/// (BLS12-381 ships both an XMD-SHA-256 and an XOF-SHAKE-256 variant). It is exposed
/// as explicit per-ciphersuite factory methods on the curve's managed backend so the
/// suite choice is always conscious. (By contrast the scalar bundle may carry a
/// baked-in hash-to-scalar for a curve that fixes a single expand-message function;
/// the group bundle stays suite-agnostic.)
/// </para>
/// </remarks>
public sealed class G1ArithmeticBackend: IDisposable
{
    private IDisposable? ownedResource;


    /// <summary>The curve whose G1 group these operations are over.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>Adds two G1 points.</summary>
    public G1AddDelegate Add { get; }

    /// <summary>Negates a G1 point.</summary>
    public G1NegateDelegate Negate { get; }

    /// <summary>Multiplies a G1 point by a scalar.</summary>
    public G1ScalarMultiplyDelegate ScalarMultiply { get; }

    /// <summary>Computes a multi-scalar multiplication (the dominant commitment-time operation).</summary>
    public G1MultiScalarMultiplyDelegate MultiScalarMultiply { get; }

    /// <summary>Tests whether bytes decode to a point on the curve; <see langword="null"/> when the backend does not supply it.</summary>
    public G1IsOnCurveDelegate? IsOnCurve { get; }

    /// <summary>Tests whether a point lies in the prime-order subgroup; <see langword="null"/> when the backend does not supply it.</summary>
    public G1IsInPrimeOrderSubgroupDelegate? IsInPrimeOrderSubgroup { get; }

    /// <summary>Whether the bundled operations use host SIMD or other hardware acceleration. A hint for wiring and telemetry, not a behavioural contract.</summary>
    public bool IsHardwareAccelerated { get; }


    /// <summary>Bundles a curve's G1 operations.</summary>
    /// <param name="curve">The curve identity.</param>
    /// <param name="add">Add backend.</param>
    /// <param name="negate">Negate backend.</param>
    /// <param name="scalarMultiply">Scalar-multiply backend.</param>
    /// <param name="multiScalarMultiply">Multi-scalar-multiply backend.</param>
    /// <param name="isOnCurve">Optional on-curve predicate; <see langword="null"/> when the backend does not supply it.</param>
    /// <param name="isInPrimeOrderSubgroup">Optional prime-order-subgroup predicate; <see langword="null"/> when the backend does not supply it.</param>
    /// <param name="isHardwareAccelerated">Whether the bundled operations use hardware acceleration.</param>
    /// <param name="ownedResource">An optional resource the bundle disposes when disposed; <see langword="null"/> when the caller retains ownership.</param>
    /// <exception cref="ArgumentNullException">When any non-optional delegate is <see langword="null"/>.</exception>
    public G1ArithmeticBackend(
        CurveParameterSet curve,
        G1AddDelegate add,
        G1NegateDelegate negate,
        G1ScalarMultiplyDelegate scalarMultiply,
        G1MultiScalarMultiplyDelegate multiScalarMultiply,
        G1IsOnCurveDelegate? isOnCurve = null,
        G1IsInPrimeOrderSubgroupDelegate? isInPrimeOrderSubgroup = null,
        bool isHardwareAccelerated = false,
        IDisposable? ownedResource = null)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(negate);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(multiScalarMultiply);

        Curve = curve;
        Add = add;
        Negate = negate;
        ScalarMultiply = scalarMultiply;
        MultiScalarMultiply = multiScalarMultiply;
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
