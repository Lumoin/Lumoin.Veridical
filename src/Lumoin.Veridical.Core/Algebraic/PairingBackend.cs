using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A bundle of one curve's pairing operations: the bilinear map
/// <c>e : G1 × G2 → GT ⊂ Fp12*</c> and the auxiliary target-field operations a
/// pairing-based verifier may use. Used only by the pairing-friendly curves
/// (BLS12-381, BN254).
/// </summary>
/// <remarks>
/// <para>
/// This mirrors <see cref="ScalarArithmeticBackend"/>, <see cref="G1ArithmeticBackend"/>,
/// and <see cref="G2ArithmeticBackend"/>: a sealed delegate-bundle with an identity
/// and a capability flag. The headline operation is <see cref="Pairing"/>;
/// <see cref="Frobenius"/> and <see cref="CyclotomicSquare"/> are auxiliary Fp12
/// operations exposed for callers that drive the final-exponentiation or
/// subgroup-membership machinery directly, and are nullable because a minimal
/// pairing backend need only supply the map itself.
/// </para>
/// </remarks>
public sealed class PairingBackend: IDisposable
{
    private IDisposable? ownedResource;


    /// <summary>The curve this pairing is defined over.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The optimal-ate pairing <c>e : G1 × G2 → Fp12</c>.</summary>
    public PairingDelegate Pairing { get; }

    /// <summary>The Fp12 Frobenius endomorphism <c>x ↦ x^p</c>; <see langword="null"/> when the backend does not supply it.</summary>
    public Fp12FrobeniusDelegate? Frobenius { get; }

    /// <summary>The Fp12 cyclotomic squaring (a specialised square on the cyclotomic subgroup); <see langword="null"/> when the backend does not supply it.</summary>
    public Fp12CyclotomicSquareDelegate? CyclotomicSquare { get; }

    /// <summary>Whether the bundled operations use host SIMD or other hardware acceleration. A hint for wiring and telemetry, not a behavioural contract.</summary>
    public bool IsHardwareAccelerated { get; }


    /// <summary>Bundles a curve's pairing operations.</summary>
    /// <param name="curve">The curve identity.</param>
    /// <param name="pairing">The pairing map.</param>
    /// <param name="frobenius">Optional Fp12 Frobenius; <see langword="null"/> when the backend does not supply it.</param>
    /// <param name="cyclotomicSquare">Optional Fp12 cyclotomic square; <see langword="null"/> when the backend does not supply it.</param>
    /// <param name="isHardwareAccelerated">Whether the bundled operations use hardware acceleration.</param>
    /// <param name="ownedResource">An optional resource the bundle disposes when disposed; <see langword="null"/> when the caller retains ownership.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="pairing"/> is <see langword="null"/>.</exception>
    public PairingBackend(
        CurveParameterSet curve,
        PairingDelegate pairing,
        Fp12FrobeniusDelegate? frobenius = null,
        Fp12CyclotomicSquareDelegate? cyclotomicSquare = null,
        bool isHardwareAccelerated = false,
        IDisposable? ownedResource = null)
    {
        ArgumentNullException.ThrowIfNull(pairing);

        Curve = curve;
        Pairing = pairing;
        Frobenius = frobenius;
        CyclotomicSquare = cyclotomicSquare;
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
