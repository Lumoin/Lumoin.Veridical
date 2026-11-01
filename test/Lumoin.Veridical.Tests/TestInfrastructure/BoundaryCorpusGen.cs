using CsCheck;
using System.Numerics;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// CsCheck byte-array generators that blend uniform random draws with a small
/// corpus of algebraically significant boundary values (zero, one, the
/// modulus's neighbours, limb-boundary bit patterns) so property sweeps
/// exercise carry-chain edges that uniform sampling alone essentially never
/// reaches.
/// </summary>
/// <remarks>
/// <para>
/// Every generator returns raw, unreduced 32-byte arrays exactly like a plain
/// <c>Gen.Byte.Array[32]</c> draw: callers canonicalize through a backend's
/// reduce delegate the same way they treat a uniform draw, so the boundary
/// values never require test code to perform its own modular arithmetic. The
/// corpus values are computed once from the field modulus via
/// <see cref="BigInteger"/> — that construction lives here, mirroring the
/// hand-picked edge vectors the agreement tests already build (e.g.
/// <c>Fp256FieldBackendAgreementTests.Bytes</c>), not in the property body.
/// </para>
/// <para>
/// <see cref="CanonicalDomain"/> supplies values already folded inside the
/// field (0, 1, 2, the midpoint, the two top neighbours, and limb patterns
/// reduced modulo the field) for algebraic-law sweeps where the operands
/// should already be meaningful field elements before the test's own
/// reduction step. <see cref="RawReduction"/> supplies values that straddle
/// or exceed the modulus (the modulus itself and its immediate neighbours, an
/// all-<c>0xFF</c> fill, single-bit-high limb patterns) for reduce and
/// round-trip paths that must accept any same-width input.
/// </para>
/// </remarks>
internal static class BoundaryCorpusGen
{
    /// <summary>The width in bytes of one canonical big-endian field element.</summary>
    private const int ElementSizeBytes = 32;

    /// <summary>
    /// The frequency weight of a uniform draw. Roughly one boundary draw per six uniform draws
    /// is frequent enough that a typical iteration count of a few hundred hits every corpus
    /// entry many times over, and sparse enough that CsCheck's shrinker still has uniform noise
    /// around each failure to work with.
    /// </summary>
    private const int UniformDrawWeight = 6;

    /// <summary>The frequency weight of a boundary draw relative to <see cref="UniformDrawWeight"/>.</summary>
    private const int BoundaryDrawWeight = 1;


    /// <summary>
    /// A generator blending uniform 32-byte draws with boundary values
    /// already folded modulo <paramref name="modulus"/>: 0, 1, 2, the
    /// midpoint <c>(p−1)/2</c>, the top two neighbours <c>p−2</c> and
    /// <c>p−1</c>, the all-ones 256-bit pattern, one single-high-bit pattern
    /// per 64-bit limb, and the alternating fills <c>0xAA</c>/<c>0x55</c> —
    /// each of the limb-pattern entries folded into the field.
    /// </summary>
    /// <param name="modulus">The field modulus the boundary values are computed against.</param>
    public static Gen<byte[]> CanonicalDomain(BigInteger modulus) =>
        Gen.Frequency<byte[]>(
            (UniformDrawWeight, Gen.Byte.Array[ElementSizeBytes]),
            (BoundaryDrawWeight, Gen.OneOf(BoundaryCorpus.CanonicalValues(modulus))));


    /// <summary>
    /// A generator blending uniform 32-byte draws with boundary values that
    /// straddle or exceed <paramref name="modulus"/> without being folded
    /// first: the modulus's immediate neighbours, twice the modulus less one
    /// (when that still fits in 32 bytes), an all-<c>0xFF</c> fill, and a
    /// single high bit set in each 64-bit limb.
    /// </summary>
    /// <param name="modulus">The field modulus the boundary values are computed against.</param>
    public static Gen<byte[]> RawReduction(BigInteger modulus) =>
        Gen.Frequency<byte[]>(
            (UniformDrawWeight, Gen.Byte.Array[ElementSizeBytes]),
            (BoundaryDrawWeight, Gen.OneOf(BoundaryCorpus.RawValues(modulus))));
}
