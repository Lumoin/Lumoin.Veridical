using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Shared scalar-vector arithmetic of the Bulletproofs range proof: power
/// vectors, inner products, and the field-one constant — the pieces both
/// <see cref="BulletproofRangeProver"/> and
/// <see cref="BulletproofRangeVerifier"/> derive from the challenges.
/// </summary>
internal static class BulletproofRangeComputation
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>Writes the field one (canonical big-endian).</summary>
    public static void WriteOne(Span<byte> destination)
    {
        destination.Clear();
        destination[^1] = 0x01;
    }


    /// <summary>Fills <paramref name="destination"/> with the powers <c>base^0 … base^{count−1}</c> as concatenated canonical scalars.</summary>
    public static void BuildPowers(
        ReadOnlySpan<byte> baseScalar,
        Span<byte> destination,
        int count,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        WriteOne(destination[..ScalarSize]);
        for(int i = 1; i < count; i++)
        {
            multiply(destination.Slice((i - 1) * ScalarSize, ScalarSize), baseScalar, destination.Slice(i * ScalarSize, ScalarSize), curve);
        }
    }


    /// <summary>Computes <c>⟨a, b⟩</c> over two concatenated scalar vectors.</summary>
    public static void InnerProduct(
        ReadOnlySpan<byte> a,
        ReadOnlySpan<byte> b,
        int count,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        destination.Clear();
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int i = 0; i < count; i++)
        {
            multiply(a.Slice(i * ScalarSize, ScalarSize), b.Slice(i * ScalarSize, ScalarSize), term, curve);
            add(destination, term, destination, curve);
        }
    }


    /// <summary>Sums the entries of a concatenated scalar vector.</summary>
    public static void SumEntries(
        ReadOnlySpan<byte> entries,
        int count,
        Span<byte> destination,
        ScalarAddDelegate add,
        CurveParameterSet curve)
    {
        destination.Clear();
        for(int i = 0; i < count; i++)
        {
            add(destination, entries.Slice(i * ScalarSize, ScalarSize), destination, curve);
        }
    }


    /// <summary>
    /// Builds the scaled second generator family <c>H'_i = y^{−i} · H_i</c>
    /// the inner-product argument runs over.
    /// </summary>
    public static void BuildScaledHFamily(
        RangeProofKey key,
        ReadOnlySpan<byte> yInversePowers,
        Span<byte> destination,
        G1ScalarMultiplyDelegate g1ScalarMul,
        CurveParameterSet curve)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        for(int i = 0; i < key.BitWidth; i++)
        {
            g1ScalarMul(key.GetGeneratorH(i), yInversePowers.Slice(i * ScalarSize, ScalarSize), destination.Slice(i * g1Size, g1Size), curve);
        }
    }


    /// <summary>Copies the first generator family <c>G_0…G_{n−1}</c> into a working buffer.</summary>
    public static void LoadGFamily(RangeProofKey key, Span<byte> destination, CurveParameterSet curve)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        for(int i = 0; i < key.BitWidth; i++)
        {
            key.GetGeneratorG(i).CopyTo(destination.Slice(i * g1Size, g1Size));
        }
    }
}
