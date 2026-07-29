using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Cross-implementation agreement tests for the constant-time
/// <see cref="Bn254ConstantTimeG1Backend"/> scalar-multiply delegate against the
/// variable-time BigInteger oracle <see cref="Bn254BigIntegerG1Reference"/>. Every
/// (point, scalar) pair — the generator, a handful of further valid points derived
/// from it through the reference delegate, and the infinity encoding, crossed with
/// the hand-picked edge scalars and a deterministic full-width sweep — must produce
/// byte-identical 32-byte gnark-convention compressed output, since the constant-time
/// ladder is a drop-in replacement at the prover-side commitment seams. Byte identity here
/// certifies the ladder arithmetic and normalization; the compressed codec is shared code
/// between the two sides and is separately pinned against EIP-196 and independently
/// computed vectors by the BN254 point-arithmetic suite. These are millisecond-scale
/// operations, so the suite is not marked <c>[Slow]</c>.
/// </summary>
[TestClass]
internal sealed class Bn254ConstantTimeG1BackendAgreementTests
{
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bn254;
    private static BigInteger Order { get; } = Bn254BigIntegerG1Reference.ScalarFieldOrder;

    private static G1ScalarMultiplyDelegate ReferenceScalarMultiply { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();
    private static G1ScalarMultiplyDelegate ConstantTimeScalarMultiply { get; } = Bn254ConstantTimeG1Backend.GetScalarMultiply();
    private static ScalarReduceDelegate ReferenceReduce { get; } = Bn254BigIntegerScalarReference.GetReduce();

    /// <summary>
    /// Compressed BN254 G1 point: the 32-byte x-coordinate with the gnark-style two-bit tag in the top
    /// bits of byte zero.
    /// </summary>
    private const int CompressedSize = WellKnownCurves.Bn254G1CompressedSizeBytes;

    private const int GeneratorPointIndex = 0;

    /// <summary>
    /// Further valid points obtained by multiplying the generator by PointMultipliers through the
    /// reference delegate itself — legitimate public points, just not the generator.
    /// </summary>
    private const int ExtraPointCount = 3;

    private const int PointCount = GeneratorPointIndex + 1 + ExtraPointCount + 1;
    private const int InfinityPointIndex = PointCount - 1;

    /// <summary>
    /// Small scalars used to derive the ExtraPointCount further points; must stay in sync with ExtraPointCount.
    /// </summary>
    private static int[] PointMultipliers { get; } = [2, 3, 7];

    /// <summary>
    /// The eight hand-picked edge residues: 0, 1, 2, r - 1, r, r + 1, a single high bit (2^255), and
    /// all-ones - the magnitude and Hamming-weight boundaries a fixed-width ladder is most likely to
    /// mishandle relative to the reference's variable-length ladder. r and r - 1 also drive the ladder
    /// through the complete formulas' exceptional inputs (the final add of r·P lands on P + (−P) = ∞).
    /// </summary>
    private const int EdgeScalarCount = 8;

    /// <summary>
    /// Deterministic full-width samples beyond the edges, exercising the general case across every bit
    /// position; a few dozen keeps the PointCount x (EdgeScalarCount + SampleScalarCount) sweep in the
    /// low seconds while still reproducing exactly run to run.
    /// </summary>
    private const int SampleScalarCount = 32;

    private const int BlockScalarCount = EdgeScalarCount + SampleScalarCount;

    /// <summary>
    /// Arbitrary but fixed salt, distinct from the streams other agreement suites draw from
    /// DeterministicScalarFill, so this suite's samples are an independent, reproducible sequence.
    /// </summary>
    private const int ScalarFillSalt = 0xB254;

    /// <summary>
    /// The top bit of a 256-bit scalar: minimal Hamming weight at full bit width.
    /// </summary>
    private const int HighBitShift = 255;


    [TestMethod]
    public void ScalarMultiplyAgreesWithReferenceOnGeneratorAtEdgeScalars()
    {
        ReadOnlySpan<byte> generator = WellKnownCurves.GetG1GeneratorCompressed(Curve);

        Span<byte> edgeScalars = stackalloc byte[EdgeScalarCount * Scalar.SizeBytes];
        WriteEdgeScalars(edgeScalars);

        Span<byte> expected = stackalloc byte[CompressedSize];
        Span<byte> actual = stackalloc byte[CompressedSize];
        for(int s = 0; s < EdgeScalarCount; s++)
        {
            ReadOnlySpan<byte> scalar = edgeScalars.Slice(s * Scalar.SizeBytes, Scalar.SizeBytes);
            ReferenceScalarMultiply(generator, scalar, expected, Curve);
            ConstantTimeScalarMultiply(generator, scalar, actual, Curve);

            Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time scalar multiply diverged from the reference on the generator at edge scalar {s}.");
        }
    }


    [TestMethod]
    public void ScalarMultiplyAgreesWithReferenceAcrossPointsAndScalars()
    {
        Span<byte> points = stackalloc byte[PointCount * CompressedSize];
        BuildPointBlock(points);

        Span<byte> scalars = stackalloc byte[BlockScalarCount * Scalar.SizeBytes];
        BuildScalarBlock(scalars);

        Span<byte> expected = stackalloc byte[CompressedSize];
        Span<byte> actual = stackalloc byte[CompressedSize];
        for(int p = 0; p < PointCount; p++)
        {
            ReadOnlySpan<byte> point = points.Slice(p * CompressedSize, CompressedSize);
            for(int s = 0; s < BlockScalarCount; s++)
            {
                ReadOnlySpan<byte> scalar = scalars.Slice(s * Scalar.SizeBytes, Scalar.SizeBytes);
                ReferenceScalarMultiply(point, scalar, expected, Curve);
                ConstantTimeScalarMultiply(point, scalar, actual, Curve);

                Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time scalar multiply diverged from the reference at point {p}, scalar {s}.");
            }
        }
    }


    /// <summary>
    /// Lays out the point block as the generator, ExtraPointCount further points obtained by multiplying
    /// it through the reference delegate, and the infinity encoding.
    /// </summary>
    private static void BuildPointBlock(Span<byte> block)
    {
        block.Clear();

        Span<byte> generator = block.Slice(GeneratorPointIndex * CompressedSize, CompressedSize);
        WellKnownCurves.GetG1GeneratorCompressed(Curve).CopyTo(generator);

        Span<byte> scalar = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < PointMultipliers.Length; i++)
        {
            WriteCanonicalBytes(PointMultipliers[i], scalar);
            ReferenceScalarMultiply(generator, scalar, block.Slice((GeneratorPointIndex + 1 + i) * CompressedSize, CompressedSize), Curve);
        }

        WellKnownCurves.GetG1IdentityCompressed(Curve).CopyTo(block.Slice(InfinityPointIndex * CompressedSize, CompressedSize));
    }


    /// <summary>
    /// Lays out the scalar block as the EdgeScalarCount edge residues followed by SampleScalarCount
    /// deterministic full-width samples.
    /// </summary>
    private static void BuildScalarBlock(Span<byte> block)
    {
        WriteEdgeScalars(block[..(EdgeScalarCount * Scalar.SizeBytes)]);

        DeterministicScalarFill.FillCanonical(block[(EdgeScalarCount * Scalar.SizeBytes)..], ScalarFillSalt, ReferenceReduce, Curve);
    }


    /// <summary>
    /// Writes the EdgeScalarCount hand-picked edge residues: slot 0 stays zero; slot 1 = 1; slot 2 = 2;
    /// slot 3 = r - 1; slot 4 = r; slot 5 = r + 1; slot 6 = a single high bit (2^255); slot 7 = all-ones.
    /// </summary>
    private static void WriteEdgeScalars(Span<byte> block)
    {
        block.Clear();

        WriteCanonicalBytes(BigInteger.One, block.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes));
        WriteCanonicalBytes(2, block.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes));
        WriteCanonicalBytes(Order - 1, block.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes));
        WriteCanonicalBytes(Order, block.Slice(4 * Scalar.SizeBytes, Scalar.SizeBytes));
        WriteCanonicalBytes(Order + 1, block.Slice(5 * Scalar.SizeBytes, Scalar.SizeBytes));
        WriteCanonicalBytes(BigInteger.One << HighBitShift, block.Slice(6 * Scalar.SizeBytes, Scalar.SizeBytes));
        block.Slice(7 * Scalar.SizeBytes, Scalar.SizeBytes).Fill(0xFF);
    }


    /// <summary>
    /// Writes value as a right-aligned canonical 32-byte big-endian scalar.
    /// </summary>
    private static void WriteCanonicalBytes(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Edge scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
