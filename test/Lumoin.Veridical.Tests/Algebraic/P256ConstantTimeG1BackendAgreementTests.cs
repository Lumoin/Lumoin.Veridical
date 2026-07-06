using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Cross-implementation agreement tests for the constant-time
/// <see cref="P256ConstantTimeG1Backend"/> scalar-multiply delegate against the
/// variable-time BigInteger oracle <see cref="P256BigIntegerG1Reference"/>. Every
/// (point, scalar) pair — the generator, a handful of further valid points derived
/// from it through the reference delegate, and the infinity encoding, crossed with
/// the hand-picked edge scalars and a deterministic full-width sweep — must produce
/// byte-identical SEC1 compressed output, since the constant-time ladder is a drop-in
/// replacement at the ECDSA/SECDSA signing seams. These are microsecond-to-low-millisecond
/// operations, so the suite is not marked <c>[Slow]</c>.
/// </summary>
[TestClass]
internal sealed class P256ConstantTimeG1BackendAgreementTests
{
    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;
    private static readonly BigInteger Order = P256BigIntegerG1Reference.ScalarFieldOrder;

    private static readonly G1ScalarMultiplyDelegate ReferenceScalarMultiply = P256BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G1ScalarMultiplyDelegate ConstantTimeScalarMultiply = P256ConstantTimeG1Backend.GetScalarMultiply();
    private static readonly ScalarReduceDelegate ReferenceReduce = P256BigIntegerScalarReference.GetReduce();

    //SEC1 compressed P-256 point: a 0x02/0x03 parity prefix plus the 32-byte x-coordinate, or the
    //single 0x00 infinity encoding.
    private const int CompressedSize = 33;

    private const int GeneratorPointIndex = 0;

    //Further valid points obtained by multiplying the generator by PointMultipliers through the
    //reference delegate itself — legitimate public points, just not the generator.
    private const int ExtraPointCount = 3;

    private const int PointCount = GeneratorPointIndex + 1 + ExtraPointCount + 1;
    private const int InfinityPointIndex = PointCount - 1;

    //Small scalars used to derive the ExtraPointCount further points; must stay in sync with ExtraPointCount.
    private static readonly int[] PointMultipliers = [2, 3, 7];

    //The eight hand-picked edge residues: 0, 1, 2, n - 1, n, n + 1, a single high bit (2^255), and
    //all-ones - the magnitude and Hamming-weight boundaries a fixed-width ladder is most likely to
    //mishandle relative to the reference's variable-length ladder.
    private const int EdgeScalarCount = 8;

    //Deterministic full-width samples beyond the edges, exercising the general case across every bit
    //position; a few dozen keeps the PointCount x (EdgeScalarCount + SampleScalarCount) sweep in the
    //low seconds while still reproducing exactly run to run.
    private const int SampleScalarCount = 32;

    private const int BlockScalarCount = EdgeScalarCount + SampleScalarCount;

    //Arbitrary but fixed salt, distinct from the streams other agreement suites draw from
    //DeterministicScalarFill, so this suite's samples are an independent, reproducible sequence.
    private const int ScalarFillSalt = 0x9256;

    //The top bit of a 256-bit scalar: minimal Hamming weight at full bit width.
    private const int HighBitShift = 255;


    [TestMethod]
    public void ScalarMultiplyAgreesWithReferenceOnGeneratorAtEdgeScalars()
    {
        Span<byte> generator = stackalloc byte[CompressedSize];
        P256BigIntegerG1Reference.Encode(P256BigIntegerG1Reference.AffinePoint.Generator, generator);

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


    //Shared harness

    //Lays out the point block as the generator, ExtraPointCount further points obtained by multiplying
    //it through the reference delegate, and the infinity encoding.
    private static void BuildPointBlock(Span<byte> block)
    {
        block.Clear();

        Span<byte> generator = block.Slice(GeneratorPointIndex * CompressedSize, CompressedSize);
        P256BigIntegerG1Reference.Encode(P256BigIntegerG1Reference.AffinePoint.Generator, generator);

        Span<byte> scalar = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < PointMultipliers.Length; i++)
        {
            WriteCanonicalBytes(PointMultipliers[i], scalar);
            ReferenceScalarMultiply(generator, scalar, block.Slice((GeneratorPointIndex + 1 + i) * CompressedSize, CompressedSize), Curve);
        }

        P256BigIntegerG1Reference.Encode(P256BigIntegerG1Reference.AffinePoint.Identity, block.Slice(InfinityPointIndex * CompressedSize, CompressedSize));
    }


    //Lays out the scalar block as the EdgeScalarCount edge residues followed by SampleScalarCount
    //deterministic full-width samples.
    private static void BuildScalarBlock(Span<byte> block)
    {
        WriteEdgeScalars(block[..(EdgeScalarCount * Scalar.SizeBytes)]);

        DeterministicScalarFill.FillCanonical(block[(EdgeScalarCount * Scalar.SizeBytes)..], ScalarFillSalt, ReferenceReduce, Curve);
    }


    //Writes the EdgeScalarCount hand-picked edge residues: slot 0 stays zero; slot 1 = 1; slot 2 = 2;
    //slot 3 = n - 1; slot 4 = n; slot 5 = n + 1; slot 6 = a single high bit (2^255); slot 7 = all-ones.
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


    //Writes value as a right-aligned canonical 32-byte big-endian scalar, mirroring the reference's WriteCoordinate.
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
