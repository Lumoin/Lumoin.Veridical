using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers.Binary;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Agreement gates for the Pippenger G1 multi-scalar multiplication: the
/// bucket method computes the same group element as the naive
/// per-point-ladder reference, so the canonical compressed encoding must be
/// byte-identical — any divergence is a defect in the windowing, the bucket
/// aggregation, or the general Jacobian addition, not a tolerance. Sizes
/// straddle the window-width breakpoints; the edge inputs include zero
/// scalars, the identity point, repeated points, and the maximal canonical
/// scalar.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381PippengerG1BackendTests
{
    private const int PointSize = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
    private const int ScalarSize = 32;

    private static readonly G1MultiScalarMultiplyDelegate ReferenceMsm = Bls12Curve381BigIntegerG1Reference.GetMultiScalarMultiply();
    private static readonly G1MultiScalarMultiplyDelegate PippengerMsm = Bls12Curve381PippengerG1Backend.GetMultiScalarMultiply();
    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;
    private static readonly byte[] DomainSeparationTag = Encoding.UTF8.GetBytes("VERIDICAL-PIPPENGER-AGREEMENT-TEST-V1");


    //Sizes straddle the window-width breakpoints of WindowBitsFor: 1-3 run the
    //2-bit floor, 8/33 the mid widths, 150 a realistic commitment-row size.
    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(8)]
    [DataRow(33)]
    [DataRow(150)]
    public void PippengerMatchesTheNaiveReference(int count)
    {
        byte[] points = BuildPoints(count, salt: 11);
        byte[] scalars = BuildScalars(count, salt: 13);

        Span<byte> expected = stackalloc byte[PointSize];
        Span<byte> actual = stackalloc byte[PointSize];
        ReferenceMsm(points, scalars, count, expected, Curve);
        PippengerMsm(points, scalars, count, actual, Curve);

        Assert.IsTrue(expected.SequenceEqual(actual), $"Pippenger must match the reference MSM at count = {count}.");
    }


    [TestMethod]
    public void PippengerHandlesTheEdgeInputs()
    {
        //Zero scalars, a repeated point, and the maximal canonical scalar in
        //one batch: the buckets must skip zero digits, accumulate duplicates,
        //and carry full-width windows.
        const int Count = 5;
        byte[] points = BuildPoints(Count, salt: 17);
        //Point 3 repeats point 1.
        Array.Copy(points, 1 * PointSize, points, 3 * PointSize, PointSize);

        byte[] scalars = new byte[Count * ScalarSize];
        //scalar 0 stays zero; scalar 1 = 1; scalar 2 = r − 1 (maximal canonical);
        //scalars 3, 4 arbitrary.
        scalars[(1 * ScalarSize) + ScalarSize - 1] = 0x01;
        Span<byte> wide = stackalloc byte[ScalarSize];
        wide.Fill(0xFF);
        Reduce(wide, scalars.AsSpan(2 * ScalarSize, ScalarSize), Curve);
        BuildScalars(2, salt: 19).AsSpan().CopyTo(scalars.AsSpan(3 * ScalarSize));

        Span<byte> expected = stackalloc byte[PointSize];
        Span<byte> actual = stackalloc byte[PointSize];
        ReferenceMsm(points, scalars, Count, expected, Curve);
        PippengerMsm(points, scalars, Count, actual, Curve);

        Assert.IsTrue(expected.SequenceEqual(actual), "Pippenger must match the reference MSM on the edge inputs.");
    }


    [TestMethod]
    public void PippengerOfAllZeroScalarsIsTheIdentity()
    {
        const int Count = 4;
        byte[] points = BuildPoints(Count, salt: 23);
        byte[] scalars = new byte[Count * ScalarSize];

        Span<byte> expected = stackalloc byte[PointSize];
        Span<byte> actual = stackalloc byte[PointSize];
        ReferenceMsm(points, scalars, Count, expected, Curve);
        PippengerMsm(points, scalars, Count, actual, Curve);

        Assert.IsTrue(expected.SequenceEqual(actual), "An all-zero MSM must be the encoded identity on both paths.");
    }


    [TestMethod]
    public void CachingDelegateAgreesAcrossRepeatAndMutatedCalls()
    {
        //The decoded-point cache must serve repeat calls (hit), never serve a
        //mutated buffer stale points (the content digest changes), and keep
        //interleaved sets independent.
        const int Count = 9;
        G1MultiScalarMultiplyDelegate caching = Bls12Curve381PippengerG1Backend.CreateCachingMultiScalarMultiply();

        byte[] firstPoints = BuildPoints(Count, salt: 29);
        byte[] secondPoints = BuildPoints(Count, salt: 31);
        byte[] scalars = BuildScalars(Count, salt: 37);

        Span<byte> expected = stackalloc byte[PointSize];
        Span<byte> actual = stackalloc byte[PointSize];

        //Cold then hot on the first set.
        ReferenceMsm(firstPoints, scalars, Count, expected, Curve);
        caching(firstPoints, scalars, Count, actual, Curve);
        Assert.IsTrue(expected.SequenceEqual(actual), "The cold caching call must match the reference.");
        caching(firstPoints, scalars, Count, actual, Curve);
        Assert.IsTrue(expected.SequenceEqual(actual), "The hot (cached) call must match the reference.");

        //An interleaved second set.
        ReferenceMsm(secondPoints, scalars, Count, expected, Curve);
        caching(secondPoints, scalars, Count, actual, Curve);
        Assert.IsTrue(expected.SequenceEqual(actual), "An interleaved second set must be independent and correct.");

        //Mutate the first buffer: the digest changes, so the cache must not
        //serve the old decoded points.
        firstPoints.AsSpan(0, PointSize).CopyTo(secondPoints.AsSpan(0, PointSize));
        ReferenceMsm(secondPoints, scalars, Count, expected, Curve);
        caching(secondPoints, scalars, Count, actual, Curve);
        Assert.IsTrue(expected.SequenceEqual(actual), "A mutated buffer must produce a fresh, correct result.");
    }


    //Valid prime-order-subgroup points from hash-to-curve over per-index
    //messages — real curve points without needing a generator constant.
    private static byte[] BuildPoints(int count, int salt)
    {
        byte[] points = new byte[count * PointSize];
        Span<byte> message = stackalloc byte[8];
        for(int i = 0; i < count; i++)
        {
            BinaryPrimitives.WriteInt32BigEndian(message[..4], salt);
            BinaryPrimitives.WriteInt32BigEndian(message[4..], i);
            _ = HashToCurve(message, DomainSeparationTag, points.AsSpan(i * PointSize, PointSize), Curve, Tag.Empty);
        }

        return points;
    }


    private static byte[] BuildScalars(int count, int salt)
    {
        byte[] scalars = new byte[count * ScalarSize];
        Lumoin.Veridical.Tests.TestInfrastructure.DeterministicScalarFill.FillCanonical(scalars, salt, Reduce, Curve);

        return scalars;
    }
}
