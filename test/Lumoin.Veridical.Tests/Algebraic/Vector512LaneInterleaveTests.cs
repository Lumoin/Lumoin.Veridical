using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Pins, with known inputs, the <see cref="Vector512{T}"/> lane semantics
/// the AVX-512 octet load and store rely on beyond what
/// <c>VectorLaneInterleaveTests</c> already pins for <see cref="Vector256{T}"/>:
/// <c>Vector512.Create(Vector256&lt;ulong&gt;, Vector256&lt;ulong&gt;)</c>'s
/// lane placement, <c>GetLower</c>/<c>GetUpper</c> as its inverse, and the
/// full octet load/store round trip built from those two primitives plus
/// the already-pinned <see cref="Vector256{T}"/> transpose.
/// </summary>
/// <remarks>
/// Every assertion in this class runs in an ordinary <see cref="Vector512{T}"/>
/// software path and needs no particular host CPU feature — <see cref="Vector512{T}"/>
/// falls back to a software implementation on hosts without AVX-512, so this
/// class is not gated on any <c>IsSupported</c> check, unlike the
/// AVX-512-specific backend agreement tests elsewhere in this namespace.
/// </remarks>
[TestClass]
internal sealed class Vector512LaneInterleaveTests
{
    /// <summary>The number of canonical bytes that make up one scalar.</summary>
    private const int ScalarByteCount = 32;

    /// <summary>The number of canonical bytes that make up one 64-bit limb.</summary>
    private const int BytesPerLimb = sizeof(ulong);

    /// <summary>The number of 64-bit limbs that compose one scalar.</summary>
    private const int LimbCount = 4;

    /// <summary>The number of independent scalars packed into one SIMD octet.</summary>
    private const int ScalarsPerOctet = 8;

    /// <summary>The number of canonical bytes per scalar octet (eight scalars, each <see cref="ScalarByteCount"/> bytes).</summary>
    private const int OctetByteCount = ScalarsPerOctet * ScalarByteCount;

    /// <summary>The number of <see cref="ulong"/> lanes in a <see cref="Vector512{T}"/>.</summary>
    private const int UInt64LaneCountPerVector512 = 8;

    /// <summary>The canonical byte offset of limb 0 (the least-significant limb), the top of the descending <c>24, 16, 8, 0</c> sequence <see cref="LoadScalarLimbs"/> reproduces per limb.</summary>
    private const int TopByteOffset = ScalarByteCount - BytesPerLimb;


    /// <summary>
    /// Lane law assumed: <c>Vector512.Create(lower, upper)</c> places
    /// the four lanes of <c>lower</c> at positions 0-3 and the four lanes
    /// of <c>upper</c> at positions 4-7, unmixed.
    /// </summary>
    [TestMethod]
    public void Vector512CreateFromTwoVector256PlacesLowerInLanesZeroToThreeAndUpperInLanesFourToSeven()
    {
        Vector256<ulong> lower = Vector256.Create(0UL, 1UL, 2UL, 3UL);
        Vector256<ulong> upper = Vector256.Create(4UL, 5UL, 6UL, 7UL);
        Vector512<ulong> combined = Vector512.Create(lower, upper);

        for(int laneIndex = 0; laneIndex < UInt64LaneCountPerVector512; laneIndex++)
        {
            ulong expected = (ulong)laneIndex;
            ulong actual = combined.GetElement(laneIndex);

            Assert.AreEqual(expected, actual, $"lane {laneIndex} of Vector512.Create(lower, upper) must equal {expected}.");
        }
    }


    /// <summary>
    /// Lane law assumed: <c>GetLower</c>/<c>GetUpper</c> invert
    /// <c>Vector512.Create(lower, upper)</c> — each recovers exactly the
    /// half-width vector that built that half of the combined vector.
    /// </summary>
    [TestMethod]
    public void GetLowerAndGetUpperInvertVector512Create()
    {
        Vector256<ulong> lower = Vector256.Create(10UL, 11UL, 12UL, 13UL);
        Vector256<ulong> upper = Vector256.Create(20UL, 21UL, 22UL, 23UL);
        Vector512<ulong> combined = Vector512.Create(lower, upper);

        Assert.AreEqual(lower, combined.GetLower(), "GetLower() must recover the vector passed as the lower half.");
        Assert.AreEqual(upper, combined.GetUpper(), "GetUpper() must recover the vector passed as the upper half.");
    }


    /// <summary>
    /// The property the backends' octet load depends on: lane <c>i</c> of the
    /// transposed <c>limbK</c> vector equals the big-endian 64-bit word read
    /// from scalar <c>i</c>'s canonical bytes at offset <c>24 - 8k</c> —
    /// exactly what a per-limb <see cref="BinaryPrimitives.ReadUInt64BigEndian"/>
    /// loop would produce, for every limb position and every scalar in the octet.
    /// </summary>
    [TestMethod]
    public void LimbLaneIEqualsBigEndianLimbReadOfScalarIAtOffsetTwentyFourMinusEightTimesLimbIndex()
    {
        Span<byte> octetBytes = stackalloc byte[OctetByteCount];
        FillSampleOctetBytes(octetBytes);

        LoadOctet(octetBytes, out Vector512<ulong> limb0, out Vector512<ulong> limb1, out Vector512<ulong> limb2, out Vector512<ulong> limb3);

        Span<Vector512<ulong>> limbs = stackalloc Vector512<ulong>[LimbCount];
        limbs[0] = limb0;
        limbs[1] = limb1;
        limbs[2] = limb2;
        limbs[3] = limb3;

        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int byteOffsetWithinScalar = TopByteOffset - (limbIndex * BytesPerLimb);
            for(int scalarIndex = 0; scalarIndex < ScalarsPerOctet; scalarIndex++)
            {
                ReadOnlySpan<byte> scalarBytes = octetBytes.Slice(scalarIndex * ScalarByteCount, ScalarByteCount);
                ulong expected = BinaryPrimitives.ReadUInt64BigEndian(scalarBytes.Slice(byteOffsetWithinScalar, BytesPerLimb));
                ulong actual = limbs[limbIndex].GetElement(scalarIndex);

                Assert.AreEqual(expected, actual, $"lane {scalarIndex} of limb{limbIndex} must equal scalar {scalarIndex}'s big-endian read at offset {byteOffsetWithinScalar}.");
            }
        }
    }


    /// <summary>
    /// The backends' octet load and store, reproduced independently of the
    /// backends themselves, must round-trip: eight canonical scalars loaded into
    /// four limb-major <see cref="Vector512{T}"/> and stored back must
    /// reproduce the original bytes exactly.
    /// </summary>
    [TestMethod]
    public void OctetRoundTripReproducesTheOriginalCanonicalBytes()
    {
        Span<byte> originalBytes = stackalloc byte[OctetByteCount];
        FillSampleOctetBytes(originalBytes);

        Span<byte> roundTrippedBytes = stackalloc byte[OctetByteCount];

        LoadOctet(originalBytes, out Vector512<ulong> limb0, out Vector512<ulong> limb1, out Vector512<ulong> limb2, out Vector512<ulong> limb3);
        StoreOctet(limb0, limb1, limb2, limb3, roundTrippedBytes);

        for(int i = 0; i < OctetByteCount; i++)
        {
            Assert.AreEqual(originalBytes[i], roundTrippedBytes[i], $"byte {i} must survive the load/store round trip unchanged.");
        }
    }


    /// <summary>Fills <paramref name="destination"/> with <c>OctetByteCount</c> distinct byte values, one per position, so every scalar and every byte position is independently identifiable.</summary>
    private static void FillSampleOctetBytes(Span<byte> destination)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)i;
        }
    }


    /// <summary>
    /// Reproduces the AVX-512 backends' octet load recipe: each
    /// scalar's four limbs are loaded by <see cref="LoadScalarLimbs"/>, the
    /// eight results are transposed in two quartets by <see cref="Transpose"/>,
    /// and each limb position's pair of quartet results is combined into one
    /// <see cref="Vector512{T}"/> by <c>Vector512.Create(lower, upper)</c>.
    /// </summary>
    private static void LoadOctet(
        ReadOnlySpan<byte> octetBytes,
        out Vector512<ulong> limb0,
        out Vector512<ulong> limb1,
        out Vector512<ulong> limb2,
        out Vector512<ulong> limb3)
    {
        Vector256<ulong> scalar0 = LoadScalarLimbs(octetBytes.Slice(0 * ScalarByteCount, ScalarByteCount));
        Vector256<ulong> scalar1 = LoadScalarLimbs(octetBytes.Slice(1 * ScalarByteCount, ScalarByteCount));
        Vector256<ulong> scalar2 = LoadScalarLimbs(octetBytes.Slice(2 * ScalarByteCount, ScalarByteCount));
        Vector256<ulong> scalar3 = LoadScalarLimbs(octetBytes.Slice(3 * ScalarByteCount, ScalarByteCount));
        Vector256<ulong> scalar4 = LoadScalarLimbs(octetBytes.Slice(4 * ScalarByteCount, ScalarByteCount));
        Vector256<ulong> scalar5 = LoadScalarLimbs(octetBytes.Slice(5 * ScalarByteCount, ScalarByteCount));
        Vector256<ulong> scalar6 = LoadScalarLimbs(octetBytes.Slice(6 * ScalarByteCount, ScalarByteCount));
        Vector256<ulong> scalar7 = LoadScalarLimbs(octetBytes.Slice(7 * ScalarByteCount, ScalarByteCount));

        Transpose(scalar0, scalar1, scalar2, scalar3, out Vector256<ulong> limb0QuartetLow, out Vector256<ulong> limb1QuartetLow, out Vector256<ulong> limb2QuartetLow, out Vector256<ulong> limb3QuartetLow);
        Transpose(scalar4, scalar5, scalar6, scalar7, out Vector256<ulong> limb0QuartetHigh, out Vector256<ulong> limb1QuartetHigh, out Vector256<ulong> limb2QuartetHigh, out Vector256<ulong> limb3QuartetHigh);

        limb0 = Vector512.Create(limb0QuartetLow, limb0QuartetHigh);
        limb1 = Vector512.Create(limb1QuartetLow, limb1QuartetHigh);
        limb2 = Vector512.Create(limb2QuartetLow, limb2QuartetHigh);
        limb3 = Vector512.Create(limb3QuartetLow, limb3QuartetHigh);
    }


    /// <summary>
    /// Reproduces the AVX-512 backends' octet store recipe: the inverse
    /// transpose, per half, of <see cref="LoadOctet"/>, followed by
    /// <see cref="StoreScalarLimbs"/> per scalar.
    /// </summary>
    private static void StoreOctet(
        Vector512<ulong> limb0,
        Vector512<ulong> limb1,
        Vector512<ulong> limb2,
        Vector512<ulong> limb3,
        Span<byte> octetBytes)
    {
        Transpose(limb0.GetLower(), limb1.GetLower(), limb2.GetLower(), limb3.GetLower(), out Vector256<ulong> scalar0, out Vector256<ulong> scalar1, out Vector256<ulong> scalar2, out Vector256<ulong> scalar3);
        Transpose(limb0.GetUpper(), limb1.GetUpper(), limb2.GetUpper(), limb3.GetUpper(), out Vector256<ulong> scalar4, out Vector256<ulong> scalar5, out Vector256<ulong> scalar6, out Vector256<ulong> scalar7);

        StoreScalarLimbs(scalar0, octetBytes.Slice(0 * ScalarByteCount, ScalarByteCount));
        StoreScalarLimbs(scalar1, octetBytes.Slice(1 * ScalarByteCount, ScalarByteCount));
        StoreScalarLimbs(scalar2, octetBytes.Slice(2 * ScalarByteCount, ScalarByteCount));
        StoreScalarLimbs(scalar3, octetBytes.Slice(3 * ScalarByteCount, ScalarByteCount));
        StoreScalarLimbs(scalar4, octetBytes.Slice(4 * ScalarByteCount, ScalarByteCount));
        StoreScalarLimbs(scalar5, octetBytes.Slice(5 * ScalarByteCount, ScalarByteCount));
        StoreScalarLimbs(scalar6, octetBytes.Slice(6 * ScalarByteCount, ScalarByteCount));
        StoreScalarLimbs(scalar7, octetBytes.Slice(7 * ScalarByteCount, ScalarByteCount));
    }


    /// <summary>Reads one scalar's 32 canonical big-endian bytes as its four 64-bit limbs, least-significant first — the backends' per-scalar load, reproduced independently here.</summary>
    private static Vector256<ulong> LoadScalarLimbs(ReadOnlySpan<byte> canonical)
    {
        Vector256<byte> canonicalBytes = Vector256.Create(canonical);
        Vector256<byte> littleEndianBytes = Vector256.Reverse(canonicalBytes);

        return littleEndianBytes.AsUInt64();
    }


    /// <summary>Writes one scalar's four 64-bit limbs as its 32 canonical big-endian bytes — the inverse of <see cref="LoadScalarLimbs"/>.</summary>
    private static void StoreScalarLimbs(Vector256<ulong> limbs, Span<byte> canonical)
    {
        Vector256<byte> littleEndianBytes = limbs.AsByte();
        Vector256<byte> canonicalBytes = Vector256.Reverse(littleEndianBytes);

        canonicalBytes.CopyTo(canonical);
    }


    /// <summary>
    /// Pairs sources <c>(v0, v1)</c> and <c>(v2, v3)</c> with <c>ZipLower</c>/
    /// <c>ZipUpper</c>, then assembles the matching half from each pair with
    /// <c>ConcatLowerLower</c>/<c>ConcatUpperUpper</c> — the same 4x4
    /// transpose <c>VectorLaneInterleaveTests</c> pins, reproduced here
    /// (not calling into the backends) so this file's octet load/store
    /// recipes depend only on primitives pinned by a test.
    /// </summary>
    private static void Transpose(
        Vector256<ulong> v0,
        Vector256<ulong> v1,
        Vector256<ulong> v2,
        Vector256<ulong> v3,
        out Vector256<ulong> w0,
        out Vector256<ulong> w1,
        out Vector256<ulong> w2,
        out Vector256<ulong> w3)
    {
        Vector256<ulong> lo01 = Vector256.ZipLower(v0, v1);
        Vector256<ulong> hi01 = Vector256.ZipUpper(v0, v1);
        Vector256<ulong> lo23 = Vector256.ZipLower(v2, v3);
        Vector256<ulong> hi23 = Vector256.ZipUpper(v2, v3);

        w0 = Vector256.ConcatLowerLower(lo01, lo23);
        w1 = Vector256.ConcatUpperUpper(lo01, lo23);
        w2 = Vector256.ConcatLowerLower(hi01, hi23);
        w3 = Vector256.ConcatUpperUpper(hi01, hi23);
    }
}