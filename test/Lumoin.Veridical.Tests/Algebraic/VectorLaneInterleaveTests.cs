using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Pins, with known inputs, the lane semantics of <see cref="Vector256{T}"/>'s
/// quartet lane-interleave primitives — <c>ZipLower</c>, <c>ZipUpper</c>,
/// <c>ConcatLowerLower</c>, <c>ConcatLowerUpper</c>, <c>ConcatUpperLower</c>,
/// <c>ConcatUpperUpper</c>, <c>UnzipEven</c>, and <c>UnzipOdd</c> over
/// <see cref="ulong"/> lanes, and <c>Reverse</c> over <see cref="byte"/>
/// lanes, against known values. These primitives are new enough that their
/// behaviour must be established here by assertion, not assumed from a
/// doc comment.
/// </summary>
/// <remarks>
/// Every assertion in this class runs in an ordinary <see cref="Vector256{T}"/>
/// software path and needs no particular host CPU feature, unlike the
/// AVX2-specific backend agreement tests elsewhere in this namespace, so
/// this class is not gated on any <c>IsSupported</c> check.
/// </remarks>
[TestClass]
internal sealed class VectorLaneInterleaveTests
{
    /// <summary>The number of <see cref="ulong"/> lanes in a <see cref="Vector256{T}"/>.</summary>
    private const int UInt64LaneCount = 4;

    /// <summary>The number of <see cref="byte"/> lanes in a <see cref="Vector256{T}"/>.</summary>
    private const int VectorByteCount = 32;

    /// <summary>The number of canonical bytes that make up one <see cref="ulong"/> limb.</summary>
    private const int BytesPerLimb = sizeof(ulong);


    /// <summary>The first sample quartet named in this class's remarks: lanes <c>(0, 1, 2, 3)</c>.</summary>
    private static Vector256<ulong> SampleA { get; } = Vector256.Create(0UL, 1UL, 2UL, 3UL);

    /// <summary>The second sample quartet named in this class's remarks: lanes <c>(4, 5, 6, 7)</c>.</summary>
    private static Vector256<ulong> SampleB { get; } = Vector256.Create(4UL, 5UL, 6UL, 7UL);

    /// <summary>Thirty-two distinct bytes, one per lane index, so a <see cref="byte"/>-lane permutation is visible in every lane.</summary>
    private static Vector256<byte> SampleCanonicalBytes { get; } = BuildSampleCanonicalBytes();


    /// <summary>Builds a 32-byte vector holding the values <c>0..31</c> in lane order, so a byte-lane permutation is visible in every lane.</summary>
    private static Vector256<byte> BuildSampleCanonicalBytes()
    {
        Span<byte> bytes = stackalloc byte[VectorByteCount];
        for(int i = 0; i < VectorByteCount; i++)
        {
            bytes[i] = (byte)i;
        }

        return Vector256.Create(bytes);
    }


    /// <summary>
    /// Lane law assumed: <c>ZipLower(a, b)</c> interleaves the lower halves of
    /// <c>a</c> and <c>b</c> element-wise, producing <c>(a0, b0, a1, b1)</c>.
    /// </summary>
    [TestMethod]
    public void ZipLowerInterleavesTheLowerHalvesElementWise()
    {
        Vector256<ulong> expected = Vector256.Create(0UL, 4UL, 1UL, 5UL);
        Vector256<ulong> actual = Vector256.ZipLower(SampleA, SampleB);

        Assert.AreEqual(expected, actual, "ZipLower(a, b) must equal (a0, b0, a1, b1).");
    }


    /// <summary>
    /// Lane law assumed: <c>ZipUpper(a, b)</c> interleaves the upper halves of
    /// <c>a</c> and <c>b</c> element-wise, producing <c>(a2, b2, a3, b3)</c>.
    /// </summary>
    [TestMethod]
    public void ZipUpperInterleavesTheUpperHalvesElementWise()
    {
        Vector256<ulong> expected = Vector256.Create(2UL, 6UL, 3UL, 7UL);
        Vector256<ulong> actual = Vector256.ZipUpper(SampleA, SampleB);

        Assert.AreEqual(expected, actual, "ZipUpper(a, b) must equal (a2, b2, a3, b3).");
    }


    /// <summary>
    /// Lane law assumed: <c>ConcatLowerLower(a, b)</c> takes the lower half of
    /// each operand, producing <c>(a0, a1, b0, b1)</c>.
    /// </summary>
    [TestMethod]
    public void ConcatLowerLowerTakesTheLowerHalfOfEachOperand()
    {
        Vector256<ulong> expected = Vector256.Create(0UL, 1UL, 4UL, 5UL);
        Vector256<ulong> actual = Vector256.ConcatLowerLower(SampleA, SampleB);

        Assert.AreEqual(expected, actual, "ConcatLowerLower(a, b) must equal (a0, a1, b0, b1).");
    }


    /// <summary>
    /// Lane law assumed: <c>ConcatLowerUpper(a, b)</c> takes the lower half of
    /// <c>a</c> and the upper half of <c>b</c>, producing <c>(a0, a1, b2, b3)</c>.
    /// </summary>
    [TestMethod]
    public void ConcatLowerUpperTakesTheLowerHalfOfFirstAndTheUpperHalfOfSecond()
    {
        Vector256<ulong> expected = Vector256.Create(0UL, 1UL, 6UL, 7UL);
        Vector256<ulong> actual = Vector256.ConcatLowerUpper(SampleA, SampleB);

        Assert.AreEqual(expected, actual, "ConcatLowerUpper(a, b) must equal (a0, a1, b2, b3).");
    }


    /// <summary>
    /// Lane law assumed: <c>ConcatUpperLower(a, b)</c> takes the upper half of
    /// <c>a</c> and the lower half of <c>b</c>, producing <c>(a2, a3, b0, b1)</c>.
    /// </summary>
    [TestMethod]
    public void ConcatUpperLowerTakesTheUpperHalfOfFirstAndTheLowerHalfOfSecond()
    {
        Vector256<ulong> expected = Vector256.Create(2UL, 3UL, 4UL, 5UL);
        Vector256<ulong> actual = Vector256.ConcatUpperLower(SampleA, SampleB);

        Assert.AreEqual(expected, actual, "ConcatUpperLower(a, b) must equal (a2, a3, b0, b1).");
    }


    /// <summary>
    /// Lane law assumed: <c>ConcatUpperUpper(a, b)</c> takes the upper half of
    /// each operand, producing <c>(a2, a3, b2, b3)</c>.
    /// </summary>
    [TestMethod]
    public void ConcatUpperUpperTakesTheUpperHalfOfEachOperand()
    {
        Vector256<ulong> expected = Vector256.Create(2UL, 3UL, 6UL, 7UL);
        Vector256<ulong> actual = Vector256.ConcatUpperUpper(SampleA, SampleB);

        Assert.AreEqual(expected, actual, "ConcatUpperUpper(a, b) must equal (a2, a3, b2, b3).");
    }


    /// <summary>
    /// Lane law assumed: <c>UnzipEven(a, b)</c> takes the even-indexed
    /// elements of <c>a</c> followed by the even-indexed elements of
    /// <c>b</c>, producing <c>(a0, a2, b0, b2)</c> — the inverse pairing of
    /// <c>ZipLower</c>/<c>ZipUpper</c> read by index parity instead of by half.
    /// </summary>
    [TestMethod]
    public void UnzipEvenTakesTheEvenIndexedElementsOfEachOperand()
    {
        Vector256<ulong> expected = Vector256.Create(0UL, 2UL, 4UL, 6UL);
        Vector256<ulong> actual = Vector256.UnzipEven(SampleA, SampleB);

        Assert.AreEqual(expected, actual, "UnzipEven(a, b) must equal (a0, a2, b0, b2).");
    }


    /// <summary>
    /// Lane law assumed: <c>UnzipOdd(a, b)</c> takes the odd-indexed elements
    /// of <c>a</c> followed by the odd-indexed elements of <c>b</c>,
    /// producing <c>(a1, a3, b1, b3)</c>.
    /// </summary>
    [TestMethod]
    public void UnzipOddTakesTheOddIndexedElementsOfEachOperand()
    {
        Vector256<ulong> expected = Vector256.Create(1UL, 3UL, 5UL, 7UL);
        Vector256<ulong> actual = Vector256.UnzipOdd(SampleA, SampleB);

        Assert.AreEqual(expected, actual, "UnzipOdd(a, b) must equal (a1, a3, b1, b3).");
    }


    /// <summary>
    /// Lane law assumed: <c>Reverse</c> over a 32-lane <see cref="Vector256{T}"/>
    /// of <see cref="byte"/> reverses the whole 32-byte sequence end to end —
    /// lane <c>i</c> of the result equals lane <c>31 - i</c> of the source —
    /// not a per-8-byte or per-16-byte lane-local reversal.
    /// </summary>
    [TestMethod]
    public void ReverseReversesTheWhole32ByteSequence()
    {
        Vector256<byte> source = SampleCanonicalBytes;
        Vector256<byte> reversed = Vector256.Reverse(source);

        for(int i = 0; i < VectorByteCount; i++)
        {
            byte expected = source.GetElement(VectorByteCount - 1 - i);
            byte actual = reversed.GetElement(i);

            Assert.AreEqual(expected, actual, $"byte {i} of the reversed vector must equal byte {VectorByteCount - 1 - i} of the source.");
        }
    }


    /// <summary>
    /// The round trip the kernel's per-scalar load relies on: a canonical
    /// 32-byte big-endian scalar loaded as <see cref="Vector256{T}"/> of
    /// <see cref="byte"/>, reversed, and reinterpreted as
    /// <see cref="Vector256{T}"/> of <see cref="ulong"/> must yield exactly
    /// the four limbs a big-endian scalar read at offsets 24, 16, 8, and 0
    /// would produce, limb 0 least significant — because reversing a
    /// big-endian byte string and reading little-endian words off it in
    /// increasing offset order reproduces the same words a big-endian
    /// reader gets reading in decreasing offset order.
    /// </summary>
    [TestMethod]
    public void ReversedCanonicalBytesReinterpretedAsUInt64MatchBigEndianLimbReads()
    {
        Vector256<byte> canonicalBytes = SampleCanonicalBytes;
        Vector256<byte> littleEndianBytes = Vector256.Reverse(canonicalBytes);
        Vector256<ulong> limbs = littleEndianBytes.AsUInt64();

        Span<byte> canonical = stackalloc byte[VectorByteCount];
        canonicalBytes.CopyTo(canonical);

        for(int limbIndex = 0; limbIndex < UInt64LaneCount; limbIndex++)
        {
            int offset = (UInt64LaneCount - 1 - limbIndex) * BytesPerLimb;
            ulong expected = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(offset, BytesPerLimb));
            ulong actual = limbs.GetElement(limbIndex);

            Assert.AreEqual(expected, actual, $"limb {limbIndex} (canonical offset {offset}) must equal the big-endian scalar read at that offset.");
        }
    }


    /// <summary>
    /// The kernel's quartet load and store share one transpose
    /// implementation because a 4x4 matrix transpose is its own inverse.
    /// This pins that property directly on top of the <c>ZipLower</c>/
    /// <c>ZipUpper</c>/<c>ConcatLowerLower</c>/<c>ConcatUpperUpper</c> lane
    /// laws asserted above: composing the pairing stage and the assembly
    /// stage twice must recover the original four input vectors.
    /// </summary>
    [TestMethod]
    public void ComposingThePairAndAssembleTransposeTwiceRecoversTheOriginalFourVectors()
    {
        Vector256<ulong> v0 = SampleA;
        Vector256<ulong> v1 = SampleB;
        Vector256<ulong> v2 = Vector256.Create(8UL, 9UL, 10UL, 11UL);
        Vector256<ulong> v3 = Vector256.Create(12UL, 13UL, 14UL, 15UL);

        Transpose(v0, v1, v2, v3, out Vector256<ulong> w0, out Vector256<ulong> w1, out Vector256<ulong> w2, out Vector256<ulong> w3);
        Transpose(w0, w1, w2, w3, out Vector256<ulong> r0, out Vector256<ulong> r1, out Vector256<ulong> r2, out Vector256<ulong> r3);

        Assert.AreEqual(v0, r0, "Transposing twice must recover the first input vector.");
        Assert.AreEqual(v1, r1, "Transposing twice must recover the second input vector.");
        Assert.AreEqual(v2, r2, "Transposing twice must recover the third input vector.");
        Assert.AreEqual(v3, r3, "Transposing twice must recover the fourth input vector.");
    }


    /// <summary>
    /// Pairs sources <c>(v0, v1)</c> and <c>(v2, v3)</c> with <c>ZipLower</c>/
    /// <c>ZipUpper</c>, then assembles the matching half from each pair with
    /// <c>ConcatLowerLower</c>/<c>ConcatUpperUpper</c> — independent of, and
    /// not calling into, the kernel's own private transpose helper.
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