using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Gates for the non-canonical field-element rejection checks added at the
/// deserialisation boundaries of <see cref="WellKnownCurves.IsCanonicalScalar"/>,
/// <see cref="R1csMatrix.FromSortedTriples"/>, and
/// <see cref="RawR1csWitness.FromCanonical"/>. A value at or above the scalar
/// field order encodes the same residue as the reduced form yet differs in bytes
/// — the "second encoding" malleability class (snarkjs CVE-2023-33252); these
/// tests confirm the gate closes that window before bytes reach the transcript or
/// arithmetic.
/// </summary>
[TestClass]
internal sealed class NonCanonicalRejectionTests
{
    //Scalar byte width: 32 bytes for all wired curves (BLS12-381, BN254, P-256).
    private const int ScalarSize = Scalar.SizeBytes;


    //These tests behaviorally pin the pre-calculated literal byte arrays in
    //WellKnownCurves against the authoritative BigInteger constants returned
    //by GetScalarFieldOrder. If the literals drift from the BigIntegers, the
    //acceptance/rejection assertions will fail.

    [TestMethod]
    [DynamicData(nameof(WiredCurves))]
    public void IsCanonicalScalarAcceptsOrderMinusOne(CurveParameterSet curve)
    {
        Span<byte> orderMinus1 = stackalloc byte[ScalarSize];
        WriteBigEndian(WellKnownCurves.GetScalarFieldOrder(curve) - 1, orderMinus1);

        Assert.IsTrue(
            WellKnownCurves.IsCanonicalScalar(orderMinus1, curve),
            $"order-1 must be accepted as a canonical scalar for {curve}.");
    }


    [TestMethod]
    [DynamicData(nameof(WiredCurves))]
    public void IsCanonicalScalarRejectsTheScalarFieldOrder(CurveParameterSet curve)
    {
        Span<byte> order = stackalloc byte[ScalarSize];
        WriteBigEndian(WellKnownCurves.GetScalarFieldOrder(curve), order);

        Assert.IsFalse(
            WellKnownCurves.IsCanonicalScalar(order, curve),
            $"The scalar field order itself must be rejected for {curve}.");
    }


    [TestMethod]
    [DynamicData(nameof(WiredCurves))]
    public void IsCanonicalScalarRejectsAllOxFF(CurveParameterSet curve)
    {
        //All-0xFF exceeds every wired curve's scalar field order.
        Span<byte> allFf = stackalloc byte[ScalarSize];
        allFf.Fill(0xFF);

        Assert.IsFalse(
            WellKnownCurves.IsCanonicalScalar(allFf, curve),
            $"All-0xFF must be rejected as non-canonical for {curve}.");
    }


    [TestMethod]
    [DynamicData(nameof(WiredCurves))]
    public void IsCanonicalScalarRejectsIncorrectLength(CurveParameterSet curve)
    {
        Span<byte> len0 = Span<byte>.Empty;
        Span<byte> len31 = stackalloc byte[31];
        Span<byte> len33 = stackalloc byte[33];
        len31.Clear();
        len33.Clear();

        Assert.IsFalse(WellKnownCurves.IsCanonicalScalar(len0, curve), $"Zero-length input must be rejected for {curve}.");
        Assert.IsFalse(WellKnownCurves.IsCanonicalScalar(len31, curve), $"31-byte input must be rejected for {curve}.");
        Assert.IsFalse(WellKnownCurves.IsCanonicalScalar(len33, curve), $"33-byte input must be rejected for {curve}.");
    }


    [TestMethod]
    [DynamicData(nameof(BlsAndBn254Curves))]
    public void FromSortedTriplesAcceptsValueAtOrderMinusOne(CurveParameterSet curve)
    {
        byte[] values = AllocateCanonicalArray(WellKnownCurves.GetScalarFieldOrder(curve) - 1);
        int[] rows = [0];
        int[] cols = [0];

        using R1csMatrix matrix = R1csMatrix.FromSortedTriples(
            rows, cols, values, 1, 1, curve, BaseMemoryPool.Shared);

        //The only meaningful assertion is that construction succeeded; the
        //triple round-trip is covered by R1csMatrixTests.
        Assert.AreEqual(1, matrix.NonzeroCount);
    }


    [TestMethod]
    [DynamicData(nameof(BlsAndBn254Curves))]
    public void FromSortedTriplesRejectsValueAtScalarFieldOrder(CurveParameterSet curve)
    {
        //A value equal to the order is the canonical second encoding of 0.
        byte[] values = AllocateCanonicalArray(WellKnownCurves.GetScalarFieldOrder(curve));
        int[] rows = [0];
        int[] cols = [0];

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = R1csMatrix.FromSortedTriples(rows, cols, values, 1, 1, curve, BaseMemoryPool.Shared));
        Assert.Contains("at or above the scalar field order", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    [DynamicData(nameof(BlsAndBn254Curves))]
    public void FromSortedTriplesRejectsValueAboveScalarFieldOrder(CurveParameterSet curve)
    {
        //All-0xFF exceeds every wired curve's scalar field order.
        byte[] values = GC.AllocateUninitializedArray<byte>(ScalarSize);
        values.AsSpan().Fill(0xFF);
        int[] rows = [0];
        int[] cols = [0];

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = R1csMatrix.FromSortedTriples(rows, cols, values, 1, 1, curve, BaseMemoryPool.Shared));
        Assert.Contains("at or above the scalar field order", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    [DynamicData(nameof(BlsAndBn254Curves))]
    public void WitnessFromCanonicalAcceptsOrderMinusOneElements(CurveParameterSet curve)
    {
        //Two elements, each order-1: both must pass the canonicity gate.
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(2 * ScalarSize);
        Span<byte> witness = owner.Memory.Span[..(2 * ScalarSize)];
        BigInteger orderMinus1 = WellKnownCurves.GetScalarFieldOrder(curve) - 1;
        WriteBigEndian(orderMinus1, witness[..ScalarSize]);
        WriteBigEndian(orderMinus1, witness.Slice(ScalarSize, ScalarSize));

        using RawR1csWitness w = RawR1csWitness.FromCanonical(witness, curve, BaseMemoryPool.Shared);

        Assert.AreEqual(2, w.WitnessVariableCount);
    }


    [TestMethod]
    [DynamicData(nameof(BlsAndBn254Curves))]
    public void WitnessFromCanonicalRejectsSecondElementAtScalarFieldOrder(CurveParameterSet curve)
    {
        //The second element (index 1) equals the field order → rejected with
        //a message naming that index.
        byte[] witness = GC.AllocateUninitializedArray<byte>(2 * ScalarSize);
        //Element 0 = order-1 (valid).
        WriteBigEndian(
            WellKnownCurves.GetScalarFieldOrder(curve) - 1,
            witness.AsSpan(0, ScalarSize));
        //Element 1 = order (non-canonical).
        WriteBigEndian(
            WellKnownCurves.GetScalarFieldOrder(curve),
            witness.AsSpan(ScalarSize, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = RawR1csWitness.FromCanonical(witness, curve, BaseMemoryPool.Shared));

        //The error message must name element 1 (the offending index).
        Assert.Contains("element 1", ex.Message, StringComparison.Ordinal);
    }


    public static IEnumerable<object[]> WiredCurves =>
    [
        [CurveParameterSet.Bls12Curve381],
        [CurveParameterSet.Bn254],
        [CurveParameterSet.P256]
    ];


    public static IEnumerable<object[]> BlsAndBn254Curves =>
    [
        [CurveParameterSet.Bls12Curve381],
        [CurveParameterSet.Bn254]
    ];


    /// <summary>
    /// Writes <paramref name="value"/> into <paramref name="destination"/> as a
    /// canonical big-endian byte sequence, right-aligned with leading zero bytes.
    /// </summary>
    private static void WriteBigEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);

        if(written < destination.Length)
        {
            //TryWriteBytes left-aligns the minimal bytes; shift right to
            //produce right-aligned big-endian with leading zero padding.
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    /// <summary>
    /// Allocates a heap byte array (suitable for lambda capture) holding the
    /// big-endian representation of <paramref name="value"/> padded to
    /// <see cref="ScalarSize"/> bytes. Used when the array must survive the
    /// lambda boundary that <c>Assert.ThrowsExactly</c> creates.
    /// </summary>
    private static byte[] AllocateCanonicalArray(BigInteger value)
    {
        byte[] array = GC.AllocateUninitializedArray<byte>(ScalarSize);
        WriteBigEndian(value, array);

        return array;
    }
}
