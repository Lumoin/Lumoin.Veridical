using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Cross-implementation agreement tests for the constant-time
/// <see cref="P256ScalarMontgomeryBackend"/> against the BigInteger oracle
/// <see cref="P256BigIntegerScalarReference"/> over the P-256 scalar field (mod the
/// group order <c>n</c>). Every secret-sensitive operation the SECDSA/ECDSA rewire
/// routes through Montgomery — add, subtract, multiply, negate, reduce, invert — must
/// produce byte-identical canonical output to the reference across a deterministic
/// sweep and the hand-picked edge residues (0 where valid, 1, <c>n − 1</c>); inversion
/// agrees on every nonzero input and, like the reference, throws on zero. These are
/// microsecond operations, so the suite is not marked <c>[Slow]</c>.
/// </summary>
[TestClass]
internal sealed class P256ScalarMontgomeryBackendAgreementTests
{
    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;
    private static readonly BigInteger Order = P256BigIntegerScalarReference.FieldOrder;

    private static readonly ScalarReduceDelegate ReferenceReduce = P256BigIntegerScalarReference.GetReduce();
    private static readonly ScalarAddDelegate ReferenceAdd = P256BigIntegerScalarReference.GetAdd();
    private static readonly ScalarSubtractDelegate ReferenceSubtract = P256BigIntegerScalarReference.GetSubtract();
    private static readonly ScalarMultiplyDelegate ReferenceMultiply = P256BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarNegateDelegate ReferenceNegate = P256BigIntegerScalarReference.GetNegate();
    private static readonly ScalarInvertDelegate ReferenceInvert = P256BigIntegerScalarReference.GetInvert();

    private static readonly ScalarAddDelegate MontgomeryAdd = P256ScalarMontgomeryBackend.GetAdd();
    private static readonly ScalarSubtractDelegate MontgomerySubtract = P256ScalarMontgomeryBackend.GetSubtract();
    private static readonly ScalarMultiplyDelegate MontgomeryMultiply = P256ScalarMontgomeryBackend.GetMultiply();
    private static readonly ScalarNegateDelegate MontgomeryNegate = P256ScalarMontgomeryBackend.GetNegate();
    private static readonly ScalarInvertDelegate MontgomeryInvert = P256ScalarMontgomeryBackend.GetInvert();
    private static readonly ScalarReduceDelegate MontgomeryReduce = P256ScalarMontgomeryBackend.GetReduce();

    //The three edge residues every operation is pinned at: 0 (valid for add/subtract/multiply/negate,
    //non-invertible), 1 (the multiplicative identity), and n − 1 (the additive inverse of 1, the largest
    //canonical scalar) — the boundaries a limb backend is most likely to mishandle.
    private const int EdgeScalarCount = 3;

    //Deterministic full-width samples beyond the edges. A few dozen scalars whose every limb is exercised
    //(DeterministicScalarFill) give the binary ops a (EdgeScalarCount + SampleScalarCount)² pair sweep that
    //still completes in microseconds, while reproducing exactly run to run.
    private const int SampleScalarCount = 48;

    private const int BlockScalarCount = EdgeScalarCount + SampleScalarCount;

    //Distinct fill salts so the wide-reduce inputs are an independent stream from the operand block.
    private const int OperandFillSalt = 0x5EC1;
    private const int WideReduceFillSalt = 0x0DD5;

    //64-byte (512-bit) reduce inputs, each two reduced scalars concatenated as hi‖lo, to exercise the
    //Montgomery hi·2²⁵⁶ + lo reduction path rather than the trivial already-reduced case.
    private const int WideReduceSampleCount = 32;


    private delegate void BinaryScalarOp(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve);


    //The single-element scalar delegate types are distinct named types with identical signatures, so they need a
    //thin adapter to the shared BinaryScalarOp the agreement harness iterates over.
    private static BinaryScalarOp AsBinary(ScalarAddDelegate op) => (a, b, result, curve) => op(a, b, result, curve);

    private static BinaryScalarOp AsBinary(ScalarSubtractDelegate op) => (a, b, result, curve) => op(a, b, result, curve);

    private static BinaryScalarOp AsBinary(ScalarMultiplyDelegate op) => (a, b, result, curve) => op(a, b, result, curve);


    [TestMethod]
    public void AddAgreesWithReference() =>
        AssertBinaryAgrees(AsBinary(ReferenceAdd), AsBinary(MontgomeryAdd), nameof(MontgomeryAdd));


    [TestMethod]
    public void SubtractAgreesWithReference() =>
        AssertBinaryAgrees(AsBinary(ReferenceSubtract), AsBinary(MontgomerySubtract), nameof(MontgomerySubtract));


    [TestMethod]
    public void MultiplyAgreesWithReference() =>
        AssertBinaryAgrees(AsBinary(ReferenceMultiply), AsBinary(MontgomeryMultiply), nameof(MontgomeryMultiply));


    [TestMethod]
    public void NegateAgreesWithReference()
    {
        Span<byte> block = stackalloc byte[BlockScalarCount * Scalar.SizeBytes];
        BuildScalarBlock(block);

        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < BlockScalarCount; i++)
        {
            ReadOnlySpan<byte> a = block.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes);
            ReferenceNegate(a, expected, Curve);
            MontgomeryNegate(a, actual, Curve);

            Assert.IsTrue(expected.SequenceEqual(actual), $"Montgomery negate diverged from the reference at scalar {i}.");
        }
    }


    [TestMethod]
    public void InvertAgreesWithReferenceOnNonzero()
    {
        Span<byte> block = stackalloc byte[BlockScalarCount * Scalar.SizeBytes];
        BuildScalarBlock(block);

        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < BlockScalarCount; i++)
        {
            ReadOnlySpan<byte> a = block.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes);
            if(a.IndexOfAnyExcept((byte)0) < 0)
            {
                //Zero is non-invertible; the throwing contract is asserted by InvertThrowsOnZeroLikeReference.
                continue;
            }

            ReferenceInvert(a, expected, Curve);
            MontgomeryInvert(a, actual, Curve);

            Assert.IsTrue(expected.SequenceEqual(actual), $"Montgomery invert diverged from the reference at scalar {i}.");
        }
    }


    [TestMethod]
    public void InvertProductIsOneOnNonzero()
    {
        Span<byte> block = stackalloc byte[BlockScalarCount * Scalar.SizeBytes];
        BuildScalarBlock(block);

        Span<byte> one = stackalloc byte[Scalar.SizeBytes];
        one[^1] = 1;

        Span<byte> inverse = stackalloc byte[Scalar.SizeBytes];
        Span<byte> product = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < BlockScalarCount; i++)
        {
            ReadOnlySpan<byte> a = block.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes);
            if(a.IndexOfAnyExcept((byte)0) < 0)
            {
                continue;
            }

            MontgomeryInvert(a, inverse, Curve);
            MontgomeryMultiply(a, inverse, product, Curve);

            Assert.IsTrue(product.SequenceEqual(one), $"a·a⁻¹ was not 1 in the Montgomery backend at scalar {i}.");
        }
    }


    [TestMethod]
    public void InvertThrowsOnZeroLikeReference()
    {
        //Both backends reject the non-invertible zero with the same exception type (the public error condition,
        //not a secret whose timing must be hidden); the rewire must not change that contract.
        Assert.ThrowsExactly<InvalidOperationException>(() => InvokeInvertOnZero(ReferenceInvert));
        Assert.ThrowsExactly<InvalidOperationException>(() => InvokeInvertOnZero(MontgomeryInvert));
    }


    [TestMethod]
    public void ReduceAgreesWithReference()
    {
        //32-byte edge inputs, including values at or above n that the canonicalising subtraction must fold down.
        Span<byte> edge = stackalloc byte[Scalar.SizeBytes];

        edge.Clear();
        AssertReduceAgrees(edge);

        WriteCanonicalBytes(Order, edge);
        AssertReduceAgrees(edge);

        WriteCanonicalBytes(Order - 1, edge);
        AssertReduceAgrees(edge);

        WriteCanonicalBytes(Order + 1, edge);
        AssertReduceAgrees(edge);

        edge.Fill(0xFF);
        AssertReduceAgrees(edge);

        //64-byte wide inputs (hi‖lo) exercising the Montgomery hi·2²⁵⁶ + lo reduction.
        Span<byte> halves = stackalloc byte[2 * WideReduceSampleCount * Scalar.SizeBytes];
        DeterministicScalarFill.FillCanonical(halves, WideReduceFillSalt, ReferenceReduce, Curve);
        for(int i = 0; i < WideReduceSampleCount; i++)
        {
            ReadOnlySpan<byte> wide = halves.Slice(i * 2 * Scalar.SizeBytes, 2 * Scalar.SizeBytes);
            AssertReduceAgrees(wide);
        }
    }


    [TestMethod]
    public void MontgomeryRoundTripIsIdentity()
    {
        Span<byte> block = stackalloc byte[BlockScalarCount * Scalar.SizeBytes];
        BuildScalarBlock(block);

        Span<byte> montgomery = stackalloc byte[Scalar.SizeBytes];
        Span<byte> back = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < BlockScalarCount; i++)
        {
            ReadOnlySpan<byte> a = block.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes);
            P256ScalarMontgomeryBackend.ToMontgomery(a, montgomery);
            P256ScalarMontgomeryBackend.FromMontgomery(montgomery, back);

            Assert.IsTrue(a.SequenceEqual(back), $"FromMontgomery(ToMontgomery(a)) was not the identity at scalar {i}.");
        }
    }


    //Shared harness

    private static void AssertBinaryAgrees(BinaryScalarOp reference, BinaryScalarOp candidate, string candidateName)
    {
        Span<byte> block = stackalloc byte[BlockScalarCount * Scalar.SizeBytes];
        BuildScalarBlock(block);

        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < BlockScalarCount; i++)
        {
            ReadOnlySpan<byte> a = block.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes);
            for(int j = 0; j < BlockScalarCount; j++)
            {
                ReadOnlySpan<byte> b = block.Slice(j * Scalar.SizeBytes, Scalar.SizeBytes);
                reference(a, b, expected, Curve);
                candidate(a, b, actual, Curve);

                Assert.IsTrue(expected.SequenceEqual(actual), $"{candidateName} diverged from the reference at scalar pair ({i}, {j}).");
            }
        }
    }


    private static void AssertReduceAgrees(ReadOnlySpan<byte> input)
    {
        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> actual = stackalloc byte[Scalar.SizeBytes];
        ReferenceReduce(input, expected, Curve);
        MontgomeryReduce(input, actual, Curve);

        Assert.IsTrue(expected.SequenceEqual(actual), $"Montgomery reduce diverged from the reference for a {input.Length}-byte input.");
    }


    private static void InvokeInvertOnZero(ScalarInvertDelegate invert)
    {
        Span<byte> zero = stackalloc byte[Scalar.SizeBytes];
        Span<byte> destination = stackalloc byte[Scalar.SizeBytes];
        invert(zero, destination, Curve);
    }


    //Lays out the operand block as the EdgeScalarCount edge residues (0, 1, n − 1) followed by
    //SampleScalarCount deterministic full-width samples.
    private static void BuildScalarBlock(Span<byte> block)
    {
        block.Clear();

        //Slot 0 stays zero; slot 1 = 1; slot 2 = n − 1.
        WriteCanonicalBytes(BigInteger.One, block.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes));
        WriteCanonicalBytes(Order - 1, block.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes));

        DeterministicScalarFill.FillCanonical(block[(EdgeScalarCount * Scalar.SizeBytes)..], OperandFillSalt, ReferenceReduce, Curve);
    }


    //Writes value as a right-aligned canonical 32-byte big-endian scalar, mirroring the reference's WriteCanonical.
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
