using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Cross-implementation agreement tests for the constant-time
/// <see cref="Bls12Curve381ConstantTimeFp2Backend"/> against the BigInteger oracle
/// <see cref="Bls12Curve381BigIntegerFp2Reference"/>. Both work over the same 96-byte
/// <c>[c0 : 48 BE][c1 : 48 BE]</c> element layout, so agreement is a direct byte
/// comparison across a deterministic element block whose components cover the
/// base-field magnitude edges (zero, one, two, <c>p−1</c>, <c>p−2</c>, <c>(p−1)/2</c>,
/// a single high bit, and full-width pseudorandom values).
/// </summary>
[TestClass]
internal sealed class Bls12Curve381ConstantTimeFp2BackendAgreementTests
{
    private static BigInteger BaseFieldPrime { get; } = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;

    private const int ComponentSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;
    private const int ElementSize = 2 * ComponentSize;

    /// <summary>
    /// The seven hand-picked edge components; the pseudorandom tail follows them, and the pairing
    /// below draws two different components per element, so every edge meets every offset
    /// combination over the sweep.
    /// </summary>
    private const int EdgeComponentCount = 7;

    /// <summary>Full-width pseudorandom components beyond the edges.</summary>
    private const int SampleComponentCount = 9;

    private const int ComponentCount = EdgeComponentCount + SampleComponentCount;

    /// <summary>
    /// The offset between the two component indices of one element: coprime to ComponentCount, so the
    /// (c0, c1) pairs walk every component while never pairing a component with itself.
    /// </summary>
    private const int ComponentPairOffset = 5;

    /// <summary>
    /// The highest bit position that fits the 381-bit base field: 2^380 &lt; p, giving the
    /// minimal-Hamming-weight component at full bit width.
    /// </summary>
    private const int ComponentHighBitShift = 380;

    /// <summary>
    /// Multiplier of a small deterministic linear congruence over the component values, used only
    /// to derive the pseudorandom tail reproducibly; the exact constants are arbitrary.
    /// </summary>
    private static BigInteger SampleMultiplier { get; } = new(0x9E3779B97F4A7C15);

    /// <summary>Increment of the tail linear congruence.</summary>
    private static BigInteger SampleIncrement { get; } = new(0xC2B2AE3D27D4EB4F);
    /// <summary>
    /// The warm-up round count runs the recurrence once before the tail is taken, so already the first
    /// tail component has been widened by the shift-and-reduce step.
    /// </summary>
    private const int SampleWarmupRounds = 1;

    private static Fp2AddDelegate ReferenceAdd { get; } = Bls12Curve381BigIntegerFp2Reference.GetAdd();
    private static Fp2SubtractDelegate ReferenceSubtract { get; } = Bls12Curve381BigIntegerFp2Reference.GetSubtract();
    private static Fp2MultiplyDelegate ReferenceMultiply { get; } = Bls12Curve381BigIntegerFp2Reference.GetMultiply();
    private static Fp2InvertDelegate ReferenceInvert { get; } = Bls12Curve381BigIntegerFp2Reference.GetInvert();

    private static ScalarAddDelegate ConstantTimeAdd { get; } = Bls12Curve381ConstantTimeFp2Backend.GetAdd();
    private static ScalarSubtractDelegate ConstantTimeSubtract { get; } = Bls12Curve381ConstantTimeFp2Backend.GetSubtract();
    private static ScalarMultiplyDelegate ConstantTimeMultiply { get; } = Bls12Curve381ConstantTimeFp2Backend.GetMultiply();
    private static ScalarInvertDelegate ConstantTimeInvert { get; } = Bls12Curve381ConstantTimeFp2Backend.GetInvert();


    [TestMethod]
    public void BinaryOperationsAgreeWithReferenceAcrossElementPairs()
    {
        Span<byte> elements = stackalloc byte[ComponentCount * ElementSize];
        BuildElementBlock(elements);

        Span<byte> expected = stackalloc byte[ElementSize];
        Span<byte> actual = stackalloc byte[ElementSize];
        for(int i = 0; i < ComponentCount; i++)
        {
            ReadOnlySpan<byte> left = elements.Slice(i * ElementSize, ElementSize);
            for(int j = 0; j < ComponentCount; j++)
            {
                ReadOnlySpan<byte> right = elements.Slice(j * ElementSize, ElementSize);

                ReferenceAdd(left, right, expected, CurveParameterSet.None);
                ConstantTimeAdd(left, right, actual, CurveParameterSet.None);
                Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time Fp2 addition diverged from the reference at pair ({i}, {j}).");

                ReferenceSubtract(left, right, expected, CurveParameterSet.None);
                ConstantTimeSubtract(left, right, actual, CurveParameterSet.None);
                Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time Fp2 subtraction diverged from the reference at pair ({i}, {j}).");

                ReferenceMultiply(left, right, expected, CurveParameterSet.None);
                ConstantTimeMultiply(left, right, actual, CurveParameterSet.None);
                Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time Fp2 multiplication diverged from the reference at pair ({i}, {j}).");
            }
        }
    }


    [TestMethod]
    public void InversionAgreesWithReferenceAcrossElements()
    {
        Span<byte> elements = stackalloc byte[ComponentCount * ElementSize];
        BuildElementBlock(elements);

        Span<byte> expected = stackalloc byte[ElementSize];
        Span<byte> actual = stackalloc byte[ElementSize];
        for(int i = 0; i < ComponentCount; i++)
        {
            ReadOnlySpan<byte> element = elements.Slice(i * ElementSize, ElementSize);

            ReferenceInvert(element, expected, CurveParameterSet.None);
            ConstantTimeInvert(element, actual, CurveParameterSet.None);
            Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time Fp2 inversion diverged from the reference at element {i}.");
        }
    }


    [TestMethod]
    public void InvertingZeroThrows()
    {
        //The delegate call sits inside the Assert.Throws lambda, so the buffers it touches must be
        //captured by the closure - a stackalloc span cannot be, so heap arrays are unavoidable here.
        byte[] zero = new byte[ElementSize];
        byte[] result = new byte[ElementSize];

        Assert.Throws<InvalidOperationException>(() => ConstantTimeInvert(zero, result, CurveParameterSet.None));
    }


    /// <summary>
    /// Lays out ComponentCount elements: element i pairs component i with component
    /// (i + ComponentPairOffset) mod ComponentCount, so no element is (c, c) and — with the offset
    /// coprime to the count — every component appears in both positions across the block. No element is
    /// (0, 0), so the whole block is invertible.
    /// </summary>
    private static void BuildElementBlock(Span<byte> block)
    {
        Span<BigInteger> components = new BigInteger[ComponentCount];
        components[0] = BigInteger.Zero;
        components[1] = BigInteger.One;
        components[2] = 2;
        components[3] = BaseFieldPrime - 1;
        components[4] = BaseFieldPrime - 2;
        components[5] = (BaseFieldPrime - 1) / 2;
        components[6] = BigInteger.One << ComponentHighBitShift;

        //The pseudorandom tail: a fixed linear congruence reduced into the field, full-width with
        //overwhelming probability after the warm-up rounds.
        BigInteger state = SampleIncrement;
        for(int warmup = 0; warmup < SampleWarmupRounds; warmup++)
        {
            state = (((state * SampleMultiplier) + SampleIncrement) << 128) % BaseFieldPrime;
        }

        for(int i = EdgeComponentCount; i < ComponentCount; i++)
        {
            state = ((state * SampleMultiplier) + SampleIncrement + i) % BaseFieldPrime;
            state = (state << 128) % BaseFieldPrime;
            components[i] = state;
        }

        for(int i = 0; i < ComponentCount; i++)
        {
            Span<byte> element = block.Slice(i * ElementSize, ElementSize);
            WriteCanonicalComponent(components[i], element[..ComponentSize]);
            WriteCanonicalComponent(components[(i + ComponentPairOffset) % ComponentCount], element[ComponentSize..]);
        }
    }


    private static void WriteCanonicalComponent(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("A base-field component did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
