using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Field-operation-granularity agreement tests for the constant-time
/// <see cref="Bn254BaseFieldMontgomeryBackend"/> against BigInteger arithmetic over the
/// BN254 base prime. The G1 ladder sweep exercises this backend only with quasi-random
/// projective coordinates; this suite drives add/subtract/multiply/invert directly at the
/// deterministic magnitude edges (zero, one, two, <c>p−1</c>, <c>p−2</c>, <c>(p−1)/2</c>,
/// a single high bit, and full-width pseudorandom values), the operands where a CIOS
/// final-subtraction or borrow-chain defect would hide from a random sweep. It is the
/// BN254 counterpart of the coverage the BLS12-381 base field receives through the Fp2
/// agreement suite.
/// </summary>
[TestClass]
internal sealed class Bn254BaseFieldMontgomeryBackendAgreementTests
{
    /// <summary>The BN254 base-field prime, taken from its single home in the G1 reference.</summary>
    private static BigInteger BaseFieldPrime { get; } = Bn254BigIntegerG1Reference.BaseFieldPrime;

    private static ScalarAddDelegate ConstantTimeAdd { get; } = Bn254BaseFieldMontgomeryBackend.GetAdd();
    private static ScalarSubtractDelegate ConstantTimeSubtract { get; } = Bn254BaseFieldMontgomeryBackend.GetSubtract();
    private static ScalarMultiplyDelegate ConstantTimeMultiply { get; } = Bn254BaseFieldMontgomeryBackend.GetMultiply();
    private static ScalarInvertDelegate ConstantTimeInvert { get; } = Bn254BaseFieldMontgomeryBackend.GetInvert();

    /// <summary>The canonical big-endian byte length of a BN254 base-field element.</summary>
    private const int ElementSize = WellKnownCurves.Bn254BaseFieldSizeBytes;

    /// <summary>The seven hand-picked edge values; the pseudorandom tail follows them in the block.</summary>
    private const int EdgeValueCount = 7;

    /// <summary>Full-width pseudorandom values beyond the edges.</summary>
    private const int SampleValueCount = 9;

    private const int ValueCount = EdgeValueCount + SampleValueCount;

    /// <summary>
    /// The highest bit position that fits the 254-bit base field: 2^253 &lt; p, giving the
    /// minimal-Hamming-weight value at full bit width.
    /// </summary>
    private const int ValueHighBitShift = 253;

    /// <summary>
    /// Multiplier and increment of a small deterministic linear congruence, used only to derive the
    /// pseudorandom tail reproducibly; the exact constants are arbitrary. The warm-up round runs the
    /// recurrence once before the tail is taken, so already the first tail value has been widened by
    /// the shift-and-reduce step.
    /// </summary>
    private static BigInteger SampleMultiplier { get; } = new(0x9E3779B97F4A7C15);
    private static BigInteger SampleIncrement { get; } = new(0xD1B54A32D192ED03);
    private const int SampleWarmupRounds = 1;


    [TestMethod]
    public void BinaryOperationsAgreeWithBigIntegerAcrossValuePairs()
    {
        Span<BigInteger> values = new BigInteger[ValueCount];
        BuildValueBlock(values);

        Span<byte> left = stackalloc byte[ElementSize];
        Span<byte> right = stackalloc byte[ElementSize];
        Span<byte> expected = stackalloc byte[ElementSize];
        Span<byte> actual = stackalloc byte[ElementSize];
        for(int i = 0; i < ValueCount; i++)
        {
            WriteCanonical(values[i], left);
            for(int j = 0; j < ValueCount; j++)
            {
                WriteCanonical(values[j], right);

                WriteCanonical(Mod(values[i] + values[j]), expected);
                ConstantTimeAdd(left, right, actual, CurveParameterSet.None);
                Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time BN254 base-field addition diverged from BigInteger at pair ({i}, {j}).");

                WriteCanonical(Mod(values[i] - values[j]), expected);
                ConstantTimeSubtract(left, right, actual, CurveParameterSet.None);
                Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time BN254 base-field subtraction diverged from BigInteger at pair ({i}, {j}).");

                WriteCanonical(Mod(values[i] * values[j]), expected);
                ConstantTimeMultiply(left, right, actual, CurveParameterSet.None);
                Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time BN254 base-field multiplication diverged from BigInteger at pair ({i}, {j}).");
            }
        }
    }


    [TestMethod]
    public void InversionAgreesWithBigIntegerAcrossValues()
    {
        Span<BigInteger> values = new BigInteger[ValueCount];
        BuildValueBlock(values);

        Span<byte> operand = stackalloc byte[ElementSize];
        Span<byte> expected = stackalloc byte[ElementSize];
        Span<byte> actual = stackalloc byte[ElementSize];

        //Slot 0 holds zero, which is not invertible; the sweep starts past it.
        for(int i = 1; i < ValueCount; i++)
        {
            WriteCanonical(values[i], operand);
            WriteCanonical(BigInteger.ModPow(values[i], BaseFieldPrime - 2, BaseFieldPrime), expected);
            ConstantTimeInvert(operand, actual, CurveParameterSet.None);

            Assert.IsTrue(expected.SequenceEqual(actual), $"Constant-time BN254 base-field inversion diverged from BigInteger at value {i}.");
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
    /// Lays out the seven edge values followed by the full-width pseudorandom tail; slot 0 is zero.
    /// </summary>
    private static void BuildValueBlock(Span<BigInteger> values)
    {
        values[0] = BigInteger.Zero;
        values[1] = BigInteger.One;
        values[2] = 2;
        values[3] = BaseFieldPrime - 1;
        values[4] = BaseFieldPrime - 2;
        values[5] = (BaseFieldPrime - 1) / 2;
        values[6] = BigInteger.One << ValueHighBitShift;

        BigInteger state = SampleIncrement;
        for(int warmup = 0; warmup < SampleWarmupRounds; warmup++)
        {
            state = (((state * SampleMultiplier) + SampleIncrement) << 128) % BaseFieldPrime;
        }

        for(int i = EdgeValueCount; i < ValueCount; i++)
        {
            state = ((state * SampleMultiplier) + SampleIncrement + i) % BaseFieldPrime;
            state = (state << 128) % BaseFieldPrime;
            values[i] = state;
        }
    }


    private static BigInteger Mod(BigInteger value)
    {
        BigInteger reduced = value % BaseFieldPrime;
        if(reduced.Sign < 0)
        {
            reduced += BaseFieldPrime;
        }

        return reduced;
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("A base-field value did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
