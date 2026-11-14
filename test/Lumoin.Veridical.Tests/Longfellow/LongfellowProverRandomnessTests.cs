using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Longfellow;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// The invariants of <see cref="LongfellowProverRandomness"/> (construction check, single-proof use, draw
/// accounting) and the supplier-side checks of <see cref="LongfellowRandomnessChecks"/>, including the
/// boundary values around the P-256 base-field prime.
/// </summary>
[TestClass]
internal sealed class LongfellowProverRandomnessTests
{
    /// <summary>A P-256 base-field element and the width of every checked value, in bytes.</summary>
    private const int FieldElementBytes = 32;

    /// <summary>The number of bytes a draw in the accounting test requests.</summary>
    private const int DrawBytes = 48;

    /// <summary>The byte value a constant source fills with.</summary>
    private const byte ConstantFill = 0x5A;


    /// <summary>Pins that a null fill delegate is rejected at construction.</summary>
    [TestMethod]
    public void ConstructionRejectsANullSource()
    {
        Assert.ThrowsExactly<ArgumentNullException>(
            () => new LongfellowProverRandomness(null!),
            "A null entropy source must reject at construction.");
    }


    /// <summary>Pins that the stream serves one proof: the first take succeeds and every later take throws.</summary>
    [TestMethod]
    public void ASpentStreamCannotServeASecondProof()
    {
        LongfellowProverRandomness randomness = TestLongfellowPrimitives.NewProverRandomness();
        Assert.IsFalse(randomness.IsSpent, "A fresh stream is unspent.");

        _ = randomness.Take();

        Assert.IsTrue(randomness.IsSpent, "Taking the stream spends it.");
        Assert.ThrowsExactly<InvalidOperationException>(
            () => randomness.Take(),
            "A spent stream must not serve a second proof.");
    }


    /// <summary>Pins that the drawn bytes come from the wrapped source and are counted.</summary>
    [TestMethod]
    public void DrawsComeFromTheSourceAndAreCounted()
    {
        LongfellowProverRandomness randomness = new(destination => destination.Fill(ConstantFill));
        Assert.AreEqual(0L, randomness.BytesDrawn, "No bytes are drawn before a proof takes the stream.");

        LongfellowRandomByteSource source = randomness.Take();
        Span<byte> first = stackalloc byte[DrawBytes];
        Span<byte> second = stackalloc byte[FieldElementBytes];
        source(first);
        source(second);

        Assert.IsLessThan(0, first.IndexOfAnyExcept(ConstantFill), "The first draw must carry the source's bytes.");
        Assert.IsLessThan(0, second.IndexOfAnyExcept(ConstantFill), "The second draw must carry the source's bytes.");
        Assert.AreEqual((long)(DrawBytes + FieldElementBytes), randomness.BytesDrawn, "Every drawn byte must be counted.");
    }


    /// <summary>Pins that the prime itself and the values above it are not canonical, while prime minus one is the largest canonical element.</summary>
    [TestMethod]
    public void BaseFieldPrimeBoundaryValuesAreClassifiedExactly()
    {
        BigInteger prime = P256BigIntegerG1Reference.BaseFieldPrime;
        Span<byte> value = stackalloc byte[FieldElementBytes];

        WriteBigEndian(prime - 1, value);
        Assert.IsTrue(((ReadOnlySpan<byte>)value).IsBelowP256BaseFieldPrime(), "Prime minus one is canonical.");

        WriteBigEndian(prime, value);
        Assert.IsFalse(((ReadOnlySpan<byte>)value).IsBelowP256BaseFieldPrime(), "The prime itself is not canonical.");

        WriteBigEndian(prime + 1, value);
        Assert.IsFalse(((ReadOnlySpan<byte>)value).IsBelowP256BaseFieldPrime(), "Prime plus one is not canonical.");

        WriteBigEndian(BigInteger.Zero, value);
        Assert.IsTrue(((ReadOnlySpan<byte>)value).IsBelowP256BaseFieldPrime(), "Zero is canonical.");

        WriteBigEndian(BigInteger.One, value);
        Assert.IsTrue(((ReadOnlySpan<byte>)value).IsBelowP256BaseFieldPrime(), "One is canonical.");

        value.Fill(byte.MaxValue);
        Assert.IsFalse(((ReadOnlySpan<byte>)value).IsBelowP256BaseFieldPrime(), "The all-0xFF value is above the prime.");
    }


    /// <summary>Pins that a value that is not exactly one field element wide is never canonical.</summary>
    [TestMethod]
    public void WrongWidthValuesAreNotCanonical()
    {
        Span<byte> shorter = stackalloc byte[FieldElementBytes - 1];
        Span<byte> longer = stackalloc byte[FieldElementBytes + 1];

        Assert.IsFalse(((ReadOnlySpan<byte>)shorter).IsBelowP256BaseFieldPrime(), "A 31-byte value is rejected.");
        Assert.IsFalse(((ReadOnlySpan<byte>)longer).IsBelowP256BaseFieldPrime(), "A 33-byte value is rejected.");
        Assert.IsFalse(ReadOnlySpan<byte>.Empty.IsBelowP256BaseFieldPrime(), "An empty value is rejected.");
    }


    /// <summary>Pins the all-zero check on empty, zero, last-byte-set and first-byte-set values.</summary>
    [TestMethod]
    public void AllZeroDetectionSeesEveryByte()
    {
        Span<byte> value = stackalloc byte[FieldElementBytes];

        Assert.IsFalse(((ReadOnlySpan<byte>)value).IsNotAllZero(), "An all-zero value is flagged.");
        Assert.IsFalse(ReadOnlySpan<byte>.Empty.IsNotAllZero(), "An empty value is flagged.");

        value[0] = 1;
        Assert.IsTrue(((ReadOnlySpan<byte>)value).IsNotAllZero(), "A set first byte is seen.");

        value.Clear();
        value[FieldElementBytes - 1] = 1;
        Assert.IsTrue(((ReadOnlySpan<byte>)value).IsNotAllZero(), "A set last byte is seen.");
    }


    /// <summary>Pins that the source check accepts a secure generator and rejects zero, constant and repeating sources.</summary>
    [TestMethod]
    public void SourceCheckSeparatesHealthyAndDegenerateSources()
    {
        Assert.IsTrue(TestLongfellowPrimitives.Entropy.ProducesDistinctNonZeroDraws(), "The system generator passes.");

        LongfellowEntropyDelegate zero = destination => destination.Clear();
        LongfellowEntropyDelegate constant = destination => destination.Fill(ConstantFill);

        Assert.IsFalse(zero.ProducesDistinctNonZeroDraws(), "An all-zero source fails.");
        Assert.IsFalse(constant.ProducesDistinctNonZeroDraws(), "A source repeating the same block fails.");
        Assert.ThrowsExactly<ArgumentNullException>(
            () => ((LongfellowEntropyDelegate)null!).ProducesDistinctNonZeroDraws(),
            "A null source rejects.");
    }


    /// <summary>Writes a non-negative value into a fixed-width big-endian span, left-padded with zeros.</summary>
    /// <param name="value">The value; it must fit the span.</param>
    /// <param name="destination">Receives the big-endian bytes.</param>
    private static void WriteBigEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        Span<byte> minimal = stackalloc byte[FieldElementBytes];
        _ = value.TryWriteBytes(minimal, out int written, isUnsigned: true, isBigEndian: true);
        minimal[..written].CopyTo(destination[(destination.Length - written)..]);
    }
}
