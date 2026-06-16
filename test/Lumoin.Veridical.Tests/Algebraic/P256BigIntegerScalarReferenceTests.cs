using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates the P-256 scalar-field reference against known-answer vectors and
/// algebraic self-consistency. The vectors were computed independently with
/// CPython's arbitrary-precision integers modulo the P-256 group order
/// <c>n</c> — an oracle outside this codebase's BigInteger path — so an error
/// in the reference's reduction or sign handling surfaces as a vector
/// mismatch, not a silent agreement of one implementation with itself. The
/// self-consistency checks (negate and invert round-trips, the order's own
/// reduction) pin the field structure independently of the vectors.
/// </summary>
[TestClass]
internal sealed class P256BigIntegerScalarReferenceTests
{
    private const int ScalarSize = 32;
    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;

    private static readonly ScalarAddDelegate Add = P256BigIntegerScalarReference.GetAdd();
    private static readonly ScalarSubtractDelegate Subtract = P256BigIntegerScalarReference.GetSubtract();
    private static readonly ScalarMultiplyDelegate Multiply = P256BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarNegateDelegate Negate = P256BigIntegerScalarReference.GetNegate();
    private static readonly ScalarInvertDelegate Invert = P256BigIntegerScalarReference.GetInvert();
    private static readonly ScalarReduceDelegate Reduce = P256BigIntegerScalarReference.GetReduce();

    //CPython, modulo n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551.
    private const string A = "c1a551f00d2b9e7733a0f1e2d3c4b5a6978869504132231415060708090a0b0c";
    private const string B = "7e6d5c4b3a2918073f2e1d0c9b8a79685746352413029100fedcba9876543210";
    private const string ExpectedAdd = "4012ae3c4754b67d72cf0eef6f4f2f0f31e7a3c6ad1d15902028f6dd82fb17cb";
    private const string ExpectedSub = "4337f5a4d302866ff472d4d6383a3c3e4042342c2e2f921316294c6f92b5d8fc";
    private const string ExpectedMul = "4b3391dfa382355f10642cc23c1f17d0f030742f48712ce6eb1100e5ee952930";
    private const string ExpectedNegA = "3e5aae0ef2d46189cc5f0e1d2c3b4a59255e915d65e57b70deb3c3baf3591a45";
    private const string ExpectedInvA = "b23a4fe3b320605b3d4ede294cb4a977affac957f1abefae300288bda51f8c43";


    [TestMethod]
    public void MatchesTheKnownAnswerVectors()
    {
        Span<byte> a = Hex(A);
        Span<byte> b = Hex(B);
        Span<byte> result = stackalloc byte[ScalarSize];

        Add(a, b, result, Curve);
        AssertHex(ExpectedAdd, result, "add");

        Subtract(a, b, result, Curve);
        AssertHex(ExpectedSub, result, "subtract");

        Multiply(a, b, result, Curve);
        AssertHex(ExpectedMul, result, "multiply");

        Negate(a, result, Curve);
        AssertHex(ExpectedNegA, result, "negate");

        Invert(a, result, Curve);
        AssertHex(ExpectedInvA, result, "invert");
    }


    [TestMethod]
    public void NegateAndInvertRoundTrip()
    {
        Span<byte> a = Hex(A);
        Span<byte> scratch = stackalloc byte[ScalarSize];
        Span<byte> back = stackalloc byte[ScalarSize];

        //a + (-a) == 0.
        Negate(a, scratch, Curve);
        Add(a, scratch, back, Curve);
        Assert.IsTrue(IsZero(back), "a + (-a) must be zero.");

        //a * a^{-1} == 1.
        Invert(a, scratch, Curve);
        Multiply(a, scratch, back, Curve);
        Assert.IsTrue(IsOne(back), "a * a^{-1} must be one.");
    }


    [TestMethod]
    public void ReducingTheOrderYieldsZero()
    {
        //n mod n == 0: reduce the canonical (right-aligned big-endian) group order.
        Span<byte> bigEndianOrder = stackalloc byte[ScalarSize];
        WriteBigEndian(WellKnownCurves.GetScalarFieldOrder(Curve), bigEndianOrder);

        Span<byte> result = stackalloc byte[ScalarSize];
        Reduce(bigEndianOrder, result, Curve);
        Assert.IsTrue(IsZero(result), "Reducing the group order must give zero.");
    }


    private static byte[] Hex(string hex) => Convert.FromHexString(hex);


    private static void AssertHex(string expected, ReadOnlySpan<byte> actual, string label) =>
        Assert.AreEqual(expected, Convert.ToHexStringLower(actual), $"P-256 scalar {label} mismatch.");


    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;


    private static bool IsOne(ReadOnlySpan<byte> value)
    {
        for(int i = 0; i < value.Length - 1; i++)
        {
            if(value[i] != 0)
            {
                return false;
            }
        }

        return value[^1] == 0x01;
    }


    private static void WriteBigEndian(System.Numerics.BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
