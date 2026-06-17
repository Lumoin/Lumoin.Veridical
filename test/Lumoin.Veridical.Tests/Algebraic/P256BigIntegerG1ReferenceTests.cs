using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates the P-256 G1 reference against known-answer vectors computed
/// independently with CPython on the short-Weierstrass curve
/// <c>y² = x³ − 3x + b</c> (an oracle outside this codebase), plus the group
/// laws the encoding must respect. The vectors pin the doubling and ladder
/// formulas (which carry the <c>a = −3</c> term, unlike the pairing curves);
/// the law checks — <c>G + (−G) = O</c>, <c>2G</c> via add equals via the
/// ladder, <c>n·G = O</c> — pin the structure independently of the vectors.
/// SEC1 round-tripping pins the 0x02/0x03/0x00 prefix handling.
/// </summary>
[TestClass]
internal sealed class P256BigIntegerG1ReferenceTests
{
    private const int CompressedSize = 33;
    private const int ScalarSize = 32;
    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;

    private static readonly G1AddDelegate Add = P256BigIntegerG1Reference.GetAdd();
    private static readonly G1NegateDelegate Negate = P256BigIntegerG1Reference.GetNegate();
    private static readonly G1ScalarMultiplyDelegate ScalarMultiply = P256BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G1MultiScalarMultiplyDelegate Msm = P256BigIntegerG1Reference.GetMultiScalarMultiply();

    //SEC1 compressed encodings, CPython on P-256.
    private const string GeneratorSec1 = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    private const string DoubleGeneratorSec1 = "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
    private const string K = "1234567890abcdeffedcba9876543210112233445566778899aabbccddeeff00";
    private const string KTimesGeneratorSec1 = "03b42872a9d76ae43dc72f7e5a92902f80f35f6c991ae9ba72ebcbd1cfad28f6c4";


    [TestMethod]
    public void DoublingTheGeneratorMatchesTheVector()
    {
        Span<byte> g = Hex(GeneratorSec1);
        Span<byte> result = stackalloc byte[CompressedSize];

        //2G via point addition G + G.
        Add(g, g, result, Curve);
        AssertHex(DoubleGeneratorSec1, result, "G + G");

        //2G via the scalar ladder.
        ScalarMultiply(g, Scalar(2), result, Curve);
        AssertHex(DoubleGeneratorSec1, result, "2·G");
    }


    [TestMethod]
    public void ScalarMultipleMatchesTheVector()
    {
        Span<byte> g = Hex(GeneratorSec1);
        Span<byte> result = stackalloc byte[CompressedSize];
        ScalarMultiply(g, Hex(K), result, Curve);
        AssertHex(KTimesGeneratorSec1, result, "k·G");
    }


    [TestMethod]
    public void GeneratorPlusNegationIsInfinity()
    {
        Span<byte> g = Hex(GeneratorSec1);
        Span<byte> negG = stackalloc byte[CompressedSize];
        Span<byte> sum = stackalloc byte[CompressedSize];
        Negate(g, negG, Curve);
        Add(g, negG, sum, Curve);

        Assert.IsTrue(
            sum.SequenceEqual(WellKnownCurves.GetG1IdentityCompressed(Curve)),
            "G + (−G) must be the canonical encoded point at infinity.");
    }


    [TestMethod]
    public void OrderTimesGeneratorIsInfinity()
    {
        //n·G = O: the generator has order n.
        Span<byte> g = Hex(GeneratorSec1);
        Span<byte> orderBytes = stackalloc byte[ScalarSize];
        WriteBigEndian(WellKnownCurves.GetScalarFieldOrder(Curve), orderBytes);

        Span<byte> result = stackalloc byte[CompressedSize];
        ScalarMultiply(g, orderBytes, result, Curve);
        Assert.IsTrue(
            result.SequenceEqual(WellKnownCurves.GetG1IdentityCompressed(Curve)),
            "n·G must be the canonical encoded point at infinity.");
    }


    [TestMethod]
    public void Sec1CompressedRoundTripsBothParities()
    {
        //Decode/encode must be the identity on both 0x02 and 0x03 prefixes.
        //2G and kG carry 0x03; produce a 0x02 point by negating one of them.
        Span<byte> oddPoint = Hex(DoubleGeneratorSec1);
        Span<byte> evenPoint = stackalloc byte[CompressedSize];
        Negate(oddPoint, evenPoint, Curve);
        Assert.AreEqual(0x02, evenPoint[0], "Negating an odd-y point must give an even-y point.");

        //Round-trip the even point through add-with-identity (decode then encode).
        Span<byte> identity = Hex("00" + new string('0', 64));
        Span<byte> roundTripped = stackalloc byte[CompressedSize];
        Add(evenPoint, identity, roundTripped, Curve);
        Assert.IsTrue(evenPoint.SequenceEqual(roundTripped), "P + O must round-trip P through decode/encode unchanged.");
    }


    [TestMethod]
    public void MultiScalarMultiplyMatchesPerPointAccumulation()
    {
        //MSM of {2·G with scalar k, G with scalar 2} equals k·(2G) + 2·G,
        //cross-checked against repeated single scalar-muls and adds.
        Span<byte> g = Hex(GeneratorSec1);
        Span<byte> twoG = Hex(DoubleGeneratorSec1);

        Span<byte> points = stackalloc byte[2 * CompressedSize];
        twoG.CopyTo(points[..CompressedSize]);
        g.CopyTo(points[CompressedSize..]);

        Span<byte> scalars = stackalloc byte[2 * ScalarSize];
        Hex(K).CopyTo(scalars[..ScalarSize]);
        Scalar(2).CopyTo(scalars[ScalarSize..]);

        Span<byte> msmResult = stackalloc byte[CompressedSize];
        Msm(points, scalars, 2, msmResult, Curve);

        //Reference: k·(2G) then + (2·G).
        Span<byte> term1 = stackalloc byte[CompressedSize];
        Span<byte> term2 = stackalloc byte[CompressedSize];
        Span<byte> expected = stackalloc byte[CompressedSize];
        ScalarMultiply(twoG, Hex(K), term1, Curve);
        ScalarMultiply(g, Scalar(2), term2, Curve);
        Add(term1, term2, expected, Curve);

        Assert.IsTrue(expected.SequenceEqual(msmResult), "MSM must equal the per-point accumulation.");
    }


    private static byte[] Hex(string hex) => Convert.FromHexString(hex);


    private static byte[] Scalar(int value)
    {
        byte[] s = new byte[ScalarSize];
        s[^1] = (byte)value;

        return s;
    }


    private static void AssertHex(string expected, ReadOnlySpan<byte> actual, string label) =>
        Assert.AreEqual(expected, Convert.ToHexStringLower(actual), $"P-256 {label} mismatch.");


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
