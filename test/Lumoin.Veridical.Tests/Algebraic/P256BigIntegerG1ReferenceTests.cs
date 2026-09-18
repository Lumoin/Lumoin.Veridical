using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates the P-256 G1 reference against known-answer vectors computed
/// independently on the short-Weierstrass curve
/// <c>y² = x³ − 3x + b</c>, plus the group
/// laws the encoding must respect. The vectors pin the doubling and ladder
/// formulas (which carry the <c>a = −3</c> term, unlike the pairing curves);
/// the law checks — <c>G + (−G) = O</c>, <c>2G</c> via add equals via the
/// ladder, <c>n·G = O</c> — pin the structure independently of the vectors.
/// SEC1 round-tripping pins the 0x02/0x03/0x00 prefix handling.
/// </summary>
[TestClass]
internal sealed class P256BigIntegerG1ReferenceTests
{
    /// <summary>
    /// The byte length of a SEC1 compressed P-256 point encoding: a one-byte parity prefix
    /// followed by the 32-byte X-coordinate.
    /// </summary>
    private const int CompressedSize = 33;

    /// <summary>
    /// The byte length of a P-256 scalar, matching the curve's 32-byte field and group order.
    /// </summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The P-256 curve parameter set under test.
    /// </summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.P256;

    /// <summary>
    /// The reference implementation's point-addition delegate for P-256.
    /// </summary>
    private static G1AddDelegate Add { get; } = P256BigIntegerG1Reference.GetAdd();

    /// <summary>
    /// The reference implementation's point-negation delegate for P-256.
    /// </summary>
    private static G1NegateDelegate Negate { get; } = P256BigIntegerG1Reference.GetNegate();

    /// <summary>
    /// The reference implementation's scalar-multiplication delegate for P-256.
    /// </summary>
    private static G1ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>
    /// The reference implementation's multi-scalar-multiplication delegate for P-256.
    /// </summary>
    private static G1MultiScalarMultiplyDelegate Msm { get; } = P256BigIntegerG1Reference.GetMultiScalarMultiply();

    /// <summary>
    /// The SEC1 compressed encoding of the P-256 generator point <c>G</c>.
    /// </summary>
    private const string GeneratorSec1 = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

    /// <summary>
    /// The SEC1 compressed encoding of <c>2G</c>, the P-256 generator doubled.
    /// </summary>
    private const string DoubleGeneratorSec1 = "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";

    /// <summary>
    /// The scalar <c>k</c> used by the scalar-multiplication vector below.
    /// </summary>
    private const string K = "1234567890abcdeffedcba9876543210112233445566778899aabbccddeeff00";

    /// <summary>
    /// The SEC1 compressed encoding of <c>k·G</c> for the scalar <see cref="K"/>.
    /// </summary>
    private const string KTimesGeneratorSec1 = "03b42872a9d76ae43dc72f7e5a92902f80f35f6c991ae9ba72ebcbd1cfad28f6c4";


    /// <summary>
    /// Verifies that doubling the generator, via point addition and via the scalar ladder,
    /// both match the known <c>2G</c> vector.
    /// </summary>
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


    /// <summary>
    /// Verifies that scalar multiplication by <see cref="K"/> matches the known <c>k·G</c> vector.
    /// </summary>
    [TestMethod]
    public void ScalarMultipleMatchesTheVector()
    {
        Span<byte> g = Hex(GeneratorSec1);
        Span<byte> result = stackalloc byte[CompressedSize];
        ScalarMultiply(g, Hex(K), result, Curve);
        AssertHex(KTimesGeneratorSec1, result, "k·G");
    }


    /// <summary>
    /// Verifies that <c>G + (−G)</c> encodes the canonical point at infinity.
    /// </summary>
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


    /// <summary>
    /// Verifies that <c>n·G</c> encodes the canonical point at infinity, where <c>n</c> is the
    /// generator's order.
    /// </summary>
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


    /// <summary>
    /// Verifies that SEC1 compressed decode/encode round-trips correctly for both the
    /// <c>0x02</c> and <c>0x03</c> parity prefixes.
    /// </summary>
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


    /// <summary>
    /// Verifies that a two-term multi-scalar multiplication matches the result of accumulating
    /// each scalar multiplication and addition individually.
    /// </summary>
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


    /// <summary>
    /// Decodes a hexadecimal string into raw bytes.
    /// </summary>
    /// <param name="hex">The hexadecimal string to decode.</param>
    /// <returns>The decoded bytes.</returns>
    private static byte[] Hex(string hex) => Convert.FromHexString(hex);


    /// <summary>
    /// Builds a big-endian P-256 scalar encoding a small non-negative integer value.
    /// </summary>
    /// <param name="value">The value the low byte of the scalar must carry.</param>
    /// <returns>A <see cref="ScalarSize"/>-byte big-endian scalar encoding <paramref name="value"/>.</returns>
    private static byte[] Scalar(int value)
    {
        byte[] s = new byte[ScalarSize];
        s[^1] = (byte)value;

        return s;
    }


    /// <summary>
    /// Asserts that the lowercase hexadecimal encoding of <paramref name="actual"/> equals
    /// <paramref name="expected"/>.
    /// </summary>
    /// <param name="expected">The expected lowercase hexadecimal encoding.</param>
    /// <param name="actual">The actual bytes to encode and compare.</param>
    /// <param name="label">A label identifying the comparison in the failure message.</param>
    private static void AssertHex(string expected, ReadOnlySpan<byte> actual, string label) =>
        Assert.AreEqual(expected, Convert.ToHexStringLower(actual), $"P-256 {label} mismatch.");


    /// <summary>
    /// Writes a <see cref="System.Numerics.BigInteger"/>'s unsigned value into a fixed-length
    /// big-endian span, left-padding with zero bytes.
    /// </summary>
    /// <param name="value">The non-negative value to write.</param>
    /// <param name="destination">The fixed-length span to fill.</param>
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
