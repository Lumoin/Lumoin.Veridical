using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-invariant and known-answer tests for BN254 (alt_bn128) G2 group
/// arithmetic over the D-twist (<see cref="Bn254BigIntegerG2Reference"/>). The
/// invariant tests state the group laws; the known-answer tests pin the gnark
/// big-endian compressed encoding and the group law against vectors computed
/// from the canonical alt_bn128 G2 generator by an independent CPython
/// implementation of the twist arithmetic.
/// </summary>
/// <remarks>
/// BN254 G2 lives on the D-twist <c>y² = x³ + 3/(9+u)</c> over Fp2, and its
/// full curve has a non-trivial cofactor, so <see cref="GeneratorIsInPrimeOrderSubgroup"/>
/// exercises the real <c>[r]·P = O</c> membership check (not the cofactor-1
/// shortcut available on G1).
/// </remarks>
[TestClass]
internal sealed class Bn254G2PointArithmeticTests
{
    private static readonly G2AddDelegate AddDelegate =
        Bn254BigIntegerG2Reference.GetAdd();

    private static readonly G2NegateDelegate NegateDelegate =
        Bn254BigIntegerG2Reference.GetNegate();

    private static readonly G2ScalarMultiplyDelegate ScalarMultiplyDelegate =
        Bn254BigIntegerG2Reference.GetScalarMultiply();

    private static readonly G2IsOnCurveDelegate IsOnCurveDelegate =
        Bn254BigIntegerG2Reference.GetIsOnCurve();

    private static readonly G2IsInPrimeOrderSubgroupDelegate IsInPrimeOrderSubgroupDelegate =
        Bn254BigIntegerG2Reference.GetIsInPrimeOrderSubgroup();

    private static readonly ScalarAddDelegate ScalarAdd =
        Bn254BigIntegerScalarReference.GetAdd();

    private static readonly ScalarReduceDelegate ScalarReduce =
        Bn254BigIntegerScalarReference.GetReduce();


    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;


    //Gnark big-endian compressed encodings (64 bytes): imaginary x.c1 first
    //(with the 2-bit tag in byte 0), then real x.c0.
    private const string GeneratorHex =
        "998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
        + "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed";
    private const string IdentityHex =
        "4000000000000000000000000000000000000000000000000000000000000000"
        + "0000000000000000000000000000000000000000000000000000000000000000";
    private const string TwoGHex =
        "e03e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad79"
        + "27dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9";
    private const string ThreeGHex =
        "9014772f57bb9742735191cd5dcfe4ebbc04156b6878a0a7c9824f32ffb66e85"
        + "06064e784db10e9051e52826e192715e8d7e478cb09a5e0012defa0694fbc7f5";
    private const string FiveGHex =
        "ca09ccf561b55fd99d1c1208dee1162457b57ac5af3759d50671e510e428b2a1"
        + "2e539c423b302d13f4e5773c603948eaf5db5df8ae8a9a9113708390a06410d8";
    private const string NegGHex =
        "d98e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
        + "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed";

    //k = 0x9e3779b9 and the independently-computed [k] G.
    private static ReadOnlySpan<byte> KScalarSource => [0x9e, 0x37, 0x79, 0xb9];
    private const string KGHex =
        "905bd56b162936a4aa1a8a310dd56cd9e3591e93ae41d30bed882ec64a016352"
        + "174dcb02e94da1fcd25da125faa4fb1f44cc5728a90c7f202f38e5fed5119202";


    private static G2Point Generator { get; set; } = null!;
    private static G2Point PointA { get; set; } = null!;  //[3] G
    private static G2Point PointB { get; set; } = null!;  //[5] G
    private static G2Point PointC { get; set; } = null!;  //[7] G


    public TestContext TestContext { get; set; } = null!;


    [ClassInitialize]
    public static void ClassInit(TestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        Generator = G2Point.Generator(CurveParameterSet.Bn254, Pool);

        using Scalar three = ScalarFromByte(0x03);
        using Scalar five = ScalarFromByte(0x05);
        using Scalar seven = ScalarFromByte(0x07);

        PointA = Generator.ScalarMultiply(three, ScalarMultiplyDelegate, Pool);
        PointB = Generator.ScalarMultiply(five, ScalarMultiplyDelegate, Pool);
        PointC = Generator.ScalarMultiply(seven, ScalarMultiplyDelegate, Pool);

        Assert.IsTrue(Generator.IsOnCurve(IsOnCurveDelegate), "Generator must lie on the twist.");
        Assert.IsTrue(Generator.IsInPrimeOrderSubgroup(IsInPrimeOrderSubgroupDelegate), "Generator must be in the prime-order subgroup.");
    }


    [ClassCleanup]
    public static void ClassCleanup()
    {
        Generator?.Dispose();
        PointA?.Dispose();
        PointB?.Dispose();
        PointC?.Dispose();
    }


    [TestMethod]
    public void GeneratorCompressedEncodingMatchesConvention()
    {
        Assert.AreEqual(GeneratorHex, Convert.ToHexStringLower(WellKnownCurves.GetG2GeneratorCompressed(CurveParameterSet.Bn254)));
        Assert.AreEqual(GeneratorHex, Convert.ToHexStringLower(Generator.AsReadOnlySpan()));
    }


    [TestMethod]
    public void IdentityCompressedEncodingMatchesConvention()
    {
        using G2Point identity = G2Point.Identity(CurveParameterSet.Bn254, Pool);
        Assert.AreEqual(IdentityHex, Convert.ToHexStringLower(WellKnownCurves.GetG2IdentityCompressed(CurveParameterSet.Bn254)));
        Assert.AreEqual(IdentityHex, Convert.ToHexStringLower(identity.AsReadOnlySpan()));
        Assert.IsTrue(identity.IsIdentity, "The wired identity encoding must decode as the point at infinity.");
    }


    [TestMethod]
    public void DoublingGeneratorMatchesVector()
    {
        using Scalar two = ScalarFromByte(0x02);
        using G2Point twoTimesG = Generator.ScalarMultiply(two, ScalarMultiplyDelegate, Pool);
        using G2Point gPlusG = Generator.Add(Generator, AddDelegate, Pool);

        Assert.AreEqual(TwoGHex, Convert.ToHexStringLower(twoTimesG.AsReadOnlySpan()), "[2] G via scalar multiplication");
        Assert.AreEqual(TwoGHex, Convert.ToHexStringLower(gPlusG.AsReadOnlySpan()), "G + G via addition");
    }


    [TestMethod]
    public void AddingDistinctMultiplesMatchesVector()
    {
        Assert.AreEqual(ThreeGHex, Convert.ToHexStringLower(PointA.AsReadOnlySpan()), "[3] G regression encoding");
        Assert.AreEqual(FiveGHex, Convert.ToHexStringLower(PointB.AsReadOnlySpan()), "[5] G regression encoding");

        using Scalar two = ScalarFromByte(0x02);
        using G2Point twoG = Generator.ScalarMultiply(two, ScalarMultiplyDelegate, Pool);
        using G2Point sum = twoG.Add(PointA, AddDelegate, Pool);

        Assert.AreEqual(FiveGHex, Convert.ToHexStringLower(sum.AsReadOnlySpan()), "2G + 3G must equal 5G");
    }


    [TestMethod]
    public void ScalarMultiplicationMatchesIndependentVector()
    {
        using Scalar k = Scalar.FromBytesReduced(KScalarSource, ScalarReduce, CurveParameterSet.Bn254, Pool);
        using G2Point kG = Generator.ScalarMultiply(k, ScalarMultiplyDelegate, Pool);

        Assert.AreEqual(KGHex, Convert.ToHexStringLower(kG.AsReadOnlySpan()), "[k] G for k = 0x9e3779b9");
    }


    [TestMethod]
    public void NegateGeneratorMatchesVector()
    {
        using G2Point negG = Generator.Negate(NegateDelegate, Pool);
        Assert.AreEqual(NegGHex, Convert.ToHexStringLower(negG.AsReadOnlySpan()), "-(G) keeps x, flips the y-sign tag to the larger root");

        using G2Point sum = Generator.Add(negG, AddDelegate, Pool);
        Assert.IsTrue(sum.IsIdentity, "G + (-G) must equal the identity.");
    }


    [TestMethod]
    public void AdditionIsCommutative()
    {
        using G2Point ab = PointA.Add(PointB, AddDelegate, Pool);
        using G2Point ba = PointB.Add(PointA, AddDelegate, Pool);

        Assert.IsTrue(ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan()));
    }


    [TestMethod]
    public void AdditionIsAssociative()
    {
        using G2Point ab = PointA.Add(PointB, AddDelegate, Pool);
        using G2Point abThenC = ab.Add(PointC, AddDelegate, Pool);

        using G2Point bc = PointB.Add(PointC, AddDelegate, Pool);
        using G2Point aThenBc = PointA.Add(bc, AddDelegate, Pool);

        Assert.IsTrue(abThenC.AsReadOnlySpan().SequenceEqual(aThenBc.AsReadOnlySpan()));
    }


    [TestMethod]
    public void AdditionWithIdentity()
    {
        using G2Point identity = G2Point.Identity(CurveParameterSet.Bn254, Pool);
        using G2Point aPlusZero = PointA.Add(identity, AddDelegate, Pool);
        using G2Point zeroPlusA = identity.Add(PointA, AddDelegate, Pool);

        Assert.IsTrue(aPlusZero.AsReadOnlySpan().SequenceEqual(PointA.AsReadOnlySpan()), "A + O must equal A.");
        Assert.IsTrue(zeroPlusA.AsReadOnlySpan().SequenceEqual(PointA.AsReadOnlySpan()), "O + A must equal A.");
    }


    [TestMethod]
    public void NegationIsAdditiveInverse()
    {
        using G2Point negA = PointA.Negate(NegateDelegate, Pool);
        using G2Point sum = PointA.Add(negA, AddDelegate, Pool);

        Assert.IsTrue(sum.IsIdentity, "A + (-A) must equal the identity.");
    }


    [TestMethod]
    public void ScalarMultiplicationIsLinear()
    {
        //(a + b) · P == (a · P) + (b · P).
        using Scalar a = ScalarFromByte(0x07);
        using Scalar b = ScalarFromByte(0x0b);
        using Scalar aPlusB = a.Add(b, ScalarAdd, Pool);

        using G2Point left = PointA.ScalarMultiply(aPlusB, ScalarMultiplyDelegate, Pool);

        using G2Point aP = PointA.ScalarMultiply(a, ScalarMultiplyDelegate, Pool);
        using G2Point bP = PointA.ScalarMultiply(b, ScalarMultiplyDelegate, Pool);
        using G2Point right = aP.Add(bP, AddDelegate, Pool);

        Assert.IsTrue(left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan()));
    }


    [TestMethod]
    public void ScalarMultiplicationBySumOfScalarsEqualsAddition()
    {
        using Scalar two = ScalarFromByte(0x02);
        using G2Point twoTimesA = PointA.ScalarMultiply(two, ScalarMultiplyDelegate, Pool);
        using G2Point aPlusA = PointA.Add(PointA, AddDelegate, Pool);

        Assert.IsTrue(twoTimesA.AsReadOnlySpan().SequenceEqual(aPlusA.AsReadOnlySpan()));
    }


    [TestMethod]
    public void GeneratorIsOnCurve()
    {
        Assert.IsTrue(Generator.IsOnCurve(IsOnCurveDelegate));
    }


    [TestMethod]
    public void GeneratorIsInPrimeOrderSubgroup()
    {
        //Non-trivial cofactor: this exercises the real [r]·P = O check.
        Assert.IsTrue(Generator.IsInPrimeOrderSubgroup(IsInPrimeOrderSubgroupDelegate));
    }


    [TestMethod]
    public void IsOnCurveRejectsUncompressedTag()
    {
        //Top two bits 0b00 is the uncompressed tag, invalid at the compressed boundary.
        using IMemoryOwner<byte> owner = Pool.Rent(WellKnownCurves.Bn254G2CompressedSizeBytes);
        Span<byte> bytes = owner.Memory.Span[..WellKnownCurves.Bn254G2CompressedSizeBytes];
        bytes.Clear();
        bytes[^1] = 0x01;

        using G2Point point = G2Point.FromCanonical(bytes, CurveParameterSet.Bn254, Pool);
        Assert.IsFalse(point.IsOnCurve(IsOnCurveDelegate));
    }


    private static Scalar ScalarFromByte(byte value)
    {
        ReadOnlySpan<byte> source = [value];
        return Scalar.FromBytesReduced(source, ScalarReduce, CurveParameterSet.Bn254, Pool);
    }
}
