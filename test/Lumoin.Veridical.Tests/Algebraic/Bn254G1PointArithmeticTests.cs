using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-invariant and known-answer tests for BN254 (alt_bn128) G1 group
/// arithmetic (<see cref="Bn254BigIntegerG1Reference"/>). The invariant tests
/// state one group law each (commutativity, associativity, identity, additive
/// inverse, scalar-multiplication linearity) over a small fixed point set; the
/// known-answer tests pin the gnark big-endian compressed encoding and check
/// the group law against vectors anchored to the Ethereum alt_bn128 precompile
/// (EIP-196) and cross-checked with an independent big-integer engine.
/// </summary>
/// <remarks>
/// <para>
/// As with the BLS12-381 G1 suite, the tests use a small fixed point set
/// rather than CsCheck sweeps: the BigInteger reference pays a 254-bit
/// modular inversion per affine <c>Add</c> and a Jacobian double-and-add per
/// scalar multiplication, which is the wrong cost profile for thousands of
/// random samples while the reference is the only backend.
/// </para>
/// <para>
/// The doubling vector is the canonical EIP-196 anchor: <c>[2] G</c> equals the
/// published <c>ecAdd((1,2),(1,2))</c> test vector
/// <c>(1368015179489954701390400359078579693043519447331113978918064868415326638035,
/// 9918110051302171585080402603319702774565515993150576347155970296011118125764)</c>.
/// The remaining multiples (<c>3G</c>, <c>5G</c>, <c>kG</c>) were produced by an
/// independent CPython implementation of the curve arithmetic and compressed
/// with the gnark convention, then locked here as regression vectors.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bn254G1PointArithmeticTests
{
    private static readonly G1AddDelegate AddDelegate =
        Bn254BigIntegerG1Reference.GetAdd();

    private static readonly G1NegateDelegate NegateDelegate =
        Bn254BigIntegerG1Reference.GetNegate();

    private static readonly G1ScalarMultiplyDelegate ScalarMultiplyDelegate =
        Bn254BigIntegerG1Reference.GetScalarMultiply();

    private static readonly G1MultiScalarMultiplyDelegate MultiScalarMultiplyDelegate =
        Bn254BigIntegerG1Reference.GetMultiScalarMultiply();

    private static readonly G1IsOnCurveDelegate IsOnCurveDelegate =
        Bn254BigIntegerG1Reference.GetIsOnCurve();

    private static readonly G1IsInPrimeOrderSubgroupDelegate IsInPrimeOrderSubgroupDelegate =
        Bn254BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    private static readonly ScalarAddDelegate ScalarAdd =
        Bn254BigIntegerScalarReference.GetAdd();

    private static readonly ScalarReduceDelegate ScalarReduce =
        Bn254BigIntegerScalarReference.GetReduce();


    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;


    //Gnark big-endian compressed encodings (32 bytes). Generator (1,2) carries
    //the 0x80 (smaller-y) tag; the identity carries the 0x40 infinity tag.
    private const string GeneratorHex = "8000000000000000000000000000000000000000000000000000000000000001";
    private const string IdentityHex = "4000000000000000000000000000000000000000000000000000000000000000";
    private const string TwoGHex = "830644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3";
    private const string ThreeGHex = "c769bf9ac56bea3ff40232bcb1b6bd159315d84715b8e679f2d355961915abf0";
    private const string FiveGHex = "97c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa9";
    private const string NegGHex = "c000000000000000000000000000000000000000000000000000000000000001";

    //k = 0x2a3bc and the independently-computed [k] G.
    private static ReadOnlySpan<byte> KScalarSource => [0x02, 0xa3, 0xbc];
    private const string KGHex = "8cd81b98a3dfca317112873b73bb1716ae62800fff93eb74c05ac4ba8ff82d1c";


    private static G1Point Generator { get; set; } = null!;

    /// <summary>Subgroup point <c>[3] · Generator</c>.</summary>
    private static G1Point PointA { get; set; } = null!;

    /// <summary>Subgroup point <c>[5] · Generator</c>.</summary>
    private static G1Point PointB { get; set; } = null!;

    /// <summary>Subgroup point <c>[7] · Generator</c>.</summary>
    private static G1Point PointC { get; set; } = null!;


    public TestContext TestContext { get; set; } = null!;


    [ClassInitialize]
    public static void ClassInit(TestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        Generator = G1Point.Generator(CurveParameterSet.Bn254, Pool);

        ReadOnlySpan<byte> threeSource = [0x03];
        ReadOnlySpan<byte> fiveSource = [0x05];
        ReadOnlySpan<byte> sevenSource = [0x07];

        using Scalar three = Scalar.FromBytesReduced(threeSource, ScalarReduce, CurveParameterSet.Bn254, Pool);
        using Scalar five = Scalar.FromBytesReduced(fiveSource, ScalarReduce, CurveParameterSet.Bn254, Pool);
        using Scalar seven = Scalar.FromBytesReduced(sevenSource, ScalarReduce, CurveParameterSet.Bn254, Pool);

        PointA = Generator.ScalarMultiply(three, ScalarMultiplyDelegate, Pool);
        PointB = Generator.ScalarMultiply(five, ScalarMultiplyDelegate, Pool);
        PointC = Generator.ScalarMultiply(seven, ScalarMultiplyDelegate, Pool);

        Assert.IsTrue(Generator.IsOnCurve(IsOnCurveDelegate), "Generator must lie on the curve.");
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
        //The wired generator bytes and a freshly produced generator point both
        //match the gnark big-endian encoding of (1, 2).
        Assert.AreEqual(GeneratorHex, Convert.ToHexStringLower(WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bn254)));
        Assert.AreEqual(GeneratorHex, Convert.ToHexStringLower(Generator.AsReadOnlySpan()));
    }


    [TestMethod]
    public void IdentityCompressedEncodingMatchesConvention()
    {
        using G1Point identity = G1Point.Identity(CurveParameterSet.Bn254, Pool);
        Assert.AreEqual(IdentityHex, Convert.ToHexStringLower(WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bn254)));
        Assert.AreEqual(IdentityHex, Convert.ToHexStringLower(identity.AsReadOnlySpan()));
        Assert.IsTrue(identity.IsIdentity, "The wired identity encoding must decode as the point at infinity.");
    }


    [TestMethod]
    public void DoublingGeneratorMatchesEip196Vector()
    {
        //[2] G computed two ways must equal the published EIP-196 ecAdd((1,2),(1,2))
        //vector: this simultaneously proves the generator decodes to (1, 2) and
        //that the doubling group law is correct over the BN254 base field.
        using Scalar two = ScalarFromByte(0x02);
        using G1Point twoTimesG = Generator.ScalarMultiply(two, ScalarMultiplyDelegate, Pool);
        using G1Point gPlusG = Generator.Add(Generator, AddDelegate, Pool);

        Assert.AreEqual(TwoGHex, Convert.ToHexStringLower(twoTimesG.AsReadOnlySpan()), "[2] G via scalar multiplication");
        Assert.AreEqual(TwoGHex, Convert.ToHexStringLower(gPlusG.AsReadOnlySpan()), "G + G via addition");
    }


    [TestMethod]
    public void AddingDistinctMultiplesMatchesVector()
    {
        //2G + 3G == 5G, with distinct addends exercising the general addition
        //formula rather than the doubling path. PointA = [3]G and PointB = [5]G
        //also serve as regression encodings for the independent vectors.
        Assert.AreEqual(ThreeGHex, Convert.ToHexStringLower(PointA.AsReadOnlySpan()), "[3] G regression encoding");
        Assert.AreEqual(FiveGHex, Convert.ToHexStringLower(PointB.AsReadOnlySpan()), "[5] G regression encoding");

        using Scalar two = ScalarFromByte(0x02);
        using G1Point twoG = Generator.ScalarMultiply(two, ScalarMultiplyDelegate, Pool);
        using G1Point sum = twoG.Add(PointA, AddDelegate, Pool);

        Assert.AreEqual(FiveGHex, Convert.ToHexStringLower(sum.AsReadOnlySpan()), "2G + 3G must equal 5G");
    }


    [TestMethod]
    public void ScalarMultiplicationMatchesIndependentVector()
    {
        using Scalar k = Scalar.FromBytesReduced(KScalarSource, ScalarReduce, CurveParameterSet.Bn254, Pool);
        using G1Point kG = Generator.ScalarMultiply(k, ScalarMultiplyDelegate, Pool);

        Assert.AreEqual(KGHex, Convert.ToHexStringLower(kG.AsReadOnlySpan()), "[k] G for k = 0x2a3bc");
    }


    [TestMethod]
    public void NegateGeneratorMatchesVector()
    {
        using G1Point negG = Generator.Negate(NegateDelegate, Pool);
        Assert.AreEqual(NegGHex, Convert.ToHexStringLower(negG.AsReadOnlySpan()), "-(G) = (1, q - 2), the larger root");

        using G1Point sum = Generator.Add(negG, AddDelegate, Pool);
        Assert.IsTrue(sum.IsIdentity, "G + (-G) must equal the identity.");
    }


    [TestMethod]
    public void MultiScalarMultiplicationMatchesSumOfTerms()
    {
        //[2] G + [3] G via a single multi-scalar multiplication equals 5G.
        int stride = WellKnownCurves.Bn254G1CompressedSizeBytes;
        int scalarStride = Scalar.SizeBytes;

        using IMemoryOwner<byte> pointsOwner = Pool.Rent(2 * stride);
        using IMemoryOwner<byte> scalarsOwner = Pool.Rent(2 * scalarStride);
        using IMemoryOwner<byte> resultOwner = Pool.Rent(stride);

        Span<byte> points = pointsOwner.Memory.Span[..(2 * stride)];
        Span<byte> scalars = scalarsOwner.Memory.Span[..(2 * scalarStride)];
        Span<byte> result = resultOwner.Memory.Span[..stride];

        //Both terms are the generator; scalars are 2 and 3.
        Generator.AsReadOnlySpan().CopyTo(points[..stride]);
        Generator.AsReadOnlySpan().CopyTo(points.Slice(stride, stride));

        scalars.Clear();
        scalars[scalarStride - 1] = 0x02;
        scalars[(2 * scalarStride) - 1] = 0x03;

        MultiScalarMultiplyDelegate(points, scalars, count: 2, result, CurveParameterSet.Bn254);

        Assert.AreEqual(FiveGHex, Convert.ToHexStringLower(result), "[2]G + [3]G via MSM must equal 5G");
    }


    [TestMethod]
    public void AdditionIsCommutative()
    {
        using G1Point ab = PointA.Add(PointB, AddDelegate, Pool);
        using G1Point ba = PointB.Add(PointA, AddDelegate, Pool);

        Assert.IsTrue(ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan()));
    }


    [TestMethod]
    public void AdditionIsAssociative()
    {
        using G1Point ab = PointA.Add(PointB, AddDelegate, Pool);
        using G1Point abThenC = ab.Add(PointC, AddDelegate, Pool);

        using G1Point bc = PointB.Add(PointC, AddDelegate, Pool);
        using G1Point aThenBc = PointA.Add(bc, AddDelegate, Pool);

        Assert.IsTrue(abThenC.AsReadOnlySpan().SequenceEqual(aThenBc.AsReadOnlySpan()));
    }


    [TestMethod]
    public void AdditionWithIdentity()
    {
        using G1Point identity = G1Point.Identity(CurveParameterSet.Bn254, Pool);
        using G1Point aPlusZero = PointA.Add(identity, AddDelegate, Pool);
        using G1Point zeroPlusA = identity.Add(PointA, AddDelegate, Pool);

        Assert.IsTrue(aPlusZero.AsReadOnlySpan().SequenceEqual(PointA.AsReadOnlySpan()), "A + O must equal A.");
        Assert.IsTrue(zeroPlusA.AsReadOnlySpan().SequenceEqual(PointA.AsReadOnlySpan()), "O + A must equal A.");
    }


    [TestMethod]
    public void NegationIsAdditiveInverse()
    {
        using G1Point negA = PointA.Negate(NegateDelegate, Pool);
        using G1Point sum = PointA.Add(negA, AddDelegate, Pool);

        Assert.IsTrue(sum.IsIdentity, "A + (-A) must equal the identity.");
    }


    [TestMethod]
    public void ScalarMultiplicationIsLinear()
    {
        //(a + b) · P == (a · P) + (b · P).
        using Scalar a = ScalarFromByte(0x07);
        using Scalar b = ScalarFromByte(0x0b);
        using Scalar aPlusB = a.Add(b, ScalarAdd, Pool);

        using G1Point left = PointA.ScalarMultiply(aPlusB, ScalarMultiplyDelegate, Pool);

        using G1Point aP = PointA.ScalarMultiply(a, ScalarMultiplyDelegate, Pool);
        using G1Point bP = PointA.ScalarMultiply(b, ScalarMultiplyDelegate, Pool);
        using G1Point right = aP.Add(bP, AddDelegate, Pool);

        Assert.IsTrue(left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan()));
    }


    [TestMethod]
    public void ScalarMultiplicationBySumOfScalarsEqualsAddition()
    {
        //[2] · P == P + P.
        using Scalar two = ScalarFromByte(0x02);
        using G1Point twoTimesA = PointA.ScalarMultiply(two, ScalarMultiplyDelegate, Pool);
        using G1Point aPlusA = PointA.Add(PointA, AddDelegate, Pool);

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
        //Cofactor 1: the membership predicate holds for every on-curve point.
        Assert.IsTrue(Generator.IsInPrimeOrderSubgroup(IsInPrimeOrderSubgroupDelegate));
    }


    [TestMethod]
    public void IsOnCurveRejectsUncompressedTag()
    {
        //A 32-byte buffer whose top two bits are 0b00 carries the uncompressed
        //tag, which is invalid at the compressed boundary and must be rejected.
        using IMemoryOwner<byte> owner = Pool.Rent(WellKnownCurves.Bn254G1CompressedSizeBytes);
        Span<byte> bytes = owner.Memory.Span[..WellKnownCurves.Bn254G1CompressedSizeBytes];
        bytes.Clear();
        bytes[^1] = 0x01;

        using G1Point point = G1Point.FromCanonical(bytes, CurveParameterSet.Bn254, Pool);
        Assert.IsFalse(point.IsOnCurve(IsOnCurveDelegate));
    }


    [TestMethod]
    public void NonCanonicalInfinityEncodingRejected()
    {
        //The canonical infinity encoding is exactly the 0x40 tag followed by
        //zeros. An infinity-tagged encoding with an extra non-tag bit or
        //trailing garbage must be rejected at decode rather than aliased onto
        //the identity: aliasing would pass the on-curve and subgroup checks
        //while evading byte-compare identity detection.
        Span<byte> probe = stackalloc byte[WellKnownCurves.Bn254G1CompressedSizeBytes];
        WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bn254).CopyTo(probe);
        probe[0] |= 0x20;
        Assert.IsFalse(IsOnCurveDelegate(probe, CurveParameterSet.Bn254), "An infinity encoding with an extra non-tag bit must be rejected.");
        Assert.IsFalse(IsInPrimeOrderSubgroupDelegate(probe, CurveParameterSet.Bn254), "The subgroup check must reject an infinity encoding with an extra non-tag bit.");

        WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bn254).CopyTo(probe);
        probe[^1] = 0x01;
        Assert.IsFalse(IsOnCurveDelegate(probe, CurveParameterSet.Bn254), "An infinity encoding with a non-zero trailing byte must be rejected.");
        Assert.IsFalse(IsInPrimeOrderSubgroupDelegate(probe, CurveParameterSet.Bn254), "The subgroup check must reject an infinity encoding with a non-zero trailing byte.");

        Assert.IsTrue(IsOnCurveDelegate(WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bn254), CurveParameterSet.Bn254), "The canonical infinity encoding must still decode.");
    }


    private static Scalar ScalarFromByte(byte value)
    {
        ReadOnlySpan<byte> source = [value];
        return Scalar.FromBytesReduced(source, ScalarReduce, CurveParameterSet.Bn254, Pool);
    }
}
