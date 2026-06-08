using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Provenance;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-invariant tests for BLS12-381 G1 group arithmetic. Each test
/// states one group law (commutativity, associativity, identity, additive
/// inverse, scalar-multiplication linearity, hash-to-curve determinism,
/// hash-to-curve subgroup membership) and verifies it for a small fixed
/// set of points prepared once per test class.
/// </summary>
/// <remarks>
/// <para>
/// The tests do not sweep random inputs with CsCheck. The BigInteger
/// reference these tests exercise pays a 381-bit
/// <see cref="System.Numerics.BigInteger.ModPow(System.Numerics.BigInteger, System.Numerics.BigInteger, System.Numerics.BigInteger)"/>
/// on every <c>Add</c> (one inversion via Fermat) and a similar cost per
/// <c>FromHashToCurve</c> (cofactor multiplication in Jacobian plus the
/// final conversion to affine), which is fundamentally incompatible with
/// CsCheck-style sweeps over many random samples — the cost is in the
/// reference, not in CsCheck, and is unavoidable while the reference is
/// the only available backend. Production backends wired later through the
/// same delegate set will be far faster and a property-test pass over
/// thousands of random points becomes appropriate then.
/// </para>
/// <para>
/// The structure of each test is the same: a pre-condition is established
/// during class setup (well-formed G1 points known to lie in the
/// prime-order subgroup), an operation is performed, and a post-condition
/// or algebraic invariant is asserted against the result. The per-test
/// work is just the operation under test plus a single equality or
/// membership assertion.
/// </para>
/// <para>
/// The shared point set <see cref="PointA"/>, <see cref="PointB"/>, and
/// <see cref="PointC"/> is computed in <see cref="ClassInit"/> as small
/// scalar multiples of the canonical generator. Building them this way
/// keeps setup cheap — each is one Jacobian scalar multiplication with a
/// single-byte scalar — while still producing distinct subgroup elements
/// suitable for testing commutativity, associativity, and linearity.
/// Subgroup membership for these points is automatic by construction:
/// scalar multiplication on a subgroup point stays inside the subgroup,
/// so the only setup-time membership check we need is on the generator
/// itself.
/// </para>
/// <para>
/// One additional point, <see cref="HashedPoint"/>, is produced via
/// <see cref="G1Point.FromHashToCurve"/> so the
/// <c>HashToCurveResult*</c> tests have a real hash-to-curve output to
/// verify against. The hash-to-curve cost is paid once per class run, not
/// once per test, because the BigInteger reference's cofactor
/// multiplication is the most expensive single operation in this suite.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381G1PointArithmeticTests
{
    private static readonly G1AddDelegate AddDelegate =
        Bls12Curve381BigIntegerG1Reference.GetAdd();

    private static readonly G1NegateDelegate NegateDelegate =
        Bls12Curve381BigIntegerG1Reference.GetNegate();

    private static readonly G1ScalarMultiplyDelegate ScalarMultiplyDelegate =
        Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    private static readonly G1HashToCurveDelegate HashToCurveDelegate =
        Bls12Curve381BigIntegerG1Reference.GetHashToCurve();

    private static readonly G1IsOnCurveDelegate IsOnCurveDelegate =
        Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();

    private static readonly G1IsInPrimeOrderSubgroupDelegate IsInPrimeOrderSubgroupDelegate =
        Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    private static readonly ScalarAddDelegate ScalarAdd =
        Bls12Curve381BigIntegerScalarReference.GetAdd();

    private static readonly ScalarReduceDelegate ScalarReduce =
        Bls12Curve381BigIntegerScalarReference.GetReduce();


    private static SensitiveMemoryPool<byte> Pool { get; } = SensitiveMemoryPool<byte>.Shared;


    /// <summary>The standard generator of the BLS12-381 G1 prime-order subgroup.</summary>
    private static G1Point Generator { get; set; } = null!;

    /// <summary>Subgroup point <c>[3] · Generator</c>.</summary>
    private static G1Point PointA { get; set; } = null!;

    /// <summary>Subgroup point <c>[5] · Generator</c>.</summary>
    private static G1Point PointB { get; set; } = null!;

    /// <summary>Subgroup point <c>[7] · Generator</c>.</summary>
    private static G1Point PointC { get; set; } = null!;

    /// <summary>A subgroup point produced via <see cref="G1Point.FromHashToCurve"/>, used by the hash-to-curve post-condition tests.</summary>
    private static G1Point HashedPoint { get; set; } = null!;


    private static ReadOnlySpan<byte> TestDstBytes => "VERIDICAL-TEST-DST-V1"u8;


    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Prepares the shared point set. <see cref="PointA"/>, <see cref="PointB"/>,
    /// and <see cref="PointC"/> are built as small scalar multiples of the
    /// canonical generator so the setup is dominated by three Jacobian
    /// double-and-add walks of a few bits each rather than three full
    /// hash-to-curve invocations (which would each carry the ~128-bit
    /// cofactor multiplication that is the BigInteger reference's most
    /// expensive single operation). One real hash-to-curve output is still
    /// produced as <see cref="HashedPoint"/> so the
    /// <c>HashToCurveResult*</c> tests have something authentic to verify.
    /// </summary>
    /// <remarks>
    /// Subgroup membership for the scalar-multiple points is automatic by
    /// construction — scalar multiplication on a subgroup point stays
    /// inside the subgroup — so the only setup-time checks are that the
    /// generator and the hashed point are themselves well-formed.
    /// </remarks>
    [ClassInitialize]
    public static void ClassInit(TestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        Generator = G1Point.Generator(CurveParameterSet.Bls12Curve381, Pool);

        ReadOnlySpan<byte> threeSource = [0x03];
        ReadOnlySpan<byte> fiveSource = [0x05];
        ReadOnlySpan<byte> sevenSource = [0x07];

        using Scalar three = Scalar.FromBytesReduced(threeSource, ScalarReduce, CurveParameterSet.Bls12Curve381, Pool);
        using Scalar five = Scalar.FromBytesReduced(fiveSource, ScalarReduce, CurveParameterSet.Bls12Curve381, Pool);
        using Scalar seven = Scalar.FromBytesReduced(sevenSource, ScalarReduce, CurveParameterSet.Bls12Curve381, Pool);

        PointA = Generator.ScalarMultiply(three, ScalarMultiplyDelegate, Pool);
        PointB = Generator.ScalarMultiply(five, ScalarMultiplyDelegate, Pool);
        PointC = Generator.ScalarMultiply(seven, ScalarMultiplyDelegate, Pool);

        HashedPoint = G1Point.FromHashToCurve("alpha"u8, TestDstBytes, HashToCurveDelegate, CurveParameterSet.Bls12Curve381, Pool);

        Assert.IsTrue(Generator.IsOnCurve(IsOnCurveDelegate), "Generator must lie on the curve.");
        Assert.IsTrue(Generator.IsInPrimeOrderSubgroup(IsInPrimeOrderSubgroupDelegate), "Generator must be in the prime-order subgroup.");
        Assert.IsTrue(HashedPoint.IsOnCurve(IsOnCurveDelegate), "Hash-to-curve output must lie on the curve.");
    }


    [ClassCleanup]
    public static void ClassCleanup()
    {
        Generator?.Dispose();
        PointA?.Dispose();
        PointB?.Dispose();
        PointC?.Dispose();
        HashedPoint?.Dispose();
    }


    [TestMethod]
    public void AdditionIsCommutative()
    {
        //Invariant: A + B == B + A for every pair (A, B) in G1.
        using G1Point ab = PointA.Add(PointB, AddDelegate, Pool);
        using G1Point ba = PointB.Add(PointA, AddDelegate, Pool);

        Assert.IsTrue(ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan()));
    }


    [TestMethod]
    public void AdditionIsAssociative()
    {
        //Invariant: (A + B) + C == A + (B + C) for every triple (A, B, C) in G1.
        using G1Point ab = PointA.Add(PointB, AddDelegate, Pool);
        using G1Point abThenC = ab.Add(PointC, AddDelegate, Pool);

        using G1Point bc = PointB.Add(PointC, AddDelegate, Pool);
        using G1Point aThenBc = PointA.Add(bc, AddDelegate, Pool);

        Assert.IsTrue(abThenC.AsReadOnlySpan().SequenceEqual(aThenBc.AsReadOnlySpan()));
    }


    [TestMethod]
    public void NegationIsAdditiveInverse()
    {
        //Invariant: A + (-A) == O for every non-identity A in G1.
        //Pre-condition: PointA = [3] · Generator is non-identity because
        //the generator has prime order r far larger than 3.
        using G1Point negA = PointA.Negate(NegateDelegate, Pool);
        using G1Point sum = PointA.Add(negA, AddDelegate, Pool);

        Assert.IsTrue(sum.IsIdentity, "A + (-A) must equal the identity.");
    }


    [TestMethod]
    public void AdditionWithIdentity()
    {
        //Invariant: A + O == A and O + A == A for every A in G1.
        using G1Point identity = G1Point.Identity(CurveParameterSet.Bls12Curve381, Pool);
        using G1Point aPlusZero = PointA.Add(identity, AddDelegate, Pool);
        using G1Point zeroPlusA = identity.Add(PointA, AddDelegate, Pool);

        Assert.IsTrue(aPlusZero.AsReadOnlySpan().SequenceEqual(PointA.AsReadOnlySpan()), "A + O must equal A.");
        Assert.IsTrue(zeroPlusA.AsReadOnlySpan().SequenceEqual(PointA.AsReadOnlySpan()), "O + A must equal A.");
    }


    [TestMethod]
    public void ScalarMultiplicationIsLinear()
    {
        //Invariant: (a + b) · P == (a · P) + (b · P) for every pair of
        //scalars (a, b) and every point P in G1. Small distinct scalars are
        //used so the inner double-and-add loop is bounded; the linearity
        //law is independent of scalar magnitude and one example is sufficient
        //to detect a sign or carry error in the linkage between scalar
        //arithmetic and group scalar multiplication.
        ReadOnlySpan<byte> aSource = [0x07];
        ReadOnlySpan<byte> bSource = [0x0b];

        using Scalar a = Scalar.FromBytesReduced(aSource, ScalarReduce, CurveParameterSet.Bls12Curve381, Pool);
        using Scalar b = Scalar.FromBytesReduced(bSource, ScalarReduce, CurveParameterSet.Bls12Curve381, Pool);
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
        //Invariant: [2] · P == P + P. A specific case of linearity, kept as a
        //separate test because it catches an off-by-one in the scalar-mul
        //bit walk independent of the scalar-arithmetic backend.
        ReadOnlySpan<byte> twoSource = [0x02];
        using Scalar two = Scalar.FromBytesReduced(twoSource, ScalarReduce, CurveParameterSet.Bls12Curve381, Pool);
        using G1Point twoTimesA = PointA.ScalarMultiply(two, ScalarMultiplyDelegate, Pool);
        using G1Point aPlusA = PointA.Add(PointA, AddDelegate, Pool);

        Assert.IsTrue(twoTimesA.AsReadOnlySpan().SequenceEqual(aPlusA.AsReadOnlySpan()));
    }


    [TestMethod]
    public void GeneratorIsOnCurve()
    {
        //Structural curve fact: the canonical generator x and y satisfy y^2 = x^3 + 4 (mod p).
        Assert.IsTrue(Generator.IsOnCurve(IsOnCurveDelegate));
    }


    [TestMethod]
    public void GeneratorIsInPrimeOrderSubgroup()
    {
        //Structural curve fact: the canonical generator has order r.
        Assert.IsTrue(Generator.IsInPrimeOrderSubgroup(IsInPrimeOrderSubgroupDelegate));
    }


    [TestMethod]
    public void HashToCurveResultIsOnCurve()
    {
        //Post-condition of FromHashToCurve: the output satisfies the curve
        //equation. HashedPoint was produced via FromHashToCurve in setup,
        //so this is exactly the post-condition we want to verify for that
        //operation.
        Assert.IsTrue(HashedPoint.IsOnCurve(IsOnCurveDelegate));
    }


    [TestMethod]
    public void HashToCurveResultIsInPrimeOrderSubgroup()
    {
        //Post-condition of FromHashToCurve: RFC 9380 §3 makes subgroup
        //clearing part of the hash-to-curve specification, so the output
        //must satisfy [r] P == O. The reference enforces this by
        //scalar-multiplying the try-and-increment preimage by the BLS12-381
        //G1 cofactor before encoding.
        Assert.IsTrue(HashedPoint.IsInPrimeOrderSubgroup(IsInPrimeOrderSubgroupDelegate));
    }


    [TestMethod]
    public void HashToCurveIsDeterministic()
    {
        //Invariant: hash-to-curve is a pure function. Repeated calls on the
        //same (message, DST) produce the same point.
        using G1Point first = G1Point.FromHashToCurve("delta"u8, TestDstBytes, HashToCurveDelegate, CurveParameterSet.Bls12Curve381, Pool);
        using G1Point second = G1Point.FromHashToCurve("delta"u8, TestDstBytes, HashToCurveDelegate, CurveParameterSet.Bls12Curve381, Pool);

        Assert.IsTrue(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()));
    }


    [TestMethod]
    public void HashToCurveProducesPointsCarryingProvenance()
    {
        //Post-condition: FromHashToCurve is a boundary factory, so the
        //produced point carries the producing backend's provenance entries
        //in its tag in addition to the algebraic-identity entries.
        ReadOnlySpan<byte> message = [0x01, 0x02, 0x03];
        using G1Point point = G1Point.FromHashToCurve(
            message,
            TestDstBytes,
            HashToCurveDelegate, CurveParameterSet.Bls12Curve381, Pool);

        Assert.IsTrue(point.Tag.TryGet(out ProviderClass providerClass),
            "Provenance entries should be present after a boundary operation.");
        Assert.AreEqual(nameof(Bls12Curve381BigIntegerG1Reference), providerClass.Name);

        Assert.AreEqual(AlgebraicRole.G1Point, point.Tag.Get<AlgebraicRole>());
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, point.Tag.Get<CurveParameterSet>());
    }
}