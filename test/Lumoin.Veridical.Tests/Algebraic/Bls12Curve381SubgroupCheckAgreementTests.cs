using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Agreement suite locking <see cref="Bls12Curve381EndomorphismG1Backend"/>
/// (Scott's <c>ψ(P) = [−u²]P</c> test, IACR ePrint 2021/1130 §6) to the
/// BigInteger reference's naive <c>[r]P == O</c> predicate. The off-subgroup
/// side is exercised by a torsion corpus with one point of every prime order
/// dividing the G1 cofactor <c>h = 3·11²·10177²·859267²·52437899²</c> plus a
/// mixed point of order <c>3r</c>; the honest side by the canonical generator
/// and assorted multiples. The β constant is pinned both algebraically
/// (<c>β² + β + 1 ≡ 0 mod p</c>) and by its eigenvalue action on the
/// generator, so a wrong cube-root pairing — which can only break
/// completeness, never soundness — fails loudly here.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381SubgroupCheckAgreementTests
{
    private static G1IsOnCurveDelegate IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    private static G1IsInPrimeOrderSubgroupDelegate NaiveIsInSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    private static G1IsInPrimeOrderSubgroupDelegate EndomorphismIsInSubgroup { get; } = Bls12Curve381EndomorphismG1Backend.GetIsInPrimeOrderSubgroup();
    private static G1ScalarMultiplyDelegate ScalarMultiply { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>
    /// Point of exact order 3, generated and self-verified by the reference
    /// harness (deterministic seed points multiplied by the group exponent
    /// over the target order; <c>E(Fp)</c> is <c>Z_{3mr} × Z_m</c> with
    /// <c>m = 11·10177·859267·52437899</c>). This is the x = 0 point with the
    /// lexicographically smaller y — the sibling of the wrong-subgroup probe
    /// pinned in the BBS suite, exercising the other y-parity flag.
    /// </summary>
    private static byte[] Order3Point { get; } = Convert.FromHexString(
        "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    /// <summary>Point of exact order 11; on-curve, <c>[11]P = O</c>, <c>[r]P ≠ O</c>, self-verified at generation.</summary>
    private static byte[] Order11Point { get; } = Convert.FromHexString(
        "99b3e2c8c6bbf59d3c326b531fc1e639d29200c28624ac604f251a12908c9b7f735318617f625954cc71cdf03229b1ef");

    /// <summary>Point of exact order 10177; on-curve, <c>[10177]P = O</c>, <c>[r]P ≠ O</c>, self-verified at generation.</summary>
    private static byte[] Order10177Point { get; } = Convert.FromHexString(
        "985e6001ca42834242f7d049fa38825b5fdbefc520a58dd73601a7e64f9dae2f5e122bf2e2a1015b7859191cd2e58686");

    /// <summary>Point of exact order 859267; on-curve, <c>[859267]P = O</c>, <c>[r]P ≠ O</c>, self-verified at generation.</summary>
    private static byte[] Order859267Point { get; } = Convert.FromHexString(
        "8d98f6e31a3547b73785be9705ce2100f49f3968f436bbaeb1685e9e2a3779975a1d7a661ab72b22322cd730e621b129");

    /// <summary>Point of exact order 52437899; on-curve, <c>[52437899]P = O</c>, <c>[r]P ≠ O</c>, self-verified at generation.</summary>
    private static byte[] Order52437899Point { get; } = Convert.FromHexString(
        "8431dabc768bcb1eb40696a5c59a377ff626be9ba1c3fa9b03305d4063fae6dcc057d08efa04efd76ed6ac7fe3e8cf5e");

    /// <summary>
    /// Point of exact order <c>3r</c>: carries an r-component AND a 3-torsion
    /// component, so it is rejected by both predicates even though its
    /// r-component alone would be a legitimate subgroup element.
    /// </summary>
    private static byte[] Order3RPoint { get; } = Convert.FromHexString(
        "a883e286f552ea2d7b205fb3cec08c4f5f806e11cf1ce2dd589aa0b85ef65f733fa488667b74bcef2fa7d3b6da5e4d81");

    /// <summary>The pinned probe from the BBS suite: x = 0 with the lexicographically larger y root, order 3.</summary>
    private static byte[] WrongSubgroupProbe { get; } = Convert.FromHexString(
        "a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    /// <summary>x = 1 is off-curve: 1 + 4 = 5 is a quadratic non-residue modulo the base field prime.</summary>
    private static byte[] OffCurvePoint { get; } = Convert.FromHexString(
        "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");

    /// <summary>Every off-subgroup corpus entry: one point per prime order dividing the cofactor, the mixed-order point, and the BBS probe.</summary>
    private static byte[][] TorsionCorpus { get; } =
    [
        Order3Point, Order11Point, Order10177Point, Order859267Point, Order52437899Point, Order3RPoint, WrongSubgroupProbe
    ];

    /// <summary>Assorted honest generator multipliers for the acceptance sweep.</summary>
    private static ulong[] HonestScalars { get; } = [2UL, 3UL, 12345UL, 0xDEADBEEFCAFEUL, ulong.MaxValue];


    /// <summary>
    /// Every torsion-corpus point lies on the curve yet is rejected by BOTH
    /// the naive and the endomorphism predicate — the agreement that makes
    /// the fast test a drop-in for the reference.
    /// </summary>
    [TestMethod]
    public void TorsionCorpusRejectedByBothPredicates()
    {
        foreach(byte[] point in TorsionCorpus)
        {
            Assert.IsTrue(IsOnCurve(point, Curve), $"Corpus point {Convert.ToHexString(point)[..16]}… must lie on the curve.");
            Assert.IsFalse(NaiveIsInSubgroup(point, Curve), $"The naive [r]P test must reject {Convert.ToHexString(point)[..16]}….");
            Assert.IsFalse(EndomorphismIsInSubgroup(point, Curve), $"The endomorphism test must reject {Convert.ToHexString(point)[..16]}….");
        }
    }


    /// <summary>
    /// The generator and assorted honest multiples are accepted by both
    /// predicates; a wrong β-eigenvalue pairing would fail here on the very
    /// first point.
    /// </summary>
    [TestMethod]
    public void HonestPointsAcceptedByBothPredicates()
    {
        ReadOnlySpan<byte> generator = WellKnownCurves.GetG1GeneratorCompressed(Curve);
        Assert.IsTrue(NaiveIsInSubgroup(generator, Curve), "The naive test must accept the generator.");
        Assert.IsTrue(EndomorphismIsInSubgroup(generator, Curve), "The endomorphism test must accept the generator.");

        Span<byte> scalar = stackalloc byte[Scalar.SizeBytes];
        Span<byte> multiple = stackalloc byte[WellKnownCurves.GetG1CompressedSizeBytes(Curve)];
        foreach(ulong k in HonestScalars)
        {
            scalar.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(scalar[^sizeof(ulong)..], k);
            ScalarMultiply(generator, scalar, multiple, Curve);
            Assert.IsTrue(NaiveIsInSubgroup(multiple, Curve), $"The naive test must accept [{k}]G.");
            Assert.IsTrue(EndomorphismIsInSubgroup(multiple, Curve), $"The endomorphism test must accept [{k}]G.");
        }
    }


    /// <summary>
    /// The identity is a subgroup member for both predicates, and undecodable
    /// input — off-curve x, a non-canonical infinity encoding, or a wrong
    /// length — is rejected by both.
    /// </summary>
    [TestMethod]
    public void EdgeEncodingsAgree()
    {
        ReadOnlySpan<byte> identity = WellKnownCurves.GetG1IdentityCompressed(Curve);
        Assert.IsTrue(NaiveIsInSubgroup(identity, Curve), "The naive test must accept the identity.");
        Assert.IsTrue(EndomorphismIsInSubgroup(identity, Curve), "The endomorphism test must accept the identity.");

        Assert.IsFalse(NaiveIsInSubgroup(OffCurvePoint, Curve), "The naive test must reject an off-curve x.");
        Assert.IsFalse(EndomorphismIsInSubgroup(OffCurvePoint, Curve), "The endomorphism test must reject an off-curve x.");

        Span<byte> nonCanonicalInfinity = stackalloc byte[WellKnownCurves.GetG1CompressedSizeBytes(Curve)];
        nonCanonicalInfinity.Clear();
        nonCanonicalInfinity[0] = 0xC0;
        nonCanonicalInfinity[^1] = 0x01;
        Assert.IsFalse(NaiveIsInSubgroup(nonCanonicalInfinity, Curve), "The naive test must reject a non-canonical infinity encoding.");
        Assert.IsFalse(EndomorphismIsInSubgroup(nonCanonicalInfinity, Curve), "The endomorphism test must reject a non-canonical infinity encoding.");

        Span<byte> truncated = stackalloc byte[WellKnownCurves.GetG1CompressedSizeBytes(Curve) - 1];
        truncated.Clear();
        truncated[0] = 0x80;
        Assert.IsFalse(NaiveIsInSubgroup(truncated, Curve), "The naive test must reject a truncated encoding.");
        Assert.IsFalse(EndomorphismIsInSubgroup(truncated, Curve), "The endomorphism test must reject a truncated encoding.");
    }


    /// <summary>
    /// Verdict agreement over a deterministic sweep of decompressable points:
    /// walking x upward, a decoded point is almost never in the prime-order
    /// subgroup (the accepting fraction is <c>1/h</c>), so the sweep pins the
    /// two predicates to identical verdicts on structurally arbitrary
    /// on-curve input rather than on hand-picked cases.
    /// </summary>
    [TestMethod]
    public void ArbitraryOnCurvePointsGetIdenticalVerdicts()
    {
        //Enough decodable x values to cross several torsion mixtures; the walk
        //starts past the x = 0 torsion point covered by the corpus.
        const int SweptPointCount = 8;

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        Span<byte> candidate = stackalloc byte[g1Size];
        int found = 0;
        for(byte x = 2; found < SweptPointCount; x++)
        {
            candidate.Clear();
            candidate[0] = 0x80;
            candidate[^1] = x;
            if(!IsOnCurve(candidate, Curve))
            {
                continue;
            }

            found++;
            bool naive = NaiveIsInSubgroup(candidate, Curve);
            bool endomorphism = EndomorphismIsInSubgroup(candidate, Curve);
            Assert.AreEqual(naive, endomorphism, $"Predicates must agree on the decodable point with x = {x}.");
        }
    }


    /// <summary>
    /// Pins the β constant algebraically — a primitive cube root of unity
    /// modulo the base field prime — and the parameter square
    /// <c>u² = 0xd201000000010000²</c>.
    /// </summary>
    [TestMethod]
    public void EndomorphismConstantsSatisfyDefiningRelations()
    {
        BigInteger p = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
        BigInteger beta = Bls12Curve381EndomorphismG1Backend.Beta;
        Assert.AreNotEqual(BigInteger.One, beta, "β must be a non-trivial cube root of unity.");
        Assert.AreEqual(BigInteger.Zero, (beta * beta + beta + 1) % p, "β must satisfy β² + β + 1 ≡ 0 mod p.");

        BigInteger u = BigInteger.Parse("0d201000000010000", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
        Assert.AreEqual(u * u, Bls12Curve381EndomorphismG1Backend.USquared, "U² must be the square of the BLS parameter magnitude.");
    }


    /// <summary>
    /// Pins the eigenvalue pairing on the generator:
    /// <c>ψ(G) = (β·x, y)</c> must equal <c>[r − u²]G = [−u²]G</c>. The other
    /// cube root realises the eigenvalue <c>u² − 1</c>, so this pin is what
    /// fails if the β constant is ever swapped for its conjugate.
    /// </summary>
    [TestMethod]
    public void BetaRealisesTheMinusUSquaredEigenvalueOnTheGenerator()
    {
        BigInteger p = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);

        Bls12Curve381BigIntegerG1Reference.AffinePoint generator =
            Bls12Curve381BigIntegerG1Reference.Decode(WellKnownCurves.GetG1GeneratorCompressed(Curve));
        var psiOfGenerator = new Bls12Curve381BigIntegerG1Reference.AffinePoint(
            generator.X * Bls12Curve381EndomorphismG1Backend.Beta % p,
            generator.Y,
            IsInfinity: false);
        Span<byte> psiEncoded = stackalloc byte[g1Size];
        Bls12Curve381BigIntegerG1Reference.Encode(psiOfGenerator, psiEncoded);

        BigInteger lambda = Bls12Curve381BigIntegerG1Reference.ScalarFieldOrder - Bls12Curve381EndomorphismG1Backend.USquared;
        Span<byte> lambdaBytes = stackalloc byte[Scalar.SizeBytes];
        FillBigEndian(lambda, lambdaBytes);
        Span<byte> lambdaTimesGenerator = stackalloc byte[g1Size];
        ScalarMultiply(WellKnownCurves.GetG1GeneratorCompressed(Curve), lambdaBytes, lambdaTimesGenerator, Curve);

        Assert.IsTrue(psiEncoded.SequenceEqual(lambdaTimesGenerator), "ψ(G) must equal [r − u²]G under the pinned β.");
    }


    /// <summary>
    /// The production BLS12-381 G1 bundle wires the endomorphism predicate —
    /// pinned by delegate identity, the same binding discipline the
    /// constant-time ladder uses.
    /// </summary>
    [TestMethod]
    public void ProductionBundleWiresTheEndomorphismPredicate()
    {
        using G1ArithmeticBackend bundle = Bls12Curve381ManagedG1Backend.Create();

        Assert.AreEqual(Bls12Curve381EndomorphismG1Backend.GetIsInPrimeOrderSubgroup(), bundle.IsInPrimeOrderSubgroup,
            "Create() must wire the endomorphism subgroup predicate.");
        Assert.AreNotEqual(Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup(), bundle.IsInPrimeOrderSubgroup,
            "The naive reference predicate remains the test-side ground truth, not the production wiring.");
    }


    /// <summary>Writes <paramref name="value"/> big-endian, right-aligned and zero-padded, into <paramref name="destination"/>.</summary>
    private static void FillBigEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        Span<byte> raw = stackalloc byte[destination.Length];
        bool written = value.TryWriteBytes(raw, out int count, isUnsigned: true, isBigEndian: true);
        Assert.IsTrue(written, "The scalar must fit its destination.");
        raw[..count].CopyTo(destination[(destination.Length - count)..]);
    }
}
