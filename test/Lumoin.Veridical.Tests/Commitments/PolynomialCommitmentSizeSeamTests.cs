using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Text;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Gates <see cref="PolynomialCommitmentProvider.CommitmentSizeBytes"/> against
/// the only thing that can settle it: the bytes <see cref="PolynomialCommitmentProvider.Commit"/>
/// actually produces. A consumer laying out a fixed-format proof splits the wire
/// bytes at the offsets this seam reports, so a seam that disagrees with the
/// commitment by one byte misreads every section after it before a single
/// cryptographic check runs — a failure that surfaces as a rejected proof with no
/// indication of where the mismatch is.
/// </summary>
/// <remarks>
/// <para>
/// Stating the length is not enough; it has to be stated for the right reason. A
/// hash-tree commitment is one Merkle node wide, and every hash-tree scheme here
/// brings its leaves to the configured node width through its own leaf
/// commitment, so the root is exactly the digest size the provider was built
/// with. The seam's contract is nevertheless the bytes Commit actually produced,
/// not the configuration that should have produced them, which is why these
/// tests compare against the commitment itself rather than restating the
/// configured figure.
/// </para>
/// <para>
/// Hyrax is the one scheme whose commitment length is not constant, so it carries
/// the case that a constant would satisfy vacuously.
/// </para>
/// </remarks>
[TestClass]
internal sealed class PolynomialCommitmentSizeSeamTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>The Merkle digest size every hash-tree scheme here is wired with.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>A query count large enough to exercise a real opening without slowing the gate.</summary>
    private const int QueryCount = 8;

    /// <summary>WHIR's initial inverse-rate exponent: rate 1/4.</summary>
    private const int WhirInitialRateLog2 = 2;

    /// <summary>WHIR's per-round target, the largest whole level the wired shapes place on distinct query cosets.</summary>
    private const int WhirSecurityLevelBits = 24;

    /// <summary>The smallest variable count the hash-tree schemes here commit at.</summary>
    private const int SmallVariableCount = 8;

    /// <summary>A larger variable count, so a length that varies with it is seen to vary.</summary>
    private const int LargeVariableCount = 9;

    /// <summary>The deterministic fill's salt.</summary>
    private const int FillSalt = 4242;

    /// <summary>The BLS12-381 scalar addition backend.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar subtraction backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar multiplication backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar inversion backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 scalar reduction backend.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 hash-to-scalar backend.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The BLS12-381 random-scalar backend.</summary>
    private static ScalarRandomDelegate ScalarRandom { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();

    /// <summary>The BLS12-381 G1 hash-to-curve backend.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The BLS12-381 G1 addition backend.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BLS12-381 G1 scalar-multiplication backend.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BLS12-381 G1 multi-scalar-multiplication backend.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The BLS12-381 G1 on-curve validation backend.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>The BLS12-381 G1 prime-order-subgroup validation backend.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The code seed the BaseFold flavors derive their encoder from.</summary>
    private static byte[] CodeSeed { get; } = Encoding.UTF8.GetBytes("veridical.test.commitment-size-seam.code.v1");

    /// <summary>The curve every artifact is tagged with.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>
    /// Every hash-tree factory states a commitment length, and it is the length of
    /// the commitment that factory's own commit path produces.
    /// </summary>
    /// <param name="schemeName">The factory to exercise.</param>
    /// <param name="variableCount">The variable count to commit at.</param>
    [TestMethod]
    [DataRow("ligero", SmallVariableCount)]
    [DataRow("ligero", LargeVariableCount)]
    [DataRow("basefold", SmallVariableCount)]
    [DataRow("basefold", LargeVariableCount)]
    [DataRow("zkbasefold", SmallVariableCount)]
    [DataRow("zkbasefold", LargeVariableCount)]
    [DataRow("whir", SmallVariableCount)]
    [DataRow("whir", LargeVariableCount)]
    [DataRow("zkwhir", SmallVariableCount)]
    [DataRow("zkwhir", LargeVariableCount)]
    public void SeamMatchesTheCommitmentTheHashTreeSchemeProduces(string schemeName, int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using PolynomialCommitmentProvider provider = NewHashTreeProvider(pool, schemeName);
        using MultilinearExtension mle = BuildMle(variableCount, pool);

        PolynomialCommitmentSizeDelegate? seam = provider.CommitmentSizeBytes;
        Assert.IsNotNull(seam, $"The {schemeName} provider must state its commitment length; a consumer cannot size the section otherwise.");

        var (commitment, blind) = provider.Commit(mle, pool);
        using(commitment)
        using(blind)
        {
            Assert.AreEqual(
                commitment.AsReadOnlySpan().Length,
                seam(variableCount),
                $"The {schemeName} seam must report the length the scheme's own commit path produces at {variableCount} variables.");
        }
    }


    /// <summary>
    /// The opening seam's domain has to be the prover's domain. A zero-layer code
    /// has nothing to fold, so the prover refuses it and no opening exists at that
    /// variable count; a length returned for one would be consumed as a section
    /// boundary before any check ran, which is the misreading the seam exists to
    /// prevent.
    /// </summary>
    [TestMethod]
    public void OpeningSeamRefusesAVariableCountNoOpeningExistsAt()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => BaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(0, Curve, QueryCount, DigestSizeBytes),
            "BaseFold cannot open a zero-layer code, so its opening seam must not state a length for one.");

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => ZkBaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(0, Curve, QueryCount, DigestSizeBytes),
            "The salted flavour opens at the committed variable count, so it must refuse a zero-layer code too.");
    }


    /// <summary>
    /// The refusal is about the code the prover sees, not the witness the caller
    /// hands in: a lift makes a zero-variable witness provable, so the lifting
    /// helper keeps answering for one.
    /// </summary>
    [TestMethod]
    public void OpeningSeamStillAnswersForAZeroVariableWitnessTheLiftMakesProvable()
    {
        int lift = ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount(0, Curve, QueryCount);
        int lifted = ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
            0, lift, Curve, QueryCount, DigestSizeBytes);

        Assert.IsGreaterThan(
            0,
            lifted,
            "A zero-variable witness is committed at the lifted layer count, so an opening exists and the seam must state its length.");
    }


    /// <summary>
    /// The Hyrax seam matches its commit path too, at two variable counts whose
    /// matrix splits differ, so a constant cannot satisfy this vacuously.
    /// </summary>
    /// <param name="variableCount">The variable count to commit at.</param>
    [TestMethod]
    [DataRow(4)]
    [DataRow(5)]
    [DataRow(6)]
    public void SeamMatchesTheCommitmentHyraxProduces(int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var dimensions = HyraxCommitmentDimensions.ForVariableCount(variableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(
            dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, pool);

        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            key, Curve, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup);

        using MultilinearExtension mle = BuildMle(variableCount, pool);

        PolynomialCommitmentSizeDelegate? seam = provider.CommitmentSizeBytes;
        Assert.IsNotNull(seam, "The Hyrax provider must state its commitment length.");

        var (commitment, blind) = provider.Commit(mle, pool);
        using(commitment)
        using(blind)
        {
            Assert.AreEqual(
                commitment.AsReadOnlySpan().Length,
                seam(variableCount),
                $"The Hyrax seam must report the length its own commit path produces at {variableCount} variables.");
        }
    }


    /// <summary>
    /// The Hyrax commitment grows with the variable count, so the seam is
    /// reporting a function rather than a constant that happens to fit.
    /// </summary>
    [TestMethod]
    public void HyraxSeamVariesWithTheVariableCount()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //Two counts whose row halves differ: 2^2 rows against 2^3.
        const int NarrowVariableCount = 4;
        const int WideVariableCount = 6;

        var dimensions = HyraxCommitmentDimensions.ForVariableCount(WideVariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(
            dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, pool);

        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            key, Curve, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup);

        PolynomialCommitmentSizeDelegate seam = provider.CommitmentSizeBytes!;

        Assert.IsLessThan(
            seam(WideVariableCount),
            seam(NarrowVariableCount),
            "A Pedersen row commitment carries one point per row, so more variables must mean a longer commitment.");
    }


    /// <summary>
    /// A hash-tree commitment is one Merkle node, so its length does not move with
    /// the variable count — the property that lets a consumer size the section
    /// before it knows the instance shape.
    /// </summary>
    /// <param name="schemeName">The factory to exercise.</param>
    [TestMethod]
    [DataRow("ligero")]
    [DataRow("basefold")]
    [DataRow("zkbasefold")]
    [DataRow("whir")]
    [DataRow("zkwhir")]
    public void HashTreeSeamIsConstantInTheVariableCount(string schemeName)
    {
        using PolynomialCommitmentProvider provider = NewHashTreeProvider(BaseMemoryPool.Shared, schemeName);
        PolynomialCommitmentSizeDelegate seam = provider.CommitmentSizeBytes!;

        Assert.AreEqual(
            seam(SmallVariableCount),
            seam(LargeVariableCount),
            $"The {schemeName} commitment is one Merkle root at every size, so its length cannot depend on the variable count.");
    }


    /// <summary>
    /// Builds one of the hash-tree providers by name.
    /// </summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="schemeName">The factory to build.</param>
    /// <returns>The provider; the caller owns its disposal.</returns>
    private static PolynomialCommitmentProvider NewHashTreeProvider(BaseMemoryPool pool, string schemeName)
    {
        return schemeName switch
        {
            "ligero" => LigeroPolynomialCommitmentScheme.Create(
                Curve, QueryCount, Add, Subtract, Multiply, Invert, Reduce, Hash, Squeeze, Hash, Merkle,
                WellKnownHashAlgorithms.Blake3),
            "basefold" => BaseFoldPolynomialCommitmentScheme.Create(
                CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                HashToScalar, pool, DigestSizeBytes),
            "zkbasefold" => ZkBaseFoldPolynomialCommitmentScheme.Create(
                CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                ScalarRandom, HashToScalar, pool, DigestSizeBytes),
            "whir" => WhirPolynomialCommitmentScheme.Create(
                Curve, WhirInitialRateLog2, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                securityLevelBits: WhirSecurityLevelBits),
            "zkwhir" => WhirPolynomialCommitmentScheme.CreateZeroKnowledge(
                Curve, WhirInitialRateLog2, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                ScalarRandom, securityLevelBits: WhirSecurityLevelBits),
            _ => throw new ArgumentOutOfRangeException(nameof(schemeName), schemeName, "Unknown scheme name.")
        };
    }


    /// <summary>
    /// A deterministic dense MLE over the boolean cube.
    /// </summary>
    /// <param name="variableCount">The polynomial's variable count.</param>
    /// <param name="pool">The pool to rent from.</param>
    /// <returns>The extension; the caller owns its disposal.</returns>
    private static MultilinearExtension BuildMle(int variableCount, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evaluations = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        DeterministicScalarFill.FillCanonical(evaluations, FillSalt, Reduce, Curve);

        return MultilinearExtension.FromEvaluations(evaluations, variableCount, Curve, pool);
    }


    /// <summary>
    /// The two-to-one Merkle compression over BLAKE3.
    /// </summary>
    /// <param name="left">The left child.</param>
    /// <param name="right">The right child.</param>
    /// <param name="output">Receives the compressed node.</param>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
