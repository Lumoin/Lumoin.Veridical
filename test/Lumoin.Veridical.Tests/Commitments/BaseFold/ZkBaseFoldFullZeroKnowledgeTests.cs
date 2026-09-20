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
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// The full zero-knowledge BaseFold evaluation (the CFS-2017 sumcheck
/// mask on top of the dimension lift), driven end to end through
/// <see cref="ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge"/>.
/// The lift closes the query and base-oracle channels; the sumcheck mask closes
/// the round-polynomial channel, so the opening is genuinely simulatable.
/// </summary>
/// <remarks>
/// <para>
/// These gate correctness — that masking the round polynomials does not perturb
/// the proven value <c>f(z)</c> and that the masked sumcheck still verifies — and
/// the binding of the mask side (a tampered <c>σ</c>, mask root, or mask base
/// oracle, like a tampered witness byte, must be rejected). The
/// bounded-independence hiding budget that makes the revealed positions
/// witness-independent is the separate statistical claim validated empirically
/// by <see cref="Lumoin.Veridical.Tests.Analysis.ZkBaseFoldHidingValidationTests"/>,
/// not asserted here. Real BLS12-381 arithmetic and production BLAKE3 throughout; the BaseFold
/// commitment test surface is uniformly BLS12-381.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ZkBaseFoldFullZeroKnowledgeTests
{
    /// <summary>The BLS12-381 scalar addition delegate the BaseFold provider computes over.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar subtraction delegate the BaseFold provider computes over.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar multiplication delegate the BaseFold provider computes over.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar inversion delegate the BaseFold provider computes over.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The delegate that reduces a wide byte buffer to a canonical BLS12-381 scalar.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The delegate that hashes arbitrary bytes to a BLS12-381 scalar, used by the Fiat-Shamir challenge derivation.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The BLS12-381 scalar randomness delegate the sumcheck mask and lift salts draw from.</summary>
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();

    /// <summary>The multilinear-extension evaluation delegate used to compute the reference value f(z).</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The Fiat-Shamir hash delegate every transcript in this file uses.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The Fiat-Shamir squeeze delegate every transcript in this file uses.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The Merkle two-to-one hash every commitment tree in this file uses.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The byte width of one BLS12-381 scalar.</summary>
    private const int ScalarSize = 32;

    /// <summary>The default Merkle digest width in bytes the non-wide-digest tests commit at.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The number of Ligero-style query positions the test providers open.</summary>
    private const int TestQueryCount = 12;

    /// <summary>
    /// The widest digest the Merkle surface admits — twice the scalar width,
    /// so the scheme's leaf commitment genuinely runs on every layer,
    /// including the sumcheck mask's own commitment tree and its nested
    /// weighted opening.
    /// </summary>
    private const int WideDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes;

    /// <summary>The BLS12-381 curve tag every delegate call in this file routes over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>
    /// The digest width is a real capability for the full zero-knowledge
    /// flavour too: the lifted salted witness tree, every fold-layer tree,
    /// the sumcheck mask's own commitment tree and its nested weighted
    /// opening all carry the configured node width, the opening fills
    /// exactly the wide-digest budget, and the masked verification chain
    /// closes.
    /// </summary>
    [TestMethod]
    public void FullZeroKnowledgeRoundTripsAtAWideDigest()
    {
        //The minimal budget-meeting lift for a one-variable witness at
        //TestQueryCount = 12, matching the corresponding round-trip row.
        const int RealVariableCount = 1;
        const int ExtraVariableCount = 6;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider(pool, ExtraVariableCount, WideDigestSizeBytes);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 27, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 29, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            using(blind)
            {
                Assert.HasCount(WideDigestSizeBytes, commitment.AsReadOnlySpan(), "The lifted hiding commitment is one Merkle root at the configured node width.");

                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, witness, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    int expectedSize = ZkBaseFoldPolynomialCommitmentScheme.GetFullZeroKnowledgeEvaluationProofSizeBytes(
                        RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, WideDigestSizeBytes);
                    Assert.HasCount(expectedSize, opening.AsReadOnlySpan(), "The full-ZK opening must fill exactly the wide-digest budget.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    Assert.IsTrue(
                        provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                        "An honest full-ZK commit→open→verify must round-trip at the wide digest.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// Verifies that an honest full zero-knowledge opening recovers the witness's true evaluation
    /// f(z), that its serialized length matches the size helper exactly, that it verifies against
    /// the correct claimed value, and that it is rejected against a wrong one.
    /// </summary>
    /// <remarks>
    /// Each <c>(d, t)</c> row is the minimal budget-meeting lift for its witness size at
    /// <c>TestQueryCount = 12</c>, as <see cref="ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount"/>
    /// computes it; the provider refuses any under-budget configuration, so these rows sit
    /// exactly at the floor the hiding budget enforces.
    /// </remarks>
    [TestMethod]
    [DataRow(1, 6)]
    [DataRow(2, 5)]
    [DataRow(3, 4)]
    [DataRow(4, 3)]
    public void FullZeroKnowledgeOpeningRecoversWitnessValueAndVerifies(int realVariableCount, int extraVariableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider(pool, extraVariableCount);

        Assert.IsTrue(provider.IsHiding, "The full ZK BaseFold provider must report itself as hiding.");

        using MultilinearExtension witness = BuildRandomMle(realVariableCount, salt: 21, pool);
        Scalar[] point = BuildPoint(realVariableCount, salt: 23, pool);

        try
        {
            using Scalar expected = witness.Evaluate(point, MleEvaluate, pool);

            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    using FiatShamirTranscript openTx = NewTranscript();
                    (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, witness, point, openTx, pool);

                    using(opening)
                    {
                        using(claimedValue)
                        {
                            //The sumcheck mask must not perturb the proven value: the
                            //lift fixes the extra coordinates to zero and the mask only
                            //blends the round polynomials, so it is still f(z).
                            Assert.IsTrue(
                                claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                                $"The full-ZK opening must recover f(z) for d = {realVariableCount}, t = {extraVariableCount}.");

                            //The serialized opening must match the size helper exactly.
                            int expectedSize = ZkBaseFoldPolynomialCommitmentScheme.GetFullZeroKnowledgeEvaluationProofSizeBytes(
                                realVariableCount, extraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
                            Assert.HasCount(expectedSize, opening.AsReadOnlySpan(), "The full-ZK opening length must match the size helper.");

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsTrue(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                $"An honest full-ZK commit→open→verify must round-trip for d = {realVariableCount}, t = {extraVariableCount}.");

                            using Scalar wrong = AddOne(claimedValue, pool);
                            using FiatShamirTranscript rejectTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, wrong, opening, rejectTx, pool),
                                "A wrong claimed value must be rejected.");
                        }
                    }
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// Verifies that the full zero-knowledge proof size is strictly larger than the lift-only
    /// hiding proof size at the same shape, since the mask side (σ, mask roots, mask base oracle,
    /// mask query openings) roughly doubles the opening.
    /// </summary>
    [TestMethod]
    public void FullZeroKnowledgeOpeningIsLargerThanTheLiftOnlyOpening()
    {
        //The mask side (σ, mask roots, mask base oracle, mask query openings)
        //roughly doubles the opening; it must be strictly larger than the
        //lift-only hiding opening at the same shape.
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;

        int liftOnly = ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
            RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
        int full = ZkBaseFoldPolynomialCommitmentScheme.GetFullZeroKnowledgeEvaluationProofSizeBytes(
            RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);

        Assert.IsGreaterThan(liftOnly, full, "The full-ZK opening must be larger than the lift-only opening (it carries the mask side).");
    }


    /// <summary>
    /// Verifies that flipping one byte of the mask sum σ, which sits immediately after the
    /// lift-only witness section, changes the verifier's recomputed challenge ρ and breaks the
    /// masked sumcheck chain, so verification is rejected.
    /// </summary>
    [TestMethod]
    public void TamperedMaskSumIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(pool, ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 31, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 33, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    using FiatShamirTranscript openTx = NewTranscript();
                    (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, witness, point, openTx, pool);

                    using(opening)
                    {
                        using(claimedValue)
                        {
                            //The mask side begins immediately after the witness (hiding)
                            //section, whose length is the lift-only opening size; the v3
                            //layout opens with com(C*)'s root, then σ, then σ_F. Flipping
                            //a σ byte changes the verifier's recomputed ρ, breaking the
                            //masked sumcheck chain.
                            int maskOffset = ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
                                RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[maskOffset + DigestSizeBytes] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered mask sum σ must be rejected.");
                        }
                    }
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// Verifies that flipping one byte of com(C*)'s root, the mask section's first field, both
    /// changes the pre-ρ transcript absorb and fails the nested weighted opening's authentication
    /// against that root, so verification is rejected.
    /// </summary>
    [TestMethod]
    public void TamperedMaskRootIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(pool, ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 61, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 63, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    using FiatShamirTranscript openTx = NewTranscript();
                    (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, witness, point, openTx, pool);

                    using(opening)
                    {
                        using(claimedValue)
                        {
                            //com(C*)'s root is the mask section's first field. Corrupting
                            //it changes the pre-ρ absorb AND fails the nested weighted
                            //opening's authentication against that root.
                            int maskCommitmentRootOffset = ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
                                RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[maskCommitmentRootOffset] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered mask commitment root must be rejected.");
                        }
                    }
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// Verifies that flipping one byte of σ_F, which follows com(C*)'s root and σ, shifts the
    /// derived weighted claim s(r) + σ_F (and the pre-ρ transcript absorb), so the nested weighted
    /// opening fails and verification is rejected.
    /// </summary>
    [TestMethod]
    public void TamperedFillerSumIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(pool, ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 71, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 73, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    using FiatShamirTranscript openTx = NewTranscript();
                    (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, witness, point, openTx, pool);

                    using(opening)
                    {
                        using(claimedValue)
                        {
                            //σ_F follows com(C*)'s root and σ. Corrupting it shifts the
                            //derived weighted claim s(r) + σ_F (and the pre-ρ absorb), so
                            //the nested weighted opening must fail against it.
                            int maskStart = ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
                                RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
                            int fillerSumOffset = maskStart + DigestSizeBytes + ScalarSize;
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[fillerSumOffset] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered filler sum σ_F must be rejected.");
                        }
                    }
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// Verifies that flipping the opening's very last byte, which sits inside a query
    /// authentication path in the nested weighted opening's final section, fails the nested IOPP
    /// authentication and is rejected.
    /// </summary>
    [TestMethod]
    public void TamperedNestedWeightedOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(pool, ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 81, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 83, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    using FiatShamirTranscript openTx = NewTranscript();
                    (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, witness, point, openTx, pool);

                    using(opening)
                    {
                        using(claimedValue)
                        {
                            //The nested weighted opening is the final section; its last
                            //byte sits inside a query authentication path, so flipping it
                            //must fail the nested IOPP authentication.
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[^1] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered nested weighted opening must be rejected.");
                        }
                    }
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Verifies that flipping one byte of the first (blended) sumcheck round polynomial is rejected.</summary>
    [TestMethod]
    public void TamperedRoundPolynomialIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(pool, ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 41, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 43, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    using FiatShamirTranscript openTx = NewTranscript();
                    (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, witness, point, openTx, pool);

                    using(opening)
                    {
                        using(claimedValue)
                        {
                            //Flip a byte in the first (blended) round polynomial.
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[0] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered round polynomial must be rejected.");
                        }
                    }
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// Verifies that two independent openings of the same commitment and point still prove the
    /// same value f(z) but produce different proof bytes, since the mask multilinear and the
    /// fold-layer salts are fresh per open — an opening is not a deterministic function of the
    /// witness.
    /// </summary>
    [TestMethod]
    public void TwoOpeningsOfTheSameStatementDiffer()
    {
        //The mask multilinear and the fold-layer salts are fresh per open, so two
        //honest openings of the same (commitment, point) are different byte strings
        //— the ZK-flavoured expectation that an opening is not a deterministic
        //function of the witness.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(pool, ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 51, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 53, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    using FiatShamirTranscript firstTx = NewTranscript();
                    (PolynomialOpening first, Scalar firstValue) = provider.Open(commitment, blind, witness, point, firstTx, pool);

                    using FiatShamirTranscript secondTx = NewTranscript();
                    (PolynomialOpening second, Scalar secondValue) = provider.Open(commitment, blind, witness, point, secondTx, pool);

                    using(first)
                    {
                        using(firstValue)
                        {
                            using(second)
                            {
                                using(secondValue)
                                {
                                    Assert.IsTrue(
                                        firstValue.AsReadOnlySpan().SequenceEqual(secondValue.AsReadOnlySpan()),
                                        "Both openings must still prove the same value f(z).");
                                    Assert.IsFalse(
                                        first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
                                        "Two full-ZK openings of the same statement must differ (fresh mask and salts).");
                                }
                            }
                        }
                    }
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Builds a provider at the default digest width using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="extraVariableCount">The number of mask variables.</param>
    private static PolynomialCommitmentProvider NewProvider(BaseMemoryPool pool, int extraVariableCount)
    {
        return NewProvider(pool, extraVariableCount, DigestSizeBytes);
    }


    /// <summary>
    /// The full zero-knowledge provider at the test figures and an explicit
    /// digest size.
    /// </summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="extraVariableCount">The number of mask variables.</param>
    /// <param name="digestSizeBytes">The Merkle digest width in bytes.</param>
    private static PolynomialCommitmentProvider NewProvider(BaseMemoryPool pool, int extraVariableCount, int digestSizeBytes)
    {
        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, HashToScalar, extraVariableCount, pool,
            digestSizeBytes: digestSizeBytes);
    }


    /// <summary>Builds a multilinear extension whose evaluations are deterministically derived from the salt and index, reduced to canonical scalars.</summary>
    private static MultilinearExtension BuildRandomMle(int variableCount, int salt, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evals = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < evaluationCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 137) + (i * 19) + 1);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 11) + (i * 31) + 3);
            Reduce(wide, evals.Slice(i * ScalarSize, ScalarSize), Curve);
        }

        return MultilinearExtension.FromEvaluations(evals, variableCount, Curve, pool);
    }


    /// <summary>Builds an evaluation point whose coordinates are deterministically derived from the salt and index, reduced to canonical scalars.</summary>
    private static Scalar[] BuildPoint(int variableCount, int salt, BaseMemoryPool pool)
    {
        var point = new Scalar[variableCount];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < variableCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 59) + (i * 23) + 2);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 29) + (i * 43) + 5);
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            Reduce(wide, owner.Memory.Span[..ScalarSize], Curve);
            point[i] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        return point;
    }


    /// <summary>Returns a scalar one greater than the given value, used to build a deliberately wrong claimed value.</summary>
    private static Scalar AddOne(Scalar value, BaseMemoryPool pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    /// <summary>Disposes every coordinate scalar an evaluation point holds.</summary>
    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    /// <summary>Builds a fresh Fiat-Shamir transcript scoped to the BaseFold scheme's canonical domain label, with an empty initial absorb.</summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the two-to-one BLAKE3 compression every Merkle tree in this file uses, hashing the concatenation of the left and right inputs.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        //Buffered for the widest node the Merkle surface admits and sliced to
        //the actual input widths, so the same compression serves the default
        //and the wide-digest providers; BLAKE3 writes exactly output.Length.
        Span<byte> combined = stackalloc byte[2 * WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The fixed domain-separation seed every provider this file constructs is derived from.</summary>
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.FullZeroKnowledge.Test"u8;
}
