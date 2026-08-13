using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.Spartan;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for <see cref="WhirPolynomialCommitmentScheme.CreateZeroKnowledge"/>:
/// the HVZK-WHIR IOPP behind the scheme-agnostic
/// <see cref="PolynomialCommitmentProvider"/> surface. These drive
/// commit → open → verify end to end through the broad leaf types —
/// exercising the hiding wire codec and the commit-then-open randomness seam
/// on the way — pin the hiding-specific surface facts (the provider reports
/// hiding, the randomized commitment differs across commits to the same
/// polynomial) and gate the claimed value against the independent big-integer
/// MLE evaluation reference. Real BLS12-381 arithmetic, production BLAKE3 and
/// entropy-free deterministic mask sampling throughout.
/// </summary>
[TestClass]
internal sealed class ZkWhirPolynomialCommitmentSchemeTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>The provider's initial inverse-rate exponent: rate 1/4.</summary>
    private const int FastInitialRateLog2 = 2;

    /// <summary>
    /// The provider's per-round target, matching the shape the
    /// zero-knowledge parameter tests pin as hiding-admissible.
    /// </summary>
    private const int FastSecurityLevelBits = 24;

    /// <summary>The scalar-add backend.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The scalar-subtract backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The scalar-multiply backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The scalar-invert backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The scalar-reduce backend.</summary>
    private static ScalarReduceDelegate Reduce { get; } = TestScalarBackends.Bls12Curve381.Reduce;

    /// <summary>The independent big-integer MLE evaluation reference.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The curve every artifact is tagged with.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>The deterministic mask-sampling seed, distinct per test class.</summary>
    private static byte[] MaskSeed { get; } = Encoding.UTF8.GetBytes("zk-whir-pcs-tests");


    [TestMethod]
    [DataRow(8)]
    [DataRow(9)]
    public void CommitOpenVerifyRoundTrips(int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(variableCount, 1, pool);
        Scalar[] point = BuildPoint(variableCount, 5, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                Assert.AreEqual(CommitmentScheme.Whir, commitment.Scheme, "Commitment must be stamped Whir.");

                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using Scalar expected = mle.Evaluate(point, MleEvaluate, pool);
                    Assert.IsTrue(
                        claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                        $"Opened claimed value must equal f(z) under the ecosystem MLE convention for n = {variableCount}.");

                    int expectedOpeningBytes = WhirPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
                        variableCount, Curve, FastInitialRateLog2, securityLevelBits: FastSecurityLevelBits);
                    Assert.HasCount(expectedOpeningBytes, opening.AsReadOnlySpan(), "The opening must have the parameter-derived length.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsTrue(verified, $"An honest hiding commit→open→verify must round-trip for n = {variableCount}.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void CommitmentsToTheSamePolynomialDiffer()
    {
        //Fresh encoding randomness per commit is the hiding path's defining
        //surface fact: a deterministic root would fingerprint the witness.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 8;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 11, pool);

        (PolynomialCommitment first, PolynomialCommitmentBlind firstBlind) = provider.Commit(mle, pool);
        using(first)
        using(firstBlind)
        {
            (PolynomialCommitment second, PolynomialCommitmentBlind secondBlind) = provider.Commit(mle, pool);
            using(second)
            using(secondBlind)
            {
                Assert.IsFalse(
                    first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
                    "Two commitments to the same polynomial must differ under fresh encoding randomness.");
            }
        }
    }


    [TestMethod]
    public void TamperedOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 8;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 2, pool);
        Scalar[] point = BuildPoint(VariableCount, 6, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    //Flip a byte inside the opening (a sumcheck mask root).
                    MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[0] ^= 0x01;

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "A tampered opening must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void TamperedCommitmentIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 8;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 3, pool);
        Scalar[] point = BuildPoint(VariableCount, 7, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using PolynomialCommitment tampered = TamperFirstByte(commitment, pool);

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(tampered, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "A tampered commitment must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void WrongClaimedValueIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 8;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 4, pool);
        Scalar[] point = BuildPoint(VariableCount, 8, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using Scalar wrong = AddOne(claimedValue, pool);

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, wrong, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "A wrong claimed value must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void TruncatedOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 8;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 9, pool);
        Scalar[] point = BuildPoint(VariableCount, 10, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using PolynomialOpening truncated = PolynomialOpening.FromBytes(
                        opening.AsReadOnlySpan()[..^1], Curve, CommitmentScheme.Whir, pool);

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, truncated, verifyTx, pool);

                    Assert.IsFalse(verified, "A truncated opening must be rejected as malformed, not thrown on.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void ProviderReportsHidingAndRefusesWeightedOpening()
    {
        using PolynomialCommitmentProvider provider = NewProvider();

        Assert.IsTrue(provider.IsHiding, "The zero-knowledge provider must report hiding.");
        Assert.IsFalse(provider.SupportsWeightedOpening, "Hiding WHIR still carries no weighted-opening path.");
        Assert.IsFalse(provider.IsAdditivelyHomomorphic, "A Merkle-root commitment must not claim additive homomorphism.");
    }


    /// <summary>
    /// The hiding WHIR provider at the fast figures with deterministic mask
    /// sampling.
    /// </summary>
    private static PolynomialCommitmentProvider NewProvider()
    {
        return WhirPolynomialCommitmentScheme.CreateZeroKnowledge(
            Curve,
            FastInitialRateLog2,
            Merkle,
            Hash,
            Squeeze,
            Reduce,
            Add,
            Subtract,
            Multiply,
            Invert,
            new DeterministicScalarRandom(MaskSeed).AsDelegate(),
            securityLevelBits: FastSecurityLevelBits);
    }


    /// <summary>
    /// A commitment copy with its first byte flipped.
    /// </summary>
    private static PolynomialCommitment TamperFirstByte(PolynomialCommitment commitment, BaseMemoryPool pool)
    {
        Span<byte> bytes = stackalloc byte[commitment.AsReadOnlySpan().Length];
        commitment.AsReadOnlySpan().CopyTo(bytes);
        bytes[0] ^= 0x01;

        return PolynomialCommitment.FromBytes(bytes, Curve, CommitmentScheme.Whir, pool);
    }


    /// <summary>
    /// A deterministic dense MLE over the boolean cube.
    /// </summary>
    private static MultilinearExtension BuildRandomMle(int variableCount, int salt, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evaluations = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        DeterministicScalarFill.FillCanonical(evaluations, salt, Reduce, Curve);

        return MultilinearExtension.FromEvaluations(evaluations, variableCount, Curve, pool);
    }


    /// <summary>
    /// A deterministic evaluation point, one scalar per variable.
    /// </summary>
    private static Scalar[] BuildPoint(int variableCount, int salt, BaseMemoryPool pool)
    {
        var point = new Scalar[variableCount];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int coordinate = 0; coordinate < variableCount; coordinate++)
        {
            wide.Clear();
            BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 59) + (coordinate * 23) + 2);
            BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 29) + (coordinate * 43) + 5);
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            Reduce(wide, owner.Memory.Span[..ScalarSize], Curve);
            point[coordinate] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        return point;
    }


    /// <summary>
    /// The claimed value plus one — a wrong but canonical value.
    /// </summary>
    private static Scalar AddOne(Scalar value, BaseMemoryPool pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    /// <summary>
    /// Disposes every coordinate of an evaluation point.
    /// </summary>
    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    /// <summary>
    /// A fresh transcript under the WHIR domain label with empty context.
    /// </summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownWhirParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// The two-to-one compression: BLAKE3 over the concatenated children.
    /// </summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * ScalarSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
