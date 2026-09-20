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

    /// <summary>
    /// The widest digest the Merkle surface admits — twice the scalar width,
    /// so the coset fold genuinely produces node-wide digests instead of
    /// taking the verbatim scalar-wide path.
    /// </summary>
    private const int WideDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes;

    /// <summary>
    /// One byte past the widest digest the Merkle surface admits: the smallest
    /// width whose authentication walk would throw rather than mismatch, so a
    /// rejection proves the funnel refused it before the walk.
    /// </summary>
    private const int OverCapCommitmentWidthBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes + 1;


    /// <summary>Verifies that an honest hiding commit-then-open-then-verify round trip succeeds, that the claimed value matches the independent MLE evaluation reference, and that the opening has the parameter-derived length.</summary>
    /// <param name="variableCount">The multilinear polynomial's variable count to exercise.</param>
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


    /// <summary>Verifies that committing the same polynomial twice yields different commitment bytes, the hiding path's defining surface fact — a deterministic root would fingerprint the witness.</summary>
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


    /// <summary>Verifies that flipping the first byte of an honest opening (inside a sumcheck mask root) makes verification reject.</summary>
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


    /// <summary>Verifies that flipping the first byte of an honest commitment makes verification reject.</summary>
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


    /// <summary>Verifies that verifying an honest opening against a claimed value one more than the true evaluation is rejected.</summary>
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


    /// <summary>Verifies that an opening truncated by one byte is rejected as malformed input rather than throwing.</summary>
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


    /// <summary>
    /// The digest width is a real capability for the hiding flavour too: the
    /// randomized codeword's coset fold produces node-wide leaf digests, the
    /// commitment root and every oracle and mask root carry the configured
    /// width, the opening fills exactly the wide-digest budget, and
    /// verification recomputes every coset leaf — including the width-one
    /// mask-group blocks — at the root's width.
    /// </summary>
    [TestMethod]
    public void CommitOpenVerifyRoundTripsAtAWideDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 8;
        using PolynomialCommitmentProvider provider = NewProvider(WideDigestSizeBytes);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 12, pool);
        Scalar[] point = BuildPoint(VariableCount, 13, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                Assert.HasCount(WideDigestSizeBytes, commitment.AsReadOnlySpan(), "The hiding commitment is one Merkle root at the configured node width.");

                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    int expectedOpeningBytes = WhirPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
                        VariableCount, Curve, FastInitialRateLog2, securityLevelBits: FastSecurityLevelBits, digestSizeBytes: WideDigestSizeBytes);
                    Assert.HasCount(expectedOpeningBytes, opening.AsReadOnlySpan(), "The hiding opening must fill exactly the wide-digest budget.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    Assert.IsTrue(
                        provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                        "An honest hiding commit→open→verify must round-trip at the wide digest.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// A hiding commitment is still one Merkle root at the provider's
    /// configured node width, so a commitment of any other width was never
    /// made by this provider and verification must reject it as a non-match.
    /// Past the Merkle surface's widest admissible digest the authentication
    /// walk would throw instead, so the refusal must land before the walk:
    /// malformed wire input is a rejection, not a fault.
    /// </summary>
    [TestMethod]
    public void VerificationRejectsACommitmentWidthTheSchemeNeverProduces()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 8;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 14, pool);
        Scalar[] point = BuildPoint(VariableCount, 15, pool);

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
                    using PolynomialCommitment atCap = CommitmentOfWidth(WideDigestSizeBytes, pool);
                    using FiatShamirTranscript atCapTx = NewTranscript();
                    Assert.IsFalse(
                        provider.VerifyEvaluation(atCap, point, claimedValue, opening, atCapTx, pool),
                        "A commitment at the Merkle surface's widest admissible digest is still not one this scheme produces and must be rejected.");

                    using PolynomialCommitment overCap = CommitmentOfWidth(OverCapCommitmentWidthBytes, pool);
                    using FiatShamirTranscript overCapTx = NewTranscript();
                    Assert.IsFalse(
                        provider.VerifyEvaluation(overCap, point, claimedValue, opening, overCapTx, pool),
                        "A commitment wider than the Merkle surface admits must be rejected as malformed wire input, not thrown on.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Verifies the zero-knowledge WHIR provider's capability flags: hiding, no weighted-opening support, and no additive homomorphism.</summary>
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
        return NewProvider(WellKnownMerkleHashParameters.DefaultDigestSizeBytes);
    }


    /// <summary>
    /// The hiding WHIR provider at the fast figures, deterministic mask
    /// sampling and an explicit digest size.
    /// </summary>
    private static PolynomialCommitmentProvider NewProvider(int digestSizeBytes)
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
            securityLevelBits: FastSecurityLevelBits,
            digestSizeBytes: digestSizeBytes);
    }


    /// <summary>
    /// A syntactically valid commitment of an arbitrary width; the content is
    /// immaterial because the width alone must already reject it.
    /// </summary>
    private static PolynomialCommitment CommitmentOfWidth(int widthBytes, BaseMemoryPool pool)
    {
        Span<byte> bytes = stackalloc byte[widthBytes];

        return PolynomialCommitment.FromBytes(bytes, Curve, CommitmentScheme.Whir, pool);
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
    /// The two-to-one compression: BLAKE3 over the concatenated children,
    /// buffered for the widest node the Merkle surface admits and sliced to
    /// the actual input widths, so the same compression serves the default
    /// and the wide-digest providers; BLAKE3 writes exactly the output's
    /// length.
    /// </summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
