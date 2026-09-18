using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for <see cref="WhirPolynomialCommitmentScheme"/>: the WHIR IOPP
/// behind the scheme-agnostic
/// <see cref="PolynomialCommitmentProvider"/> surface. These drive
/// commit → open → verify end to end through the broad
/// <see cref="PolynomialCommitment"/> / <see cref="PolynomialOpening"/> leaf
/// types — exercising the wire codec on the way — and gate the claimed value
/// against the independent big-integer MLE evaluation reference, which pins
/// the coefficient-order convention to the rest of the provider ecosystem.
/// Real BLS12-381 arithmetic and production BLAKE3 throughout.
/// </summary>
[TestClass]
internal sealed class WhirPolynomialCommitmentSchemeTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>The provider's initial inverse-rate exponent: rate 1/4.</summary>
    private const int FastInitialRateLog2 = 2;

    /// <summary>
    /// The provider's per-round target: 24 bits is the largest whole level
    /// the wired polynomial shapes can place on distinct query cosets.
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


    /// <summary>
    /// Verifies that an honest commit→open→verify round trip stamps the commitment
    /// <see cref="CommitmentScheme.Whir"/>, opens to the value the independent big-integer MLE
    /// reference computes, produces an opening of the schedule-derived length, and verifies.
    /// </summary>
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

                    int expectedOpeningBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
                        variableCount, Curve, FastInitialRateLog2, securityLevelBits: FastSecurityLevelBits);
                    Assert.HasCount(expectedOpeningBytes, opening.AsReadOnlySpan(), "The opening must have the schedule-derived length.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsTrue(verified, $"An honest commit→open→verify must round-trip for n = {variableCount}.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Verifies that flipping the opening's first byte, a folded-oracle root, makes verification reject it.</summary>
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
                    //Flip a byte inside the opening (a folded-oracle root).
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


    /// <summary>Verifies that a commitment copy with its first byte flipped is rejected against a genuine opening.</summary>
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


    /// <summary>Verifies that a claimed value one off from the true evaluation is rejected against a genuine opening.</summary>
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


    /// <summary>Verifies that an opening truncated by its last byte is rejected as malformed wire input rather than thrown on.</summary>
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
    /// The digest width is a real capability, not a label: at a node width
    /// other than the scalar width the coset fold produces node-wide leaf
    /// digests, the commitment root and every oracle root carry the
    /// configured width, the opening fills exactly the budget the wire
    /// layout prices, and verification recomputes the coset leaf at the
    /// root's width.
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
                Assert.HasCount(WideDigestSizeBytes, commitment.AsReadOnlySpan(), "The commitment is one Merkle root at the configured node width.");

                PolynomialCommitmentSizeDelegate? commitmentSeam = provider.CommitmentSizeBytes;
                Assert.IsNotNull(commitmentSeam, "A hash-tree provider must state its commitment width.");
                Assert.AreEqual(WideDigestSizeBytes, commitmentSeam(VariableCount), "The commitment seam must state the width Commit produces.");

                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    int expectedOpeningBytes = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
                        VariableCount, Curve, FastInitialRateLog2, securityLevelBits: FastSecurityLevelBits, digestSizeBytes: WideDigestSizeBytes);
                    Assert.HasCount(expectedOpeningBytes, opening.AsReadOnlySpan(), "The opening must fill exactly the wide-digest budget.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    Assert.IsTrue(
                        provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                        "An honest commit→open→verify must round-trip at the wide digest.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// A commitment is one Merkle root at the provider's configured node
    /// width, so a commitment of any other width was never made by this
    /// provider and verification must reject it as a non-match. Past the
    /// Merkle surface's widest admissible digest the authentication walk would
    /// throw instead, so the refusal must land before the walk: malformed wire
    /// input is a rejection, not a fault.
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


    /// <summary>Verifies that a plain WHIR provider reports no weighted-opening support, no hiding, and no additive homomorphism.</summary>
    [TestMethod]
    public void ProviderRefusesWeightedOpening()
    {
        using PolynomialCommitmentProvider provider = NewProvider();

        Assert.IsFalse(provider.SupportsWeightedOpening, "Plain WHIR is binding-only: no weighted-opening path.");
        Assert.IsFalse(provider.IsHiding, "Plain WHIR must not claim hiding.");
        Assert.IsFalse(provider.IsAdditivelyHomomorphic, "A Merkle-root commitment must not claim additive homomorphism.");
    }


    /// <summary>
    /// The provider answers the opening-length question from the schedule it
    /// was built with, and answers it identically to the public sizing
    /// function. A consumer laying out a fixed-format proof reads the seam
    /// rather than reassembling the arithmetic, so the two must not drift.
    /// </summary>
    [TestMethod]
    [DataRow(8)]
    [DataRow(9)]
    [DataRow(12)]
    public void ProviderSizingSeamAgreesWithThePublicSizingFunction(int variableCount)
    {
        using PolynomialCommitmentProvider provider = NewProvider();

        PolynomialOpeningSizeDelegate? seam = provider.EvaluationProofSizeBytes;
        Assert.IsNotNull(seam, "A WHIR provider must expose the opening-length seam; its query counts vary per round, so no repetition count can stand in for it.");

        int expected = WhirPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            variableCount,
            Curve,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);

        Assert.AreEqual(expected, seam(variableCount), "The provider's opening length must match the public sizing function at the same figures.");
    }


    /// <summary>
    /// The scheme-specific sizing figures the other providers carry cannot
    /// describe WHIR, so a consumer that reads them instead of the seam gets
    /// nothing to work with. Stating it here keeps a future change from
    /// quietly populating <see cref="PolynomialCommitmentProvider.QueryCount"/>
    /// with one round's count and making the omission look like an oversight.
    /// </summary>
    [TestMethod]
    public void ProviderCarriesNoSingleQueryCount()
    {
        using PolynomialCommitmentProvider provider = NewProvider();

        Assert.IsNull(provider.QueryCount, "WHIR's query count varies per round; no single value describes the scheme.");
        Assert.IsNotNull(provider.EvaluationProofSizeBytes, "The seam is what replaces it.");
    }


    /// <summary>The pinned test's MLE variable count.</summary>
    private const int PinnedVariableCount = 8;

    /// <summary>
    /// The evaluation-table salt: with <see cref="PinnedPointSalt"/>, it fully determines the commit
    /// and open below by fixed integer arithmetic, and a non-hiding commit draws no randomness at any
    /// step. That determinism is what makes a content pin meaningful here, and it is why a hiding
    /// scheme can only be pinned by length.
    /// </summary>
    private const int PinnedMleSalt = 1;

    /// <summary>The evaluation-point salt, paired with <see cref="PinnedMleSalt"/> to fully determine the commit and open below.</summary>
    private const int PinnedPointSalt = 5;

    /// <summary>
    /// The pinned commitment's digest rather than its serialized bytes: an opening runs to
    /// kilobytes, and a digest reports one flipped byte exactly as loudly at a fraction of the size.
    /// </summary>
    private const string PinnedCommitmentDigest = "D9FC4E1023A9984604E8D59577AE936D05A97F9F2BCF3150D7C1474312FA3CFA";

    /// <summary>
    /// The pinned opening's digest rather than its serialized bytes: an opening runs to kilobytes,
    /// and a digest reports one flipped byte exactly as loudly at a fraction of the size.
    /// </summary>
    private const string PinnedOpeningDigest = "9B23FC1E877B6AE006F2057EDCA0CDA793850DDBED5B73AA2D1AE3D6D5C62876";


    /// <summary>
    /// Pins the exact bytes an honest commit and open produce at the wired
    /// digest size, so a change to the serialized form is a decision rather
    /// than a side effect. The commitment and the opening are published
    /// artifacts: they travel inside packaged proof files and across the
    /// command-line surface, so a reader on the far side of a version boundary
    /// parses whatever this test lets through.
    /// </summary>
    /// <remarks>
    /// Widths are the reason this pin earns its place. A hash-tree commitment
    /// is one Merkle node wide and its authentication paths are priced by the
    /// configured digest size; those two figures agree under the wired pairing
    /// of a 32-byte hash with a 32-byte scalar, so a change that redefined
    /// either in terms of the other would leave every shipped byte where it is
    /// and stay invisible to a round-trip test, which proves only that the
    /// writer and the reader still agree with each other. Updating a constant
    /// here is correct only once the format change it reports has been shown
    /// to be intended.
    /// </remarks>
    [TestMethod]
    public void CommitmentAndOpeningBytesAreUnchangedAtTheWiredDigestSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(PinnedVariableCount, PinnedMleSalt, pool);
        Scalar[] point = BuildPoint(PinnedVariableCount, PinnedPointSalt, pool);

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
                    Assert.AreEqual(
                        PinnedCommitmentDigest,
                        PinnedDigestOf(commitment.AsReadOnlySpan()),
                        "The serialized commitment bytes changed; the wire format moved.");

                    Assert.AreEqual(
                        PinnedOpeningDigest,
                        PinnedDigestOf(opening.AsReadOnlySpan()),
                        "The serialized opening bytes changed; the wire format moved.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Hashes a serialized artifact down to the constant the pin above carries.</summary>
    private static string PinnedDigestOf(ReadOnlySpan<byte> serialized)
    {
        Span<byte> digest = stackalloc byte[WellKnownMerkleHashParameters.DefaultDigestSizeBytes];
        Blake3.Hash(serialized, digest);

        return Convert.ToHexString(digest);
    }


    /// <summary>The WHIR provider at the fast figures.</summary>
    private static PolynomialCommitmentProvider NewProvider()
    {
        return NewProvider(WellKnownMerkleHashParameters.DefaultDigestSizeBytes);
    }


    /// <summary>
    /// The WHIR provider at the fast figures and an explicit digest size.
    /// </summary>
    private static PolynomialCommitmentProvider NewProvider(int digestSizeBytes)
    {
        return WhirPolynomialCommitmentScheme.Create(
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
