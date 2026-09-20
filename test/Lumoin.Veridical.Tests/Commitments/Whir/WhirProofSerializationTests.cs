using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the WHIR proof wire codec: a serialize →
/// deserialize round-trip that still verifies, the exact schedule-derived
/// length, and the reader funnel's rejections — a truncated buffer, a
/// non-canonical out-of-domain reply, final-polynomial element and opening
/// block value, and the digest-size caps. The real scalar arithmetic and the
/// production BLAKE3 hash are wired throughout.
/// </summary>
[TestClass]
internal sealed class WhirProofSerializationTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The codec shape's variable count: a 2^8-coefficient message with the
    /// paper's constant k = 4 gives two iterations, one folded-oracle root
    /// and one out-of-domain reply — every wire section non-empty.
    /// </summary>
    private const int FastVariableCount = 8;

    /// <summary>The codec shape's initial inverse-rate exponent: rate 1/4.</summary>
    private const int FastInitialRateLog2 = 2;

    /// <summary>
    /// The codec shape's per-round target: 24 bits is the largest whole
    /// level the shape can place on distinct query cosets.
    /// </summary>
    private const int FastSecurityLevelBits = 24;

    /// <summary>The wired Merkle digest size: BLAKE3's 32 bytes.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>A fill salt for the coefficient stream, distinct from the statement stream.</summary>
    private const int CoefficientSalt = 61;

    /// <summary>A fill salt for the statement-point stream, distinct from the coefficient stream.</summary>
    private const int StatementPointSalt = 62;

    /// <summary>The BLS12-381 scalar backend bundle.</summary>
    private static ScalarArithmeticBackend Bls { get; } = TestScalarBackends.Bls12Curve381;

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The compression paired with the node width it produces.</summary>
    private static MerkleCommitmentParameters TreeParameters { get; } = new(Merkle, WellKnownMerkleHashParameters.DefaultDigestSizeBytes);


    /// <summary>Verifies that an honest proof's serialized bytes are exactly the schedule-derived length and deserialize back into a proof that still verifies.</summary>
    [TestMethod]
    public void SerializedProofRoundTripsAndVerifies()
    {
        WhirParameterSchedule schedule = CreateFastSchedule();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ProofRun run = ProofRun.Create(schedule, pool);
        (IMemoryOwner<byte> bytesOwner, int length) = WhirProofSerialization.ToBytes(run.Proof, DigestSizeBytes, pool);
        using(bytesOwner)
        {
            Assert.AreEqual(WhirProofSerialization.ComputeLength(schedule, DigestSizeBytes), length, "The serialized length must equal the schedule-derived figure.");

            using WhirIoppProof deserialized = WhirProofSerialization.FromBytes(bytesOwner.Memory.Span[..length], schedule, DigestSizeBytes, pool);
            using FiatShamirTranscript verifierTranscript = NewTranscript();
            bool verified = WhirIoppVerifier.Verify(
                schedule,
                run.Commitment,
                deserialized,
                run.ConstraintCoefficients,
                run.ConstraintPoints,
                run.Target,
                verifierTranscript,
                Merkle,
                Hash,
                Squeeze,
                Bls.Reduce,
                Bls.Add,
                Bls.Subtract,
                Bls.Multiply,
                Bls.Invert,
                pool);

            Assert.IsTrue(verified, "A deserialized honest proof must verify.");
        }
    }


    /// <summary>Verifies that a proof buffer one byte short of the schedule-derived length is refused by the exact-length check.</summary>
    [TestMethod]
    public void TruncatedBytesAreRejected()
    {
        WhirParameterSchedule schedule = CreateFastSchedule();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ProofRun run = ProofRun.Create(schedule, pool);
        (IMemoryOwner<byte> bytesOwner, int length) = WhirProofSerialization.ToBytes(run.Proof, DigestSizeBytes, pool);
        using(bytesOwner)
        {
            Assert.Throws<ArgumentException>(
                () => WhirProofSerialization.FromBytes(bytesOwner.Memory.Span[..(length - 1)], schedule, DigestSizeBytes, pool),
                "A truncated proof must be refused by the exact-length check.");
        }
    }


    /// <summary>Verifies that overwriting the first out-of-domain reply (which sits after the oracle roots and round polynomials) with an all-ones, non-canonical encoding is refused at the reader funnel.</summary>
    [TestMethod]
    public void NonCanonicalOutOfDomainReplyIsRejected()
    {
        WhirParameterSchedule schedule = CreateFastSchedule();
        int replyOffset = RootsSectionBytes(schedule) + RoundPolynomialSectionBytes(schedule);

        AssertNonCanonicalSectionIsRejected(schedule, replyOffset);
    }


    /// <summary>Verifies that overwriting the first final-polynomial element with an all-ones, non-canonical encoding is refused at the reader funnel.</summary>
    [TestMethod]
    public void NonCanonicalFinalPolynomialIsRejected()
    {
        WhirParameterSchedule schedule = CreateFastSchedule();
        int finalOffset = RootsSectionBytes(schedule)
            + RoundPolynomialSectionBytes(schedule)
            + ((schedule.IterationCount - 1) * ScalarSize);

        AssertNonCanonicalSectionIsRejected(schedule, finalOffset);
    }


    /// <summary>Verifies that overwriting the first opening block value with an all-ones, non-canonical encoding is refused at the reader funnel.</summary>
    [TestMethod]
    public void NonCanonicalOpeningBlockIsRejected()
    {
        WhirParameterSchedule schedule = CreateFastSchedule();
        int openingsOffset = RootsSectionBytes(schedule)
            + RoundPolynomialSectionBytes(schedule)
            + ((schedule.IterationCount - 1) * ScalarSize)
            + ((1 << schedule.FinalVariableCount) * ScalarSize);

        AssertNonCanonicalSectionIsRejected(schedule, openingsOffset);
    }


    /// <summary>Verifies that computing a serialized length with a non-positive or above-cap digest size is refused.</summary>
    [TestMethod]
    public void DigestSizeCapsAreEnforced()
    {
        WhirParameterSchedule schedule = CreateFastSchedule();

        Assert.Throws<ArgumentOutOfRangeException>(
            () => WhirProofSerialization.ComputeLength(schedule, 0),
            "A non-positive digest size must be refused.");
        Assert.Throws<ArgumentOutOfRangeException>(
            () => WhirProofSerialization.ComputeLength(schedule, WellKnownMerkleHashParameters.MaximumDigestSizeBytes + 1),
            "A digest size above the cap must be refused.");
    }


    /// <summary>
    /// Serializes an honest proof, overwrites one element at the given wire
    /// offset with the all-ones non-canonical encoding, and asserts the
    /// reader funnel refuses it.
    /// </summary>
    private static void AssertNonCanonicalSectionIsRejected(WhirParameterSchedule schedule, int scalarOffset)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ProofRun run = ProofRun.Create(schedule, pool);
        (IMemoryOwner<byte> bytesOwner, int length) = WhirProofSerialization.ToBytes(run.Proof, DigestSizeBytes, pool);
        using(bytesOwner)
        {
            Memory<byte> bytes = bytesOwner.Memory[..length];
            bytes.Span.Slice(scalarOffset, ScalarSize).Fill(0xFF);

            Assert.Throws<ArgumentException>(
                () => WhirProofSerialization.FromBytes(bytesOwner.Memory.Span[..length], schedule, DigestSizeBytes, pool),
                "A non-canonical scalar encoding must be refused at the reader funnel.");
        }
    }


    /// <summary>
    /// The oracle-roots section's byte length for the schedule.
    /// </summary>
    private static int RootsSectionBytes(WhirParameterSchedule schedule)
    {
        return (schedule.IterationCount - 1) * DigestSizeBytes;
    }


    /// <summary>
    /// The round-polynomials section's byte length for the schedule: two
    /// stored coefficients per compressed polynomial.
    /// </summary>
    private static int RoundPolynomialSectionBytes(WhirParameterSchedule schedule)
    {
        const int StoredCoefficients = 2;

        return schedule.IterationCount * schedule.FoldingParameter * StoredCoefficients * ScalarSize;
    }


    /// <summary>
    /// One honest evaluation-claim proof run: the statement buffers, the
    /// proof and the input commitment, disposed together.
    /// </summary>
    private sealed class ProofRun: IDisposable
    {
        /// <summary>The rented buffer backing every statement section.</summary>
        private IMemoryOwner<byte> StatementOwner { get; }

        /// <summary>The byte length of the coefficient section.</summary>
        private int MessageBytes { get; }

        /// <summary>The byte length of the constraint-point section.</summary>
        private int PointBytes { get; }

        /// <summary>The proof under test.</summary>
        public WhirIoppProof Proof { get; }

        /// <summary>The input oracle's Merkle root.</summary>
        public MerkleRoot Commitment { get; }

        /// <summary>The single constraint's scale, one element.</summary>
        public ReadOnlySpan<byte> ConstraintCoefficients => StatementOwner.Memory.Span.Slice(MessageBytes, ScalarSize);

        /// <summary>The single constraint's point coordinates.</summary>
        public ReadOnlySpan<byte> ConstraintPoints => StatementOwner.Memory.Span.Slice(MessageBytes + ScalarSize, PointBytes);

        /// <summary>The honestly evaluated target <c>σ</c>, one element.</summary>
        public ReadOnlySpan<byte> Target => StatementOwner.Memory.Span.Slice(MessageBytes + ScalarSize + PointBytes, ScalarSize);


        /// <summary>Wraps the run's parts; the run takes ownership.</summary>
        private ProofRun(IMemoryOwner<byte> statementOwner, int messageBytes, int pointBytes, WhirIoppProof proof, MerkleRoot commitment)
        {
            this.StatementOwner = statementOwner;
            this.MessageBytes = messageBytes;
            this.PointBytes = pointBytes;
            Proof = proof;
            Commitment = commitment;
        }


        /// <summary>Proves one honest evaluation claim for the schedule's shape.</summary>
        public static ProofRun Create(WhirParameterSchedule schedule, BaseMemoryPool pool)
        {
            int variableCount = schedule.VariableCount;
            int messageBytes = (1 << variableCount) * ScalarSize;
            int pointBytes = variableCount * ScalarSize;
            int totalBytes = messageBytes + ScalarSize + pointBytes + ScalarSize;

            IMemoryOwner<byte> owner = pool.Rent(totalBytes);
            try
            {
                Span<byte> buffers = owner.Memory.Span[..totalBytes];
                Span<byte> coefficients = buffers[..messageBytes];
                Span<byte> scale = buffers.Slice(messageBytes, ScalarSize);
                Span<byte> point = buffers.Slice(messageBytes + ScalarSize, pointBytes);
                Span<byte> target = buffers.Slice(messageBytes + ScalarSize + pointBytes, ScalarSize);

                DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, Bls.Reduce, Bls.Curve);
                DeterministicScalarFill.FillCanonical(point, StatementPointSalt, Bls.Reduce, Bls.Curve);
                scale.Clear();
                scale[ScalarSize - 1] = 0x01;
                WhirMultilinear.EvaluateCoefficientsAtPoint(
                    coefficients, point, variableCount, target, Bls.Add, Bls.Multiply, Bls.Curve, pool);

                using FiatShamirTranscript proverTranscript = NewTranscript();
                (WhirIoppProof proof, MerkleRoot commitment) = WhirIoppProver.Prove(
                    schedule, coefficients, scale, point, target, proverTranscript, TreeParameters, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, pool);

                return new ProofRun(owner, messageBytes, pointBytes, proof, commitment);
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            //The pool zeroes rented buffers on return.
            Proof.Dispose();
            Commitment.Dispose();
            StatementOwner.Dispose();
        }
    }


    /// <summary>
    /// The fast codec schedule on BLS12-381.
    /// </summary>
    private static WhirParameterSchedule CreateFastSchedule()
    {
        return WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);
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
