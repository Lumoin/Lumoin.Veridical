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


    [TestMethod]
    public void NonCanonicalOutOfDomainReplyIsRejected()
    {
        //The out-of-domain replies sit after the oracle roots and the round
        //polynomials; overwriting one with all-ones bytes encodes an integer
        //above both wired scalar orders.
        WhirParameterSchedule schedule = CreateFastSchedule();
        int replyOffset = RootsSectionBytes(schedule) + RoundPolynomialSectionBytes(schedule);

        AssertNonCanonicalSectionIsRejected(schedule, replyOffset);
    }


    [TestMethod]
    public void NonCanonicalFinalPolynomialIsRejected()
    {
        WhirParameterSchedule schedule = CreateFastSchedule();
        int finalOffset = RootsSectionBytes(schedule)
            + RoundPolynomialSectionBytes(schedule)
            + ((schedule.IterationCount - 1) * ScalarSize);

        AssertNonCanonicalSectionIsRejected(schedule, finalOffset);
    }


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
        private readonly IMemoryOwner<byte> statementOwner;
        private readonly int messageBytes;
        private readonly int pointBytes;

        /// <summary>The proof under test.</summary>
        public WhirIoppProof Proof { get; }

        /// <summary>The input oracle's Merkle root.</summary>
        public MerkleRoot Commitment { get; }

        /// <summary>The single constraint's scale, one element.</summary>
        public ReadOnlySpan<byte> ConstraintCoefficients => statementOwner.Memory.Span.Slice(messageBytes, ScalarSize);

        /// <summary>The single constraint's point coordinates.</summary>
        public ReadOnlySpan<byte> ConstraintPoints => statementOwner.Memory.Span.Slice(messageBytes + ScalarSize, pointBytes);

        /// <summary>The honestly evaluated target <c>σ</c>, one element.</summary>
        public ReadOnlySpan<byte> Target => statementOwner.Memory.Span.Slice(messageBytes + ScalarSize + pointBytes, ScalarSize);


        /// <summary>Wraps the run's parts; the run takes ownership.</summary>
        private ProofRun(IMemoryOwner<byte> statementOwner, int messageBytes, int pointBytes, WhirIoppProof proof, MerkleRoot commitment)
        {
            this.statementOwner = statementOwner;
            this.messageBytes = messageBytes;
            this.pointBytes = pointBytes;
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
                    schedule, coefficients, scale, point, target, proverTranscript, Merkle, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, pool);

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
            statementOwner.Dispose();
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
