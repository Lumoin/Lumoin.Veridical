using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.Spartan;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Text;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the HVZK-WHIR proof wire codec (4.2 phase C3): a serialize →
/// deserialize round-trip that still verifies, the exact parameter-derived
/// length, the mask-total offset seam, and the reader funnel's rejections — a
/// truncated buffer, a non-canonical mask total, private out-of-domain reply
/// and blinded reveal element, and the digest-size caps — plus a byte-level
/// root tamper that parses but fails verification. The real scalar
/// arithmetic, the production BLAKE3 hash and entropy-free deterministic mask
/// sampling are wired throughout.
/// </summary>
[TestClass]
internal sealed class ZkWhirProofSerializationTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The codec shape's variable count: a 2^8-coefficient message with the
    /// paper's constant k = 4 gives two iterations — every wire section
    /// non-empty, including one code-switch round and three mask groups.
    /// </summary>
    private const int FastVariableCount = 8;

    /// <summary>The codec shape's initial inverse-rate exponent: rate 1/4.</summary>
    private const int FastInitialRateLog2 = 2;

    /// <summary>
    /// The codec shape's per-round target, matching the shape the
    /// zero-knowledge parameter tests pin as hiding-admissible.
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

    /// <summary>The deterministic mask-sampling seed, distinct per test class.</summary>
    private static byte[] MaskSeed { get; } = Encoding.UTF8.GetBytes("zk-whir-proof-serialization-tests");


    [TestMethod]
    public void SerializedProofRoundTripsAndVerifies()
    {
        WhirZkParameters parameters = CreateFastParameters();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ProofRun run = ProofRun.Create(parameters, pool);
        (IMemoryOwner<byte> bytesOwner, int length) = ZkWhirProofSerialization.ToBytes(run.Proof, DigestSizeBytes, pool);
        using(bytesOwner)
        {
            Assert.AreEqual(ZkWhirProofSerialization.ComputeLength(parameters, DigestSizeBytes), length, "The serialized length must equal the parameter-derived figure.");

            using ZkWhirIoppProof deserialized = ZkWhirProofSerialization.FromBytes(bytesOwner.Memory.Span[..length], parameters, DigestSizeBytes, pool);
            Assert.IsTrue(VerifyAgainst(run, deserialized, parameters, pool), "A deserialized honest hiding proof must verify.");
        }
    }


    [TestMethod]
    public void TruncatedBytesAreRejected()
    {
        WhirZkParameters parameters = CreateFastParameters();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ProofRun run = ProofRun.Create(parameters, pool);
        (IMemoryOwner<byte> bytesOwner, int length) = ZkWhirProofSerialization.ToBytes(run.Proof, DigestSizeBytes, pool);
        using(bytesOwner)
        {
            Assert.Throws<ArgumentException>(
                () => ZkWhirProofSerialization.FromBytes(bytesOwner.Memory.Span[..(length - 1)], parameters, DigestSizeBytes, pool),
                "A truncated proof must be refused by the exact-length check.");
        }
    }


    [TestMethod]
    public void NonCanonicalMaskTotalIsRejectedAtEveryBatchOffset()
    {
        //The offsets come from the codec's own seam accessor, so this also
        //pins that accessor to the actual layout.
        WhirZkParameters parameters = CreateFastParameters();

        for(int batch = 0; batch < parameters.Schedule.IterationCount; batch++)
        {
            AssertNonCanonicalSectionIsRejected(parameters, ZkWhirProofSerialization.ComputeMaskTotalOffset(parameters, batch, DigestSizeBytes));
        }
    }


    [TestMethod]
    public void NonCanonicalPrivateReplyIsRejected()
    {
        //The private replies sit after the mask roots, mask totals, masked
        //wires and both root sections.
        WhirZkParameters parameters = CreateFastParameters();
        int replyOffset = MaskRootsSectionBytes(parameters)
            + MaskTotalsSectionBytes(parameters)
            + WireSectionBytes(parameters)
            + (2 * (parameters.Schedule.IterationCount - 1) * DigestSizeBytes);

        AssertNonCanonicalSectionIsRejected(parameters, replyOffset);
    }


    [TestMethod]
    public void NonCanonicalBlindedRevealIsRejected()
    {
        //The blinded source message opens the reveal section, after the
        //shift-opening section and the base case's roots and masked claim.
        WhirZkParameters parameters = CreateFastParameters();
        int revealOffset = MaskRootsSectionBytes(parameters)
            + MaskTotalsSectionBytes(parameters)
            + WireSectionBytes(parameters)
            + (2 * (parameters.Schedule.IterationCount - 1) * DigestSizeBytes)
            + ((parameters.Schedule.IterationCount - 1) * ScalarSize)
            + OracleOpeningsSectionBytes(parameters)
            + ((1 + ((2 * parameters.Schedule.IterationCount) - 1)) * DigestSizeBytes)
            + ScalarSize;

        AssertNonCanonicalSectionIsRejected(parameters, revealOffset);
    }


    [TestMethod]
    public void TamperedMaskedClaimParsesButFailsVerification()
    {
        //A low-order flip of the masked claim μ_g stays canonical, so the
        //reader funnel accepts it; the base case's joint check
        //⟨f*, W⟩ + Σ⟨ξ*, u⟩ = μ_g + γ·target must then break. C2's object
        //walls never tampered μ_g — this closes that surface at the byte
        //level.
        WhirZkParameters parameters = CreateFastParameters();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        int claimOffset = MaskRootsSectionBytes(parameters)
            + MaskTotalsSectionBytes(parameters)
            + WireSectionBytes(parameters)
            + (2 * (parameters.Schedule.IterationCount - 1) * DigestSizeBytes)
            + ((parameters.Schedule.IterationCount - 1) * ScalarSize)
            + OracleOpeningsSectionBytes(parameters)
            + ((1 + ((2 * parameters.Schedule.IterationCount) - 1)) * DigestSizeBytes);

        using ProofRun run = ProofRun.Create(parameters, pool);
        (IMemoryOwner<byte> bytesOwner, int length) = ZkWhirProofSerialization.ToBytes(run.Proof, DigestSizeBytes, pool);
        using(bytesOwner)
        {
            bytesOwner.Memory.Span[claimOffset + ScalarSize - 1] ^= 0x01;

            using ZkWhirIoppProof deserialized = ZkWhirProofSerialization.FromBytes(bytesOwner.Memory.Span[..length], parameters, DigestSizeBytes, pool);
            Assert.IsFalse(VerifyAgainst(run, deserialized, parameters, pool), "A tampered masked claim must fail the joint check.");
        }
    }


    [TestMethod]
    public void TamperedRootByteParsesButFailsVerification()
    {
        //A root digest carries no canonical form, so the reader funnel
        //accepts the flip; the Fiat-Shamir replay and the Merkle
        //authentication must then break.
        WhirZkParameters parameters = CreateFastParameters();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ProofRun run = ProofRun.Create(parameters, pool);
        (IMemoryOwner<byte> bytesOwner, int length) = ZkWhirProofSerialization.ToBytes(run.Proof, DigestSizeBytes, pool);
        using(bytesOwner)
        {
            bytesOwner.Memory.Span[0] ^= 0x01;

            using ZkWhirIoppProof deserialized = ZkWhirProofSerialization.FromBytes(bytesOwner.Memory.Span[..length], parameters, DigestSizeBytes, pool);
            Assert.IsFalse(VerifyAgainst(run, deserialized, parameters, pool), "A tampered sumcheck mask root must fail verification.");
        }
    }


    [TestMethod]
    public void DigestSizeCapsAreEnforced()
    {
        WhirZkParameters parameters = CreateFastParameters();

        Assert.Throws<ArgumentOutOfRangeException>(
            () => ZkWhirProofSerialization.ComputeLength(parameters, 0),
            "A non-positive digest size must be refused.");
        Assert.Throws<ArgumentOutOfRangeException>(
            () => ZkWhirProofSerialization.ComputeLength(parameters, WellKnownMerkleHashParameters.MaximumDigestSizeBytes + 1),
            "A digest size above the cap must be refused.");
    }


    /// <summary>
    /// Serializes an honest proof, overwrites one element at the given wire
    /// offset with the all-ones non-canonical encoding, and asserts the
    /// reader funnel refuses it.
    /// </summary>
    private static void AssertNonCanonicalSectionIsRejected(WhirZkParameters parameters, int scalarOffset)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ProofRun run = ProofRun.Create(parameters, pool);
        (IMemoryOwner<byte> bytesOwner, int length) = ZkWhirProofSerialization.ToBytes(run.Proof, DigestSizeBytes, pool);
        using(bytesOwner)
        {
            bytesOwner.Memory.Span.Slice(scalarOffset, ScalarSize).Fill(0xFF);

            Assert.Throws<ArgumentException>(
                () => ZkWhirProofSerialization.FromBytes(bytesOwner.Memory.Span[..length], parameters, DigestSizeBytes, pool),
                "A non-canonical scalar encoding must be refused at the reader funnel.");
        }
    }


    /// <summary>
    /// Verifies a proof against a run's statement with a fresh transcript.
    /// </summary>
    private static bool VerifyAgainst(ProofRun run, ZkWhirIoppProof proof, WhirZkParameters parameters, BaseMemoryPool pool)
    {
        using FiatShamirTranscript verifierTranscript = NewTranscript();

        return ZkWhirIoppVerifier.Verify(
            parameters,
            run.Commitment,
            proof,
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
    }


    /// <summary>
    /// The sumcheck-mask-roots section's byte length: one digest per batch.
    /// </summary>
    private static int MaskRootsSectionBytes(WhirZkParameters parameters)
    {
        return parameters.Schedule.IterationCount * DigestSizeBytes;
    }


    /// <summary>
    /// The mask-totals section's byte length: one element per batch.
    /// </summary>
    private static int MaskTotalsSectionBytes(WhirZkParameters parameters)
    {
        return parameters.Schedule.IterationCount * ScalarSize;
    }


    /// <summary>
    /// The masked-wires section's byte length: <c>k</c> wires per batch at
    /// <c>max(ℓ_zk - 1, 2)</c> stored coefficients.
    /// </summary>
    private static int WireSectionBytes(WhirZkParameters parameters)
    {
        int storedCoefficients = Math.Max(parameters.MaskMessageLength - 1, 2);

        return parameters.Schedule.IterationCount * parameters.Schedule.FoldingParameter * storedCoefficients * ScalarSize;
    }


    /// <summary>
    /// The per-oracle openings section's byte length: per oracle its
    /// scheduled query count of coset blocks and coset-folded paths.
    /// </summary>
    private static int OracleOpeningsSectionBytes(WhirZkParameters parameters)
    {
        WhirParameterSchedule schedule = parameters.Schedule;
        int blockBytes = (1 << schedule.FoldingParameter) * ScalarSize;
        int total = 0;
        for(int oracle = 0; oracle < schedule.IterationCount; oracle++)
        {
            int pathBytes = (schedule.Rounds[oracle].DomainSizeLog2 - schedule.FoldingParameter) * DigestSizeBytes;
            total += schedule.Rounds[oracle].QueryCount * (blockBytes + pathBytes);
        }

        return total;
    }


    /// <summary>
    /// One honest hiding evaluation-claim proof run: the statement buffers,
    /// the proof and the input commitment, disposed together.
    /// </summary>
    private sealed class ProofRun: IDisposable
    {
        private readonly IMemoryOwner<byte> statementOwner;
        private readonly int messageBytes;
        private readonly int pointBytes;

        /// <summary>The proof under test.</summary>
        public ZkWhirIoppProof Proof { get; }

        /// <summary>The input oracle's zero-knowledge Merkle root.</summary>
        public MerkleRoot Commitment { get; }

        /// <summary>The single constraint's scale, one element.</summary>
        public ReadOnlySpan<byte> ConstraintCoefficients => statementOwner.Memory.Span.Slice(messageBytes, ScalarSize);

        /// <summary>The single constraint's point coordinates.</summary>
        public ReadOnlySpan<byte> ConstraintPoints => statementOwner.Memory.Span.Slice(messageBytes + ScalarSize, pointBytes);

        /// <summary>The honestly evaluated target <c>σ</c>, one element.</summary>
        public ReadOnlySpan<byte> Target => statementOwner.Memory.Span.Slice(messageBytes + ScalarSize + pointBytes, ScalarSize);


        /// <summary>Wraps the run's parts; the run takes ownership.</summary>
        private ProofRun(IMemoryOwner<byte> statementOwner, int messageBytes, int pointBytes, ZkWhirIoppProof proof, MerkleRoot commitment)
        {
            this.statementOwner = statementOwner;
            this.messageBytes = messageBytes;
            this.pointBytes = pointBytes;
            Proof = proof;
            Commitment = commitment;
        }


        /// <summary>Proves one honest hiding evaluation claim for the parameters' shape.</summary>
        public static ProofRun Create(WhirZkParameters parameters, BaseMemoryPool pool)
        {
            int variableCount = parameters.Schedule.VariableCount;
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
                (ZkWhirIoppProof proof, MerkleRoot commitment) = ZkWhirIoppProver.Prove(
                    parameters,
                    coefficients,
                    scale,
                    point,
                    target,
                    proverTranscript,
                    Merkle,
                    Hash,
                    Squeeze,
                    Bls.Reduce,
                    Bls.Add,
                    Bls.Subtract,
                    Bls.Multiply,
                    Bls.Invert,
                    new DeterministicScalarRandom(MaskSeed).AsDelegate(),
                    pool);

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
    /// The fast hiding-admissible parameters on BLS12-381.
    /// </summary>
    private static WhirZkParameters CreateFastParameters()
    {
        return WhirZkParameters.Create(WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits));
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
