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
using System.Runtime.InteropServices;
using System.Text;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the HVZK-WHIR prover and verifier
/// (eprint 2026/391 Construction 9.7): honest hiding round-trips on both wired
/// curves and on the shapes that exercise every pipeline branch — the
/// two-iteration reference, a non-constant final polynomial and the
/// single-iteration base-case-only collapse — plus a tamper wall over the
/// hiding path's own surfaces: the input commitment, a code-switch mask root,
/// a shift opening, a carried mask opening and the claimed target must each
/// break verification. The real scalar arithmetic, the production BLAKE3
/// hash and entropy-free deterministic mask sampling are wired throughout.
/// </summary>
[TestClass]
internal sealed class ZkWhirIoppTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The reference shape's variable count: a 2^8-coefficient message with
    /// the default k = 4 gives two iterations — one code-switch round, three
    /// mask groups and both budget expressions.
    /// </summary>
    private const int FastVariableCount = 8;

    /// <summary>The reference shape's initial inverse-rate exponent: rate 1/4.</summary>
    private const int FastInitialRateLog2 = 2;

    /// <summary>
    /// The reference per-round target, matching the plain IOPP tests' fast
    /// shape — the shape the zero-knowledge parameter tests pin as
    /// hiding-admissible.
    /// </summary>
    private const int FastSecurityLevelBits = 24;

    /// <summary>
    /// The remainder shape's variable count: two k = 4 iterations leave a
    /// four-coefficient final message, exercising a non-constant blinded
    /// source reveal.
    /// </summary>
    private const int RemainderVariableCount = 10;

    /// <summary>The remainder shape's per-round target; its larger domains afford 32 bits.</summary>
    private const int RemainderSecurityLevelBits = 32;

    /// <summary>
    /// The base-case-only shape's variable count: m = k collapses the
    /// protocol to a single iteration with no code-switch round — the masked
    /// base case lands directly on the input oracle.
    /// </summary>
    private const int SingleIterationVariableCount = 4;

    /// <summary>
    /// The base-case-only shape's inverse-rate exponent: rate 1/32 leaves 31
    /// spare limb rows, enough for the 15-query budget its 14-bit target
    /// prices — rate 1/16 would leave only 15 and the hiding extension would
    /// refuse the shape.
    /// </summary>
    private const int SingleIterationRateLog2 = 5;

    /// <summary>The base-case-only shape's per-round target.</summary>
    private const int SingleIterationSecurityLevelBits = 14;

    /// <summary>A fill salt for the coefficient stream, distinct from the statement stream.</summary>
    private const int CoefficientSalt = 61;

    /// <summary>A fill salt for the statement-point stream, distinct from the coefficient stream.</summary>
    private const int StatementPointSalt = 62;

    /// <summary>The BLS12-381 scalar backend bundle.</summary>
    private static ScalarArithmeticBackend Bls { get; } = TestScalarBackends.Bls12Curve381;

    /// <summary>The BN254 scalar backend bundle.</summary>
    private static ScalarArithmeticBackend Bn { get; } = TestScalarBackends.Bn254;

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The deterministic mask-sampling seed, distinct per test class.</summary>
    private static byte[] MaskSeed { get; } = Encoding.UTF8.GetBytes("zk-whir-iopp-tests");


    [TestMethod]
    public void HonestHidingEvaluationClaimRoundTripsOnBls12Curve381()
    {
        WhirZkParameters parameters = FastParameters(Bls);

        Assert.IsTrue(ProveThenVerifyEvaluationClaim(parameters, Bls), "An honest hiding evaluation-claim proof must verify on BLS12-381.");
    }


    [TestMethod]
    public void HonestHidingEvaluationClaimRoundTripsOnBn254()
    {
        WhirZkParameters parameters = FastParameters(Bn);

        Assert.IsTrue(ProveThenVerifyEvaluationClaim(parameters, Bn), "An honest hiding evaluation-claim proof must verify on BN254.");
    }


    [TestMethod]
    public void HonestHidingNonConstantFinalMessageRoundTrips()
    {
        WhirZkParameters parameters = WhirZkParameters.Create(WhirParameterSchedule.Create(
            Bls.Curve,
            RemainderVariableCount,
            FastInitialRateLog2,
            securityLevelBits: RemainderSecurityLevelBits));

        Assert.AreEqual(2, parameters.Schedule.FinalVariableCount);
        Assert.IsTrue(ProveThenVerifyEvaluationClaim(parameters, Bls), "An honest hiding proof with a non-constant final message must verify.");
    }


    [TestMethod]
    public void HonestHidingBaseCaseOnlyShapeRoundTrips()
    {
        WhirZkParameters parameters = WhirZkParameters.Create(WhirParameterSchedule.Create(
            Bls.Curve,
            SingleIterationVariableCount,
            SingleIterationRateLog2,
            securityLevelBits: SingleIterationSecurityLevelBits));

        Assert.AreEqual(1, parameters.Schedule.IterationCount);
        Assert.IsTrue(ProveThenVerifyEvaluationClaim(parameters, Bls), "An honest hiding proof with no code-switch round must verify.");
    }


    [TestMethod]
    public void HonestHidingPlainProximityRoundTrips()
    {
        WhirZkParameters parameters = FastParameters(Bls);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        int messageLength = 1 << FastVariableCount;
        using IMemoryOwner<byte> coefficientsOwner = pool.Rent(messageLength * ScalarSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..(messageLength * ScalarSize)];
        DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, Bls.Reduce, Bls.Curve);

        //Plain proximity: no constraints and a zero target — the source side
        //of every batch is the zero weight, so the wires carry the masks and
        //the auxiliary chain alone.
        Span<byte> target = stackalloc byte[ScalarSize];
        target.Clear();

        using FiatShamirTranscript proverTranscript = NewTranscript();
        (ZkWhirIoppProof proof, MerkleRoot commitment) = ZkWhirIoppProver.Prove(
            parameters, coefficients, [], [], target, proverTranscript,
            Merkle, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Invert,
            new DeterministicScalarRandom(MaskSeed).AsDelegate(), pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            bool verified = ZkWhirIoppVerifier.Verify(
                parameters, commitment, proof, [], [], target, verifierTranscript,
                Merkle, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Invert, pool);

            Assert.IsTrue(verified, "An honest hiding plain-proximity proof must verify.");
        }
    }


    [TestMethod]
    public void TamperedInputCommitmentIsRejected()
    {
        Assert.IsFalse(
            TamperedRunVerifies(static (proof, commitment) =>
                MemoryMarshal.AsMemory(commitment.AsReadOnlyMemory()).Span[0] ^= 0x01),
            "A tampered input commitment must break verification.");
    }


    [TestMethod]
    public void TamperedCodeSwitchMaskRootIsRejected()
    {
        Assert.IsFalse(
            TamperedRunVerifies(static (proof, commitment) =>
                MemoryMarshal.AsMemory(proof.CodeSwitchMaskRoots[0].AsReadOnlyMemory()).Span[0] ^= 0x01),
            "A tampered code-switch mask root must break verification.");
    }


    [TestMethod]
    public void TamperedShiftOpeningIsRejected()
    {
        Assert.IsFalse(
            TamperedRunVerifies(static (proof, commitment) =>
                MemoryMarshal.AsMemory(proof.OpeningsForOracle(0)[0].BlockValues).Span[^1] ^= 0x01),
            "A tampered shift-query opening must break verification.");
    }


    [TestMethod]
    public void TamperedCarriedMaskOpeningIsRejected()
    {
        Assert.IsFalse(
            TamperedRunVerifies(static (proof, commitment) =>
                MemoryMarshal.AsMemory(proof.OpeningsForMaskGroup(0).Carried[0].BlockValues).Span[^1] ^= 0x01),
            "A tampered carried mask opening must break verification.");
    }


    [TestMethod]
    public void TamperedSumcheckMaskRootIsRejected()
    {
        Assert.IsFalse(
            TamperedRunVerifies(static (proof, commitment) =>
                MemoryMarshal.AsMemory(proof.SumcheckMaskRoots[0].AsReadOnlyMemory()).Span[0] ^= 0x01),
            "A tampered sumcheck mask root must break verification.");
    }


    [TestMethod]
    public void WrongTargetIsRejected()
    {
        WhirZkParameters parameters = FastParameters(Bls);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using EvaluationStatement statement = EvaluationStatement.Create(parameters.Schedule, Bls, pool);
        using FiatShamirTranscript proverTranscript = NewTranscript();
        (ZkWhirIoppProof proof, MerkleRoot commitment) = ZkWhirIoppProver.Prove(
            parameters, statement.Coefficients, statement.ConstraintCoefficients, statement.ConstraintPoints,
            statement.Target, proverTranscript, Merkle, Hash, Squeeze,
            Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Invert,
            new DeterministicScalarRandom(MaskSeed).AsDelegate(), pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Span<byte> wrongTarget = stackalloc byte[ScalarSize];
            statement.Target.CopyTo(wrongTarget);
            wrongTarget[^1] ^= 0x01;

            bool verified = ZkWhirIoppVerifier.Verify(
                parameters, commitment, proof, statement.ConstraintCoefficients, statement.ConstraintPoints,
                wrongTarget, verifierTranscript, Merkle, Hash, Squeeze,
                Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Invert, pool);

            Assert.IsFalse(verified, "A hiding proof verified against a different target must be rejected.");
        }
    }


    [TestMethod]
    public void ProverRejectsInconsistentTarget()
    {
        WhirZkParameters parameters = FastParameters(Bls);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using EvaluationStatement statement = EvaluationStatement.Create(parameters.Schedule, Bls, pool);

        Assert.Throws<ArgumentException>(() => ProveWithFlippedTarget(parameters, statement, pool));
    }


    /// <summary>
    /// Attempts an honest run against a target whose low bit is flipped; the
    /// prover's statement-consistency guard must refuse before any oracle
    /// work.
    /// </summary>
    private static void ProveWithFlippedTarget(WhirZkParameters parameters, EvaluationStatement statement, BaseMemoryPool pool)
    {
        Span<byte> wrongTarget = stackalloc byte[ScalarSize];
        statement.Target.CopyTo(wrongTarget);
        wrongTarget[^1] ^= 0x01;

        using FiatShamirTranscript transcript = NewTranscript();
        (ZkWhirIoppProof proof, MerkleRoot commitment) = ZkWhirIoppProver.Prove(
            parameters, statement.Coefficients, statement.ConstraintCoefficients, statement.ConstraintPoints,
            wrongTarget, transcript, Merkle, Hash, Squeeze,
            Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Invert,
            new DeterministicScalarRandom(MaskSeed).AsDelegate(), pool);

        //Only reached when the guard failed to fire; release before the
        //assertion reports the missing exception.
        proof.Dispose();
        commitment.Dispose();
    }


    /// <summary>
    /// The reference hiding parameters over the given backend's curve.
    /// </summary>
    private static WhirZkParameters FastParameters(ScalarArithmeticBackend backend)
    {
        return WhirZkParameters.Create(WhirParameterSchedule.Create(
            backend.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits));
    }


    /// <summary>
    /// One evaluation-claim statement: deterministic coefficients, one
    /// constraint <c>eq(z, ·)</c> at a deterministic point, and the honestly
    /// evaluated target — the pieces every round-trip and tamper test shares.
    /// </summary>
    private sealed class EvaluationStatement: IDisposable
    {
        private readonly IMemoryOwner<byte> owner;
        private readonly int messageBytes;
        private readonly int pointBytes;

        /// <summary>The multilinear coefficient vector.</summary>
        public ReadOnlySpan<byte> Coefficients => owner.Memory.Span[..messageBytes];

        /// <summary>The single constraint's scale, one element.</summary>
        public ReadOnlySpan<byte> ConstraintCoefficients => owner.Memory.Span.Slice(messageBytes, ScalarSize);

        /// <summary>The single constraint's point coordinates.</summary>
        public ReadOnlySpan<byte> ConstraintPoints => owner.Memory.Span.Slice(messageBytes + ScalarSize, pointBytes);

        /// <summary>The honestly evaluated target <c>σ</c>, one element.</summary>
        public ReadOnlySpan<byte> Target => owner.Memory.Span.Slice(messageBytes + ScalarSize + pointBytes, ScalarSize);


        /// <summary>Wraps the populated statement buffer; the statement takes ownership.</summary>
        private EvaluationStatement(IMemoryOwner<byte> owner, int messageBytes, int pointBytes)
        {
            this.owner = owner;
            this.messageBytes = messageBytes;
            this.pointBytes = pointBytes;
        }


        /// <summary>Builds the statement for the schedule's shape over the given backend.</summary>
        public static EvaluationStatement Create(WhirParameterSchedule schedule, ScalarArithmeticBackend backend, BaseMemoryPool pool)
        {
            int variableCount = schedule.VariableCount;
            int messageBytes = (1 << variableCount) * ScalarSize;
            int pointBytes = variableCount * ScalarSize;
            int totalBytes = messageBytes + ScalarSize + pointBytes + ScalarSize;

            IMemoryOwner<byte> owner = pool.Rent(totalBytes);
            Span<byte> buffers = owner.Memory.Span[..totalBytes];
            Span<byte> coefficients = buffers[..messageBytes];
            Span<byte> constraintCoefficient = buffers.Slice(messageBytes, ScalarSize);
            Span<byte> constraintPoint = buffers.Slice(messageBytes + ScalarSize, pointBytes);
            Span<byte> target = buffers.Slice(messageBytes + ScalarSize + pointBytes, ScalarSize);

            DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, backend.Reduce, backend.Curve);
            DeterministicScalarFill.FillCanonical(constraintPoint, StatementPointSalt, backend.Reduce, backend.Curve);
            constraintCoefficient.Clear();
            constraintCoefficient[ScalarSize - 1] = 0x01;
            WhirMultilinear.EvaluateCoefficientsAtPoint(
                coefficients, constraintPoint, variableCount, target, backend.Add, backend.Multiply, backend.Curve, pool);

            return new EvaluationStatement(owner, messageBytes, pointBytes);
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            //The pool zeroes rented buffers on return.
            owner.Dispose();
        }
    }


    /// <summary>
    /// Runs one honest hiding evaluation-claim round-trip for the parameters
    /// and reports the verification outcome.
    /// </summary>
    private static bool ProveThenVerifyEvaluationClaim(WhirZkParameters parameters, ScalarArithmeticBackend backend)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using EvaluationStatement statement = EvaluationStatement.Create(parameters.Schedule, backend, pool);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        (ZkWhirIoppProof proof, MerkleRoot commitment) = ZkWhirIoppProver.Prove(
            parameters, statement.Coefficients, statement.ConstraintCoefficients, statement.ConstraintPoints,
            statement.Target, proverTranscript, Merkle, Hash, Squeeze,
            backend.Reduce, backend.Add, backend.Subtract, backend.Multiply, backend.Invert,
            new DeterministicScalarRandom(MaskSeed).AsDelegate(), pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            return ZkWhirIoppVerifier.Verify(
                parameters, commitment, proof, statement.ConstraintCoefficients, statement.ConstraintPoints,
                statement.Target, verifierTranscript, Merkle, Hash, Squeeze,
                backend.Reduce, backend.Add, backend.Subtract, backend.Multiply, backend.Invert, pool);
        }
    }


    /// <summary>
    /// Proves the fast BLS hiding evaluation claim honestly, applies the
    /// tamper, and reports whether the tampered run still verifies.
    /// </summary>
    private static bool TamperedRunVerifies(Action<ZkWhirIoppProof, MerkleRoot> tamper)
    {
        WhirZkParameters parameters = FastParameters(Bls);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using EvaluationStatement statement = EvaluationStatement.Create(parameters.Schedule, Bls, pool);
        using FiatShamirTranscript proverTranscript = NewTranscript();
        (ZkWhirIoppProof proof, MerkleRoot commitment) = ZkWhirIoppProver.Prove(
            parameters, statement.Coefficients, statement.ConstraintCoefficients, statement.ConstraintPoints,
            statement.Target, proverTranscript, Merkle, Hash, Squeeze,
            Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Invert,
            new DeterministicScalarRandom(MaskSeed).AsDelegate(), pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            tamper(proof, commitment);

            return ZkWhirIoppVerifier.Verify(
                parameters, commitment, proof, statement.ConstraintCoefficients, statement.ConstraintPoints,
                statement.Target, verifierTranscript, Merkle, Hash, Squeeze,
                Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Invert, pool);
        }
    }


    /// <summary>
    /// A fresh transcript under the WHIR domain label, as both endpoints
    /// initialise it.
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
