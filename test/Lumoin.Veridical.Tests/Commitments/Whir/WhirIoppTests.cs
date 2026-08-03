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
using System.Linq;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the WHIR IOPP prover and verifier (4.2 phase A): honest
/// round-trips on both wired curves for the two phase-A statement shapes —
/// an evaluation claim (<c>ŵ = Z·eq(z, ·)</c>) and plain proximity
/// (<c>ŵ = 0</c>, <c>σ = 0</c>) — a full-λ round-trip with the schedule's
/// pinned query counts, and a tamper wall: a flipped commitment, oracle root,
/// opening value or claimed target must each break verification. The real
/// scalar arithmetic and the production BLAKE3 hash are wired throughout.
/// </summary>
[TestClass]
internal sealed class WhirIoppTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The fast shape's variable count: a 2^8-coefficient message with the
    /// paper's constant k = 4 gives two iterations and a constant final
    /// polynomial.
    /// </summary>
    private const int FastVariableCount = 8;

    /// <summary>The fast shape's initial inverse-rate exponent: rate 1/4.</summary>
    private const int FastInitialRateLog2 = 2;

    /// <summary>
    /// The fast shape's per-round target: 24 bits is the largest whole level
    /// the shape can place on distinct query cosets (round 1 offers a 2^5
    /// query domain). Protocol correctness does not depend on the
    /// soundness-driven repetition count, which the schedule tests pin.
    /// </summary>
    private const int FastSecurityLevelBits = 24;

    /// <summary>
    /// The remainder shape's variable count: a 2^10-coefficient message
    /// leaves two variables after two k = 4 iterations, exercising a
    /// non-constant final polynomial and the pow-expanded final query points.
    /// </summary>
    private const int RemainderVariableCount = 10;

    /// <summary>The remainder shape's per-round target; its larger domains afford 32 bits.</summary>
    private const int RemainderSecurityLevelBits = 32;

    /// <summary>
    /// The full-λ shape's variable count for the slow gate: 2^12 coefficients
    /// carry the classical 128-bit target through three iterations.
    /// </summary>
    private const int FullVariableCount = 12;

    /// <summary>The full-λ shape's initial inverse-rate exponent: rate 1/4.</summary>
    private const int FullInitialRateLog2 = 2;

    /// <summary>A fill salt for the coefficient stream, distinct from the statement stream.</summary>
    private const int CoefficientSalt = 31;

    /// <summary>A fill salt for the statement-point stream, distinct from the coefficient stream.</summary>
    private const int StatementPointSalt = 32;

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


    [TestMethod]
    public void HonestEvaluationClaimRoundTripsOnBls12Curve381()
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);

        Assert.IsTrue(ProveThenVerifyEvaluationClaim(schedule, Bls), "An honest evaluation-claim proof must verify on BLS12-381.");
    }


    [TestMethod]
    public void HonestEvaluationClaimRoundTripsOnBn254()
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bn.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);

        Assert.IsTrue(ProveThenVerifyEvaluationClaim(schedule, Bn), "An honest evaluation-claim proof must verify on BN254.");
    }


    [TestMethod]
    public void HonestPlainProximityRoundTripsOnBls12Curve381()
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        int messageLength = 1 << FastVariableCount;
        using IMemoryOwner<byte> coefficientsOwner = pool.Rent(messageLength * ScalarSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..(messageLength * ScalarSize)];
        DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, Bls.Reduce, Bls.Curve);

        //Plain proximity: no constraints and a zero target, so the weight is
        //identically zero and every sumcheck message is the zero polynomial;
        //the queries alone bind the oracles to the fold chain.
        Span<byte> target = stackalloc byte[ScalarSize];
        target.Clear();

        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirIoppProver.Prove(
            schedule, coefficients, [], [], target, proverTranscript, Merkle, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            bool verified = WhirIoppVerifier.Verify(
                schedule, commitment, proof, [], [], target, verifierTranscript, Merkle, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Invert, pool);

            Assert.IsTrue(verified, "An honest plain-proximity proof must verify.");
        }
    }


    [TestMethod]
    public void NonConstantFinalPolynomialRoundTrips()
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            RemainderVariableCount,
            FastInitialRateLog2,
            securityLevelBits: RemainderSecurityLevelBits);

        Assert.AreEqual(2, schedule.FinalVariableCount);
        Assert.IsTrue(ProveThenVerifyEvaluationClaim(schedule, Bls), "An honest proof with a non-constant final polynomial must verify.");
    }


    [TestMethod]
    [TestCategory("Slow")]
    public void FullSecurityEvaluationClaimRoundTrips()
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FullVariableCount,
            FullInitialRateLog2);

        //t_i = ⌈128 / -log2(1 - δ_i)⌉ at unique-decoding radii for rate
        //exponents {2, 5, 8}, derived by hand from Theorem 5.2.
        int[] expectedQueryCounts = [189, 134, 129];
        Assert.AreSequenceEqual(expectedQueryCounts, schedule.Rounds.Select(static round => round.QueryCount).ToArray());

        Assert.IsTrue(ProveThenVerifyEvaluationClaim(schedule, Bls), "An honest full-λ evaluation-claim proof must verify.");
    }


    [TestMethod]
    public void SingleIterationShapeRoundTrips()
    {
        //m = k collapses the protocol to one iteration: no main loop, no
        //folded oracles, no out-of-domain replies — the final queries land
        //directly on the input oracle. Rate 1/16 affords a 14-bit target on
        //the 2^4 query domain.
        const int SingleIterationVariableCount = 4;
        const int SingleIterationRateLog2 = 4;
        const int SingleIterationSecurityLevelBits = 14;
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            SingleIterationVariableCount,
            SingleIterationRateLog2,
            securityLevelBits: SingleIterationSecurityLevelBits);

        Assert.AreEqual(1, schedule.IterationCount);
        Assert.IsTrue(ProveThenVerifyEvaluationClaim(schedule, Bls), "An honest single-iteration proof must verify.");
    }


    [TestMethod]
    public void NonDefaultFoldingParameterRoundTrips()
    {
        //k = 2 on the fast message shape gives four iterations with two
        //sumcheck rounds each, exercising a fold width the paper's constant
        //k = 4 never touches.
        const int NarrowFoldingParameter = 2;
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            NarrowFoldingParameter,
            FastSecurityLevelBits);

        Assert.AreEqual(4, schedule.IterationCount);
        Assert.IsTrue(ProveThenVerifyEvaluationClaim(schedule, Bls), "An honest k = 2 proof must verify.");
    }


    [TestMethod]
    public void TwoConstraintStatementRoundTrips()
    {
        //Two equality-kernel constraints with distinct scales and points:
        //σ = λ_1·f̂(z_1) + λ_2·f̂(z_2), the smallest multi-constraint weight.
        const int SecondPointSalt = 33;
        const int ScaleSalt = 34;
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        int variableCount = schedule.VariableCount;
        int messageBytes = (1 << variableCount) * ScalarSize;
        int pointBytes = variableCount * ScalarSize;
        int totalBytes = messageBytes + (2 * ScalarSize) + (2 * pointBytes) + ScalarSize;
        using IMemoryOwner<byte> buffersOwner = pool.Rent(totalBytes);
        Span<byte> buffers = buffersOwner.Memory.Span[..totalBytes];
        Span<byte> coefficients = buffers[..messageBytes];
        Span<byte> scales = buffers.Slice(messageBytes, 2 * ScalarSize);
        Span<byte> points = buffers.Slice(messageBytes + (2 * ScalarSize), 2 * pointBytes);
        Span<byte> target = buffers.Slice(messageBytes + (2 * ScalarSize) + (2 * pointBytes), ScalarSize);

        DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(scales, ScaleSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(points[..pointBytes], StatementPointSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(points[pointBytes..], SecondPointSalt, Bls.Reduce, Bls.Curve);

        //σ = λ_1·f̂(z_1) + λ_2·f̂(z_2).
        Span<byte> evaluation = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        target.Clear();
        for(int constraint = 0; constraint < 2; constraint++)
        {
            WhirMultilinear.EvaluateCoefficientsAtPoint(
                coefficients,
                points.Slice(constraint * pointBytes, pointBytes),
                variableCount,
                evaluation,
                Bls.Add,
                Bls.Multiply,
                Bls.Curve,
                pool);
            Bls.Multiply(scales.Slice(constraint * ScalarSize, ScalarSize), evaluation, term, Bls.Curve);
            Bls.Add(target, term, target, Bls.Curve);
        }

        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirIoppProver.Prove(
            schedule, coefficients, scales, points, target, proverTranscript, Merkle, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            bool verified = WhirIoppVerifier.Verify(
                schedule, commitment, proof, scales, points, target, verifierTranscript, Merkle, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Invert, pool);

            Assert.IsTrue(verified, "An honest two-constraint proof must verify.");
        }
    }


    [TestMethod]
    public void MismatchedScheduleShapeIsRejected()
    {
        //A proof produced under the fast schedule verified against a schedule
        //with a different per-round target has different query counts, so the
        //structural shape check must refuse before any transcript work.
        const int OtherSecurityLevelBits = 16;
        WhirParameterSchedule proverSchedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);
        WhirParameterSchedule verifierSchedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: OtherSecurityLevelBits);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using EvaluationStatement statement = EvaluationStatement.Create(proverSchedule, Bls, pool);
        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirIoppProver.Prove(
            proverSchedule,
            statement.Coefficients,
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            statement.Target,
            proverTranscript,
            Merkle,
            Hash,
            Squeeze,
            Bls.Reduce,
            Bls.Add,
            Bls.Subtract,
            Bls.Multiply,
            pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            bool verified = WhirIoppVerifier.Verify(
                verifierSchedule,
                commitment,
                proof,
                statement.ConstraintCoefficients,
                statement.ConstraintPoints,
                statement.Target,
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

            Assert.IsFalse(verified, "A proof whose dimensions do not match the verifier's schedule must be rejected.");
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
    public void TamperedOracleRootIsRejected()
    {
        Assert.IsFalse(
            TamperedRunVerifies(static (proof, commitment) =>
                MemoryMarshal.AsMemory(proof.OracleRoots[0].AsReadOnlyMemory()).Span[0] ^= 0x01),
            "A tampered folded-oracle root must break verification.");
    }


    [TestMethod]
    public void TamperedOpeningValueIsRejected()
    {
        Assert.IsFalse(
            TamperedRunVerifies(static (proof, commitment) =>
                MemoryMarshal.AsMemory(proof.OpeningsForOracle(0)[0].BlockValues).Span[^1] ^= 0x01),
            "A tampered opening value must break verification.");
    }


    [TestMethod]
    public void WrongTargetIsRejected()
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using EvaluationStatement statement = EvaluationStatement.Create(schedule, Bls, pool);
        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirIoppProver.Prove(
            schedule,
            statement.Coefficients,
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            statement.Target,
            proverTranscript,
            Merkle,
            Hash,
            Squeeze,
            Bls.Reduce,
            Bls.Add,
            Bls.Subtract,
            Bls.Multiply,
            pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Span<byte> wrongTarget = stackalloc byte[ScalarSize];
            statement.Target.CopyTo(wrongTarget);
            wrongTarget[^1] ^= 0x01;

            bool verified = WhirIoppVerifier.Verify(
                schedule,
                commitment,
                proof,
                statement.ConstraintCoefficients,
                statement.ConstraintPoints,
                wrongTarget,
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

            Assert.IsFalse(verified, "A proof verified against a different target must be rejected.");
        }
    }


    [TestMethod]
    public void ProverRejectsInconsistentTarget()
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using EvaluationStatement statement = EvaluationStatement.Create(schedule, Bls, pool);

        Assert.Throws<ArgumentException>(() => ProveWithFlippedTarget(schedule, statement, pool));
    }


    /// <summary>
    /// Attempts an honest run against a target whose low bit is flipped; the
    /// prover's statement-consistency guard must refuse before any oracle
    /// work.
    /// </summary>
    private static void ProveWithFlippedTarget(WhirParameterSchedule schedule, EvaluationStatement statement, BaseMemoryPool pool)
    {
        Span<byte> wrongTarget = stackalloc byte[ScalarSize];
        statement.Target.CopyTo(wrongTarget);
        wrongTarget[^1] ^= 0x01;

        using FiatShamirTranscript transcript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirIoppProver.Prove(
            schedule,
            statement.Coefficients,
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            wrongTarget,
            transcript,
            Merkle,
            Hash,
            Squeeze,
            Bls.Reduce,
            Bls.Add,
            Bls.Subtract,
            Bls.Multiply,
            pool);

        //Only reached when the guard failed to fire; release before the
        //assertion reports the missing exception.
        proof.Dispose();
        commitment.Dispose();
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
    /// Runs one honest evaluation-claim round-trip for the schedule and
    /// reports the verification outcome.
    /// </summary>
    private static bool ProveThenVerifyEvaluationClaim(WhirParameterSchedule schedule, ScalarArithmeticBackend backend)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using EvaluationStatement statement = EvaluationStatement.Create(schedule, backend, pool);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirIoppProver.Prove(
            schedule,
            statement.Coefficients,
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            statement.Target,
            proverTranscript,
            Merkle,
            Hash,
            Squeeze,
            backend.Reduce,
            backend.Add,
            backend.Subtract,
            backend.Multiply,
            pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            return WhirIoppVerifier.Verify(
                schedule,
                commitment,
                proof,
                statement.ConstraintCoefficients,
                statement.ConstraintPoints,
                statement.Target,
                verifierTranscript,
                Merkle,
                Hash,
                Squeeze,
                backend.Reduce,
                backend.Add,
                backend.Subtract,
                backend.Multiply,
                backend.Invert,
                pool);
        }
    }


    /// <summary>
    /// Proves the fast BLS evaluation claim honestly, applies the tamper, and
    /// reports whether the tampered run still verifies.
    /// </summary>
    private static bool TamperedRunVerifies(Action<WhirIoppProof, MerkleRoot> tamper)
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Bls.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using EvaluationStatement statement = EvaluationStatement.Create(schedule, Bls, pool);
        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirIoppProver.Prove(
            schedule,
            statement.Coefficients,
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            statement.Target,
            proverTranscript,
            Merkle,
            Hash,
            Squeeze,
            Bls.Reduce,
            Bls.Add,
            Bls.Subtract,
            Bls.Multiply,
            pool);
        using(proof)
        using(commitment)
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            tamper(proof, commitment);

            return WhirIoppVerifier.Verify(
                schedule,
                commitment,
                proof,
                statement.ConstraintCoefficients,
                statement.ConstraintPoints,
                statement.Target,
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
