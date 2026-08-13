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
/// Tests for the WHIR multi-claim batching layer (WHIR Construction 5.5):
/// honest batched round-trips on both wired curves,
/// mixed per-claim constraint shapes including a constraint-free claim, the
/// single-claim degenerate batch, the Theorem 5.6 ledger-row pins, and the
/// rejection wall — a tampered claim target, a shifted claim boundary over
/// identical flat spans, malformed batch shapes and an inconsistent prover
/// target must all refuse. The real scalar arithmetic and the production
/// BLAKE3 hash are wired throughout.
/// </summary>
[TestClass]
internal sealed class WhirConstraintBatchingTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The batch shape's variable count: a 2^8-coefficient message with the
    /// paper's constant k = 4 gives two iterations and a constant final
    /// polynomial.
    /// </summary>
    private const int FastVariableCount = 8;

    /// <summary>The batch shape's initial inverse-rate exponent: rate 1/4.</summary>
    private const int FastInitialRateLog2 = 2;

    /// <summary>
    /// The batch shape's per-round target: 24 bits is the largest whole
    /// level the shape can place on distinct query cosets. Protocol
    /// correctness does not depend on the soundness-driven repetition count.
    /// </summary>
    private const int FastSecurityLevelBits = 24;

    /// <summary>The claim count of the standard three-claim batch the round-trip tests share.</summary>
    private const int StandardClaimCount = 3;

    /// <summary>A fill salt for the coefficient stream, distinct from every statement stream.</summary>
    private const int CoefficientSalt = 41;

    /// <summary>The base fill salt for constraint points; claim <c>i</c>'s point uses this plus <c>i</c>.</summary>
    private const int PointSaltBase = 42;

    /// <summary>A fill salt for the constraint scales, distinct from the point streams.</summary>
    private const int ScaleSalt = 51;

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
    public void HonestThreeClaimBatchRoundTripsOnBls12Curve381()
    {
        WhirParameterSchedule schedule = CreateFastSchedule(Bls);
        int[] counts = SingleConstraintCounts(StandardClaimCount);

        using BatchStatement statement = BatchStatement.Create(schedule, counts, Bls, BaseMemoryPool.Shared);

        Assert.IsTrue(ProveThenVerifyBatch(schedule, counts, statement, Bls), "An honest three-claim batch must verify on BLS12-381.");
    }


    [TestMethod]
    public void HonestThreeClaimBatchRoundTripsOnBn254()
    {
        WhirParameterSchedule schedule = CreateFastSchedule(Bn);
        int[] counts = SingleConstraintCounts(StandardClaimCount);

        using BatchStatement statement = BatchStatement.Create(schedule, counts, Bn, BaseMemoryPool.Shared);

        Assert.IsTrue(ProveThenVerifyBatch(schedule, counts, statement, Bn), "An honest three-claim batch must verify on BN254.");
    }


    [TestMethod]
    public void MixedShapeBatchWithConstraintFreeClaimRoundTrips()
    {
        //Claim shapes [2, 0, 1]: a two-constraint claim, a constraint-free
        //claim whose target is the zero weighted sum, and a single-constraint
        //claim — the boundary encoding and the γ-power scaling must line up
        //across all three.
        WhirParameterSchedule schedule = CreateFastSchedule(Bls);
        int[] counts = [2, 0, 1];

        using BatchStatement statement = BatchStatement.Create(schedule, counts, Bls, BaseMemoryPool.Shared);

        Assert.IsTrue(ProveThenVerifyBatch(schedule, counts, statement, Bls), "An honest mixed-shape batch must verify.");
    }


    [TestMethod]
    public void SingleClaimBatchRoundTrips()
    {
        //The degenerate t = 1 batch: γ is squeezed but the first claim's
        //power is γ^0, so the combined statement equals the single claim.
        WhirParameterSchedule schedule = CreateFastSchedule(Bls);
        int[] counts = SingleConstraintCounts(1);

        using BatchStatement statement = BatchStatement.Create(schedule, counts, Bls, BaseMemoryPool.Shared);

        Assert.IsTrue(ProveThenVerifyBatch(schedule, counts, statement, Bls), "An honest single-claim batch must verify.");
    }


    [TestMethod]
    public void BatchingLedgerRowPinsTheoremFiveSixBound()
    {
        WhirParameterSchedule schedule = CreateFastSchedule(Bls);

        //Unique decoding pins ℓ = 1, so ε = (t-1)/|F|: two claims price the
        //full field floor and three claims one bit under it.
        const int TwoClaims = 2;
        const int ThreeClaims = 3;
        WhirSoundnessLedgerRow twoClaimRow = WhirConstraintBatching.ComputeBatchingLedgerRow(schedule, TwoClaims);
        WhirSoundnessLedgerRow threeClaimRow = WhirConstraintBatching.ComputeBatchingLedgerRow(schedule, ThreeClaims);
        WhirSoundnessLedgerRow singleClaimRow = WhirConstraintBatching.ComputeBatchingLedgerRow(schedule, 1);

        Assert.AreEqual(WhirRoundErrorKind.ConstraintBatching, twoClaimRow.Kind);
        Assert.AreEqual((double)schedule.FieldFloorBits, twoClaimRow.ErrorBits);
        Assert.AreEqual(schedule.FieldFloorBits - 1.0, threeClaimRow.ErrorBits);
        Assert.IsTrue(double.IsPositiveInfinity(singleClaimRow.ErrorBits), "A single-claim batch must price as an error-free row.");
    }


    [TestMethod]
    public void TamperedClaimTargetIsRejected()
    {
        WhirParameterSchedule schedule = CreateFastSchedule(Bls);
        int[] counts = SingleConstraintCounts(StandardClaimCount);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BatchStatement statement = BatchStatement.Create(schedule, counts, Bls, pool);
        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirConstraintBatching.Prove(
            schedule,
            statement.Coefficients,
            counts,
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            statement.ClaimTargets,
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
        using(IMemoryOwner<byte> tamperedOwner = pool.Rent(statement.ClaimTargets.Length))
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Span<byte> tamperedTargets = tamperedOwner.Memory.Span[..statement.ClaimTargets.Length];
            statement.ClaimTargets.CopyTo(tamperedTargets);
            tamperedTargets[^1] ^= 0x01;

            bool verified = WhirConstraintBatching.Verify(
                schedule,
                commitment,
                proof,
                counts,
                statement.ConstraintCoefficients,
                statement.ConstraintPoints,
                tamperedTargets,
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

            Assert.IsFalse(verified, "A batch verified against a tampered claim target must be rejected.");
        }
    }


    [TestMethod]
    public void ShiftedClaimBoundaryIsRejected()
    {
        //The same flat spans split as [1, 1] when proving and [2, 0] when
        //verifying: the second constraint's γ power changes, so the absorbed
        //boundary encoding and the combined weight both diverge and the
        //proof must refuse.
        WhirParameterSchedule schedule = CreateFastSchedule(Bls);
        int[] proverCounts = [1, 1];
        int[] verifierCounts = [2, 0];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BatchStatement statement = BatchStatement.Create(schedule, proverCounts, Bls, pool);
        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirConstraintBatching.Prove(
            schedule,
            statement.Coefficients,
            proverCounts,
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            statement.ClaimTargets,
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
            bool verified = WhirConstraintBatching.Verify(
                schedule,
                commitment,
                proof,
                verifierCounts,
                statement.ConstraintCoefficients,
                statement.ConstraintPoints,
                statement.ClaimTargets,
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

            Assert.IsFalse(verified, "A batch verified under a shifted claim boundary must be rejected.");
        }
    }


    [TestMethod]
    public void MalformedBatchShapesThrow()
    {
        WhirParameterSchedule schedule = CreateFastSchedule(Bls);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BatchStatement statement = BatchStatement.Create(schedule, SingleConstraintCounts(StandardClaimCount), Bls, pool);

        Assert.Throws<ArgumentException>(
            () => VerifyBatchWithCounts(schedule, [], statement, pool),
            "An empty claim list must be refused.");
        Assert.Throws<ArgumentException>(
            () => VerifyBatchWithCounts(schedule, [1, -1, 3], statement, pool),
            "A negative constraint count must be refused.");
        Assert.Throws<ArgumentException>(
            () => VerifyBatchWithCounts(schedule, [1, 1], statement, pool),
            "A claim count that does not match the targets span must be refused.");
        Assert.Throws<ArgumentException>(
            () => VerifyBatchWithCounts(schedule, [1, 1, 2], statement, pool),
            "A constraint total that does not match the flat spans must be refused.");
    }


    [TestMethod]
    public void ProverRejectsInconsistentClaimTarget()
    {
        WhirParameterSchedule schedule = CreateFastSchedule(Bls);
        int[] counts = SingleConstraintCounts(StandardClaimCount);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BatchStatement statement = BatchStatement.Create(schedule, counts, Bls, pool);

        Assert.Throws<ArgumentException>(
            () => ProveWithFlippedClaimTarget(schedule, counts, statement, pool),
            "The prover must refuse a batch whose combined claim does not hold.");
    }


    /// <summary>
    /// Attempts an honest batch run with the last claim target's low bit
    /// flipped; the inner prover's statement-consistency guard must refuse.
    /// </summary>
    private static void ProveWithFlippedClaimTarget(
        WhirParameterSchedule schedule,
        int[] counts,
        BatchStatement statement,
        BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> tamperedOwner = pool.Rent(statement.ClaimTargets.Length);
        Span<byte> tamperedTargets = tamperedOwner.Memory.Span[..statement.ClaimTargets.Length];
        statement.ClaimTargets.CopyTo(tamperedTargets);
        tamperedTargets[^1] ^= 0x01;

        using FiatShamirTranscript transcript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirConstraintBatching.Prove(
            schedule,
            statement.Coefficients,
            counts,
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            tamperedTargets,
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
    /// Runs a batch verification of a throwaway honest proof under the given
    /// claim counts — the shape-validation targets of the malformed-batch
    /// test, which must throw before any transcript work.
    /// </summary>
    private static void VerifyBatchWithCounts(
        WhirParameterSchedule schedule,
        int[] counts,
        BatchStatement statement,
        BaseMemoryPool pool)
    {
        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirConstraintBatching.Prove(
            schedule,
            statement.Coefficients,
            SingleConstraintCounts(StandardClaimCount),
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            statement.ClaimTargets,
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
            WhirConstraintBatching.Verify(
                schedule,
                commitment,
                proof,
                counts,
                statement.ConstraintCoefficients,
                statement.ConstraintPoints,
                statement.ClaimTargets,
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
    /// One batch statement: deterministic coefficients and, per claim, the
    /// scheduled number of scaled equality constraints at deterministic
    /// points with the honestly evaluated target
    /// <c>σ_i = Σ_c λ_c·f̂(p_c)</c>.
    /// </summary>
    private sealed class BatchStatement: IDisposable
    {
        private readonly IMemoryOwner<byte> owner;
        private readonly int messageBytes;
        private readonly int scalesBytes;
        private readonly int pointsBytes;
        private readonly int targetsBytes;

        /// <summary>The multilinear coefficient vector.</summary>
        public ReadOnlySpan<byte> Coefficients => owner.Memory.Span[..messageBytes];

        /// <summary>Every claim's constraint scales, concatenated in claim order.</summary>
        public ReadOnlySpan<byte> ConstraintCoefficients => owner.Memory.Span.Slice(messageBytes, scalesBytes);

        /// <summary>Every claim's constraint points, concatenated in claim order.</summary>
        public ReadOnlySpan<byte> ConstraintPoints => owner.Memory.Span.Slice(messageBytes + scalesBytes, pointsBytes);

        /// <summary>The honestly evaluated claim targets, one element per claim.</summary>
        public ReadOnlySpan<byte> ClaimTargets => owner.Memory.Span.Slice(messageBytes + scalesBytes + pointsBytes, targetsBytes);


        /// <summary>Wraps the populated statement buffer; the statement takes ownership.</summary>
        private BatchStatement(IMemoryOwner<byte> owner, int messageBytes, int scalesBytes, int pointsBytes, int targetsBytes)
        {
            this.owner = owner;
            this.messageBytes = messageBytes;
            this.scalesBytes = scalesBytes;
            this.pointsBytes = pointsBytes;
            this.targetsBytes = targetsBytes;
        }


        /// <summary>Builds the statement for the schedule's shape and the given per-claim constraint counts over the given backend.</summary>
        public static BatchStatement Create(
            WhirParameterSchedule schedule,
            int[] claimConstraintCounts,
            ScalarArithmeticBackend backend,
            BaseMemoryPool pool)
        {
            int variableCount = schedule.VariableCount;
            int pointBytes = variableCount * ScalarSize;
            int totalConstraints = 0;
            foreach(int count in claimConstraintCounts)
            {
                totalConstraints += count;
            }

            int messageBytes = (1 << variableCount) * ScalarSize;
            int scalesBytes = totalConstraints * ScalarSize;
            int pointsBytes = totalConstraints * pointBytes;
            int targetsBytes = claimConstraintCounts.Length * ScalarSize;
            int totalBytes = messageBytes + scalesBytes + pointsBytes + targetsBytes;

            IMemoryOwner<byte> owner = pool.Rent(totalBytes);
            Span<byte> buffers = owner.Memory.Span[..totalBytes];
            Span<byte> coefficients = buffers[..messageBytes];
            Span<byte> scales = buffers.Slice(messageBytes, scalesBytes);
            Span<byte> points = buffers.Slice(messageBytes + scalesBytes, pointsBytes);
            Span<byte> targets = buffers.Slice(messageBytes + scalesBytes + pointsBytes, targetsBytes);

            DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, backend.Reduce, backend.Curve);
            DeterministicScalarFill.FillCanonical(scales, ScaleSalt, backend.Reduce, backend.Curve);

            Span<byte> evaluation = stackalloc byte[ScalarSize];
            Span<byte> term = stackalloc byte[ScalarSize];
            int constraintOffset = 0;
            for(int claim = 0; claim < claimConstraintCounts.Length; claim++)
            {
                Span<byte> target = targets.Slice(claim * ScalarSize, ScalarSize);
                target.Clear();
                for(int constraint = 0; constraint < claimConstraintCounts[claim]; constraint++)
                {
                    int index = constraintOffset + constraint;
                    Span<byte> point = points.Slice(index * pointBytes, pointBytes);
                    DeterministicScalarFill.FillCanonical(point, PointSaltBase + index, backend.Reduce, backend.Curve);
                    WhirMultilinear.EvaluateCoefficientsAtPoint(
                        coefficients, point, variableCount, evaluation, backend.Add, backend.Multiply, backend.Curve, pool);
                    backend.Multiply(scales.Slice(index * ScalarSize, ScalarSize), evaluation, term, backend.Curve);
                    backend.Add(target, term, target, backend.Curve);
                }

                constraintOffset += claimConstraintCounts[claim];
            }

            return new BatchStatement(owner, messageBytes, scalesBytes, pointsBytes, targetsBytes);
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            //The pool zeroes rented buffers on return.
            owner.Dispose();
        }
    }


    /// <summary>
    /// The fast batch schedule over the given backend's curve.
    /// </summary>
    private static WhirParameterSchedule CreateFastSchedule(ScalarArithmeticBackend backend)
    {
        return WhirParameterSchedule.Create(
            backend.Curve,
            FastVariableCount,
            FastInitialRateLog2,
            securityLevelBits: FastSecurityLevelBits);
    }


    /// <summary>
    /// A claim-count list of the given length with one constraint per claim.
    /// </summary>
    private static int[] SingleConstraintCounts(int claimCount)
    {
        var counts = new int[claimCount];
        Array.Fill(counts, 1);

        return counts;
    }


    /// <summary>
    /// Runs one honest batched round-trip for the schedule and reports the
    /// verification outcome.
    /// </summary>
    private static bool ProveThenVerifyBatch(
        WhirParameterSchedule schedule,
        int[] counts,
        BatchStatement statement,
        ScalarArithmeticBackend backend)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        (WhirIoppProof proof, MerkleRoot commitment) = WhirConstraintBatching.Prove(
            schedule,
            statement.Coefficients,
            counts,
            statement.ConstraintCoefficients,
            statement.ConstraintPoints,
            statement.ClaimTargets,
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
            return WhirConstraintBatching.Verify(
                schedule,
                commitment,
                proof,
                counts,
                statement.ConstraintCoefficients,
                statement.ConstraintPoints,
                statement.ClaimTargets,
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
