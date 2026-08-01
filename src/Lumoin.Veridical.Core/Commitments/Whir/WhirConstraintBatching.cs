using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The WHIR multi-claim batching layer (WHIR Construction 5.5): reduces
/// <c>t</c> separate claims <c>(ŵ_i, σ_i)</c> against one committed
/// polynomial to a single claim by a random linear combination — the verifier
/// samples <c>γ</c> and both endpoints run the single-statement IOPP on
/// <c>ŵ = Σ_i γ^i·ŵ_i</c> and <c>σ = Σ_i γ^i·σ_i</c>. Because every wired
/// weight is the equality-kernel shape <c>Z·Σ_c λ_c·eq(p_c, ·)</c>, the
/// combination stays in that shape: each claim's coefficients are scaled by
/// its <c>γ</c> power and the constraint points pass through unchanged, so
/// the sumcheck degree bound is unaffected.
/// </summary>
/// <remarks>
/// The combination challenge is sound only against a polynomial fixed before
/// the challenge exists, so the layer binds the batch statement and the input
/// oracle's Merkle root into the transcript before squeezing <c>γ</c>. The
/// combination costs one ledger row, <c>ε ≤ (t-1)·ℓ/|F|</c> for <c>ℓ</c> the
/// initial code's list-size bound (WHIR Theorem 5.6), prefixing the
/// single-statement rounds; both endpoints refuse a batch whose row lands
/// under the schedule's security target.
/// </remarks>
public static class WhirConstraintBatching
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Prices the batch combination row of WHIR Theorem 5.6,
    /// <c>ε ≤ (t-1)·ℓ/|F|</c>, for a batch of
    /// <paramref name="claimCount"/> claims under the schedule's regime. A
    /// single-claim batch pays no combination error and prices as an
    /// error-free row.
    /// </summary>
    /// <param name="schedule">The parameter schedule fixing the initial code's list-size bound and the field floor.</param>
    /// <param name="claimCount">The number of batched claims <c>t</c>, at least 1.</param>
    /// <returns>The ledger row prefixing the single-statement ledger.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="schedule"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="claimCount"/> is not positive.</exception>
    public static WhirSoundnessLedgerRow ComputeBatchingLedgerRow(WhirParameterSchedule schedule, int claimCount)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(claimCount);

        double errorBits = claimCount == 1
            ? double.PositiveInfinity
            : schedule.FieldFloorBits - Math.Log2((claimCount - 1) * schedule.Rounds[0].ListSizeBound);

        return new WhirSoundnessLedgerRow(WhirRoundErrorKind.ConstraintBatching, 0, 0, errorBits);
    }


    /// <summary>
    /// Produces a WHIR proof for <c>t</c> separate claims
    /// <c>Σ_b f̂(b)·(Σ_c λ_c·eq(p_c, b)) = σ_i</c> against the polynomial
    /// with the given coefficient vector, by combining them under the batch
    /// challenge and proving the combined claim.
    /// </summary>
    /// <param name="schedule">The parameter schedule both endpoints derive from the same public figures.</param>
    /// <param name="coefficients">The multilinear coefficient vector, <c>2^m</c> elements for the schedule's variable count <c>m</c>.</param>
    /// <param name="claimConstraintCounts">The per-claim constraint counts splitting the flat constraint spans; one entry per claim, at least one claim.</param>
    /// <param name="constraintCoefficients">Every claim's constraint scales <c>λ_c</c>, concatenated in claim order.</param>
    /// <param name="constraintPoints">Every claim's constraint points <c>p_c</c>, <c>m</c> elements per constraint, concatenated in claim order.</param>
    /// <param name="claimTargets">The claimed sums <c>σ_i</c>, one element per claim.</param>
    /// <param name="transcript">The Fiat-Shamir transcript, already initialised with the protocol's public context.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for deriving challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="pool">The pool to rent working and proof buffers from.</param>
    /// <returns>The proof and the input oracle's Merkle root — the public commitment the verifier needs; the caller owns both.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the batch shape, the batch cannot reach the schedule's security target, or a claim does not hold for the coefficients.</exception>
    public static (WhirIoppProof Proof, MerkleRoot InputCommitment) Prove(
        WhirParameterSchedule schedule,
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<int> claimConstraintCounts,
        ReadOnlySpan<byte> constraintCoefficients,
        ReadOnlySpan<byte> constraintPoints,
        ReadOnlySpan<byte> claimTargets,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);

        CurveParameterSet curve = schedule.Curve;
        ValidateBatchShape(schedule, claimConstraintCounts, constraintCoefficients, constraintPoints, claimTargets, out int totalConstraintCount);
        ThrowIfBatchMissesTarget(schedule, claimConstraintCounts.Length, nameof(claimConstraintCounts));

        //The combination challenge must not be samplable before the
        //polynomial is fixed: bind the whole batch and the input oracle's
        //root, then squeeze γ.
        transcript.AbsorbWhirBatchStatement(claimTargets, claimConstraintCounts, constraintCoefficients, constraintPoints, hash, pool);
        using MerkleRoot boundCommitment = WhirIoppProver.ComputeInputCommitment(schedule, coefficients, merkleHash, add, subtract, multiply, pool);
        transcript.AbsorbWhirOracleRoot(boundCommitment, hash);

        using Scalar gamma = transcript.SqueezeWhirBatchCombinationChallenge(squeeze, hash, reduce, curve, pool);

        using IMemoryOwner<byte> combinedOwner = pool.Rent((totalConstraintCount + 1) * ScalarSize);
        Span<byte> combined = combinedOwner.Memory.Span[..((totalConstraintCount + 1) * ScalarSize)];
        Span<byte> scaledCoefficients = combined[..(totalConstraintCount * ScalarSize)];
        Span<byte> combinedTarget = combined.Slice(totalConstraintCount * ScalarSize, ScalarSize);
        CombineStatements(claimTargets, claimConstraintCounts, constraintCoefficients, gamma.AsReadOnlySpan(), scaledCoefficients, combinedTarget, add, multiply, curve);

        (WhirIoppProof proof, MerkleRoot inputCommitment) = WhirIoppProver.Prove(
            schedule,
            coefficients,
            scaledCoefficients,
            constraintPoints,
            combinedTarget,
            transcript,
            merkleHash,
            hash,
            squeeze,
            reduce,
            add,
            subtract,
            multiply,
            pool);

        //Both roots come from the same deterministic encode-and-commit; a
        //mismatch means the two paths diverged, which is an internal fault
        //rather than a caller error.
        if(!inputCommitment.AsReadOnlySpan().SequenceEqual(boundCommitment.AsReadOnlySpan()))
        {
            proof.Dispose();
            inputCommitment.Dispose();
            throw new InvalidOperationException("The batching layer's input commitment does not match the prover's.");
        }

        return (proof, inputCommitment);
    }


    /// <summary>
    /// Verifies a WHIR proof of <c>t</c> separate claims produced by
    /// <see cref="Prove"/>, replaying the batch combination against the
    /// input oracle's Merkle commitment and verifying the combined claim.
    /// </summary>
    /// <param name="schedule">The parameter schedule, derived independently from the same public figures the prover used.</param>
    /// <param name="inputCommitment">The input oracle's Merkle root.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="claimConstraintCounts">The per-claim constraint counts splitting the flat constraint spans; one entry per claim, at least one claim.</param>
    /// <param name="constraintCoefficients">Every claim's constraint scales <c>λ_c</c>, concatenated in claim order.</param>
    /// <param name="constraintPoints">Every claim's constraint points <c>p_c</c>, <c>m</c> elements per constraint, concatenated in claim order.</param>
    /// <param name="claimTargets">The claimed sums <c>σ_i</c>, one element per claim.</param>
    /// <param name="transcript">The Fiat-Shamir transcript, initialised with the same public context the prover used.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for deriving challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend (for the fold recomputation's <c>1/(2x)</c> factors).</param>
    /// <param name="pool">The pool to rent working buffers from.</param>
    /// <returns><see langword="true"/> iff every check passes.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the batch shape or the batch cannot reach the schedule's security target.</exception>
    public static bool Verify(
        WhirParameterSchedule schedule,
        MerkleRoot inputCommitment,
        WhirIoppProof proof,
        ReadOnlySpan<int> claimConstraintCounts,
        ReadOnlySpan<byte> constraintCoefficients,
        ReadOnlySpan<byte> constraintPoints,
        ReadOnlySpan<byte> claimTargets,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        ArgumentNullException.ThrowIfNull(inputCommitment);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);

        CurveParameterSet curve = schedule.Curve;
        ValidateBatchShape(schedule, claimConstraintCounts, constraintCoefficients, constraintPoints, claimTargets, out int totalConstraintCount);
        ThrowIfBatchMissesTarget(schedule, claimConstraintCounts.Length, nameof(claimConstraintCounts));

        transcript.AbsorbWhirBatchStatement(claimTargets, claimConstraintCounts, constraintCoefficients, constraintPoints, hash, pool);
        transcript.AbsorbWhirOracleRoot(inputCommitment, hash);

        using Scalar gamma = transcript.SqueezeWhirBatchCombinationChallenge(squeeze, hash, reduce, curve, pool);

        using IMemoryOwner<byte> combinedOwner = pool.Rent((totalConstraintCount + 1) * ScalarSize);
        Span<byte> combined = combinedOwner.Memory.Span[..((totalConstraintCount + 1) * ScalarSize)];
        Span<byte> scaledCoefficients = combined[..(totalConstraintCount * ScalarSize)];
        Span<byte> combinedTarget = combined.Slice(totalConstraintCount * ScalarSize, ScalarSize);
        CombineStatements(claimTargets, claimConstraintCounts, constraintCoefficients, gamma.AsReadOnlySpan(), scaledCoefficients, combinedTarget, add, multiply, curve);

        return WhirIoppVerifier.Verify(
            schedule,
            inputCommitment,
            proof,
            scaledCoefficients,
            constraintPoints,
            combinedTarget,
            transcript,
            merkleHash,
            hash,
            squeeze,
            reduce,
            add,
            subtract,
            multiply,
            invert,
            pool);
    }


    /// <summary>
    /// Combines the batch under the challenge: claim <c>i</c>'s constraint
    /// scales and target are multiplied by <c>γ^i</c>, so the first claim
    /// passes through unscaled and the combined statement keeps the
    /// equality-kernel weight shape over the unchanged constraint points.
    /// </summary>
    /// <param name="claimTargets">The claim targets, one element per claim.</param>
    /// <param name="claimConstraintCounts">The per-claim constraint counts.</param>
    /// <param name="constraintCoefficients">The flat constraint scales in claim order.</param>
    /// <param name="gamma">The batch combination challenge.</param>
    /// <param name="scaledCoefficients">Receives the scaled constraint coefficients, same layout as the input scales.</param>
    /// <param name="combinedTarget">Receives the combined target, one element.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="curve">The curve whose scalar field the batch lives in.</param>
    private static void CombineStatements(
        ReadOnlySpan<byte> claimTargets,
        ReadOnlySpan<int> claimConstraintCounts,
        ReadOnlySpan<byte> constraintCoefficients,
        ReadOnlySpan<byte> gamma,
        Span<byte> scaledCoefficients,
        Span<byte> combinedTarget,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> gammaPower = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        gammaPower.Clear();
        gammaPower[ScalarSize - 1] = 0x01;
        combinedTarget.Clear();

        int constraintOffset = 0;
        for(int claim = 0; claim < claimConstraintCounts.Length; claim++)
        {
            if(claim > 0)
            {
                multiply(gammaPower, gamma, gammaPower, curve);
            }

            multiply(gammaPower, claimTargets.Slice(claim * ScalarSize, ScalarSize), term, curve);
            add(combinedTarget, term, combinedTarget, curve);

            for(int constraint = 0; constraint < claimConstraintCounts[claim]; constraint++)
            {
                int offset = (constraintOffset + constraint) * ScalarSize;
                multiply(gammaPower, constraintCoefficients.Slice(offset, ScalarSize), scaledCoefficients.Slice(offset, ScalarSize), curve);
            }

            constraintOffset += claimConstraintCounts[claim];
        }
    }


    /// <summary>
    /// Validates the flat batch spans against the claim boundaries and the
    /// schedule's shape.
    /// </summary>
    /// <param name="schedule">The parameter schedule fixing the per-constraint point width.</param>
    /// <param name="claimConstraintCounts">The per-claim constraint counts.</param>
    /// <param name="constraintCoefficients">The flat constraint scales.</param>
    /// <param name="constraintPoints">The flat constraint points.</param>
    /// <param name="claimTargets">The claim targets.</param>
    /// <param name="totalConstraintCount">Receives the total constraint count across the batch.</param>
    private static void ValidateBatchShape(
        WhirParameterSchedule schedule,
        ReadOnlySpan<int> claimConstraintCounts,
        ReadOnlySpan<byte> constraintCoefficients,
        ReadOnlySpan<byte> constraintPoints,
        ReadOnlySpan<byte> claimTargets,
        out int totalConstraintCount)
    {
        if(claimConstraintCounts.IsEmpty)
        {
            throw new ArgumentException("A batch must carry at least one claim.", nameof(claimConstraintCounts));
        }

        //Accumulate in long so a hostile count list cannot overflow the
        //total; the length checks below divide rather than multiply, so no
        //product can wrap into a coincidental match either.
        long total = 0;
        foreach(int count in claimConstraintCounts)
        {
            if(count < 0)
            {
                throw new ArgumentException("Every claim's constraint count must be non-negative.", nameof(claimConstraintCounts));
            }

            total += count;
        }

        if(claimTargets.Length != (long)claimConstraintCounts.Length * ScalarSize)
        {
            throw new ArgumentException(
                $"The claim targets must be one {ScalarSize}-byte element per claim ({claimConstraintCounts.Length} claims); received {claimTargets.Length} bytes.",
                nameof(claimTargets));
        }

        if(constraintCoefficients.Length % ScalarSize != 0 || total != constraintCoefficients.Length / ScalarSize)
        {
            throw new ArgumentException(
                $"The constraint coefficients must carry {total} whole {ScalarSize}-byte elements; received {constraintCoefficients.Length} bytes.",
                nameof(constraintCoefficients));
        }

        int pointStride = schedule.VariableCount * ScalarSize;
        if(constraintPoints.Length % pointStride != 0 || total != constraintPoints.Length / pointStride)
        {
            throw new ArgumentException(
                $"The constraint points must carry {schedule.VariableCount} elements per constraint for {total} constraints; received {constraintPoints.Length} bytes.",
                nameof(constraintPoints));
        }

        totalConstraintCount = (int)total;
    }


    /// <summary>
    /// Fails loudly when the batch combination row lands under the
    /// schedule's security target: a batch large enough to breach the
    /// target must be split rather than silently degrade the proof.
    /// </summary>
    /// <param name="schedule">The parameter schedule fixing the target.</param>
    /// <param name="claimCount">The number of batched claims.</param>
    /// <param name="parameterName">The caller's parameter name for the thrown exception.</param>
    private static void ThrowIfBatchMissesTarget(WhirParameterSchedule schedule, int claimCount, string parameterName)
    {
        WhirSoundnessLedgerRow row = ComputeBatchingLedgerRow(schedule, claimCount);
        if(row.ErrorBits < schedule.SecurityLevelBits)
        {
            throw new ArgumentException(
                $"Batching {claimCount} claims realises {row.ErrorBits:F2} bits of combination soundness, under the {schedule.SecurityLevelBits}-bit target.",
                parameterName);
        }
    }
}
