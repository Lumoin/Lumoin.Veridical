using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The WHIR IOPP verifier (WHIR Construction 5.1, decision phase): replays the
/// Fiat-Shamir schedule against the statement, the input oracle's commitment
/// and the proof messages, chains the compressed sumcheck claims, recomputes
/// <c>Fold(f_(i-1), α_(i-1))</c> at every queried point from the
/// authenticated coset blocks, and closes with the final polynomial's
/// consistency and constraint-sum checks. A malformed proof is reported as a
/// non-match rather than an exception; only broken caller inputs throw.
/// </summary>
/// <remarks>
/// The verifier's copy of the weight polynomial is symbolic: every wired
/// weight is <c>Z·Σ_c λ_c·eq(p_c, ·)</c>, so it tracks the constraint list
/// <c>(λ_c, p_c)</c>, multiplies each <c>λ_c</c> by the matching equality
/// factor as sumcheck challenges bind coordinates, and appends the
/// out-of-domain and shift constraints each iteration adds — reaching, at the
/// final check, the same weight the prover's folded table represents.
/// </remarks>
public static class WhirIoppVerifier
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// The sumcheck round polynomials are quadratic for every wired weight
    /// shape; a proof carrying any other degree is malformed.
    /// </summary>
    private const int RoundPolynomialDegree = 2;


    /// <summary>
    /// Verifies a WHIR proof of the statement
    /// <c>Σ_b f̂(b)·(Σ_c λ_c·eq(p_c, b)) = σ</c> against the input oracle's
    /// Merkle commitment.
    /// </summary>
    /// <param name="schedule">The parameter schedule, derived independently from the same public figures the prover used.</param>
    /// <param name="inputCommitment">The input oracle's Merkle root.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="constraintCoefficients">The constraint scales <c>λ_c</c>, one element per constraint; may be empty for plain proximity.</param>
    /// <param name="constraintPoints">The constraint points <c>p_c</c>, <c>m</c> elements per constraint, first variable first.</param>
    /// <param name="target">The claimed sum <c>σ</c>, one element.</param>
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
    /// <exception cref="ArgumentException">When a statement span does not match the schedule's shape.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Every rented buffer and tracked constraint is registered in the disposables list and released in the finally block.")]
    public static bool Verify(
        WhirParameterSchedule schedule,
        MerkleRoot inputCommitment,
        WhirIoppProof proof,
        ReadOnlySpan<byte> constraintCoefficients,
        ReadOnlySpan<byte> constraintPoints,
        ReadOnlySpan<byte> target,
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

        int variableCount = schedule.VariableCount;
        int foldingParameter = schedule.FoldingParameter;
        int iterationCount = schedule.IterationCount;
        CurveParameterSet curve = schedule.Curve;
        ValidateStatementShape(constraintCoefficients, constraintPoints, target, variableCount, out int constraintCount);

        if(!ProofShapeMatches(schedule, proof))
        {
            return false;
        }

        var encoder = WhirCosetEncoder.Create(add, subtract, multiply, curve, pool);
        var disposables = new List<IDisposable>();
        var constraints = new List<TrackedConstraint>();

        try
        {
            transcript.AbsorbWhirStatement(target, constraintCoefficients, constraintPoints, hash);
            transcript.AbsorbWhirOracleRoot(inputCommitment, hash);

            for(int constraint = 0; constraint < constraintCount; constraint++)
            {
                constraints.Add(TrackConstraint(
                    constraintCoefficients.Slice(constraint * ScalarSize, ScalarSize),
                    constraintPoints.Slice(constraint * variableCount * ScalarSize, variableCount * ScalarSize),
                    variableCount,
                    pool,
                    disposables));
            }

            //The running claim, the current iteration's raw challenge block
            //(feeding the next iteration's fold recomputation), and the
            //single-element temporaries.
            Span<byte> claim = stackalloc byte[ScalarSize];
            target.CopyTo(claim);
            Span<byte> challengeBlock = RentTracked(foldingParameter * ScalarSize, pool, disposables);
            Span<byte> blockScratch = RentTracked((1 << foldingParameter) * ScalarSize, pool, disposables);
            Span<byte> digestScratch = RentTracked(Math.Max(1, (1 << foldingParameter) / 2 * ScalarSize), pool, disposables);
            Span<byte> coordinates = RentTracked(variableCount * ScalarSize, pool, disposables);
            Span<byte> queryRoot = stackalloc byte[ScalarSize];
            Span<byte> domainRoot = stackalloc byte[ScalarSize];
            Span<byte> strideRoot = stackalloc byte[ScalarSize];
            Span<byte> basePoint = stackalloc byte[ScalarSize];
            Span<byte> queryPoint = stackalloc byte[ScalarSize];
            Span<byte> foldedValue = stackalloc byte[ScalarSize];
            Span<byte> gammaPower = stackalloc byte[ScalarSize];
            Span<byte> term = stackalloc byte[ScalarSize];
            encoder.DeriveDomainRoot(foldingParameter, strideRoot);

            int currentVariableCount = variableCount;
            int roundPolynomialIndex = 0;
            for(int iteration = 0; iteration < iterationCount; iteration++)
            {
                if(iteration > 0)
                {
                    MerkleRoot currentRoot = proof.OracleRoots[iteration - 1];
                    transcript.AbsorbWhirOracleRoot(currentRoot, hash);

                    using Scalar outOfDomainPoint = transcript.SqueezeWhirOutOfDomainPoint(squeeze, hash, reduce, curve, pool);
                    Scalar reply = proof.OutOfDomainReplies[iteration - 1];
                    transcript.AbsorbWhirOutOfDomainReply(reply.AsReadOnlySpan(), hash);

                    WhirRoundParameters previous = schedule.Rounds[iteration - 1];
                    int queryDomainLog2 = previous.DomainSizeLog2 - foldingParameter;
                    var indices = new int[previous.QueryCount];
                    for(int query = 0; query < indices.Length; query++)
                    {
                        indices[query] = transcript.SqueezeWhirQueryIndex(
                            WellKnownWhirTranscriptLabels.ShiftQueryIndex,
                            1 << queryDomainLog2,
                            squeeze,
                            hash);
                    }

                    using Scalar gamma = transcript.SqueezeWhirCombinationChallenge(squeeze, hash, reduce, curve, pool);

                    //Authenticate every queried block against the previous
                    //oracle's root, recompute the fold, and accumulate the
                    //claim delta γ·y + Σ_j γ^(j+1)·g(z_j) while the challenge
                    //block still holds the previous iteration's challenges.
                    MerkleRoot previousRoot = iteration - 1 == 0 ? inputCommitment : proof.OracleRoots[iteration - 2];
                    IReadOnlyList<WhirQueryOpening> shiftOpenings = proof.OpeningsForOracle(iteration - 1);
                    encoder.DeriveDomainRoot(previous.DomainSizeLog2, domainRoot);
                    encoder.DeriveDomainRoot(queryDomainLog2, queryRoot);

                    multiply(gamma.AsReadOnlySpan(), reply.AsReadOnlySpan(), term, curve);
                    add(claim, term, claim, curve);
                    gamma.AsReadOnlySpan().CopyTo(gammaPower);

                    //The out-of-domain constraint joins the list at scale γ.
                    Span<byte> pointCoordinates = coordinates[..(currentVariableCount * ScalarSize)];
                    WhirMultilinear.ExpandPowPoint(outOfDomainPoint.AsReadOnlySpan(), currentVariableCount, pointCoordinates, multiply, curve);
                    constraints.Add(TrackConstraint(gammaPower, pointCoordinates, currentVariableCount, pool, disposables));

                    for(int query = 0; query < indices.Length; query++)
                    {
                        WhirQueryOpening opening = shiftOpenings[query];
                        if(!AuthenticateOpening(opening, previousRoot, indices[query], merkleHash, digestScratch))
                        {
                            return false;
                        }

                        opening.BlockValues.Span.CopyTo(blockScratch);
                        WhirFold.ComputeDomainPoint(domainRoot, indices[query], basePoint, multiply, curve);
                        WhirFold.FoldCosetBlock(
                            blockScratch,
                            foldingParameter,
                            challengeBlock,
                            basePoint,
                            strideRoot,
                            foldedValue,
                            add,
                            subtract,
                            multiply,
                            invert,
                            curve,
                            pool);

                        multiply(gammaPower, gamma.AsReadOnlySpan(), gammaPower, curve);
                        multiply(gammaPower, foldedValue, term, curve);
                        add(claim, term, claim, curve);

                        //The matching shift constraint at scale γ^(j+1).
                        WhirFold.ComputeDomainPoint(queryRoot, indices[query], queryPoint, multiply, curve);
                        WhirMultilinear.ExpandPowPoint(queryPoint, currentVariableCount, pointCoordinates, multiply, curve);
                        constraints.Add(TrackConstraint(gammaPower, pointCoordinates, currentVariableCount, pool, disposables));
                    }
                }

                for(int round = 0; round < foldingParameter; round++)
                {
                    CompressedRoundPolynomial roundPolynomial = proof.RoundPolynomials[roundPolynomialIndex++];
                    if(roundPolynomial.Degree != RoundPolynomialDegree || roundPolynomial.Curve.Code != curve.Code)
                    {
                        return false;
                    }

                    transcript.AbsorbWhirSumcheckPolynomial(roundPolynomial, hash);

                    //c_1 = claim − 2·c_0 − c_2, then the new claim is the
                    //polynomial at the squeezed challenge by Horner.
                    ReadOnlySpan<byte> constantTerm = roundPolynomial.GetStoredCoefficientBytes(0);
                    ReadOnlySpan<byte> quadraticTerm = roundPolynomial.GetStoredCoefficientBytes(1);
                    Span<byte> linearTerm = term;
                    subtract(claim, constantTerm, linearTerm, curve);
                    subtract(linearTerm, constantTerm, linearTerm, curve);
                    subtract(linearTerm, quadraticTerm, linearTerm, curve);

                    using Scalar challenge = transcript.SqueezeWhirFoldChallenge(squeeze, hash, reduce, curve, pool);
                    ReadOnlySpan<byte> challengeBytes = challenge.AsReadOnlySpan();
                    challengeBytes.CopyTo(challengeBlock.Slice(round * ScalarSize, ScalarSize));

                    multiply(quadraticTerm, challengeBytes, claim, curve);
                    add(claim, linearTerm, claim, curve);
                    multiply(claim, challengeBytes, claim, curve);
                    add(claim, constantTerm, claim, curve);

                    FoldConstraints(constraints, challengeBytes, add, subtract, multiply, curve);
                    currentVariableCount--;
                }
            }

            //Final polynomial: absorbed in the clear, then the final queries
            //check it against the fold of the last oracle, and the constraint
            //sum closes the sumcheck chain.
            ReadOnlySpan<byte> finalCoefficients = proof.FinalPolynomial;
            transcript.AbsorbWhirFinalPolynomial(finalCoefficients, hash);

            WhirRoundParameters last = schedule.Rounds[iterationCount - 1];
            int finalQueryDomainLog2 = last.DomainSizeLog2 - foldingParameter;
            MerkleRoot lastRoot = iterationCount == 1 ? inputCommitment : proof.OracleRoots[iterationCount - 2];
            IReadOnlyList<WhirQueryOpening> finalOpenings = proof.OpeningsForOracle(iterationCount - 1);
            encoder.DeriveDomainRoot(last.DomainSizeLog2, domainRoot);
            encoder.DeriveDomainRoot(finalQueryDomainLog2, queryRoot);

            Span<byte> pointEvaluation = stackalloc byte[ScalarSize];
            for(int query = 0; query < last.QueryCount; query++)
            {
                int index = transcript.SqueezeWhirQueryIndex(
                    WellKnownWhirTranscriptLabels.FinalQueryIndex,
                    1 << finalQueryDomainLog2,
                    squeeze,
                    hash);

                WhirQueryOpening opening = finalOpenings[query];
                if(!AuthenticateOpening(opening, lastRoot, index, merkleHash, digestScratch))
                {
                    return false;
                }

                opening.BlockValues.Span.CopyTo(blockScratch);
                WhirFold.ComputeDomainPoint(domainRoot, index, basePoint, multiply, curve);
                WhirFold.FoldCosetBlock(
                    blockScratch,
                    foldingParameter,
                    challengeBlock,
                    basePoint,
                    strideRoot,
                    foldedValue,
                    add,
                    subtract,
                    multiply,
                    invert,
                    curve,
                    pool);

                WhirFold.ComputeDomainPoint(queryRoot, index, queryPoint, multiply, curve);
                Span<byte> pointCoordinates = coordinates[..(currentVariableCount * ScalarSize)];
                WhirMultilinear.ExpandPowPoint(queryPoint, currentVariableCount, pointCoordinates, multiply, curve);
                WhirMultilinear.EvaluateCoefficientsAtPoint(
                    finalCoefficients,
                    pointCoordinates,
                    currentVariableCount,
                    pointEvaluation,
                    add,
                    multiply,
                    curve,
                    pool);

                if(!pointEvaluation.SequenceEqual(foldedValue))
                {
                    return false;
                }
            }

            return FinalConstraintSumMatches(
                finalCoefficients,
                currentVariableCount,
                constraints,
                claim,
                add,
                subtract,
                multiply,
                curve,
                pool);
        }
        finally
        {
            for(int index = disposables.Count - 1; index >= 0; index--)
            {
                disposables[index].Dispose();
            }
        }
    }


    /// <summary>
    /// One symbolic weight constraint <c>λ·eq(p, ·)</c>: the scale mutates as
    /// challenges bind coordinates and the cursor tracks how many leading
    /// coordinates have been consumed. Shared with the hiding verifier, whose
    /// source-claim tracking is the same machinery with <c>ε</c>-rescaled
    /// coefficients.
    /// </summary>
    internal sealed class TrackedConstraint: IDisposable
    {
        /// <summary>The mutable scale <c>λ</c>, one element.</summary>
        public IMemoryOwner<byte> Coefficient { get; }

        /// <summary>The constraint point's coordinates, first variable first.</summary>
        public IMemoryOwner<byte> Coordinates { get; }

        /// <summary>The total coordinate count.</summary>
        public int CoordinateCount { get; }

        /// <summary>The count of leading coordinates already bound by challenges.</summary>
        public int Cursor { get; set; }


        /// <summary>Wraps the pool-rented parts; the constraint takes ownership.</summary>
        public TrackedConstraint(IMemoryOwner<byte> coefficient, IMemoryOwner<byte> coordinates, int coordinateCount)
        {
            Coefficient = coefficient;
            Coordinates = coordinates;
            CoordinateCount = coordinateCount;
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            //The pool zeroes rented buffers on return.
            Coefficient.Dispose();
            Coordinates.Dispose();
        }
    }


    /// <summary>
    /// Validates the statement spans against the schedule's shape.
    /// </summary>
    private static void ValidateStatementShape(
        ReadOnlySpan<byte> constraintCoefficients,
        ReadOnlySpan<byte> constraintPoints,
        ReadOnlySpan<byte> target,
        int variableCount,
        out int constraintCount)
    {
        if(constraintCoefficients.Length % ScalarSize != 0)
        {
            throw new ArgumentException(
                $"The constraint coefficients must be whole {ScalarSize}-byte elements; received {constraintCoefficients.Length} bytes.",
                nameof(constraintCoefficients));
        }

        constraintCount = constraintCoefficients.Length / ScalarSize;
        if(constraintPoints.Length != constraintCount * variableCount * ScalarSize)
        {
            throw new ArgumentException(
                $"The constraint points must carry {variableCount} elements per constraint ({constraintCount * variableCount * ScalarSize} bytes); received {constraintPoints.Length} bytes.",
                nameof(constraintPoints));
        }

        if(target.Length != ScalarSize)
        {
            throw new ArgumentException($"The target must be one {ScalarSize}-byte element; received {target.Length} bytes.", nameof(target));
        }
    }


    /// <summary>
    /// Structural checks: every proof dimension must equal the schedule's
    /// derived figure. A mismatch is a malformed proof, reported as a
    /// non-match.
    /// </summary>
    private static bool ProofShapeMatches(WhirParameterSchedule schedule, WhirIoppProof proof)
    {
        int iterationCount = schedule.IterationCount;
        int expectedFinalLength = (1 << schedule.FinalVariableCount) * ScalarSize;
        int blockBytes = (1 << schedule.FoldingParameter) * ScalarSize;

        if(proof.OracleRoots.Count != iterationCount - 1
            || proof.RoundPolynomials.Count != iterationCount * schedule.FoldingParameter
            || proof.OutOfDomainReplies.Count != iterationCount - 1
            || proof.FinalPolynomial.Length != expectedFinalLength)
        {
            return false;
        }

        for(int oracle = 0; oracle < iterationCount; oracle++)
        {
            IReadOnlyList<WhirQueryOpening> openings = proof.OpeningsForOracle(oracle);
            if(openings.Count != schedule.Rounds[oracle].QueryCount)
            {
                return false;
            }

            foreach(WhirQueryOpening opening in openings)
            {
                if(opening.BlockValues.Length != blockBytes)
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>
    /// Copies a constraint's scale and point into pool-owned storage and
    /// registers the tracked constraint for disposal.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented coefficient and coordinate buffers transfer ownership to the returned constraint, which is registered in the disposables list.")]
    internal static TrackedConstraint TrackConstraint(
        ReadOnlySpan<byte> coefficient,
        ReadOnlySpan<byte> coordinates,
        int coordinateCount,
        BaseMemoryPool pool,
        List<IDisposable> disposables)
    {
        IMemoryOwner<byte> coefficientOwner = pool.Rent(ScalarSize);
        coefficient.CopyTo(coefficientOwner.Memory.Span[..ScalarSize]);

        IMemoryOwner<byte> coordinatesOwner = pool.Rent(Math.Max(1, coordinateCount * ScalarSize));
        coordinates.CopyTo(coordinatesOwner.Memory.Span[..(coordinateCount * ScalarSize)]);

        var tracked = new TrackedConstraint(coefficientOwner, coordinatesOwner, coordinateCount);
        disposables.Add(tracked);

        return tracked;
    }


    /// <summary>
    /// Binds one sumcheck challenge into every constraint: the scale picks up
    /// the equality factor <c>eq(p, α) = 2pα − p − α + 1</c> of its next
    /// coordinate.
    /// </summary>
    internal static void FoldConstraints(
        List<TrackedConstraint> constraints,
        ReadOnlySpan<byte> challenge,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> factor = stackalloc byte[ScalarSize];
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[ScalarSize - 1] = 0x01;

        foreach(TrackedConstraint constraint in constraints)
        {
            ReadOnlySpan<byte> coordinate = constraint.Coordinates.Memory.Span.Slice(constraint.Cursor * ScalarSize, ScalarSize);
            Span<byte> scale = constraint.Coefficient.Memory.Span[..ScalarSize];

            multiply(coordinate, challenge, factor, curve);
            add(factor, factor, factor, curve);
            subtract(factor, coordinate, factor, curve);
            subtract(factor, challenge, factor, curve);
            add(factor, one, factor, curve);
            multiply(scale, factor, scale, curve);
            constraint.Cursor++;
        }
    }


    /// <summary>
    /// Recomputes the coset leaf digest from the revealed values and
    /// authenticates it at the block index against the oracle's root.
    /// </summary>
    internal static bool AuthenticateOpening(
        WhirQueryOpening opening,
        MerkleRoot root,
        int blockIndex,
        MerkleHashDelegate merkleHash,
        Span<byte> digestScratch)
    {
        Span<byte> digest = stackalloc byte[ScalarSize];
        WhirCosetLeaf.ComputeLeafDigest(opening.BlockValues.Span, merkleHash, digest, digestScratch);

        return opening.Path.Verify(root, blockIndex, digest, merkleHash);
    }


    /// <summary>
    /// The closing check of the sumcheck chain: the remaining constraint
    /// suffix weight summed against the final polynomial over its cube must
    /// equal the running claim.
    /// </summary>
    private static bool FinalConstraintSumMatches(
        ReadOnlySpan<byte> finalCoefficients,
        int finalVariableCount,
        List<TrackedConstraint> constraints,
        ReadOnlySpan<byte> claim,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int size = 1 << finalVariableCount;
        using IMemoryOwner<byte> tablesOwner = pool.Rent(2 * size * ScalarSize);
        Span<byte> tables = tablesOwner.Memory.Span[..(2 * size * ScalarSize)];
        Span<byte> weightTable = tables[..(size * ScalarSize)];
        Span<byte> evaluationTable = tables.Slice(size * ScalarSize, size * ScalarSize);
        weightTable.Clear();

        foreach(TrackedConstraint constraint in constraints)
        {
            ReadOnlySpan<byte> suffix = constraint.Coordinates.Memory.Span.Slice(
                constraint.Cursor * ScalarSize,
                (constraint.CoordinateCount - constraint.Cursor) * ScalarSize);
            WhirMultilinear.AccumulateScaledEqTable(
                weightTable,
                suffix,
                constraint.Coefficient.Memory.Span[..ScalarSize],
                finalVariableCount,
                add,
                subtract,
                multiply,
                curve,
                pool);
        }

        finalCoefficients.CopyTo(evaluationTable);
        WhirMultilinear.CoefficientsToCubeEvaluations(evaluationTable, finalVariableCount, add, curve);

        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        sum.Clear();
        for(int index = 0; index < size; index++)
        {
            multiply(
                evaluationTable.Slice(index * ScalarSize, ScalarSize),
                weightTable.Slice(index * ScalarSize, ScalarSize),
                product,
                curve);
            add(sum, product, sum, curve);
        }

        return sum.SequenceEqual(claim);
    }


    /// <summary>
    /// Rents a working buffer, registers it for the uniform disposal pass,
    /// and returns its working span.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The buffer is tracked in the disposables list and released in the verifier's finally block.")]
    private static Span<byte> RentTracked(int byteLength, BaseMemoryPool pool, List<IDisposable> disposables)
    {
        IMemoryOwner<byte> owner = pool.Rent(byteLength);
        disposables.Add(owner);

        return owner.Memory.Span[..byteLength];
    }
}
