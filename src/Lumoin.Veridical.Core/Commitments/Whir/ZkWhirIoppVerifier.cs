using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The HVZK-WHIR verifier (eprint 2026/391 Construction 9.7): replays the
/// hiding transcript in the prover's order — per batch the joint claim, mask
/// oracle root, mask total and masked wires; per code-switch round the folded
/// oracle's root, the code-switch mask root, the private out-of-domain sample
/// and the shift queries; then the masked base case — and decides by the
/// base case's three checks: the source spot checks
/// <c>Enc(f*, r*)(z) = g(z) + γ·f(z)</c>, the mask spot checks
/// <c>Enc(ξ*_i, r*_i)(y) = s'_i(y) + γ·ξ_i(y)</c>, and the joint claim
/// <c>⟨f*, W⟩ + Σ_i ⟨ξ*_i, u_i⟩ = μ_g + γ·target</c>. A malformed proof is
/// reported as a non-match rather than an exception; only broken caller
/// inputs and the loud out-of-domain gate throw.
/// </summary>
/// <remarks>
/// The carried relation is tracked exactly as on the prover side but from
/// public data only: the source part as the symbolic constraint list
/// (coefficients rescaled by <c>ε</c> per batch, extended by the
/// <c>γ</c>-scaled out-of-domain and shift constraints), the mask part as the
/// dense covectors (carried ones rescaled by <c>ε·2^(-k)</c> per batch). The
/// running target needs no source/mask split — it is the joint claim
/// throughout, so every batch replays against it with a zero auxiliary.
/// </remarks>
public static class ZkWhirIoppVerifier
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Verifies an HVZK-WHIR proof of the statement
    /// <c>Σ_b f̂(b)·(Σ_c λ_c·eq(p_c, b)) = σ</c> against the input oracle's
    /// zero-knowledge commitment.
    /// </summary>
    /// <param name="parameters">The zero-knowledge parameter extension, derived independently from the same public figures the prover used.</param>
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
    /// <param name="invert">Scalar-invert backend, for the fold recomputation and the covector rescale factors.</param>
    /// <param name="pool">The pool to rent working buffers from.</param>
    /// <returns><see langword="true"/> iff every check passes.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a statement span does not match the schedule's shape.</exception>
    /// <exception cref="InvalidOperationException">When a squeezed private out-of-domain point is inadmissible — a probability-<c>1/|F|</c> transcript event both endpoints fail loudly on.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Every rented buffer and tracked constraint is registered in the disposables list and released in the finally block.")]
    public static bool Verify(
        WhirZkParameters parameters,
        MerkleRoot inputCommitment,
        ZkWhirIoppProof proof,
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
        ArgumentNullException.ThrowIfNull(parameters);
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

        WhirParameterSchedule schedule = parameters.Schedule;
        int variableCount = schedule.VariableCount;
        int foldingParameter = schedule.FoldingParameter;
        int iterationCount = schedule.IterationCount;
        CurveParameterSet curve = schedule.Curve;
        ValidateStatementShape(constraintCoefficients, constraintPoints, target, variableCount, out int constraintCount);

        List<(WhirMaskCodeShape Shape, int Width)> groupLayout = DeriveGroupLayout(parameters);
        if(!ProofShapeMatches(parameters, proof, groupLayout))
        {
            return false;
        }

        var encoder = WhirCosetEncoder.Create(add, subtract, multiply, curve, pool);
        var disposables = new List<IDisposable>();
        var constraints = new List<WhirIoppVerifier.TrackedConstraint>();
        var covectorOwners = new List<IMemoryOwner<byte>>();
        var covectorLengths = new List<int>();
        var carriedGroupRoots = new List<MerkleRoot>();

        try
        {
            transcript.AbsorbWhirStatement(target, constraintCoefficients, constraintPoints, hash);
            transcript.AbsorbWhirOracleRoot(inputCommitment, hash);

            for(int constraint = 0; constraint < constraintCount; constraint++)
            {
                constraints.Add(WhirIoppVerifier.TrackConstraint(
                    constraintCoefficients.Slice(constraint * ScalarSize, ScalarSize),
                    constraintPoints.Slice(constraint * variableCount * ScalarSize, variableCount * ScalarSize),
                    variableCount,
                    pool,
                    disposables));
            }

            //Working state: the running joint claim, the current batch's fold
            //challenges (feeding the next round's leaf folds), and the
            //single-element temporaries.
            Span<byte> claim = stackalloc byte[ScalarSize];
            target.CopyTo(claim);
            Span<byte> zero = stackalloc byte[ScalarSize];
            zero.Clear();
            Span<byte> epsilon = stackalloc byte[ScalarSize];
            Span<byte> residual = stackalloc byte[ScalarSize];
            Span<byte> term = stackalloc byte[ScalarSize];
            Span<byte> gammaPower = stackalloc byte[ScalarSize];
            Span<byte> queryRoot = stackalloc byte[ScalarSize];
            Span<byte> domainRoot = stackalloc byte[ScalarSize];
            Span<byte> strideRoot = stackalloc byte[ScalarSize];
            Span<byte> basePoint = stackalloc byte[ScalarSize];
            Span<byte> queryPoint = stackalloc byte[ScalarSize];
            Span<byte> foldedValue = stackalloc byte[ScalarSize];
            Span<byte> rescaleFactor = stackalloc byte[ScalarSize];
            Span<byte> half = stackalloc byte[ScalarSize];
            WriteCanonicalUInt(2, half);
            invert(half, half, curve);
            Span<byte> halfPowK = stackalloc byte[ScalarSize];
            WriteCanonicalUInt(1, halfPowK);
            for(int round = 0; round < foldingParameter; round++)
            {
                multiply(halfPowK, half, halfPowK, curve);
            }

            Span<byte> challengeBlock = RentTracked(foldingParameter * ScalarSize, pool, disposables);
            Span<byte> coordinates = RentTracked(variableCount * ScalarSize, pool, disposables);
            int maxRowWidth = 1 << foldingParameter;
            foreach((WhirMaskCodeShape _, int width) in groupLayout)
            {
                maxRowWidth = Math.Max(maxRowWidth, (int)BitOperations.RoundUpToPowerOf2((uint)width));
            }

            Span<byte> blockScratch = RentTracked(maxRowWidth * ScalarSize, pool, disposables);
            Span<byte> digestScratch = RentTracked(Math.Max(1, maxRowWidth / 2) * ScalarSize, pool, disposables);
            encoder.DeriveDomainRoot(foldingParameter, strideRoot);

            int currentVariableCount = variableCount;
            int wireIndex = 0;
            for(int iteration = 0; iteration < iterationCount; iteration++)
            {
                if(iteration > 0)
                {
                    transcript.AbsorbWhirOracleRoot(proof.OracleRoots[iteration - 1], hash);
                    transcript.AbsorbWhirCodeSwitchMaskRoot(proof.CodeSwitchMaskRoots[iteration - 1], hash);
                    carriedGroupRoots.Add(proof.CodeSwitchMaskRoots[iteration - 1]);

                    int previousRandomnessCount = parameters.OracleRandomnessCounts[iteration - 1];
                    WhirMaskCodeShape switchShape = parameters.SwitchMaskShapes[iteration - 1];
                    int currentSize = 1 << currentVariableCount;

                    //Private out-of-domain sample: the reply is absorbed as
                    //sent; its consistency is enforced through the batched
                    //relation the base case settles.
                    using Scalar outOfDomainPoint = transcript.SqueezeWhirPrivateOutOfDomainPoint(squeeze, hash, reduce, curve, pool);
                    ZkWhirCodeSwitch.ThrowIfOutOfDomainPointsInadmissible(
                        outOfDomainPoint.AsReadOnlySpan(),
                        WhirZkParameters.OutOfDomainSamplesPerIteration);
                    Scalar reply = proof.PrivateOutOfDomainReplies[iteration - 1];
                    transcript.AbsorbWhirPrivateOutOfDomainReply(reply.AsReadOnlySpan(), hash);

                    //Shift queries against the previous oracle.
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
                    //oracle's root, recompute the fold at the last batch's
                    //challenges, and batch the fresh values into the claim.
                    MerkleRoot previousRoot = iteration - 1 == 0 ? inputCommitment : proof.OracleRoots[iteration - 2];
                    IReadOnlyList<WhirQueryOpening> shiftOpenings = proof.OpeningsForOracle(iteration - 1);
                    encoder.DeriveDomainRoot(previous.DomainSizeLog2, domainRoot);
                    encoder.DeriveDomainRoot(queryDomainLog2, queryRoot);

                    multiply(gamma.AsReadOnlySpan(), reply.AsReadOnlySpan(), term, curve);
                    add(claim, term, claim, curve);
                    gamma.AsReadOnlySpan().CopyTo(gammaPower);

                    Span<byte> pointCoordinates = coordinates[..(currentVariableCount * ScalarSize)];
                    WhirMultilinear.ExpandPowPoint(outOfDomainPoint.AsReadOnlySpan(), currentVariableCount, pointCoordinates, multiply, curve);
                    constraints.Add(WhirIoppVerifier.TrackConstraint(gammaPower, pointCoordinates, currentVariableCount, pool, disposables));

                    Span<byte> queryPoints = RentTracked(indices.Length * ScalarSize, pool, disposables);
                    Span<byte> queryCoefficients = RentTracked(indices.Length * ScalarSize, pool, disposables);
                    for(int query = 0; query < indices.Length; query++)
                    {
                        WhirQueryOpening opening = shiftOpenings[query];
                        if(!WhirIoppVerifier.AuthenticateOpening(opening, previousRoot, indices[query], merkleHash, digestScratch))
                        {
                            return false;
                        }

                        Span<byte> block = blockScratch[..((1 << foldingParameter) * ScalarSize)];
                        opening.BlockValues.Span.CopyTo(block);
                        WhirFold.ComputeDomainPoint(domainRoot, indices[query], basePoint, multiply, curve);
                        WhirFold.FoldCosetBlock(
                            block,
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

                        WhirFold.ComputeDomainPoint(queryRoot, indices[query], queryPoint, multiply, curve);
                        queryPoint.CopyTo(queryPoints.Slice(query * ScalarSize, ScalarSize));
                        gammaPower.CopyTo(queryCoefficients.Slice(query * ScalarSize, ScalarSize));
                        WhirMultilinear.ExpandPowPoint(queryPoint, currentVariableCount, pointCoordinates, multiply, curve);
                        constraints.Add(WhirIoppVerifier.TrackConstraint(gammaPower, pointCoordinates, currentVariableCount, pool, disposables));
                    }

                    //The switch-mask covector joins the carried relation at
                    //scale one.
                    IMemoryOwner<byte> covectorOwner = pool.Rent(switchShape.MessageLength * ScalarSize);
                    disposables.Add(covectorOwner);
                    ZkWhirCodeSwitch.WriteSwitchMaskCovector(
                        currentSize,
                        previousRandomnessCount,
                        WhirZkParameters.OutOfDomainSamplesPerIteration,
                        outOfDomainPoint.AsReadOnlySpan(),
                        gamma.AsReadOnlySpan(),
                        queryPoints,
                        queryCoefficients,
                        covectorOwner.Memory.Span[..(switchShape.MessageLength * ScalarSize)],
                        add,
                        multiply,
                        curve);
                    covectorOwners.Add(covectorOwner);
                    covectorLengths.Add(switchShape.MessageLength);
                }

                //Replay the iteration's masked sumcheck batch against the
                //running joint claim; the auxiliary is zero because the claim
                //is already joint.
                var wires = new CompressedRoundPolynomial[foldingParameter];
                for(int round = 0; round < foldingParameter; round++)
                {
                    wires[round] = proof.BatchWirePolynomials[wireIndex++];
                }

                ZkWhirMaskedSumcheckVerifier.ReplayBatch(
                    wires,
                    proof.SumcheckMaskRoots[iteration],
                    proof.MaskTotals[iteration].AsReadOnlySpan(),
                    claim,
                    zero,
                    parameters.MaskMessageLength,
                    transcript,
                    hash,
                    squeeze,
                    reduce,
                    add,
                    subtract,
                    multiply,
                    curve,
                    pool,
                    epsilon,
                    challengeBlock,
                    residual);
                residual.CopyTo(claim);
                carriedGroupRoots.Add(proof.SumcheckMaskRoots[iteration]);

                //Source constraints fold and absorb ε; carried covectors and
                //their claims absorb ε·2^(-k); the batch's fresh mask
                //covectors enter at scale one.
                for(int round = 0; round < foldingParameter; round++)
                {
                    WhirIoppVerifier.FoldConstraints(constraints, challengeBlock.Slice(round * ScalarSize, ScalarSize), add, subtract, multiply, curve);
                }

                foreach(WhirIoppVerifier.TrackedConstraint constraint in constraints)
                {
                    Span<byte> scale = constraint.Coefficient.Memory.Span[..ScalarSize];
                    multiply(scale, epsilon, scale, curve);
                }

                multiply(epsilon, halfPowK, rescaleFactor, curve);
                RescaleCovectors(covectorOwners, covectorLengths, rescaleFactor, multiply, curve);
                for(int mask = 0; mask < foldingParameter; mask++)
                {
                    IMemoryOwner<byte> maskCovectorOwner = pool.Rent(parameters.MaskMessageLength * ScalarSize);
                    disposables.Add(maskCovectorOwner);
                    ZkWhirMaskedSumcheckVerifier.WriteMaskResidualCovector(
                        challengeBlock.Slice(mask * ScalarSize, ScalarSize),
                        parameters.MaskMessageLength,
                        maskCovectorOwner.Memory.Span[..(parameters.MaskMessageLength * ScalarSize)],
                        multiply,
                        curve);
                    covectorOwners.Add(maskCovectorOwner);
                    covectorLengths.Add(parameters.MaskMessageLength);
                }

                currentVariableCount -= foldingParameter;
            }

            //Masked base case (Construction 7.2).
            int finalVariableCount = currentVariableCount;
            int finalMessageLength = 1 << finalVariableCount;
            WhirRoundParameters last = schedule.Rounds[iterationCount - 1];
            int finalQueryDomainLog2 = last.DomainSizeLog2 - foldingParameter;

            transcript.AbsorbWhirBaseCaseFreshRoot(proof.BaseCaseFreshRoot, hash);
            for(int group = 0; group < groupLayout.Count; group++)
            {
                transcript.AbsorbWhirBaseCaseMaskRoot(proof.BaseCaseMaskRoots[group], hash);
            }

            transcript.AbsorbWhirBaseCaseClaim(proof.BaseCaseMaskedClaim.AsReadOnlySpan(), hash);
            using Scalar baseGamma = transcript.SqueezeWhirBaseCaseCombinationChallenge(squeeze, hash, reduce, curve, pool);

            ReadOnlySpan<byte> blindedSourceMessage = proof.BlindedSourceMessage;
            ReadOnlySpan<byte> blindedSourceRandomness = proof.BlindedSourceRandomness;
            transcript.AbsorbWhirBaseCaseReveal(blindedSourceMessage, blindedSourceRandomness, hash);
            ReadOnlySpan<byte> blindedMaskReveals = proof.BlindedMaskReveals;
            int revealOffset = 0;
            for(int group = 0; group < groupLayout.Count; group++)
            {
                (WhirMaskCodeShape shape, int width) = groupLayout[group];
                for(int member = 0; member < width; member++)
                {
                    transcript.AbsorbWhirBaseCaseMaskReveal(
                        blindedMaskReveals.Slice(revealOffset, shape.MessageLength * ScalarSize),
                        blindedMaskReveals.Slice(revealOffset + (shape.MessageLength * ScalarSize), shape.RandomnessLength * ScalarSize),
                        hash);
                    revealOffset += (shape.MessageLength + shape.RandomnessLength) * ScalarSize;
                }
            }

            //Source spot checks: Enc(f*, r*)(z) = g(z) + γ·f(z) at the
            //squeezed positions, f(z) recomputed from the last oracle's
            //authenticated coset blocks.
            MerkleRoot lastRoot = iterationCount == 1 ? inputCommitment : proof.OracleRoots[iterationCount - 2];
            IReadOnlyList<WhirQueryOpening> sourceOpenings = proof.OpeningsForOracle(iterationCount - 1);
            encoder.DeriveDomainRoot(last.DomainSizeLog2, domainRoot);
            encoder.DeriveDomainRoot(finalQueryDomainLog2, queryRoot);
            Span<byte> expected = stackalloc byte[ScalarSize];
            for(int query = 0; query < last.QueryCount; query++)
            {
                int index = transcript.SqueezeWhirQueryIndex(
                    WellKnownWhirTranscriptLabels.FinalQueryIndex,
                    1 << finalQueryDomainLog2,
                    squeeze,
                    hash);

                WhirQueryOpening sourceOpening = sourceOpenings[query];
                if(!WhirIoppVerifier.AuthenticateOpening(sourceOpening, lastRoot, index, merkleHash, digestScratch))
                {
                    return false;
                }

                WhirQueryOpening freshOpening = proof.BaseCaseFreshOpenings[query];
                if(!WhirIoppVerifier.AuthenticateOpening(freshOpening, proof.BaseCaseFreshRoot, index, merkleHash, digestScratch))
                {
                    return false;
                }

                Span<byte> block = blockScratch[..((1 << foldingParameter) * ScalarSize)];
                sourceOpening.BlockValues.Span.CopyTo(block);
                WhirFold.ComputeDomainPoint(domainRoot, index, basePoint, multiply, curve);
                WhirFold.FoldCosetBlock(
                    block,
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

                //Enc(f*, r*)(z) by the zero-evader form on the concatenated
                //blinded coefficients at the position's domain point.
                WhirFold.ComputeDomainPoint(queryRoot, index, queryPoint, multiply, curve);
                ZkWhirCodeSwitch.EvaluatePaddedOutOfDomain(
                    queryPoint,
                    blindedSourceMessage,
                    blindedSourceRandomness,
                    expected,
                    add,
                    multiply,
                    curve);

                multiply(baseGamma.AsReadOnlySpan(), foldedValue, term, curve);
                add(term, freshOpening.BlockValues.Span[..ScalarSize], term, curve);
                if(!expected.SequenceEqual(term))
                {
                    return false;
                }
            }

            //Mask spot checks per group: Enc(ξ*_i, r*_i)(y) = s'_i(y) + γ·ξ_i(y)
            //at t_zk shared positions, one Merkle path per oracle serving
            //every member.
            revealOffset = 0;
            for(int group = 0; group < groupLayout.Count; group++)
            {
                (WhirMaskCodeShape shape, int width) = groupLayout[group];
                (IReadOnlyList<WhirQueryOpening> carried, IReadOnlyList<WhirQueryOpening> fresh) = proof.OpeningsForMaskGroup(group);
                encoder.DeriveDomainRoot(shape.DomainSizeLog2, domainRoot);
                for(int query = 0; query < parameters.MaskQueryCount; query++)
                {
                    int index = transcript.SqueezeWhirQueryIndex(
                        WellKnownWhirTranscriptLabels.MaskQueryIndex,
                        shape.DomainSize,
                        squeeze,
                        hash);

                    WhirQueryOpening carriedOpening = carried[query];
                    if(!WhirIoppVerifier.AuthenticateOpening(carriedOpening, carriedGroupRoots[group], index, merkleHash, digestScratch))
                    {
                        return false;
                    }

                    WhirQueryOpening freshOpening = fresh[query];
                    if(!WhirIoppVerifier.AuthenticateOpening(freshOpening, proof.BaseCaseMaskRoots[group], index, merkleHash, digestScratch))
                    {
                        return false;
                    }

                    WhirFold.ComputeDomainPoint(domainRoot, index, queryPoint, multiply, curve);
                    int memberOffset = revealOffset;
                    for(int member = 0; member < width; member++)
                    {
                        ZkWhirCodeSwitch.EvaluatePaddedOutOfDomain(
                            queryPoint,
                            blindedMaskReveals.Slice(memberOffset, shape.MessageLength * ScalarSize),
                            blindedMaskReveals.Slice(memberOffset + (shape.MessageLength * ScalarSize), shape.RandomnessLength * ScalarSize),
                            expected,
                            add,
                            multiply,
                            curve);
                        memberOffset += (shape.MessageLength + shape.RandomnessLength) * ScalarSize;

                        multiply(baseGamma.AsReadOnlySpan(), carriedOpening.BlockValues.Span.Slice(member * ScalarSize, ScalarSize), term, curve);
                        add(term, freshOpening.BlockValues.Span.Slice(member * ScalarSize, ScalarSize), term, curve);
                        if(!expected.SequenceEqual(term))
                        {
                            return false;
                        }
                    }
                }

                revealOffset += width * (shape.MessageLength + shape.RandomnessLength) * ScalarSize;
            }

            //Joint claim: ⟨f*, W⟩ + Σ_i ⟨ξ*_i, u_i⟩ = μ_g + γ·target, the
            //relation evaluated on the blinded reveals against the carried
            //weight and covectors.
            return JointClaimMatches(
                proof,
                groupLayout,
                constraints,
                covectorOwners,
                covectorLengths,
                finalVariableCount,
                claim,
                baseGamma.AsReadOnlySpan(),
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
    /// The chronological mask-group layout both endpoints derive from the
    /// parameters: the initial batch's sumcheck group, then per code-switch
    /// round the width-one switch group and the following batch's sumcheck
    /// group — <c>2M − 1</c> groups. Shared with the wire codec, whose
    /// opening sections it sizes.
    /// </summary>
    internal static List<(WhirMaskCodeShape Shape, int Width)> DeriveGroupLayout(WhirZkParameters parameters)
    {
        int iterationCount = parameters.Schedule.IterationCount;
        int foldingParameter = parameters.Schedule.FoldingParameter;
        var layout = new List<(WhirMaskCodeShape, int)>
        {
            (parameters.SumcheckMaskShape, foldingParameter)
        };
        for(int iteration = 1; iteration < iterationCount; iteration++)
        {
            layout.Add((parameters.SwitchMaskShapes[iteration - 1], 1));
            layout.Add((parameters.SumcheckMaskShape, foldingParameter));
        }

        return layout;
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
    /// Structural checks: every proof dimension must equal the figure derived
    /// from the parameters. A mismatch is a malformed proof, reported as a
    /// non-match.
    /// </summary>
    private static bool ProofShapeMatches(
        WhirZkParameters parameters,
        ZkWhirIoppProof proof,
        List<(WhirMaskCodeShape Shape, int Width)> groupLayout)
    {
        WhirParameterSchedule schedule = parameters.Schedule;
        int iterationCount = schedule.IterationCount;
        int foldingParameter = schedule.FoldingParameter;
        int expectedWireDegree = Math.Max(parameters.MaskMessageLength - 1, 2);
        int blockBytes = (1 << foldingParameter) * ScalarSize;

        if(proof.BatchWirePolynomials.Count != iterationCount * foldingParameter
            || proof.SumcheckMaskRoots.Count != iterationCount
            || proof.MaskTotals.Count != iterationCount
            || proof.OracleRoots.Count != iterationCount - 1
            || proof.CodeSwitchMaskRoots.Count != iterationCount - 1
            || proof.PrivateOutOfDomainReplies.Count != iterationCount - 1
            || proof.MaskGroupCount != groupLayout.Count
            || proof.BaseCaseMaskRoots.Count != groupLayout.Count)
        {
            return false;
        }

        foreach(CompressedRoundPolynomial wire in proof.BatchWirePolynomials)
        {
            if(wire.Degree != expectedWireDegree || wire.Curve.Code != schedule.Curve.Code)
            {
                return false;
            }
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

        int finalMessageLength = 1 << schedule.FinalVariableCount;
        int lastRandomnessCount = parameters.OracleRandomnessCounts[iterationCount - 1];
        if(proof.BlindedSourceMessage.Length != finalMessageLength * ScalarSize
            || proof.BlindedSourceRandomness.Length != lastRandomnessCount * ScalarSize)
        {
            return false;
        }

        int revealBytes = 0;
        foreach((WhirMaskCodeShape shape, int width) in groupLayout)
        {
            revealBytes += width * (shape.MessageLength + shape.RandomnessLength) * ScalarSize;
        }

        if(proof.BlindedMaskReveals.Length != revealBytes)
        {
            return false;
        }

        if(proof.BaseCaseFreshOpenings.Count != schedule.Rounds[iterationCount - 1].QueryCount)
        {
            return false;
        }

        foreach(WhirQueryOpening opening in proof.BaseCaseFreshOpenings)
        {
            if(opening.BlockValues.Length != ScalarSize)
            {
                return false;
            }
        }

        for(int group = 0; group < groupLayout.Count; group++)
        {
            int rowBytes = (int)BitOperations.RoundUpToPowerOf2((uint)groupLayout[group].Width) * ScalarSize;
            (IReadOnlyList<WhirQueryOpening> carried, IReadOnlyList<WhirQueryOpening> fresh) = proof.OpeningsForMaskGroup(group);
            if(carried.Count != parameters.MaskQueryCount || fresh.Count != parameters.MaskQueryCount)
            {
                return false;
            }

            foreach(WhirQueryOpening opening in carried)
            {
                if(opening.BlockValues.Length != rowBytes)
                {
                    return false;
                }
            }

            foreach(WhirQueryOpening opening in fresh)
            {
                if(opening.BlockValues.Length != rowBytes)
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>
    /// The closing check: the blinded source reveal against the materialized
    /// constraint weight plus the blinded mask reveals against the carried
    /// covectors must equal <c>μ_g + γ·target</c>.
    /// </summary>
    private static bool JointClaimMatches(
        ZkWhirIoppProof proof,
        List<(WhirMaskCodeShape Shape, int Width)> groupLayout,
        List<WhirIoppVerifier.TrackedConstraint> constraints,
        List<IMemoryOwner<byte>> covectorOwners,
        List<int> covectorLengths,
        int finalVariableCount,
        ReadOnlySpan<byte> claim,
        ReadOnlySpan<byte> gamma,
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

        foreach(WhirIoppVerifier.TrackedConstraint constraint in constraints)
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

        proof.BlindedSourceMessage.CopyTo(evaluationTable);
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

        ReadOnlySpan<byte> blindedMaskReveals = proof.BlindedMaskReveals;
        Span<byte> dot = stackalloc byte[ScalarSize];
        int revealOffset = 0;
        int covectorIndex = 0;
        for(int group = 0; group < groupLayout.Count; group++)
        {
            (WhirMaskCodeShape shape, int width) = groupLayout[group];
            for(int member = 0; member < width; member++)
            {
                ReadOnlySpan<byte> covector = covectorOwners[covectorIndex].Memory.Span[..(covectorLengths[covectorIndex] * ScalarSize)];
                ReadOnlySpan<byte> blindedMessage = blindedMaskReveals.Slice(revealOffset, shape.MessageLength * ScalarSize);
                dot.Clear();
                for(int element = 0; element < covectorLengths[covectorIndex]; element++)
                {
                    multiply(
                        blindedMessage.Slice(element * ScalarSize, ScalarSize),
                        covector.Slice(element * ScalarSize, ScalarSize),
                        product,
                        curve);
                    add(dot, product, dot, curve);
                }

                add(sum, dot, sum, curve);
                revealOffset += (shape.MessageLength + shape.RandomnessLength) * ScalarSize;
                covectorIndex++;
            }
        }

        //μ_g + γ·target.
        Span<byte> expected = stackalloc byte[ScalarSize];
        multiply(gamma, claim, expected, curve);
        add(expected, proof.BaseCaseMaskedClaim.AsReadOnlySpan(), expected, curve);

        return sum.SequenceEqual(expected);
    }


    /// <summary>
    /// Multiplies every element of every stored covector by the batch's
    /// rescale factor <c>ε·2^(-k)</c>.
    /// </summary>
    private static void RescaleCovectors(
        List<IMemoryOwner<byte>> covectorOwners,
        List<int> covectorLengths,
        ReadOnlySpan<byte> factor,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        for(int covector = 0; covector < covectorOwners.Count; covector++)
        {
            Span<byte> elements = covectorOwners[covector].Memory.Span[..(covectorLengths[covector] * ScalarSize)];
            for(int offset = 0; offset < elements.Length; offset += ScalarSize)
            {
                Span<byte> element = elements.Slice(offset, ScalarSize);
                multiply(element, factor, element, curve);
            }
        }
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


    /// <summary>
    /// Writes a small integer as a canonical big-endian field element.
    /// </summary>
    private static void WriteCanonicalUInt(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }
}
