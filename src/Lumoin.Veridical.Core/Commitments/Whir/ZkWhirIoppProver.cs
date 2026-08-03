using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The HVZK-WHIR prover (eprint 2026/391 Construction 9.7 on our
/// Construction 5.1 shape): proves the weighted-sum statement
/// <c>Σ_b f̂(b)·(Σ_c λ_c·eq(p_c, b)) = σ</c> without revealing anything about
/// the committed polynomial beyond it. Every oracle is a zero-knowledge
/// encoding <c>Encode(message ‖ randomness)</c> over the unchanged domain,
/// every fold batch runs the masked sumcheck of Construction 6.3, every
/// iteration commits a fresh code-switch mask and answers its out-of-domain
/// sample privately through the zero-evader form, and the cleartext final
/// polynomial is replaced by the masked base case of Construction 7.2.
/// </summary>
/// <remarks>
/// <para>
/// The carried relation is tracked in two parts kept in step with the
/// transcript: the source part as the working weight table (rescaled by
/// <c>ε</c> after every batch, extended by the <c>γ</c>-scaled out-of-domain
/// and shift constraints each iteration adds) and the mask part as a list of
/// dense covectors over the committed mask messages (the carried ones
/// rescaled by <c>ε·2^(-k)</c> per batch, fresh ones entering at scale one),
/// whose running total rides each batch as its auxiliary constant.
/// </para>
/// <para>
/// The non-hiding prover, verifier and their transcript schedule are
/// untouched: this sibling type adds the hiding path beside them, and its
/// t = 0 shapes degenerate byte-for-byte to the plain encodings.
/// </para>
/// </remarks>
public static class ZkWhirIoppProver
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Produces an HVZK-WHIR proof for the statement
    /// <c>Σ_b f̂(b)·(Σ_c λ_c·eq(p_c, b)) = σ</c> over the polynomial with the
    /// given coefficient vector.
    /// </summary>
    /// <param name="parameters">The zero-knowledge parameter extension both endpoints derive from the same public figures.</param>
    /// <param name="coefficients">The multilinear coefficient vector, <c>2^m</c> elements for the schedule's variable count <c>m</c>.</param>
    /// <param name="constraintCoefficients">The constraint scales <c>λ_c</c>, one element per constraint; may be empty for plain proximity.</param>
    /// <param name="constraintPoints">The constraint points <c>p_c</c>, <c>m</c> elements per constraint, first variable first.</param>
    /// <param name="target">The claimed sum <c>σ</c>, one element.</param>
    /// <param name="transcript">The Fiat-Shamir transcript, already initialised with the protocol's public context.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for deriving challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend, for the auxiliary carry and covector rescale factors.</param>
    /// <param name="maskRandom">The entropy-sourced sampler behind every hiding ingredient: encoding randomness, masks, pads and blinds.</param>
    /// <param name="pool">The pool to rent working and proof buffers from.</param>
    /// <returns>The proof and the input oracle's Merkle root — the public commitment the verifier needs; the caller owns both.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the schedule's shape, or the statement does not hold for the coefficients.</exception>
    /// <exception cref="InvalidOperationException">When a squeezed private out-of-domain point is inadmissible — a probability-<c>1/|F|</c> transcript event that must fail loudly rather than leak.</exception>
    public static (ZkWhirIoppProof Proof, MerkleRoot InputCommitment) Prove(
        WhirZkParameters parameters,
        ReadOnlySpan<byte> coefficients,
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
        ScalarRandomDelegate maskRandom,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(maskRandom);
        ArgumentNullException.ThrowIfNull(pool);

        //Every argument is validated before the sampler is touched, so an
        //invalid call never advances a stateful sampler. Sampling the input
        //oracle's randomness first then preserves the draw order of the
        //single-call path, so both entry points produce identical
        //transcripts from the same sampler state.
        int inputRandomnessBytes = parameters.OracleRandomnessElementCount(0) * ScalarSize;
        using IMemoryOwner<byte> inputRandomnessOwner = pool.Rent(inputRandomnessBytes);
        Span<byte> inputRandomness = inputRandomnessOwner.Memory.Span[..inputRandomnessBytes];
        FillWithScalars(inputRandomness, maskRandom, parameters.Schedule.Curve);

        return Prove(
            parameters,
            coefficients,
            inputRandomness,
            constraintCoefficients,
            constraintPoints,
            target,
            transcript,
            merkleHash,
            hash,
            squeeze,
            reduce,
            add,
            subtract,
            multiply,
            invert,
            maskRandom,
            pool);
    }


    /// <summary>
    /// Produces an HVZK-WHIR proof as the sampling overload does, with the
    /// input oracle's encoding randomness supplied by the caller instead of
    /// drawn from the sampler. This is the commit-then-open seam: a
    /// polynomial-commitment provider samples the randomness at commit time,
    /// computes the public commitment with
    /// <see cref="ComputeInputCommitment"/>, carries the randomness as the
    /// commitment's blind, and re-supplies it here so the proof's input
    /// oracle is the committed one.
    /// </summary>
    /// <param name="parameters">The zero-knowledge parameter extension both endpoints derive from the same public figures.</param>
    /// <param name="coefficients">The multilinear coefficient vector, <c>2^m</c> elements for the schedule's variable count <c>m</c>.</param>
    /// <param name="inputRandomness">The input oracle's encoding randomness, <c>t_0·2^k</c> canonical elements the caller sampled at commit time.</param>
    /// <param name="constraintCoefficients">The constraint scales <c>λ_c</c>, one element per constraint; may be empty for plain proximity.</param>
    /// <param name="constraintPoints">The constraint points <c>p_c</c>, <c>m</c> elements per constraint, first variable first.</param>
    /// <param name="target">The claimed sum <c>σ</c>, one element.</param>
    /// <param name="transcript">The Fiat-Shamir transcript, already initialised with the protocol's public context.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for deriving challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend, for the auxiliary carry and covector rescale factors.</param>
    /// <param name="maskRandom">The entropy-sourced sampler behind every remaining hiding ingredient: later oracles' encoding randomness, masks, pads and blinds.</param>
    /// <param name="pool">The pool to rent working and proof buffers from.</param>
    /// <returns>The proof and the input oracle's Merkle root — the public commitment the verifier needs; the caller owns both.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the schedule's shape, or the statement does not hold for the coefficients.</exception>
    /// <exception cref="InvalidOperationException">When a squeezed private out-of-domain point is inadmissible — a probability-<c>1/|F|</c> transcript event that must fail loudly rather than leak.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Working buffers, trees and mask groups are disposed in the finally block; the parts the proof keeps transfer ownership to the returned proof, and on a failed run the partial parts are disposed before rethrowing.")]
    public static (ZkWhirIoppProof Proof, MerkleRoot InputCommitment) Prove(
        WhirZkParameters parameters,
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> inputRandomness,
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
        ScalarRandomDelegate maskRandom,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(maskRandom);
        ArgumentNullException.ThrowIfNull(pool);

        if(inputRandomness.Length != parameters.OracleRandomnessElementCount(0) * ScalarSize)
        {
            throw new ArgumentException(
                $"The input oracle's encoding randomness must be {parameters.OracleRandomnessElementCount(0) * ScalarSize} bytes; received {inputRandomness.Length}.",
                nameof(inputRandomness));
        }

        WhirParameterSchedule schedule = parameters.Schedule;
        int variableCount = schedule.VariableCount;
        int foldingParameter = schedule.FoldingParameter;
        int iterationCount = schedule.IterationCount;
        CurveParameterSet curve = schedule.Curve;
        int messageLength = 1 << variableCount;
        ValidateStatementShape(coefficients, constraintCoefficients, constraintPoints, target, variableCount, messageLength, out int constraintCount);

        var encoder = WhirCosetEncoder.Create(add, subtract, multiply, curve, pool);
        var disposables = new List<IDisposable>();

        //Chronological mask state: the committed groups, one dense covector
        //per member at its accumulated scale, and the running mask-claim
        //total riding each batch as its auxiliary constant.
        var groups = new List<ZkWhirMaskGroup>();
        var covectorOwners = new List<IMemoryOwner<byte>>();
        var covectorLengths = new List<int>();

        //Proof part accumulators.
        var batchWires = new CompressedRoundPolynomial?[iterationCount * foldingParameter];
        var sumcheckMaskRoots = new MerkleRoot?[iterationCount];
        var maskTotals = new Scalar?[iterationCount];
        var oracleRoots = new MerkleRoot?[Math.Max(0, iterationCount - 1)];
        var codeSwitchMaskRoots = new MerkleRoot?[Math.Max(0, iterationCount - 1)];
        var outOfDomainReplies = new Scalar?[Math.Max(0, iterationCount - 1)];
        WhirQueryOpening[]?[] openings = new WhirQueryOpening[iterationCount][];
        MerkleRoot? baseCaseFreshRoot = null;
        MerkleRoot?[] baseCaseMaskRoots = [];
        Scalar? baseCaseMaskedClaim = null;
        WhirQueryOpening[]? baseCaseFreshOpenings = null;
        WhirQueryOpening[]?[] baseCaseCarriedMaskOpenings = [];
        WhirQueryOpening[]?[] baseCaseFreshMaskOpenings = [];
        IMemoryOwner<byte>? blindedRevealsOwner = null;
        MerkleRoot? inputCommitment = null;
        bool assembled = false;

        var leavesOwners = new IMemoryOwner<byte>?[iterationCount];
        var trees = new MerkleTree?[iterationCount];

        try
        {
            transcript.AbsorbWhirStatement(target, constraintCoefficients, constraintPoints, hash);

            //The extended working coefficients: the message followed by the
            //oracle's appended encoding randomness, folded together so the
            //folded randomness is in place when the next code-switch reads it.
            int extendedCapacity = 0;
            for(int i = 0; i < iterationCount; i++)
            {
                extendedCapacity = Math.Max(
                    extendedCapacity,
                    (1 << schedule.Rounds[i].VariableCount) + parameters.OracleRandomnessElementCount(i));
            }

            Span<byte> working = RentTracked(extendedCapacity * ScalarSize, pool, disposables);
            coefficients.CopyTo(working);
            int currentMessageLength = messageLength;
            int currentRandomnessLength = parameters.OracleRandomnessElementCount(0);
            inputRandomness.CopyTo(working.Slice(currentMessageLength * ScalarSize, currentRandomnessLength * ScalarSize));

            Span<byte> functionTable = RentTracked(messageLength * ScalarSize, pool, disposables);
            coefficients.CopyTo(functionTable);
            WhirMultilinear.CoefficientsToCubeEvaluations(functionTable, variableCount, add, curve);

            Span<byte> weightTable = RentTracked(messageLength * ScalarSize, pool, disposables);
            weightTable.Clear();
            for(int constraint = 0; constraint < constraintCount; constraint++)
            {
                WhirMultilinear.AccumulateScaledEqTable(
                    weightTable,
                    constraintPoints.Slice(constraint * variableCount * ScalarSize, variableCount * ScalarSize),
                    constraintCoefficients.Slice(constraint * ScalarSize, ScalarSize),
                    variableCount,
                    add,
                    subtract,
                    multiply,
                    curve,
                    pool);
            }

            ThrowIfStatementDoesNotHold(functionTable, weightTable, messageLength, target, add, multiply, curve);

            CommitZkOracle(
                0,
                working[..((currentMessageLength + currentRandomnessLength) * ScalarSize)],
                currentMessageLength,
                schedule,
                encoder,
                merkleHash,
                leavesOwners,
                trees,
                pool,
                disposables);
            transcript.AbsorbWhirOracleRoot(trees[0]!.Root, hash);

            //Per-iteration scratch and single-element temporaries.
            Span<byte> coordinates = RentTracked(variableCount * ScalarSize, pool, disposables);
            Span<byte> sourceClaim = stackalloc byte[ScalarSize];
            Span<byte> aux = stackalloc byte[ScalarSize];
            aux.Clear();
            Span<byte> epsilon = stackalloc byte[ScalarSize];
            Span<byte> term = stackalloc byte[ScalarSize];
            Span<byte> value = stackalloc byte[ScalarSize];
            Span<byte> gammaPower = stackalloc byte[ScalarSize];
            Span<byte> queryRoot = stackalloc byte[ScalarSize];
            Span<byte> queryPoint = stackalloc byte[ScalarSize];
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
            target.CopyTo(sourceClaim);

            int currentVariableCount = variableCount;
            for(int iteration = 0; iteration < iterationCount; iteration++)
            {
                if(iteration > 0)
                {
                    int previousRandomnessCount = parameters.OracleRandomnessCounts[iteration - 1];
                    WhirMaskCodeShape switchShape = parameters.SwitchMaskShapes[iteration - 1];
                    int currentSize = 1 << currentVariableCount;

                    //The switch mask message: the previous oracle's folded
                    //randomness followed by the fresh out-of-domain pad. The
                    //folded randomness is copied out before the working tail
                    //is refilled for the next oracle's commitment.
                    Span<byte> switchMessage = RentTracked(switchShape.MessageLength * ScalarSize, pool, disposables);
                    working.Slice(currentSize * ScalarSize, previousRandomnessCount * ScalarSize)
                        .CopyTo(switchMessage);
                    FillWithScalars(
                        switchMessage[(previousRandomnessCount * ScalarSize)..],
                        maskRandom,
                        curve);

                    //Commit the next oracle: the folded message with fresh
                    //encoding randomness on the iteration's scheduled domain.
                    currentRandomnessLength = parameters.OracleRandomnessElementCount(iteration);
                    FillWithScalars(
                        working.Slice(currentSize * ScalarSize, currentRandomnessLength * ScalarSize),
                        maskRandom,
                        curve);
                    CommitZkOracle(
                        iteration,
                        working[..((currentSize + currentRandomnessLength) * ScalarSize)],
                        currentSize,
                        schedule,
                        encoder,
                        merkleHash,
                        leavesOwners,
                        trees,
                        pool,
                        disposables);
                    transcript.AbsorbWhirOracleRoot(trees[iteration]!.Root, hash);
                    oracleRoots[iteration - 1] = MerkleRoot.FromBytes(trees[iteration]!.Root.AsReadOnlySpan(), pool);

                    //Commit the code-switch mask as its own width-one group.
                    ZkWhirMaskGroup switchGroup = ZkWhirMaskGroup.CreateFromMessages(
                        switchShape,
                        1,
                        switchMessage,
                        encoder,
                        merkleHash,
                        maskRandom,
                        curve,
                        pool);
                    disposables.Add(switchGroup);
                    transcript.AbsorbWhirCodeSwitchMaskRoot(switchGroup.Tree.Root, hash);
                    codeSwitchMaskRoots[iteration - 1] = MerkleRoot.FromBytes(switchGroup.Tree.Root.AsReadOnlySpan(), pool);

                    //Private out-of-domain sample: the reply evaluates
                    //(message ‖ randomness ‖ pad) at ρ; the fresh pad makes
                    //it uniform (the zero-evader of Lemma 9.3).
                    using Scalar outOfDomainPoint = transcript.SqueezeWhirPrivateOutOfDomainPoint(squeeze, hash, reduce, curve, pool);
                    ZkWhirCodeSwitch.ThrowIfOutOfDomainPointsInadmissible(
                        outOfDomainPoint.AsReadOnlySpan(),
                        WhirZkParameters.OutOfDomainSamplesPerIteration);
                    ZkWhirCodeSwitch.EvaluatePaddedOutOfDomain(
                        outOfDomainPoint.AsReadOnlySpan(),
                        working[..(currentSize * ScalarSize)],
                        switchMessage,
                        value,
                        add,
                        multiply,
                        curve);
                    transcript.AbsorbWhirPrivateOutOfDomainReply(value, hash);
                    outOfDomainReplies[iteration - 1] = WrapScalar(value, curve, pool);

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

                    openings[iteration - 1] = BuildRowOpenings(
                        trees[iteration - 1]!,
                        leavesOwners[iteration - 1]!.Memory.Span,
                        1 << foldingParameter,
                        indices,
                        pool);

                    using Scalar gamma = transcript.SqueezeWhirCombinationChallenge(squeeze, hash, reduce, curve, pool);

                    //Fresh constraints: γ scales the out-of-domain constraint
                    //and γ^(q+2) the q-th shift constraint, on both the source
                    //weight and the switch-mask covector.
                    Span<byte> pointCoordinates = coordinates[..(currentVariableCount * ScalarSize)];
                    gamma.AsReadOnlySpan().CopyTo(gammaPower);
                    WhirMultilinear.ExpandPowPoint(outOfDomainPoint.AsReadOnlySpan(), currentVariableCount, pointCoordinates, multiply, curve);
                    WhirMultilinear.AccumulateScaledEqTable(
                        weightTable[..(currentSize * ScalarSize)],
                        pointCoordinates,
                        gammaPower,
                        currentVariableCount,
                        add,
                        subtract,
                        multiply,
                        curve,
                        pool);

                    Span<byte> queryPoints = RentTracked(indices.Length * ScalarSize, pool, disposables);
                    Span<byte> queryCoefficients = RentTracked(indices.Length * ScalarSize, pool, disposables);
                    encoder.DeriveDomainRoot(queryDomainLog2, queryRoot);
                    for(int query = 0; query < indices.Length; query++)
                    {
                        WhirFold.ComputeDomainPoint(queryRoot, indices[query], queryPoint, multiply, curve);
                        queryPoint.CopyTo(queryPoints.Slice(query * ScalarSize, ScalarSize));
                        multiply(gammaPower, gamma.AsReadOnlySpan(), gammaPower, curve);
                        gammaPower.CopyTo(queryCoefficients.Slice(query * ScalarSize, ScalarSize));

                        WhirMultilinear.ExpandPowPoint(queryPoint, currentVariableCount, pointCoordinates, multiply, curve);
                        WhirMultilinear.AccumulateScaledEqTable(
                            weightTable[..(currentSize * ScalarSize)],
                            pointCoordinates,
                            gammaPower,
                            currentVariableCount,
                            add,
                            subtract,
                            multiply,
                            curve,
                            pool);
                    }

                    //The switch-mask covector joins the carried relation at
                    //scale one; the pad slots receive only the out-of-domain
                    //layer.
                    IMemoryOwner<byte> covectorOwner = pool.Rent(switchShape.MessageLength * ScalarSize);
                    disposables.Add(covectorOwner);
                    Span<byte> covector = covectorOwner.Memory.Span[..(switchShape.MessageLength * ScalarSize)];
                    ZkWhirCodeSwitch.WriteSwitchMaskCovector(
                        currentSize,
                        previousRandomnessCount,
                        WhirZkParameters.OutOfDomainSamplesPerIteration,
                        outOfDomainPoint.AsReadOnlySpan(),
                        gamma.AsReadOnlySpan(),
                        queryPoints,
                        queryCoefficients,
                        covector,
                        add,
                        multiply,
                        curve);
                    groups.Add(switchGroup);
                    covectorOwners.Add(covectorOwner);
                    covectorLengths.Add(switchShape.MessageLength);
                    WriteDotProduct(covector, switchMessage, switchShape.MessageLength, value, add, multiply, curve);
                    add(aux, value, aux, curve);

                    WriteDotProduct(
                        functionTable[..(currentSize * ScalarSize)],
                        weightTable[..(currentSize * ScalarSize)],
                        currentSize,
                        sourceClaim,
                        add,
                        multiply,
                        curve);
                }

                //The iteration's masked sumcheck batch.
                int batchSize = 1 << currentVariableCount;
                ZkWhirMaskGroup batchGroup = ZkWhirMaskGroup.Create(
                    parameters.SumcheckMaskShape,
                    foldingParameter,
                    encoder,
                    merkleHash,
                    maskRandom,
                    curve,
                    pool);
                disposables.Add(batchGroup);

                CompressedRoundPolynomial[] wires = ZkWhirMaskedSumcheckProver.RunBatch(
                    functionTable,
                    weightTable,
                    batchSize,
                    batchGroup,
                    sourceClaim,
                    aux,
                    transcript,
                    hash,
                    squeeze,
                    reduce,
                    add,
                    subtract,
                    multiply,
                    invert,
                    pool,
                    epsilon,
                    challengeBlock);
                for(int round = 0; round < foldingParameter; round++)
                {
                    batchWires[(iteration * foldingParameter) + round] = wires[round];
                }

                sumcheckMaskRoots[iteration] = MerkleRoot.FromBytes(batchGroup.Tree.Root.AsReadOnlySpan(), pool);
                batchGroup.WriteMaskTotal(value, add, multiply);
                maskTotals[iteration] = WrapScalar(value, curve, pool);

                //Carried covectors and their running total absorb ε·2^(-k)
                //before the batch's fresh masks enter at scale one.
                multiply(epsilon, halfPowK, rescaleFactor, curve);
                RescaleCovectors(covectorOwners, covectorLengths, rescaleFactor, multiply, curve);
                multiply(aux, rescaleFactor, aux, curve);
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

                groups.Add(batchGroup);
                batchGroup.WriteMaskResidual(challengeBlock[..(foldingParameter * ScalarSize)], value, add, multiply);
                add(aux, value, aux, curve);

                //The residual weight side carries ε; the evaluation side stays
                //the honest folded message, so the next oracle commits it
                //verbatim.
                int foldedSize = batchSize >> foldingParameter;
                for(int index = 0; index < foldedSize; index++)
                {
                    Span<byte> entry = weightTable.Slice(index * ScalarSize, ScalarSize);
                    multiply(entry, epsilon, entry, curve);
                }

                //Fold the extended coefficients with the batch's challenges:
                //the appended randomness block stays contiguous under the
                //pairing and lands folded right after the folded message.
                int extendedLength = batchSize + parameters.OracleRandomnessElementCount(iteration);
                for(int round = 0; round < foldingParameter; round++)
                {
                    WhirFold.FoldCoefficients(
                        working[..(extendedLength * ScalarSize)],
                        challengeBlock.Slice(round * ScalarSize, ScalarSize),
                        working[..(extendedLength / 2 * ScalarSize)],
                        add,
                        multiply,
                        curve);
                    extendedLength /= 2;
                }

                currentVariableCount -= foldingParameter;
                WriteDotProduct(
                    functionTable[..((1 << currentVariableCount) * ScalarSize)],
                    weightTable[..((1 << currentVariableCount) * ScalarSize)],
                    1 << currentVariableCount,
                    sourceClaim,
                    add,
                    multiply,
                    curve);
            }

            //Masked base case (Construction 7.2) on the virtual folded oracle.
            int finalVariableCount = currentVariableCount;
            int finalMessageLength = 1 << finalVariableCount;
            int lastRandomnessCount = parameters.OracleRandomnessCounts[iterationCount - 1];
            WhirRoundParameters last = schedule.Rounds[iterationCount - 1];
            int finalQueryDomainLog2 = last.DomainSizeLog2 - foldingParameter;
            var sourceShape = new WhirMaskCodeShape(finalMessageLength, lastRandomnessCount, finalQueryDomainLog2);

            ZkWhirMaskGroup freshMain = ZkWhirMaskGroup.Create(sourceShape, 1, encoder, merkleHash, maskRandom, curve, pool);
            disposables.Add(freshMain);
            transcript.AbsorbWhirBaseCaseFreshRoot(freshMain.Tree.Root, hash);
            baseCaseFreshRoot = MerkleRoot.FromBytes(freshMain.Tree.Root.AsReadOnlySpan(), pool);

            baseCaseMaskRoots = new MerkleRoot?[groups.Count];
            var blinds = new ZkWhirMaskGroup[groups.Count];
            for(int group = 0; group < groups.Count; group++)
            {
                ZkWhirMaskGroup blind = ZkWhirMaskGroup.Create(
                    groups[group].Shape,
                    groups[group].MaskCount,
                    encoder,
                    merkleHash,
                    maskRandom,
                    curve,
                    pool);
                disposables.Add(blind);
                blinds[group] = blind;
                transcript.AbsorbWhirBaseCaseMaskRoot(blind.Tree.Root, hash);
                baseCaseMaskRoots[group] = MerkleRoot.FromBytes(blind.Tree.Root.AsReadOnlySpan(), pool);
            }

            //The masked claim μ_g: the relation evaluated on the fresh masks
            //instead of the secrets, fixed before γ is known.
            Span<byte> maskedClaim = stackalloc byte[ScalarSize];
            Span<byte> freshEvaluations = RentTracked(finalMessageLength * ScalarSize, pool, disposables);
            freshMain.MaskCoefficients(0).CopyTo(freshEvaluations);
            WhirMultilinear.CoefficientsToCubeEvaluations(freshEvaluations, finalVariableCount, add, curve);
            WriteDotProduct(
                freshEvaluations,
                weightTable[..(finalMessageLength * ScalarSize)],
                finalMessageLength,
                maskedClaim,
                add,
                multiply,
                curve);
            int covectorIndex = 0;
            for(int group = 0; group < groups.Count; group++)
            {
                for(int member = 0; member < groups[group].MaskCount; member++)
                {
                    int length = covectorLengths[covectorIndex];
                    WriteDotProduct(
                        blinds[group].MaskCoefficients(member),
                        covectorOwners[covectorIndex].Memory.Span[..(length * ScalarSize)],
                        length,
                        value,
                        add,
                        multiply,
                        curve);
                    add(maskedClaim, value, maskedClaim, curve);
                    covectorIndex++;
                }
            }

            transcript.AbsorbWhirBaseCaseClaim(maskedClaim, hash);
            baseCaseMaskedClaim = WrapScalar(maskedClaim, curve, pool);

            using Scalar baseGamma = transcript.SqueezeWhirBaseCaseCombinationChallenge(squeeze, hash, reduce, curve, pool);

            //One-time-pad reveals: reveal = fresh + γ·secret, in one pooled
            //buffer laid out source message, source randomness, then per
            //member the blinded message and randomness.
            int revealMemberElements = 0;
            for(int group = 0; group < groups.Count; group++)
            {
                revealMemberElements += groups[group].MaskCount * (groups[group].Shape.MessageLength + groups[group].Shape.RandomnessLength);
            }

            int blindedSourceMessageLength = finalMessageLength * ScalarSize;
            int blindedSourceRandomnessLength = lastRandomnessCount * ScalarSize;
            int blindedMaskRevealsLength = revealMemberElements * ScalarSize;
            blindedRevealsOwner = pool.Rent(blindedSourceMessageLength + blindedSourceRandomnessLength + blindedMaskRevealsLength);
            Span<byte> reveals = blindedRevealsOwner.Memory.Span[..(blindedSourceMessageLength + blindedSourceRandomnessLength + blindedMaskRevealsLength)];

            Span<byte> blindedSourceMessage = reveals[..blindedSourceMessageLength];
            WriteBlinded(
                freshMain.MaskCoefficients(0),
                working[..blindedSourceMessageLength],
                baseGamma.AsReadOnlySpan(),
                blindedSourceMessage,
                add,
                multiply,
                curve);
            Span<byte> blindedSourceRandomness = reveals.Slice(blindedSourceMessageLength, blindedSourceRandomnessLength);
            WriteBlinded(
                freshMain.EncodingRandomness(0),
                working.Slice(blindedSourceMessageLength, blindedSourceRandomnessLength),
                baseGamma.AsReadOnlySpan(),
                blindedSourceRandomness,
                add,
                multiply,
                curve);
            transcript.AbsorbWhirBaseCaseReveal(blindedSourceMessage, blindedSourceRandomness, hash);

            int revealOffset = blindedSourceMessageLength + blindedSourceRandomnessLength;
            for(int group = 0; group < groups.Count; group++)
            {
                for(int member = 0; member < groups[group].MaskCount; member++)
                {
                    int messageBytes = groups[group].Shape.MessageLength * ScalarSize;
                    int randomnessBytes = groups[group].Shape.RandomnessLength * ScalarSize;
                    Span<byte> blindedMessage = reveals.Slice(revealOffset, messageBytes);
                    WriteBlinded(
                        blinds[group].MaskCoefficients(member),
                        groups[group].MaskCoefficients(member),
                        baseGamma.AsReadOnlySpan(),
                        blindedMessage,
                        add,
                        multiply,
                        curve);
                    revealOffset += messageBytes;
                    Span<byte> blindedRandomness = reveals.Slice(revealOffset, randomnessBytes);
                    WriteBlinded(
                        blinds[group].EncodingRandomness(member),
                        groups[group].EncodingRandomness(member),
                        baseGamma.AsReadOnlySpan(),
                        blindedRandomness,
                        add,
                        multiply,
                        curve);
                    revealOffset += randomnessBytes;
                    transcript.AbsorbWhirBaseCaseMaskReveal(blindedMessage, blindedRandomness, hash);
                }
            }

            //Source spot checks: the last committed oracle and the fresh main
            //mask, opened at shared positions on the folded domain.
            var finalIndices = new int[last.QueryCount];
            for(int query = 0; query < finalIndices.Length; query++)
            {
                finalIndices[query] = transcript.SqueezeWhirQueryIndex(
                    WellKnownWhirTranscriptLabels.FinalQueryIndex,
                    1 << finalQueryDomainLog2,
                    squeeze,
                    hash);
            }

            openings[iterationCount - 1] = BuildRowOpenings(
                trees[iterationCount - 1]!,
                leavesOwners[iterationCount - 1]!.Memory.Span,
                1 << foldingParameter,
                finalIndices,
                pool);
            baseCaseFreshOpenings = BuildRowOpenings(
                freshMain.Tree,
                freshMain.InterleavedLeaves,
                freshMain.PaddedRowWidth,
                finalIndices,
                pool);

            //Mask spot checks: t_zk shared positions per group, opening the
            //carried oracle and its fresh blind.
            baseCaseCarriedMaskOpenings = new WhirQueryOpening[groups.Count][];
            baseCaseFreshMaskOpenings = new WhirQueryOpening[groups.Count][];
            for(int group = 0; group < groups.Count; group++)
            {
                var maskIndices = new int[parameters.MaskQueryCount];
                for(int query = 0; query < maskIndices.Length; query++)
                {
                    maskIndices[query] = transcript.SqueezeWhirQueryIndex(
                        WellKnownWhirTranscriptLabels.MaskQueryIndex,
                        groups[group].Shape.DomainSize,
                        squeeze,
                        hash);
                }

                baseCaseCarriedMaskOpenings[group] = BuildRowOpenings(
                    groups[group].Tree,
                    groups[group].InterleavedLeaves,
                    groups[group].PaddedRowWidth,
                    maskIndices,
                    pool);
                baseCaseFreshMaskOpenings[group] = BuildRowOpenings(
                    blinds[group].Tree,
                    blinds[group].InterleavedLeaves,
                    blinds[group].PaddedRowWidth,
                    maskIndices,
                    pool);
            }

            inputCommitment = MerkleRoot.FromBytes(trees[0]!.Root.AsReadOnlySpan(), pool);

            var proof = new ZkWhirIoppProof(
                parameters,
                Array.ConvertAll(batchWires, wire => wire!),
                Array.ConvertAll(sumcheckMaskRoots, root => root!),
                Array.ConvertAll(maskTotals, total => total!),
                Array.ConvertAll(oracleRoots, root => root!),
                Array.ConvertAll(codeSwitchMaskRoots, root => root!),
                Array.ConvertAll(outOfDomainReplies, reply => reply!),
                Array.ConvertAll(openings, oracleOpenings => oracleOpenings!),
                baseCaseFreshRoot,
                Array.ConvertAll(baseCaseMaskRoots, root => root!),
                baseCaseMaskedClaim,
                baseCaseFreshOpenings,
                Array.ConvertAll(baseCaseCarriedMaskOpenings, groupOpenings => groupOpenings!),
                Array.ConvertAll(baseCaseFreshMaskOpenings, groupOpenings => groupOpenings!),
                blindedRevealsOwner,
                blindedSourceMessageLength,
                blindedSourceRandomnessLength,
                blindedMaskRevealsLength);
            assembled = true;

            return (proof, inputCommitment);
        }
        finally
        {
            if(!assembled)
            {
                DisposeAllBuilt(batchWires);
                DisposeAllBuilt(sumcheckMaskRoots);
                DisposeAllBuilt(maskTotals);
                DisposeAllBuilt(oracleRoots);
                DisposeAllBuilt(codeSwitchMaskRoots);
                DisposeAllBuilt(outOfDomainReplies);
                foreach(WhirQueryOpening[]? oracleOpenings in openings)
                {
                    if(oracleOpenings is not null)
                    {
                        DisposeAllBuilt(oracleOpenings);
                    }
                }

                baseCaseFreshRoot?.Dispose();
                DisposeAllBuilt(baseCaseMaskRoots);
                baseCaseMaskedClaim?.Dispose();
                if(baseCaseFreshOpenings is not null)
                {
                    DisposeAllBuilt(baseCaseFreshOpenings);
                }

                DisposeAllNestedBuilt(baseCaseCarriedMaskOpenings);
                DisposeAllNestedBuilt(baseCaseFreshMaskOpenings);
                blindedRevealsOwner?.Dispose();
                inputCommitment?.Dispose();
            }

            //The pool zeroes rented buffers on return; the mask groups scrub
            //their own witnesses on disposal.
            for(int index = disposables.Count - 1; index >= 0; index--)
            {
                disposables[index].Dispose();
            }
        }
    }


    /// <summary>
    /// Computes the input oracle's zero-knowledge commitment root without
    /// producing a proof — the deterministic encode-and-commit for a caller
    /// that binds the commitment into a transcript before proving. The
    /// randomness must be the same <c>t_0·2^k</c> elements later given to the
    /// prover for transcripts to agree; the hiding surface layers key
    /// management above this.
    /// </summary>
    /// <param name="parameters">The zero-knowledge parameter extension fixing the initial domain, leaf shape and randomness budget.</param>
    /// <param name="coefficients">The multilinear coefficient vector, <c>2^m</c> elements.</param>
    /// <param name="randomness">The appended encoding randomness, <c>t_0·2^k</c> elements.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="pool">The pool to rent working buffers from.</param>
    /// <returns>The input oracle's Merkle root; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span does not match the schedule's shape.</exception>
    public static MerkleRoot ComputeInputCommitment(
        WhirZkParameters parameters,
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> randomness,
        MerkleHashDelegate merkleHash,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);

        WhirParameterSchedule schedule = parameters.Schedule;
        int messageLength = 1 << schedule.VariableCount;
        int randomnessLength = parameters.OracleRandomnessElementCount(0);
        if(coefficients.Length != messageLength * ScalarSize)
        {
            throw new ArgumentException(
                $"The coefficient vector must carry {messageLength} elements ({messageLength * ScalarSize} bytes); received {coefficients.Length}.",
                nameof(coefficients));
        }

        if(randomness.Length != randomnessLength * ScalarSize)
        {
            throw new ArgumentException(
                $"The encoding randomness must carry {randomnessLength} elements ({randomnessLength * ScalarSize} bytes); received {randomness.Length}.",
                nameof(randomness));
        }

        int domainSizeLog2 = schedule.Rounds[0].DomainSizeLog2;
        int foldingParameter = schedule.FoldingParameter;
        int domainLength = 1 << domainSizeLog2;
        int blockCount = domainLength >> foldingParameter;
        int blockSize = 1 << foldingParameter;

        var encoder = WhirCosetEncoder.Create(add, subtract, multiply, schedule.Curve, pool);
        using IMemoryOwner<byte> leavesOwner = pool.Rent(domainLength * ScalarSize);
        Span<byte> leaves = leavesOwner.Memory.Span[..(domainLength * ScalarSize)];
        encoder.EncodeToCosetLeavesWithRandomness(coefficients, randomness, domainSizeLog2, foldingParameter, leaves);

        using IMemoryOwner<byte> digestsOwner = pool.Rent(blockCount * ScalarSize);
        Span<byte> digests = digestsOwner.Memory.Span[..(blockCount * ScalarSize)];
        WhirCosetLeaf.ComputeLeafDigests(leaves, blockCount, blockSize, merkleHash, digests, pool);

        using MerkleTree tree = MerkleTree.Build(digests, blockCount, merkleHash, pool);

        return MerkleRoot.FromBytes(tree.Root.AsReadOnlySpan(), pool);
    }


    /// <summary>
    /// Validates the statement spans against the schedule's shape.
    /// </summary>
    private static void ValidateStatementShape(
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> constraintCoefficients,
        ReadOnlySpan<byte> constraintPoints,
        ReadOnlySpan<byte> target,
        int variableCount,
        int messageLength,
        out int constraintCount)
    {
        if(coefficients.Length != messageLength * ScalarSize)
        {
            throw new ArgumentException(
                $"The coefficient vector must carry {messageLength} elements ({messageLength * ScalarSize} bytes); received {coefficients.Length}.",
                nameof(coefficients));
        }

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
                $"The constraint points must carry {variableCount} elements per constraint ({constraintCount * variableCount * ScalarSize} bytes); received {constraintPoints.Length}.",
                nameof(constraintPoints));
        }

        if(target.Length != ScalarSize)
        {
            throw new ArgumentException($"The target must be one {ScalarSize}-byte element; received {target.Length} bytes.", nameof(target));
        }
    }


    /// <summary>
    /// Fails loudly when the claimed sum does not hold for the working
    /// tables: a proof of a false statement would only fail at the verifier,
    /// far from the caller's mistake.
    /// </summary>
    private static void ThrowIfStatementDoesNotHold(
        ReadOnlySpan<byte> functionTable,
        ReadOnlySpan<byte> weightTable,
        int size,
        ReadOnlySpan<byte> target,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> sum = stackalloc byte[ScalarSize];
        WriteDotProduct(functionTable, weightTable, size, sum, add, multiply, curve);
        if(!sum.SequenceEqual(target))
        {
            throw new ArgumentException("The claimed target does not equal the weighted sum of the supplied coefficients.", nameof(target));
        }
    }


    /// <summary>
    /// Encodes the extended coefficient vector — message and appended
    /// randomness — onto its scheduled domain in coset-contiguous order,
    /// compresses the coset leaves and builds the oracle's Merkle tree,
    /// tracking both in the working storage.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The leaves owner and the tree are tracked in the disposables list and released in the prover's finally block.")]
    private static void CommitZkOracle(
        int oracleIndex,
        ReadOnlySpan<byte> extendedCoefficients,
        int messageElementCount,
        WhirParameterSchedule schedule,
        WhirCosetEncoder encoder,
        MerkleHashDelegate merkleHash,
        IMemoryOwner<byte>?[] leavesOwners,
        MerkleTree?[] trees,
        BaseMemoryPool pool,
        List<IDisposable> disposables)
    {
        int domainSizeLog2 = schedule.Rounds[oracleIndex].DomainSizeLog2;
        int foldingParameter = schedule.FoldingParameter;
        int domainLength = 1 << domainSizeLog2;
        int blockCount = domainLength >> foldingParameter;
        int blockSize = 1 << foldingParameter;

        IMemoryOwner<byte> leavesOwner = pool.Rent(domainLength * ScalarSize);
        disposables.Add(leavesOwner);
        leavesOwners[oracleIndex] = leavesOwner;
        Span<byte> leaves = leavesOwner.Memory.Span[..(domainLength * ScalarSize)];
        encoder.EncodeToCosetLeavesWithRandomness(
            extendedCoefficients[..(messageElementCount * ScalarSize)],
            extendedCoefficients[(messageElementCount * ScalarSize)..],
            domainSizeLog2,
            foldingParameter,
            leaves);

        using IMemoryOwner<byte> digestsOwner = pool.Rent(blockCount * ScalarSize);
        Span<byte> digests = digestsOwner.Memory.Span[..(blockCount * ScalarSize)];
        WhirCosetLeaf.ComputeLeafDigests(leaves, blockCount, blockSize, merkleHash, digests, pool);

        MerkleTree tree = MerkleTree.Build(digests, blockCount, merkleHash, pool);
        disposables.Add(tree);
        trees[oracleIndex] = tree;
    }


    /// <summary>
    /// Reveals the queried rows of a committed oracle: the row values from
    /// the row-contiguous leaves and each leaf's authentication path. Serves
    /// both the <c>2^k</c>-coset oracle blocks and the interleaved mask-group
    /// rows.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Each opening's values buffer and path transfer ownership to the returned openings, which the proof owns and disposes; on a mid-sequence failure the catch block releases every part built so far.")]
    private static WhirQueryOpening[] BuildRowOpenings(
        MerkleTree tree,
        ReadOnlySpan<byte> leaves,
        int rowElementCount,
        int[] indices,
        BaseMemoryPool pool)
    {
        int rowBytes = rowElementCount * ScalarSize;
        var result = new WhirQueryOpening[indices.Length];
        int built = 0;
        try
        {
            for(int query = 0; query < indices.Length; query++)
            {
                IMemoryOwner<byte> values = pool.Rent(rowBytes);
                MerkleAuthenticationPath path;
                try
                {
                    leaves.Slice(indices[query] * rowBytes, rowBytes).CopyTo(values.Memory.Span[..rowBytes]);
                    path = tree.BuildPath(indices[query], pool);
                }
                catch
                {
                    values.Dispose();
                    throw;
                }

                result[query] = new WhirQueryOpening(values, rowBytes, path);
                built++;
            }
        }
        catch
        {
            for(int query = 0; query < built; query++)
            {
                result[query].Dispose();
            }

            throw;
        }

        return result;
    }


    /// <summary>
    /// Writes <c>destination = Σ a_i·b_i</c> over <paramref name="count"/>
    /// elements.
    /// </summary>
    private static void WriteDotProduct(
        ReadOnlySpan<byte> a,
        ReadOnlySpan<byte> b,
        int count,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        destination[..ScalarSize].Clear();
        for(int index = 0; index < count; index++)
        {
            multiply(a.Slice(index * ScalarSize, ScalarSize), b.Slice(index * ScalarSize, ScalarSize), product, curve);
            add(destination, product, destination, curve);
        }
    }


    /// <summary>
    /// Writes the one-time-pad reveal <c>destination = fresh + γ·secret</c>
    /// element-wise.
    /// </summary>
    private static void WriteBlinded(
        ReadOnlySpan<byte> fresh,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> gamma,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int offset = 0; offset < destination.Length; offset += ScalarSize)
        {
            multiply(secret.Slice(offset, ScalarSize), gamma, term, curve);
            add(fresh.Slice(offset, ScalarSize), term, destination.Slice(offset, ScalarSize), curve);
        }
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
    [SuppressMessage("Reliability", "CA2000", Justification = "The buffer is tracked in the disposables list and released in the prover's finally block.")]
    private static Span<byte> RentTracked(int byteLength, BaseMemoryPool pool, List<IDisposable> disposables)
    {
        IMemoryOwner<byte> owner = pool.Rent(byteLength);
        disposables.Add(owner);

        return owner.Memory.Span[..byteLength];
    }


    /// <summary>
    /// Fills a buffer with freshly sampled canonical scalars, one delegate
    /// call per element. Shared with the polynomial-commitment seam, which
    /// samples the input oracle's encoding randomness at commit time.
    /// </summary>
    internal static void FillWithScalars(Span<byte> destination, ScalarRandomDelegate random, CurveParameterSet curve)
    {
        for(int offset = 0; offset < destination.Length; offset += ScalarSize)
        {
            _ = random(destination.Slice(offset, ScalarSize), curve, WellKnownAlgebraicTags.ScalarFor(curve));
        }
    }


    /// <summary>
    /// Copies a computed value into a pool-owned <see cref="Scalar"/>.
    /// </summary>
    private static Scalar WrapScalar(ReadOnlySpan<byte> value, CurveParameterSet curve, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        value.CopyTo(owner.Memory.Span[..ScalarSize]);

        return new Scalar(owner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }


    /// <summary>
    /// Disposes every non-null entry of a partially assembled part array —
    /// the failed-run cleanup of proof parts not yet owned by a proof.
    /// </summary>
    private static void DisposeAllBuilt<T>(T?[] parts) where T: class, IDisposable
    {
        foreach(T? part in parts)
        {
            part?.Dispose();
        }
    }


    /// <summary>
    /// Disposes every non-null opening of a partially assembled nested part
    /// array.
    /// </summary>
    private static void DisposeAllNestedBuilt(WhirQueryOpening[]?[] parts)
    {
        foreach(WhirQueryOpening[]? groupOpenings in parts)
        {
            if(groupOpenings is not null)
            {
                DisposeAllBuilt(groupOpenings);
            }
        }
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
