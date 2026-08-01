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
/// The WHIR IOPP prover (WHIR Construction 5.1): proves that a committed
/// multilinear polynomial satisfies an equality-kernel weighted-sum statement
/// <c>Σ_b f̂(b)·(Σ_c λ_c·eq(p_c, b)) = σ</c> — the shape carrying both plain
/// proximity (no constraints, <c>σ = 0</c>) and evaluation claims
/// (<c>λ = 1</c>, <c>p = pow(z, m)</c>, <c>σ = f̂(z)</c>). Each iteration
/// interleaves <c>k</c> sumcheck rounds with the folding of the oracle, sends
/// the folded oracle on a domain half the size (the STIR-style rate
/// improvement), answers one out-of-domain sample, and folds the shift-query
/// constraints of the previous oracle into the running weight.
/// </summary>
/// <remarks>
/// The prover maintains three synchronized views of the running polynomial:
/// the coefficient vector (folded per challenge, feeding the
/// <see cref="WhirCosetEncoder"/> and the out-of-domain replies), its
/// evaluation table over the boolean cube, and the weight's evaluation table
/// (both bound per challenge, feeding the degree-2 round polynomials). The
/// input oracle's Merkle root is the public commitment: the prover absorbs it
/// after the statement, and the verifier must be given the same root.
/// </remarks>
public static class WhirIoppProver
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// The sumcheck round polynomials are quadratic: the weight is linear in
    /// <c>Z</c> and multilinear in the point variables for every wired
    /// statement, so the per-round product of the f-table and weight-table
    /// lines has degree 2.
    /// </summary>
    private const int RoundPolynomialDegree = 2;


    /// <summary>
    /// Produces a WHIR proof for the statement
    /// <c>Σ_b f̂(b)·(Σ_c λ_c·eq(p_c, b)) = σ</c> over the polynomial with the
    /// given coefficient vector.
    /// </summary>
    /// <param name="schedule">The parameter schedule both endpoints derive from the same public figures.</param>
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
    /// <param name="pool">The pool to rent working and proof buffers from.</param>
    /// <returns>The proof and the input oracle's Merkle root — the public commitment the verifier needs; the caller owns both.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the schedule's shape, or the statement does not hold for the coefficients.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Working buffers and trees are disposed in the finally block; the parts the proof keeps transfer ownership to the returned proof, and on a failed run the partial parts are disposed before rethrowing.")]
    public static (WhirIoppProof Proof, MerkleRoot InputCommitment) Prove(
        WhirParameterSchedule schedule,
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

        int variableCount = schedule.VariableCount;
        int foldingParameter = schedule.FoldingParameter;
        int iterationCount = schedule.IterationCount;
        CurveParameterSet curve = schedule.Curve;
        int messageLength = 1 << variableCount;
        ValidateStatementShape(coefficients, constraintCoefficients, constraintPoints, target, variableCount, messageLength, out int constraintCount);

        var encoder = WhirCosetEncoder.Create(add, subtract, multiply, curve, pool);
        var disposables = new List<IDisposable>();
        var leavesOwners = new IMemoryOwner<byte>?[iterationCount];
        var trees = new MerkleTree?[iterationCount];
        var roundPolynomials = new CompressedRoundPolynomial?[iterationCount * foldingParameter];
        var outOfDomainReplies = new Scalar?[iterationCount - 1];
        WhirQueryOpening[]?[] openings = new WhirQueryOpening[iterationCount][];
        MerkleRoot?[] rootCopies = new MerkleRoot[iterationCount - 1];
        IMemoryOwner<byte>? finalOwner = null;
        MerkleRoot? inputCommitment = null;
        bool assembled = false;

        try
        {
            transcript.AbsorbWhirStatement(target, constraintCoefficients, constraintPoints, hash);

            //The three synchronized working views, all rented at full message
            //size and consumed from the front as folding halves them.
            Span<byte> workingCoefficients = RentTracked(messageLength * ScalarSize, pool, disposables);
            coefficients.CopyTo(workingCoefficients);

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

            CommitOracle(0, workingCoefficients[..(messageLength * ScalarSize)], schedule, encoder, merkleHash, leavesOwners, trees, pool, disposables);
            transcript.AbsorbWhirOracleRoot(trees[0]!.Root, hash);

            //Per-iteration scratch reused across the loop: the pow-expanded
            //constraint coordinates (at most the full variable count) and the
            //single-element temporaries.
            Span<byte> coordinates = RentTracked(variableCount * ScalarSize, pool, disposables);
            Span<byte> evaluation = stackalloc byte[ScalarSize];
            Span<byte> queryRoot = stackalloc byte[ScalarSize];
            Span<byte> queryPoint = stackalloc byte[ScalarSize];
            Span<byte> gammaPower = stackalloc byte[ScalarSize];

            int currentVariableCount = variableCount;
            int roundPolynomialIndex = 0;
            for(int iteration = 0; iteration < iterationCount; iteration++)
            {
                if(iteration > 0)
                {
                    int currentSize = 1 << currentVariableCount;
                    CommitOracle(iteration, workingCoefficients[..(currentSize * ScalarSize)], schedule, encoder, merkleHash, leavesOwners, trees, pool, disposables);
                    transcript.AbsorbWhirOracleRoot(trees[iteration]!.Root, hash);

                    //Out-of-domain sample and reply.
                    using Scalar outOfDomainPoint = transcript.SqueezeWhirOutOfDomainPoint(squeeze, hash, reduce, curve, pool);
                    Span<byte> pointCoordinates = coordinates[..(currentVariableCount * ScalarSize)];
                    WhirMultilinear.ExpandPowPoint(outOfDomainPoint.AsReadOnlySpan(), currentVariableCount, pointCoordinates, multiply, curve);
                    WhirMultilinear.EvaluateCoefficientsAtPoint(
                        workingCoefficients[..(currentSize * ScalarSize)],
                        pointCoordinates,
                        currentVariableCount,
                        evaluation,
                        add,
                        multiply,
                        curve,
                        pool);
                    transcript.AbsorbWhirOutOfDomainReply(evaluation, hash);
                    outOfDomainReplies[iteration - 1] = WrapScalar(evaluation, curve, pool);

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

                    openings[iteration - 1] = BuildOpenings(trees[iteration - 1]!, leavesOwners[iteration - 1]!, foldingParameter, indices, pool);

                    using Scalar gamma = transcript.SqueezeWhirCombinationChallenge(squeeze, hash, reduce, curve, pool);

                    //Weight update: γ scales the out-of-domain constraint and
                    //γ^(j+1) the j-th shift constraint, matching the verifier's
                    //claim update and Construction 5.1's ŵ_i definition.
                    gamma.AsReadOnlySpan().CopyTo(gammaPower);
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

                    encoder.DeriveDomainRoot(queryDomainLog2, queryRoot);
                    for(int query = 0; query < indices.Length; query++)
                    {
                        WhirFold.ComputeDomainPoint(queryRoot, indices[query], queryPoint, multiply, curve);
                        WhirMultilinear.ExpandPowPoint(queryPoint, currentVariableCount, pointCoordinates, multiply, curve);
                        multiply(gammaPower, gamma.AsReadOnlySpan(), gammaPower, curve);
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
                }

                for(int round = 0; round < foldingParameter; round++)
                {
                    int size = 1 << currentVariableCount;
                    CompressedRoundPolynomial roundPolynomial = ComputeRoundPolynomial(
                        functionTable[..(size * ScalarSize)],
                        weightTable[..(size * ScalarSize)],
                        size,
                        add,
                        subtract,
                        multiply,
                        curve,
                        pool);
                    roundPolynomials[roundPolynomialIndex++] = roundPolynomial;
                    transcript.AbsorbWhirSumcheckPolynomial(roundPolynomial, hash);

                    using Scalar challenge = transcript.SqueezeWhirFoldChallenge(squeeze, hash, reduce, curve, pool);
                    ReadOnlySpan<byte> challengeBytes = challenge.AsReadOnlySpan();
                    WhirMultilinear.BindFirstVariable(functionTable, size, challengeBytes, add, subtract, multiply, curve);
                    WhirMultilinear.BindFirstVariable(weightTable, size, challengeBytes, add, subtract, multiply, curve);
                    WhirFold.FoldCoefficients(
                        workingCoefficients[..(size * ScalarSize)],
                        challengeBytes,
                        workingCoefficients[..(size / 2 * ScalarSize)],
                        add,
                        multiply,
                        curve);
                    currentVariableCount--;
                }
            }

            //Final polynomial in the clear, then the final queries against the
            //last oracle.
            int finalLength = (1 << currentVariableCount) * ScalarSize;
            ReadOnlySpan<byte> finalCoefficients = workingCoefficients[..finalLength];
            transcript.AbsorbWhirFinalPolynomial(finalCoefficients, hash);

            WhirRoundParameters last = schedule.Rounds[iterationCount - 1];
            int finalQueryDomainLog2 = last.DomainSizeLog2 - foldingParameter;
            var finalIndices = new int[last.QueryCount];
            for(int query = 0; query < finalIndices.Length; query++)
            {
                finalIndices[query] = transcript.SqueezeWhirQueryIndex(
                    WellKnownWhirTranscriptLabels.FinalQueryIndex,
                    1 << finalQueryDomainLog2,
                    squeeze,
                    hash);
            }

            openings[iterationCount - 1] = BuildOpenings(trees[iterationCount - 1]!, leavesOwners[iterationCount - 1]!, foldingParameter, finalIndices, pool);

            //Assemble the proof-owned parts and the input commitment.
            for(int iteration = 1; iteration < iterationCount; iteration++)
            {
                rootCopies[iteration - 1] = MerkleRoot.FromBytes(trees[iteration]!.Root.AsReadOnlySpan(), pool);
            }

            finalOwner = pool.Rent(finalLength);
            finalCoefficients.CopyTo(finalOwner.Memory.Span[..finalLength]);

            inputCommitment = MerkleRoot.FromBytes(trees[0]!.Root.AsReadOnlySpan(), pool);

            var proof = new WhirIoppProof(
                schedule,
                Array.ConvertAll(rootCopies, root => root!),
                Array.ConvertAll(roundPolynomials, polynomial => polynomial!),
                Array.ConvertAll(outOfDomainReplies, reply => reply!),
                finalOwner,
                finalLength,
                Array.ConvertAll(openings, oracleOpenings => oracleOpenings!));
            assembled = true;

            return (proof, inputCommitment);
        }
        finally
        {
            if(!assembled)
            {
                DisposeAll(roundPolynomials);
                DisposeAll(outOfDomainReplies);
                DisposeAll(rootCopies);
                foreach(WhirQueryOpening[]? oracleOpenings in openings)
                {
                    if(oracleOpenings is not null)
                    {
                        DisposeAll(oracleOpenings);
                    }
                }

                finalOwner?.Dispose();
                inputCommitment?.Dispose();
            }

            //The pool zeroes rented buffers on return, so the working state's
            //witness-derived bytes need no explicit scrub here.
            for(int index = disposables.Count - 1; index >= 0; index--)
            {
                disposables[index].Dispose();
            }
        }
    }


    /// <summary>
    /// Computes the input oracle's Merkle root for the given coefficient
    /// vector without producing a proof: the same deterministic
    /// encode-and-commit the prover performs, exposed so a caller can bind
    /// the commitment into a transcript before proving — the batching layer
    /// and the polynomial-commitment surface both commit first and prove
    /// later.
    /// </summary>
    /// <param name="schedule">The parameter schedule fixing the initial domain and leaf shape.</param>
    /// <param name="coefficients">The multilinear coefficient vector, <c>2^m</c> elements for the schedule's variable count <c>m</c>.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="pool">The pool to rent working buffers from.</param>
    /// <returns>The input oracle's Merkle root; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the coefficient vector does not match the schedule's shape.</exception>
    public static MerkleRoot ComputeInputCommitment(
        WhirParameterSchedule schedule,
        ReadOnlySpan<byte> coefficients,
        MerkleHashDelegate merkleHash,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);

        int messageLength = 1 << schedule.VariableCount;
        if(coefficients.Length != messageLength * ScalarSize)
        {
            throw new ArgumentException(
                $"The coefficient vector must carry {messageLength} elements ({messageLength * ScalarSize} bytes); received {coefficients.Length}.",
                nameof(coefficients));
        }

        int domainSizeLog2 = schedule.Rounds[0].DomainSizeLog2;
        int foldingParameter = schedule.FoldingParameter;
        int domainLength = 1 << domainSizeLog2;
        int blockCount = domainLength >> foldingParameter;
        int blockSize = 1 << foldingParameter;

        var encoder = WhirCosetEncoder.Create(add, subtract, multiply, schedule.Curve, pool);
        using IMemoryOwner<byte> leavesOwner = pool.Rent(domainLength * ScalarSize);
        Span<byte> leaves = leavesOwner.Memory.Span[..(domainLength * ScalarSize)];
        encoder.EncodeToCosetLeaves(coefficients, domainSizeLog2, foldingParameter, leaves);

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
    /// Fails loudly when the claimed sum does not hold for the working tables:
    /// a proof of a false statement would only fail at the verifier, far from
    /// the caller's mistake.
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
        Span<byte> product = stackalloc byte[ScalarSize];
        sum.Clear();
        for(int index = 0; index < size; index++)
        {
            multiply(functionTable.Slice(index * ScalarSize, ScalarSize), weightTable.Slice(index * ScalarSize, ScalarSize), product, curve);
            add(sum, product, sum, curve);
        }

        if(!sum.SequenceEqual(target))
        {
            throw new ArgumentException("The claimed target does not equal the weighted sum of the supplied coefficients.", nameof(target));
        }
    }


    /// <summary>
    /// Encodes the current coefficient vector onto its scheduled domain in
    /// coset-contiguous order, compresses the coset leaves and builds the
    /// oracle's Merkle tree, tracking both in the working storage.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The leaves owner and the tree are tracked in the disposables list and released in the prover's finally block.")]
    private static void CommitOracle(
        int oracleIndex,
        ReadOnlySpan<byte> currentCoefficients,
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
        encoder.EncodeToCosetLeaves(currentCoefficients, domainSizeLog2, foldingParameter, leaves);

        using IMemoryOwner<byte> digestsOwner = pool.Rent(blockCount * ScalarSize);
        Span<byte> digests = digestsOwner.Memory.Span[..(blockCount * ScalarSize)];
        WhirCosetLeaf.ComputeLeafDigests(leaves, blockCount, blockSize, merkleHash, digests, pool);

        MerkleTree tree = MerkleTree.Build(digests, blockCount, merkleHash, pool);
        disposables.Add(tree);
        trees[oracleIndex] = tree;
    }


    /// <summary>
    /// Reveals the queried coset blocks of an oracle: the block values from
    /// the coset-contiguous codeword and the leaf's authentication path.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Each opening's values buffer and path transfer ownership to the returned openings, which the proof owns and disposes; on a mid-sequence failure the catch block releases every part built so far.")]
    private static WhirQueryOpening[] BuildOpenings(
        MerkleTree tree,
        IMemoryOwner<byte> leavesOwner,
        int foldingParameter,
        int[] indices,
        BaseMemoryPool pool)
    {
        int blockSize = 1 << foldingParameter;
        int blockBytes = blockSize * ScalarSize;
        ReadOnlySpan<byte> leaves = leavesOwner.Memory.Span;

        var result = new WhirQueryOpening[indices.Length];
        int built = 0;
        try
        {
            for(int query = 0; query < indices.Length; query++)
            {
                IMemoryOwner<byte> values = pool.Rent(blockBytes);
                MerkleAuthenticationPath path;
                try
                {
                    leaves.Slice(indices[query] * blockBytes, blockBytes).CopyTo(values.Memory.Span[..blockBytes]);
                    path = tree.BuildPath(indices[query], pool);
                }
                catch
                {
                    values.Dispose();
                    throw;
                }

                result[query] = new WhirQueryOpening(values, blockBytes, path);
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
    /// The degree-2 round polynomial of the f-table and weight-table product
    /// in the first (current) variable, compressed to <c>(c_0, c_2)</c>:
    /// pairs are even/odd entries, <c>c_0 = Σ f_even·w_even</c> and
    /// <c>c_2 = Σ (f_odd − f_even)·(w_odd − w_even)</c>; the linear term is
    /// elided and the verifier reconstructs it from the running claim.
    /// </summary>
    private static CompressedRoundPolynomial ComputeRoundPolynomial(
        ReadOnlySpan<byte> functionTable,
        ReadOnlySpan<byte> weightTable,
        int size,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        Span<byte> compressed = stackalloc byte[RoundPolynomialDegree * ScalarSize];
        compressed.Clear();
        Span<byte> constantTerm = compressed[..ScalarSize];
        Span<byte> quadraticTerm = compressed.Slice(ScalarSize, ScalarSize);

        Span<byte> functionSlope = stackalloc byte[ScalarSize];
        Span<byte> weightSlope = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        int half = size / 2;
        for(int pair = 0; pair < half; pair++)
        {
            ReadOnlySpan<byte> functionEven = functionTable.Slice(2 * pair * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> functionOdd = functionTable.Slice(((2 * pair) + 1) * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> weightEven = weightTable.Slice(2 * pair * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> weightOdd = weightTable.Slice(((2 * pair) + 1) * ScalarSize, ScalarSize);

            multiply(functionEven, weightEven, product, curve);
            add(constantTerm, product, constantTerm, curve);

            subtract(functionOdd, functionEven, functionSlope, curve);
            subtract(weightOdd, weightEven, weightSlope, curve);
            multiply(functionSlope, weightSlope, product, curve);
            add(quadraticTerm, product, quadraticTerm, curve);
        }

        return CompressedRoundPolynomial.FromCompressedBytes(compressed, RoundPolynomialDegree, curve, pool);
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
    private static void DisposeAll<T>(T?[] items) where T: class, IDisposable
    {
        foreach(T? item in items)
        {
            item?.Dispose();
        }
    }
}
