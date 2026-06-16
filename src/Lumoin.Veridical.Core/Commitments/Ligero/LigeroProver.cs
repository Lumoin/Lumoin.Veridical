using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The Ligero prover: commits to the witness-and-constraint tableau, then
/// answers the verifier's three tests — low-degree, dot-product (linear) and
/// quadratic — over a Fiat-Shamir transcript, and opens the challenged columns
/// with their Merkle paths. The result is a self-contained <see cref="LigeroProof"/>.
/// </summary>
/// <remarks>
/// <para>
/// The schedule, mirrored exactly by <see cref="LigeroVerifier"/>: absorb the
/// column commitment root, squeeze the test challenges <c>u_ldt</c>, <c>αl</c>,
/// <c>αq</c>, <c>u_quad</c>, compute and absorb the responses <c>y_ldt</c>,
/// <c>y_dot</c>, <c>y_quad</c>, then squeeze the opened-column indices and open
/// those columns. Drawing the indices only after the responses are absorbed is
/// what stops the prover from tailoring a response to the columns that will be
/// checked.
/// </para>
/// <para>
/// Follows "Ligero: Lightweight Sublinear Arguments Without a Trusted Setup"
/// (Ames, Hazay, Ishai, Venkitasubramaniam, IACR ePrint 2022/1608) — structural
/// reference only, no code dependency.
/// </para>
/// </remarks>
public static class LigeroProver
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Produces a Ligero proof that the committed witness satisfies the linear
    /// and quadratic constraints.
    /// </summary>
    /// <param name="parameters">The tableau layout.</param>
    /// <param name="witnesses">The witness vector; exactly <c>WitnessCount · 32</c> canonical bytes.</param>
    /// <param name="linearConstraintCount">The number of linear constraints <c>nl</c>.</param>
    /// <param name="linearConstraints">The linear terms.</param>
    /// <param name="linearTargets">The linear targets <c>b</c>; <c>nl</c> canonical scalars.</param>
    /// <param name="quadraticConstraints">The multiplication constraints; exactly <see cref="LigeroParameters.QuadraticConstraintCount"/> of them.</param>
    /// <param name="transcriptSeed">The public-input seed the transcript is initialised with.</param>
    /// <param name="random">Prover-randomness backend for the tableau blinding.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="reduce">Scalar-reduce backend for the challenge squeeze.</param>
    /// <param name="hash">The fixed-output transcript hash backend.</param>
    /// <param name="squeeze">The transcript XOF backend.</param>
    /// <param name="columnHash">The one-shot bytes-to-digest hash producing a Merkle leaf from a whole column.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent working buffers from.</param>
    /// <returns>The proof; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a backend, the parameters or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the layout.</exception>
    /// <exception cref="InvalidOperationException">When the witness does not satisfy a linear constraint (the quadratic check is enforced by the tableau build).</exception>
    public static LigeroProof Prove(
        LigeroParameters parameters,
        ReadOnlySpan<byte> witnesses,
        int linearConstraintCount,
        ReadOnlySpan<LigeroLinearConstraint> linearConstraints,
        ReadOnlySpan<byte> linearTargets,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        ReadOnlySpan<byte> transcriptSeed,
        ScalarRandomDelegate random,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate columnHash,
        MerkleHashDelegate merkleHash,
        string hashAlgorithm,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        if(linearTargets.Length != linearConstraintCount * ScalarSize)
        {
            throw new ArgumentException($"Linear targets must be {linearConstraintCount * ScalarSize} bytes; received {linearTargets.Length}.", nameof(linearTargets));
        }

        //Fail fast on an unsatisfiable statement before paying for the tableau encode.
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        AssertLinearConstraintsSatisfied(parameters, witnesses, linearConstraintCount, linearConstraints, linearTargets, add, multiply, subtract, curve, pool);

        using LigeroCommitment commitment = Commit(
            parameters, witnesses, quadraticConstraints, random,
            add, subtract, multiply, invert, columnHash, hashAlgorithm, merkleHash, curve, pool);

        return Prove(
            commitment, linearConstraintCount, linearConstraints, linearTargets, transcriptSeed,
            add, subtract, multiply, invert, reduce, hash, squeeze, curve, pool);
    }


    /// <summary>
    /// Builds and commits the tableau without proving anything: the returned
    /// <see cref="LigeroCommitment"/> carries the encoded tableau, its Merkle
    /// tree and the witness, so a commit-then-challenge protocol can absorb the
    /// root first and later call
    /// <see cref="Prove(LigeroCommitment, int, ReadOnlySpan{LigeroLinearConstraint}, ReadOnlySpan{byte}, ReadOnlySpan{byte}, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarReduceDelegate, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, CurveParameterSet, BaseMemoryPool)"/>
    /// with challenge-derived constraints — without rebuilding and re-encoding
    /// the tableau. The quadratic constraints participate in the tableau layout,
    /// so they bind at commit time; the linear constraints do not, so they bind
    /// at prove time.
    /// </summary>
    /// <param name="parameters">The tableau layout.</param>
    /// <param name="witnesses">The witness vector; exactly <c>WitnessCount · 32</c> canonical bytes.</param>
    /// <param name="quadraticConstraints">The multiplication constraints; exactly <see cref="LigeroParameters.QuadraticConstraintCount"/> of them.</param>
    /// <param name="random">Prover-randomness backend for the tableau blinding.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="columnHash">The one-shot bytes-to-digest hash producing a Merkle leaf from a whole column.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent working buffers from.</param>
    /// <returns>The standing commitment; the caller owns its disposal.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The tableau, tree and witness copy transfer ownership to the returned LigeroCommitment, which releases them through its own Dispose; on a fault they are released before rethrow.")]
    public static LigeroCommitment Commit(
        LigeroParameters parameters,
        ReadOnlySpan<byte> witnesses,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        ScalarRandomDelegate random,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        FiatShamirHashDelegate columnHash,
        string hashAlgorithm,
        MerkleHashDelegate merkleHash,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(columnHash);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(pool);

        LigeroTableau tableau = LigeroTableau.Build(parameters, witnesses, quadraticConstraints, random, add, subtract, multiply, invert, curve, pool);
        MerkleTree? tree = null;
        IMemoryOwner<byte>? witnessOwner = null;
        try
        {
            tree = tableau.CommitColumns(columnHash, hashAlgorithm, merkleHash, pool);
            //The retained witness copy is secret and lives until the commitment is disposed; pin it (too large
            //for the native tier) so it is not left behind in a relocated heap block.
            witnessOwner = pool.Rent(witnesses.Length, AllocationKind.Pinned);
            witnesses.CopyTo(witnessOwner.Memory.Span);

            return new LigeroCommitment(parameters, tableau, tree, witnessOwner, witnesses.Length, quadraticConstraints.ToArray(), hashAlgorithm);
        }
        catch
        {
            if(witnessOwner is not null)
            {
                witnessOwner.Memory.Span.Clear();
                witnessOwner.Dispose();
            }

            tree?.Dispose();
            tableau.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Proves the committed witness satisfies the linear constraints (and the
    /// quadratic constraints the commitment was built over), reading the
    /// already-encoded tableau out of <paramref name="commitment"/>. The
    /// commitment is not consumed: it stays usable, and the caller disposes it.
    /// </summary>
    /// <param name="commitment">The standing commitment from <see cref="Commit"/>.</param>
    /// <param name="linearConstraintCount">The number of linear constraints <c>nl</c>.</param>
    /// <param name="linearConstraints">The linear terms.</param>
    /// <param name="linearTargets">The linear targets <c>b</c>; <c>nl</c> canonical scalars.</param>
    /// <param name="transcriptSeed">The public-input seed the transcript is initialised with.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="reduce">Scalar-reduce backend for the challenge squeeze.</param>
    /// <param name="hash">The fixed-output transcript hash backend.</param>
    /// <param name="squeeze">The transcript XOF backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent working buffers from.</param>
    /// <returns>The proof; the caller owns its disposal.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The response and opened-column buffers and the root transfer ownership to the returned LigeroProof, which releases them through its own Dispose; the tableau and tree belong to the commitment.")]
    public static LigeroProof Prove(
        LigeroCommitment commitment,
        int linearConstraintCount,
        ReadOnlySpan<LigeroLinearConstraint> linearConstraints,
        ReadOnlySpan<byte> linearTargets,
        ReadOnlySpan<byte> transcriptSeed,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(pool);

        LigeroParameters parameters = commitment.Parameters;
        if(linearTargets.Length != linearConstraintCount * ScalarSize)
        {
            throw new ArgumentException($"Linear targets must be {linearConstraintCount * ScalarSize} bytes; received {linearTargets.Length}.", nameof(linearTargets));
        }

        AssertLinearConstraintsSatisfied(parameters, commitment.Witnesses, linearConstraintCount, linearConstraints, linearTargets, add, multiply, subtract, curve, pool);

        LigeroTableau tableau = commitment.Tableau;
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints = commitment.QuadraticConstraints;

        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownLigeroDomainLabels.LigeroV1),
            transcriptSeed,
            commitment.HashAlgorithm,
            hash,
            pool);

        transcript.AbsorbLigeroTableauRoot(commitment.Tree.Root, hash);

        //Squeeze the three tests' challenges from the commitment.
        int nwqrow = parameters.WitnessQuadraticRowCount;
        int nq = parameters.QuadraticConstraintCount;
        int nqtriples = parameters.QuadraticTripleCount;

        using IMemoryOwner<byte> challengesOwner = pool.Rent((nwqrow + linearConstraintCount + (3 * nq) + nqtriples) * ScalarSize);
        Span<byte> challenges = challengesOwner.Memory.Span[..((nwqrow + linearConstraintCount + (3 * nq) + nqtriples) * ScalarSize)];
        Span<byte> uLowDegree = challenges[..(nwqrow * ScalarSize)];
        Span<byte> alphaLinear = challenges.Slice(nwqrow * ScalarSize, linearConstraintCount * ScalarSize);
        Span<byte> alphaQuadratic = challenges.Slice((nwqrow + linearConstraintCount) * ScalarSize, 3 * nq * ScalarSize);
        Span<byte> uQuadratic = challenges.Slice((nwqrow + linearConstraintCount + (3 * nq)) * ScalarSize, nqtriples * ScalarSize);
        SqueezeChallenges(transcript, uLowDegree, alphaLinear, alphaQuadratic, uQuadratic, nwqrow, linearConstraintCount, nq, nqtriples, squeeze, hash, reduce, curve, pool);

        using IMemoryOwner<byte> matrixOwner = LigeroConstraintMatrix.Build(parameters, linearConstraintCount, linearConstraints, quadraticConstraints, alphaLinear, alphaQuadratic, add, subtract, multiply, curve, pool);

        //Compute the responses into the packed proof buffer.
        IMemoryOwner<byte> responsesOwner = pool.Rent(LigeroProof.ResponseBufferSize(parameters));
        bool transferred = false;
        try
        {
            ComputeResponses(parameters, tableau, matrixOwner.Memory.Span, uLowDegree, uQuadratic, responsesOwner.Memory.Span, add, subtract, multiply, invert, curve, pool);

            //Absorb the responses, then draw the opened-column indices.
            int block = parameters.Block;
            int dblock = parameters.DoubleBlock;
            Span<byte> responses = responsesOwner.Memory.Span;
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LowDegreeResponse), responses[..(block * ScalarSize)], hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.DotResponse), responses.Slice(block * ScalarSize, dblock * ScalarSize), hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.QuadraticResponse), responses[((block + dblock) * ScalarSize)..], hash);

            int nreq = parameters.OpenedColumnCount;
            Span<int> indices = stackalloc int[nreq];
            transcript.SqueezeLigeroDistinctColumnIndices(parameters.BlockExtension, nreq, indices, squeeze, hash);

            LigeroProof proof = OpenColumns(parameters, tableau, commitment.Tree, indices, responsesOwner, pool);
            transferred = true;

            return proof;
        }
        finally
        {
            if(!transferred)
            {
                responsesOwner.Memory.Span.Clear();
                responsesOwner.Dispose();
            }
        }
    }


    //Squeezes the four challenge vectors under their pinned labels, in schedule order.
    private static void SqueezeChallenges(
        FiatShamirTranscript transcript,
        Span<byte> uLowDegree,
        Span<byte> alphaLinear,
        Span<byte> alphaQuadratic,
        Span<byte> uQuadratic,
        int nwqrow,
        int linearConstraintCount,
        int nq,
        int nqtriples,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LowDegreeChallenge), nwqrow, uLowDegree, squeeze, hash, reduce, curve, pool);
        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LinearChallenge), linearConstraintCount, alphaLinear, squeeze, hash, reduce, curve, pool);
        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.QuadraticConstraintChallenge), 3 * nq, alphaQuadratic, squeeze, hash, reduce, curve, pool);
        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.QuadraticRowChallenge), nqtriples, uQuadratic, squeeze, hash, reduce, curve, pool);
    }


    //Computes y_ldt, y_dot and y_quad into the packed response buffer
    //(y_ldt | y_dot | y_quad_0 | y_quad_2). Asserts the witness block of y_quad
    //is zero (it must be, since the operands satisfy W[z] = W[x]·W[y]).
    private static void ComputeResponses(
        LigeroParameters parameters,
        LigeroTableau tableau,
        ReadOnlySpan<byte> matrix,
        ReadOnlySpan<byte> uLowDegree,
        ReadOnlySpan<byte> uQuadratic,
        Span<byte> responses,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;
        int nwqrow = parameters.WitnessQuadraticRowCount;
        int nqtriples = parameters.QuadraticTripleCount;

        Span<byte> yLowDegree = responses[..(block * ScalarSize)];
        Span<byte> yDot = responses.Slice(block * ScalarSize, dblock * ScalarSize);
        Span<byte> scratch = stackalloc byte[ScalarSize];

        //y_ldt = ILDT[0..block) + Σ_i u_ldt[i] · row_{iw+i}[0..block).
        tableau.GetRowSpan(LigeroParameters.LowDegreeRowIndex)[..(block * ScalarSize)].CopyTo(yLowDegree);
        for(int i = 0; i < nwqrow; i++)
        {
            ReadOnlySpan<byte> row = tableau.GetRowSpan(LigeroParameters.FirstWitnessRowIndex + i)[..(block * ScalarSize)];
            AddAssignScaled(yLowDegree, ScalarAt(uLowDegree, i), row, block, scratch, add, multiply, curve);
        }

        //y_dot = IDOT[0..dblock) + Σ_i Aext_i ⊗ row_{iw+i}[0..dblock), where
        //Aext_i is [0^r | A[i,:]] RS-extended block -> dblock.
        tableau.GetRowSpan(LigeroParameters.DotRowIndex)[..(dblock * ScalarSize)].CopyTo(yDot);

        using IMemoryOwner<byte> aextMessageOwner = pool.Rent(block * ScalarSize);
        Span<byte> aextMessage = aextMessageOwner.Memory.Span[..(block * ScalarSize)];
        using IMemoryOwner<byte> aextOwner = pool.Rent(dblock * ScalarSize);
        Span<byte> aext = aextOwner.Memory.Span[..(dblock * ScalarSize)];

        //The weights depend only on the domain and the message length; one computation serves
        //every Aext extension in the loop.
        using IMemoryOwner<byte> aextWeightsOwner = pool.Rent(block * ScalarSize);
        Span<byte> aextWeights = aextWeightsOwner.Memory.Span[..(block * ScalarSize)];
        LigeroReedSolomonEncoder.ComputeWeights(block, parameters.NodeDomain, aextWeights, subtract, multiply, invert, curve, pool);
        for(int i = 0; i < nwqrow; i++)
        {
            aextMessage.Clear();
            matrix.Slice(i * w * ScalarSize, w * ScalarSize).CopyTo(aextMessage[(r * ScalarSize)..]);
            LigeroReedSolomonEncoder.Encode(aextMessage, block, aext, dblock, parameters.NodeDomain, aextWeights, add, subtract, multiply, invert, curve, pool);

            ReadOnlySpan<byte> row = tableau.GetRowSpan(LigeroParameters.FirstWitnessRowIndex + i)[..(dblock * ScalarSize)];
            AddAssignPointwise(yDot, aext, row, dblock, scratch, add, multiply, curve);
        }

        //y_quad = IQUAD[0..dblock) + Σ_t u_quad[t] · (z_t[0..dblock) − x_t ⊗ y_t).
        using IMemoryOwner<byte> yQuadOwner = pool.Rent(dblock * ScalarSize);
        Span<byte> yQuad = yQuadOwner.Memory.Span[..(dblock * ScalarSize)];
        tableau.GetRowSpan(LigeroParameters.QuadraticRowIndex)[..(dblock * ScalarSize)].CopyTo(yQuad);

        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];
        for(int t = 0; t < nqtriples; t++)
        {
            ReadOnlySpan<byte> xRow = tableau.GetRowSpan(parameters.FirstQuadraticXRowIndex + t)[..(dblock * ScalarSize)];
            ReadOnlySpan<byte> yRow = tableau.GetRowSpan(parameters.FirstQuadraticYRowIndex + t)[..(dblock * ScalarSize)];
            ReadOnlySpan<byte> zRow = tableau.GetRowSpan(parameters.FirstQuadraticZRowIndex + t)[..(dblock * ScalarSize)];
            ReadOnlySpan<byte> uQuad = ScalarAt(uQuadratic, t);

            for(int k = 0; k < dblock; k++)
            {
                multiply(ScalarAt(xRow, k), ScalarAt(yRow, k), product, curve);
                subtract(ScalarAt(zRow, k), product, difference, curve);
                multiply(uQuad, difference, product, curve);
                add(ScalarAt(yQuad, k), product, scratch, curve);
                scratch.CopyTo(ScalarAt(yQuad, k));
            }
        }

        //The witness block [r, block) of y_quad must be zero; transmit only the
        //non-zero halves y_quad_0 = [0, r) and y_quad_2 = [block, dblock).
        for(int k = r; k < block; k++)
        {
            if(!IsZeroScalar(ScalarAt(yQuad, k)))
            {
                throw new InvalidOperationException($"y_quad witness-block entry {k} is non-zero; a quadratic operand row is inconsistent.");
            }
        }

        int quadraticLowOffset = (block + dblock) * ScalarSize;
        yQuad[..(r * ScalarSize)].CopyTo(responses.Slice(quadraticLowOffset, r * ScalarSize));
        yQuad[(block * ScalarSize)..].CopyTo(responses[(quadraticLowOffset + (r * ScalarSize))..]);
    }


    //Gathers the opened columns and their Merkle paths into a proof. The column
    //at draw position j is the tableau column DoubleBlock + indices[j]; its
    //Merkle leaf index is indices[j].
    [SuppressMessage("Reliability", "CA2000", Justification = "The opened-column buffer and the root transfer ownership to the returned LigeroProof; on a mid-loop fault the partially built paths and buffers are released before rethrow.")]
    private static LigeroProof OpenColumns(
        LigeroParameters parameters,
        LigeroTableau tableau,
        MerkleTree tree,
        ReadOnlySpan<int> indices,
        IMemoryOwner<byte> responsesOwner,
        BaseMemoryPool pool)
    {
        int nreq = parameters.OpenedColumnCount;
        int columnBytes = parameters.RowCount * ScalarSize;
        int doubleBlock = parameters.DoubleBlock;

        IMemoryOwner<byte> columnsOwner = pool.Rent(nreq * columnBytes);
        MerkleAuthenticationPath[] paths = new MerkleAuthenticationPath[nreq];
        int built = 0;
        try
        {
            Span<byte> columns = columnsOwner.Memory.Span[..(nreq * columnBytes)];
            for(int j = 0; j < nreq; j++)
            {
                tableau.GetColumn(doubleBlock + indices[j], columns.Slice(j * columnBytes, columnBytes));
                paths[j] = tree.BuildPath(indices[j], pool);
                built++;
            }

            MerkleRoot root = MerkleRoot.FromBytes(tree.Root.AsReadOnlySpan(), pool);
            return new LigeroProof(parameters, root, responsesOwner, columnsOwner, paths);
        }
        catch
        {
            for(int j = 0; j < built; j++)
            {
                paths[j].Dispose();
            }

            columnsOwner.Memory.Span.Clear();
            columnsOwner.Dispose();
            throw;
        }
    }


    //Asserts each linear constraint c holds: Σ over its terms of
    //coefficient · W[witnessIndex] equals the target b[c]. Internal so a
    //commit-then-challenge caller can fail fast before paying for the encode.
    internal static void AssertLinearConstraintsSatisfied(
        LigeroParameters parameters,
        ReadOnlySpan<byte> witnesses,
        int linearConstraintCount,
        ReadOnlySpan<LigeroLinearConstraint> linearConstraints,
        ReadOnlySpan<byte> linearTargets,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        ScalarSubtractDelegate subtract,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        if(linearConstraintCount == 0)
        {
            return;
        }

        using IMemoryOwner<byte> sumsOwner = pool.Rent(linearConstraintCount * ScalarSize);
        Span<byte> sums = sumsOwner.Memory.Span[..(linearConstraintCount * ScalarSize)];
        sums.Clear();

        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        foreach(LigeroLinearConstraint term in linearConstraints)
        {
            if((uint)term.ConstraintIndex >= (uint)linearConstraintCount)
            {
                throw new ArgumentOutOfRangeException(nameof(linearConstraints), $"Linear term constraint index {term.ConstraintIndex} is outside [0, {linearConstraintCount}).");
            }

            if((uint)term.WitnessIndex >= (uint)parameters.WitnessCount)
            {
                throw new ArgumentOutOfRangeException(nameof(linearConstraints), $"Linear term witness index {term.WitnessIndex} is outside [0, {parameters.WitnessCount}).");
            }

            multiply(term.Coefficient.Span, witnesses.Slice(term.WitnessIndex * ScalarSize, ScalarSize), product, curve);
            add(ScalarAt(sums, term.ConstraintIndex), product, scratch, curve);
            scratch.CopyTo(ScalarAt(sums, term.ConstraintIndex));
        }

        for(int c = 0; c < linearConstraintCount; c++)
        {
            subtract(ScalarAt(sums, c), ScalarAt(linearTargets, c), scratch, curve);
            if(!IsZeroScalar(scratch))
            {
                throw new InvalidOperationException($"Linear constraint {c} is unsatisfied: the witness terms do not sum to the target.");
            }
        }
    }


    //acc[k] += coefficient · vector[k] for k in [0, length).
    private static void AddAssignScaled(
        Span<byte> accumulator,
        ReadOnlySpan<byte> coefficient,
        ReadOnlySpan<byte> vector,
        int length,
        Span<byte> scratch,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> sum = stackalloc byte[ScalarSize];
        for(int k = 0; k < length; k++)
        {
            multiply(coefficient, ScalarAt(vector, k), scratch, curve);
            Span<byte> slot = ScalarAt(accumulator, k);
            add(slot, scratch, sum, curve);
            sum.CopyTo(slot);
        }
    }


    //acc[k] += a[k] · b[k] for k in [0, length).
    private static void AddAssignPointwise(
        Span<byte> accumulator,
        ReadOnlySpan<byte> a,
        ReadOnlySpan<byte> b,
        int length,
        Span<byte> scratch,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> sum = stackalloc byte[ScalarSize];
        for(int k = 0; k < length; k++)
        {
            multiply(ScalarAt(a, k), ScalarAt(b, k), scratch, curve);
            Span<byte> slot = ScalarAt(accumulator, k);
            add(slot, scratch, sum, curve);
            sum.CopyTo(slot);
        }
    }


    private static Span<byte> ScalarAt(Span<byte> buffer, int index) => buffer.Slice(index * ScalarSize, ScalarSize);

    private static ReadOnlySpan<byte> ScalarAt(ReadOnlySpan<byte> buffer, int index) => buffer.Slice(index * ScalarSize, ScalarSize);


    //A canonical scalar is the field's zero exactly when every byte is zero.
    private static bool IsZeroScalar(ReadOnlySpan<byte> scalar) => scalar.IndexOfAnyExcept((byte)0) < 0;
}
