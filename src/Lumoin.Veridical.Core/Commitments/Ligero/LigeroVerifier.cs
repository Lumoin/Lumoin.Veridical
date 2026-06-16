using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The Ligero verifier: replays the prover's Fiat-Shamir schedule against the
/// committed root, then runs the four checks that establish the witness
/// satisfies the constraint system — Merkle authentication of the opened
/// columns, the low-degree test, the dot-product (linear) test with its value
/// check, and the quadratic test.
/// </summary>
/// <remarks>
/// Every check evaluates the prover's transmitted response polynomial at the
/// opened-column positions and compares it against the same value recomputed
/// directly from the opened columns. Because the opened-column indices are drawn
/// from the transcript only after the responses are absorbed, a response that is
/// not the claimed low-degree combination disagrees at a random column with
/// overwhelming probability. Structural reference: "Ligero" (Ames, Hazay, Ishai,
/// Venkitasubramaniam, IACR ePrint 2022/1608); no code dependency.
/// </remarks>
public static class LigeroVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Verifies <paramref name="proof"/> against the public constraint system.
    /// </summary>
    /// <param name="parameters">The tableau layout the proof was produced under.</param>
    /// <param name="proof">The proof to check.</param>
    /// <param name="linearConstraintCount">The number of linear constraints <c>nl</c>.</param>
    /// <param name="linearConstraints">The linear terms.</param>
    /// <param name="linearTargets">The linear targets <c>b</c>; <c>nl</c> canonical scalars.</param>
    /// <param name="quadraticConstraints">The multiplication constraints.</param>
    /// <param name="transcriptSeed">The public-input seed; must match the prover's.</param>
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
    /// <returns><see langword="true"/> iff every check passes.</returns>
    /// <exception cref="ArgumentNullException">When a backend, the parameters, the proof or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the layout.</exception>
    public static bool Verify(
        LigeroParameters parameters,
        LigeroProof proof,
        int linearConstraintCount,
        ReadOnlySpan<LigeroLinearConstraint> linearConstraints,
        ReadOnlySpan<byte> linearTargets,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        ReadOnlySpan<byte> transcriptSeed,
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
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(columnHash);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(pool);

        if(linearTargets.Length != linearConstraintCount * ScalarSize)
        {
            throw new ArgumentException($"Linear targets must be {linearConstraintCount * ScalarSize} bytes; received {linearTargets.Length}.", nameof(linearTargets));
        }

        int nwqrow = parameters.WitnessQuadraticRowCount;
        int nq = parameters.QuadraticConstraintCount;
        int nqtriples = parameters.QuadraticTripleCount;
        int nreq = parameters.OpenedColumnCount;

        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownLigeroDomainLabels.LigeroV1),
            transcriptSeed,
            hashAlgorithm,
            hash,
            pool);

        transcript.AbsorbLigeroTableauRoot(proof.Root, hash);

        using IMemoryOwner<byte> challengesOwner = pool.Rent((nwqrow + linearConstraintCount + (3 * nq) + nqtriples) * ScalarSize);
        Span<byte> challenges = challengesOwner.Memory.Span[..((nwqrow + linearConstraintCount + (3 * nq) + nqtriples) * ScalarSize)];
        Span<byte> uLowDegree = challenges[..(nwqrow * ScalarSize)];
        Span<byte> alphaLinear = challenges.Slice(nwqrow * ScalarSize, linearConstraintCount * ScalarSize);
        Span<byte> alphaQuadratic = challenges.Slice((nwqrow + linearConstraintCount) * ScalarSize, 3 * nq * ScalarSize);
        Span<byte> uQuadratic = challenges.Slice((nwqrow + linearConstraintCount + (3 * nq)) * ScalarSize, nqtriples * ScalarSize);

        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LowDegreeChallenge), nwqrow, uLowDegree, squeeze, hash, reduce, curve, pool);
        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LinearChallenge), linearConstraintCount, alphaLinear, squeeze, hash, reduce, curve, pool);
        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.QuadraticConstraintChallenge), 3 * nq, alphaQuadratic, squeeze, hash, reduce, curve, pool);
        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.QuadraticRowChallenge), nqtriples, uQuadratic, squeeze, hash, reduce, curve, pool);

        using IMemoryOwner<byte> matrixOwner = LigeroConstraintMatrix.Build(parameters, linearConstraintCount, linearConstraints, quadraticConstraints, alphaLinear, alphaQuadratic, add, subtract, multiply, curve, pool);

        //Absorb the responses in the prover's order, then re-derive the indices.
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.LowDegreeResponse), proof.LowDegreeResponse, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.DotResponse), proof.DotResponse, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.QuadraticResponse), proof.QuadraticResponse, hash);

        Span<int> indices = stackalloc int[nreq];
        transcript.SqueezeLigeroDistinctColumnIndices(parameters.BlockExtension, nreq, indices, squeeze, hash);

        //The opened-column evaluation points: column DoubleBlock + idx maps to RS
        //node DoubleBlock + idx for both the block- and dblock-degree interpolants.
        Span<int> points = stackalloc int[nreq];
        for(int j = 0; j < nreq; j++)
        {
            points[j] = dblock + indices[j];
        }

        if(!MerkleCheck(proof, indices, columnHash, merkleHash, hashAlgorithm))
        {
            return false;
        }

        using IMemoryOwner<byte> weightsBlockOwner = pool.Rent(block * ScalarSize);
        Span<byte> weightsBlock = weightsBlockOwner.Memory.Span[..(block * ScalarSize)];
        using IMemoryOwner<byte> weightsDoubleBlockOwner = pool.Rent(dblock * ScalarSize);
        Span<byte> weightsDoubleBlock = weightsDoubleBlockOwner.Memory.Span[..(dblock * ScalarSize)];
        if(parameters.NodeDomain == LigeroNodeDomain.BinaryField)
        {
            BarycentricInterpolation.ComputeBinaryNodeWeights(block, weightsBlock, multiply, invert, curve, pool);
            BarycentricInterpolation.ComputeBinaryNodeWeights(dblock, weightsDoubleBlock, multiply, invert, curve, pool);
        }
        else
        {
            BarycentricInterpolation.ComputeConsecutiveNodeWeights(block, weightsBlock, subtract, multiply, invert, curve, pool);
            BarycentricInterpolation.ComputeConsecutiveNodeWeights(dblock, weightsDoubleBlock, subtract, multiply, invert, curve, pool);
        }

        if(!LowDegreeCheck(parameters, proof, indices, points, uLowDegree, weightsBlock, add, subtract, multiply, invert, curve, pool))
        {
            return false;
        }

        if(!DotCheck(parameters, proof, indices, points, matrixOwner.Memory.Span, alphaLinear, linearTargets, linearConstraintCount, weightsBlock, weightsDoubleBlock, add, subtract, multiply, invert, curve, pool))
        {
            return false;
        }

        return QuadraticCheck(parameters, proof, indices, points, uQuadratic, weightsDoubleBlock, add, subtract, multiply, invert, curve, pool);
    }


    //Recompute each opened column's leaf from its bytes and authenticate it.
    private static bool MerkleCheck(
        LigeroProof proof,
        ReadOnlySpan<int> indices,
        FiatShamirHashDelegate columnHash,
        MerkleHashDelegate merkleHash,
        string hashAlgorithm)
    {
        Span<byte> leaf = stackalloc byte[ScalarSize];
        for(int j = 0; j < indices.Length; j++)
        {
            columnHash(proof.OpenedColumn(j), leaf, hashAlgorithm);
            if(!proof.GetPath(j).Verify(proof.Root, indices[j], leaf, merkleHash))
            {
                return false;
            }
        }

        return true;
    }


    //yc[j] = req[ILDT,j] + Σ_i u_ldt[i]·req[IW+i,j]; yp[j] = y_ldt interpolated to
    //the opened positions. Pass iff yc == yp at every opened column.
    private static bool LowDegreeCheck(
        LigeroParameters parameters,
        LigeroProof proof,
        ReadOnlySpan<int> indices,
        ReadOnlySpan<int> points,
        ReadOnlySpan<byte> uLowDegree,
        ReadOnlySpan<byte> weightsBlock,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int nreq = indices.Length;
        int nwqrow = parameters.WitnessQuadraticRowCount;

        using IMemoryOwner<byte> ypOwner = pool.Rent(nreq * ScalarSize);
        Span<byte> yp = ypOwner.Memory.Span[..(nreq * ScalarSize)];
        BarycentricInterpolation.EvaluateAtPoints(proof.LowDegreeResponse, weightsBlock, parameters.Block, points, yp, add, subtract, multiply, invert, curve, pool);

        Span<byte> accumulator = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        for(int j = 0; j < nreq; j++)
        {
            ReqAt(proof, j, LigeroParameters.LowDegreeRowIndex).CopyTo(accumulator);
            for(int i = 0; i < nwqrow; i++)
            {
                AddScaled(accumulator, ScalarAt(uLowDegree, i), ReqAt(proof, j, LigeroParameters.FirstWitnessRowIndex + i), scratch, add, multiply, curve);
            }

            if(!accumulator.SequenceEqual(ScalarAt(yp, j)))
            {
                return false;
            }
        }

        return true;
    }


    //yc[j] = req[IDOT,j] + Σ_i Areq_i[j]·req[IW+i,j], where Areq_i is Aext_i
    //evaluated at the opened positions; yp[j] = y_dot interpolated there. Plus the
    //value check Σ_c b[c]·αl[c] == Σ_{k∈[r,block)} y_dot[k].
    private static bool DotCheck(
        LigeroParameters parameters,
        LigeroProof proof,
        ReadOnlySpan<int> indices,
        ReadOnlySpan<int> points,
        ReadOnlySpan<byte> matrix,
        ReadOnlySpan<byte> alphaLinear,
        ReadOnlySpan<byte> linearTargets,
        int linearConstraintCount,
        ReadOnlySpan<byte> weightsBlock,
        ReadOnlySpan<byte> weightsDoubleBlock,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int nreq = indices.Length;
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;
        int nwqrow = parameters.WitnessQuadraticRowCount;

        using IMemoryOwner<byte> ypOwner = pool.Rent(nreq * ScalarSize);
        Span<byte> yp = ypOwner.Memory.Span[..(nreq * ScalarSize)];
        BarycentricInterpolation.EvaluateAtPoints(proof.DotResponse, weightsDoubleBlock, dblock, points, yp, add, subtract, multiply, invert, curve, pool);

        using IMemoryOwner<byte> ycOwner = pool.Rent(nreq * ScalarSize);
        Span<byte> yc = ycOwner.Memory.Span[..(nreq * ScalarSize)];
        for(int j = 0; j < nreq; j++)
        {
            ReqAt(proof, j, LigeroParameters.DotRowIndex).CopyTo(ScalarAt(yc, j));
        }

        //Per row: evaluate Aext_i = [0^r | A[i,:]] (extended from block) at the
        //opened points, then yc[j] += Areq_i[j]·req[IW+i,j].
        using IMemoryOwner<byte> aextMessageOwner = pool.Rent(block * ScalarSize);
        Span<byte> aextMessage = aextMessageOwner.Memory.Span[..(block * ScalarSize)];
        using IMemoryOwner<byte> areqOwner = pool.Rent(nreq * ScalarSize);
        Span<byte> areq = areqOwner.Memory.Span[..(nreq * ScalarSize)];

        Span<byte> scratch = stackalloc byte[ScalarSize];
        for(int i = 0; i < nwqrow; i++)
        {
            aextMessage.Clear();
            matrix.Slice(i * w * ScalarSize, w * ScalarSize).CopyTo(aextMessage[(r * ScalarSize)..]);
            BarycentricInterpolation.EvaluateAtPoints(aextMessage, weightsBlock, block, points, areq, add, subtract, multiply, invert, curve, pool);

            for(int j = 0; j < nreq; j++)
            {
                AddScaled(ScalarAt(yc, j), ScalarAt(areq, j), ReqAt(proof, j, LigeroParameters.FirstWitnessRowIndex + i), scratch, add, multiply, curve);
            }
        }

        for(int j = 0; j < nreq; j++)
        {
            if(!ScalarAt(yc, j).SequenceEqual(ScalarAt(yp, j)))
            {
                return false;
            }
        }

        //Value check: Σ_c b[c]·αl[c] must equal the witness-block sum of y_dot.
        Span<byte> left = stackalloc byte[ScalarSize];
        left.Clear();
        for(int c = 0; c < linearConstraintCount; c++)
        {
            AddScaled(left, ScalarAt(linearTargets, c), ScalarAt(alphaLinear, c), scratch, add, multiply, curve);
        }

        Span<byte> right = stackalloc byte[ScalarSize];
        right.Clear();
        ReadOnlySpan<byte> dotResponse = proof.DotResponse;
        for(int k = r; k < block; k++)
        {
            add(right, ScalarAt(dotResponse, k), scratch, curve);
            scratch.CopyTo(right);
        }

        return left.SequenceEqual(right);
    }


    //yc[j] = req[IQUAD,j] + Σ_t u_quad[t]·(req[IQZ+t,j] − req[IQX+t,j]·req[IQY+t,j]);
    //yp[j] = the rebuilt y_quad = [y_quad_0 | 0^w | y_quad_2] interpolated there.
    private static bool QuadraticCheck(
        LigeroParameters parameters,
        LigeroProof proof,
        ReadOnlySpan<int> indices,
        ReadOnlySpan<int> points,
        ReadOnlySpan<byte> uQuadratic,
        ReadOnlySpan<byte> weightsDoubleBlock,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int nreq = indices.Length;
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int nqtriples = parameters.QuadraticTripleCount;

        //Rebuild the full y_quad = [y_quad_0 | 0^w | y_quad_2] and interpolate.
        using IMemoryOwner<byte> yQuadOwner = pool.Rent(dblock * ScalarSize);
        Span<byte> yQuad = yQuadOwner.Memory.Span[..(dblock * ScalarSize)];
        yQuad.Clear();
        proof.QuadraticResponseLow.CopyTo(yQuad[..(r * ScalarSize)]);
        proof.QuadraticResponseHigh.CopyTo(yQuad[(block * ScalarSize)..]);

        using IMemoryOwner<byte> ypOwner = pool.Rent(nreq * ScalarSize);
        Span<byte> yp = ypOwner.Memory.Span[..(nreq * ScalarSize)];
        BarycentricInterpolation.EvaluateAtPoints(yQuad, weightsDoubleBlock, dblock, points, yp, add, subtract, multiply, invert, curve, pool);

        Span<byte> accumulator = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> scaled = stackalloc byte[ScalarSize];
        for(int j = 0; j < nreq; j++)
        {
            ReqAt(proof, j, LigeroParameters.QuadraticRowIndex).CopyTo(accumulator);
            for(int t = 0; t < nqtriples; t++)
            {
                multiply(ReqAt(proof, j, parameters.FirstQuadraticXRowIndex + t), ReqAt(proof, j, parameters.FirstQuadraticYRowIndex + t), product, curve);
                subtract(ReqAt(proof, j, parameters.FirstQuadraticZRowIndex + t), product, difference, curve);
                multiply(ScalarAt(uQuadratic, t), difference, scaled, curve);
                add(accumulator, scaled, product, curve);
                product.CopyTo(accumulator);
            }

            if(!accumulator.SequenceEqual(ScalarAt(yp, j)))
            {
                return false;
            }
        }

        return true;
    }


    //accumulator += coefficient · value.
    private static void AddScaled(
        Span<byte> accumulator,
        ReadOnlySpan<byte> coefficient,
        ReadOnlySpan<byte> value,
        Span<byte> scratch,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        multiply(coefficient, value, scratch, curve);
        Span<byte> sum = stackalloc byte[ScalarSize];
        add(accumulator, scratch, sum, curve);
        sum.CopyTo(accumulator);
    }


    //The j-th opened column's entry for the given tableau row.
    private static ReadOnlySpan<byte> ReqAt(LigeroProof proof, int openedColumnIndex, int rowIndex) =>
        proof.OpenedColumn(openedColumnIndex).Slice(rowIndex * ScalarSize, ScalarSize);


    private static Span<byte> ScalarAt(Span<byte> buffer, int index) => buffer.Slice(index * ScalarSize, ScalarSize);

    private static ReadOnlySpan<byte> ScalarAt(ReadOnlySpan<byte> buffer, int index) => buffer.Slice(index * ScalarSize, ScalarSize);
}
