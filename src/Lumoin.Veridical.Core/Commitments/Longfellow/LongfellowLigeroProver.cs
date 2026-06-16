using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The wire-format-conformant Ligero prove flow, a faithful port of google/longfellow-zk's
/// <c>LigeroProver::prove</c> (<c>lib/ligero/ligero_prover.h</c>). Given a standing
/// <see cref="LongfellowLigeroCommitment"/> and the linear constraints, it answers the verifier's
/// three tests — low-degree, dot-product (linear) and quadratic — over the
/// <see cref="LongfellowTranscript"/>, then opens the challenged columns with their compressed Merkle
/// multi-proof, producing a <see cref="LongfellowLigeroProof"/> whose every field mirrors the
/// reference's <c>LigeroProof</c>.
/// </summary>
/// <remarks>
/// <para>
/// The transcript schedule, byte-precise (the commitment root is absorbed by the caller before this
/// runs, exactly as the reference's <c>commit()</c> does its <c>write_commitment</c>):
/// </para>
/// <list type="number">
///   <item><description>absorb <c>hash_of_llterm</c> (the theorem statement), 32 bytes through the byte-string write.</description></item>
///   <item><description>squeeze <c>u_ldt</c> (<c>nwqrow</c> elements); compute <c>y_ldt</c>.</description></item>
///   <item><description>squeeze <c>alphal</c> (<c>nl</c> elements) and <c>alphaq</c> (<c>3·nq</c> elements); build the inner-product vector <c>A</c>; compute <c>y_dot</c>.</description></item>
///   <item><description>squeeze <c>u_quad</c> (<c>nqtriples</c> elements); compute <c>y_quad_0</c>, <c>y_quad_2</c>.</description></item>
///   <item><description>absorb the four response rows (<c>y_ldt</c>, <c>y_dot</c>, <c>y_quad_0</c>, <c>y_quad_2</c>) as field-element arrays.</description></item>
///   <item><description>squeeze <c>idx</c> (<c>nreq</c> distinct columns in <c>[0, block_ext)</c>); gather the opened columns; open the Merkle proof.</description></item>
/// </list>
/// <para>
/// Drawing <c>idx</c> only after the responses are absorbed is what stops the prover from tailoring a
/// response to the columns that will be checked — the soundness of the commit-then-challenge order.
/// </para>
/// <para>
/// The response-row linear algebra, mirroring <c>blas.h</c> over the LCH14 binary field:
/// </para>
/// <list type="bullet">
///   <item><description><c>y_ldt[0..block)</c> = ILDT row's block prefix, plus <c>Σ_i u_ldt[i] · row_{iw+i}[0..block)</c> over the <c>nwqrow</c> witness-and-quadratic rows.</description></item>
///   <item><description><c>y_dot[0..dblock)</c> = IDOT row's dblock prefix, plus <c>Σ_i Aext_i ⊙ row_{iw+i}[0..dblock)</c>, where <c>Aext_i = [0^r | A[i,:]]</c> RS-extended block→dblock and <c>⊙</c> is the pointwise product.</description></item>
///   <item><description><c>y_quad[0..dblock)</c> = IQUAD row's dblock prefix, plus <c>Σ_t u_quad[t] · (z_t[0..dblock) − x_t ⊙ y_t)</c> over the <c>nqtriples</c> triples; the witness block <c>[r, block)</c> is provably zero and only the two halves <c>y_quad_0 = [0, r)</c> and <c>y_quad_2 = [block, dblock)</c> are transmitted.</description></item>
///   <item><description><c>req[i, :]</c> gathers row <c>i</c>'s tableau elements at the opened extension columns <c>dblock + idx[j]</c>, for every row <c>i</c> in <c>[0, nrow)</c>.</description></item>
/// </list>
/// <para>
/// The inner-product vector <c>A[nwqrow, w]</c> folds the constraints with their challenges
/// (<c>LigeroCommon::inner_product_vector</c>): each linear term adds <c>k · alphal[c]</c> to its
/// witness column, and each quadratic constraint adds its three <c>alphaq</c> challenges to the
/// routing rows while subtracting them from the multiplicand witness columns.
/// </para>
/// </remarks>
internal static class LongfellowLigeroProver
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The reference's MerkleNonce::kLength and Digest::kLength: nonce and digest are 32 bytes each.
    private const int NonceLength = 32;
    private const int DigestLength = 32;


    /// <summary>
    /// Proves the committed witness satisfies the linear constraints (and the quadratic constraints
    /// the commitment was built over), reading the already-encoded tableau out of
    /// <paramref name="commitment"/>. The commitment is not consumed; the caller disposes it.
    /// </summary>
    /// <param name="commitment">The standing commitment from <see cref="LongfellowLigeroCommitment.Commit(LongfellowLigeroParameters, ReadOnlySpan{byte}, ReadOnlySpan{LigeroQuadraticConstraint}, int, int, LongfellowRandomByteSource, LongfellowRowEncoderFactory, LongfellowFieldProfile, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, Lumoin.Veridical.Core.Commitments.BaseFold.MerkleHashDelegate, FiatShamirHashDelegate, string, CurveParameterSet, BaseMemoryPool)"/>.</param>
    /// <param name="transcript">The transcript, already seeded and with the commitment root absorbed; this flow drives it from the theorem-statement absorb onward.</param>
    /// <param name="linearConstraintCount">The number of linear constraints <c>nl</c>.</param>
    /// <param name="linearConstraints">The linear terms; each contributes <c>coefficient · W[witnessIndex]</c> to its constraint.</param>
    /// <param name="theoremStatementHash">The 32-byte <c>hash_of_llterm</c> absorbed before any challenge.</param>
    /// <param name="quadraticConstraints">The multiplication constraints; exactly <see cref="LongfellowLigeroParameters.QuadraticConstraintCount"/> of them, identical to those the commitment was built over.</param>
    /// <param name="encoderFactory">Builds the systematic Reed–Solomon row encoder per shape (the Aext block→dblock extension): binary LCH14 or prime FFT-convolution.</param>
    /// <param name="profile">The field profile: the on-wire element width and the <c>to_bytes_field</c> framing for the response absorbs.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent working buffers from.</param>
    /// <returns>The proof; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a backend, the commitment, the transcript or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the layout.</exception>
    /// <exception cref="InvalidOperationException">When the quadratic response's witness block is non-zero (an inconsistent operand row).</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The response, opened-column, nonce and path buffers transfer ownership to the returned LongfellowLigeroProof, which releases them through its own Dispose; on a fault they are released before rethrow.")]
    public static LongfellowLigeroProof Prove(
        LongfellowLigeroCommitment commitment,
        LongfellowTranscript transcript,
        int linearConstraintCount,
        ReadOnlySpan<LigeroLinearConstraint> linearConstraints,
        ReadOnlySpan<byte> theoremStatementHash,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(encoderFactory);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);

        LongfellowLigeroParameters parameters = commitment.Parameters;

        if(theoremStatementHash.Length != DigestLength)
        {
            throw new ArgumentException($"The theorem statement hash is {DigestLength} bytes; received {theoremStatementHash.Length}.", nameof(theoremStatementHash));
        }

        if(quadraticConstraints.Length != parameters.QuadraticConstraintCount)
        {
            throw new ArgumentException($"Expected {parameters.QuadraticConstraintCount} quadratic constraints; received {quadraticConstraints.Length}.", nameof(quadraticConstraints));
        }

        int nwqrow = parameters.WitnessQuadraticRowCount;
        int nq = parameters.QuadraticConstraintCount;
        int nqtriples = parameters.QuadraticTripleCount;

        //Absorb the theorem statement, then squeeze the four challenge vectors in schedule order.
        transcript.AbsorbByteString(theoremStatementHash);

        int challengeCount = nwqrow + linearConstraintCount + (3 * nq) + nqtriples;
        using IMemoryOwner<byte> challengesOwner = pool.Rent(challengeCount * ScalarSize);
        Span<byte> challenges = challengesOwner.Memory.Span[..(challengeCount * ScalarSize)];
        Span<byte> uLowDegree = challenges[..(nwqrow * ScalarSize)];
        Span<byte> alphaLinear = challenges.Slice(nwqrow * ScalarSize, linearConstraintCount * ScalarSize);
        Span<byte> alphaQuadratic = challenges.Slice((nwqrow + linearConstraintCount) * ScalarSize, 3 * nq * ScalarSize);
        Span<byte> uQuadratic = challenges.Slice((nwqrow + linearConstraintCount + (3 * nq)) * ScalarSize, nqtriples * ScalarSize);

        SqueezeFieldElements(transcript, profile, uLowDegree, nwqrow);
        SqueezeFieldElements(transcript, profile, alphaLinear, linearConstraintCount);
        SqueezeFieldElements(transcript, profile, alphaQuadratic, 3 * nq);
        SqueezeFieldElements(transcript, profile, uQuadratic, nqtriples);

        //Fold the constraints with their challenges into A[nwqrow, w].
        using IMemoryOwner<byte> matrixOwner = pool.Rent(nwqrow * parameters.WitnessPerRow * ScalarSize);
        Span<byte> matrix = matrixOwner.Memory.Span[..(nwqrow * parameters.WitnessPerRow * ScalarSize)];
        BuildInnerProductVector(parameters, linearConstraintCount, linearConstraints, quadraticConstraints, alphaLinear, alphaQuadratic, matrix, add, subtract, multiply, curve);

        IMemoryOwner<byte> responseOwner = pool.Rent(LongfellowLigeroProof.ResponseBufferSize(parameters));
        bool transferred = false;
        try
        {
            ComputeResponses(commitment, parameters, matrix, uLowDegree, uQuadratic, responseOwner.Memory.Span, encoderFactory, add, subtract, multiply, curve, pool);

            AbsorbResponses(transcript, parameters, profile, responseOwner.Memory.Span, pool);

            //The opened-column indices are pooled like every other proof member; ownership passes
            //to OpenColumns once the squeeze has filled them.
            int nreq = parameters.OpenedColumnCount;
            IMemoryOwner<byte> indicesOwner = pool.Rent(nreq * sizeof(int));
            bool indicesTransferred = false;
            try
            {
                Span<int> indices = MemoryMarshal.Cast<byte, int>(indicesOwner.Memory.Span[..(nreq * sizeof(int))]);
                transcript.SqueezeIndexSubset(parameters.BlockExtension, nreq, indices);

                indicesTransferred = true;
                LongfellowLigeroProof proof = OpenColumns(commitment, parameters, indicesOwner, responseOwner, pool);
                transferred = true;

                return proof;
            }
            finally
            {
                if(!indicesTransferred)
                {
                    indicesOwner.Memory.Span[..(nreq * sizeof(int))].Clear();
                    indicesOwner.Dispose();
                }
            }
        }
        finally
        {
            if(!transferred)
            {
                responseOwner.Memory.Span[..LongfellowLigeroProof.ResponseBufferSize(parameters)].Clear();
                responseOwner.Dispose();
            }
        }
    }


    //Absorbs the four response rows as field-element arrays (the reference's ts.write(y, 1, n, F)).
    //Each row is converted to the field's little-endian to_bytes_field framing the transcript expects.
    private static void AbsorbResponses(LongfellowTranscript transcript, LongfellowLigeroParameters parameters, LongfellowFieldProfile profile, ReadOnlySpan<byte> responses, BaseMemoryPool pool)
    {
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int quadHigh = dblock - block;

        AbsorbElementArray(transcript, profile, responses[..(block * ScalarSize)], block, pool);
        AbsorbElementArray(transcript, profile, responses.Slice(block * ScalarSize, dblock * ScalarSize), dblock, pool);
        AbsorbElementArray(transcript, profile, responses.Slice((block + dblock) * ScalarSize, r * ScalarSize), r, pool);
        AbsorbElementArray(transcript, profile, responses[(((block + dblock) * ScalarSize) + (r * ScalarSize))..], quadHigh, pool);
    }


    //Converts `count` canonical scalars to the field's little-endian framing and absorbs them as one
    //field-element array.
    private static void AbsorbElementArray(LongfellowTranscript transcript, LongfellowFieldProfile profile, ReadOnlySpan<byte> canonical, int count, BaseMemoryPool pool)
    {
        int elementBytes = profile.ElementBytes;
        using IMemoryOwner<byte> owner = pool.Rent(Math.Max(count, 1) * elementBytes);
        Span<byte> littleEndian = owner.Memory.Span[..(count * elementBytes)];
        try
        {
            for(int i = 0; i < count; i++)
            {
                profile.ToBytesField(canonical.Slice(i * ScalarSize, ScalarSize), littleEndian.Slice(i * elementBytes, elementBytes));
            }

            transcript.AbsorbFieldElementArray(littleEndian, count, elementBytes);
        }
        finally
        {
            littleEndian.Clear();
        }
    }


    //Squeezes `count` challenge field elements through the field's sample loop, the shape of
    //gen_uldt / gen_alphal / gen_alphaq / gen_uquad (each a tsv.elt(Elt[], n, F) = elt(F) per element).
    //GF(2^128) is one 16-byte draw per element (never rejects); the Fp256 profile reject-redraws.
    private static void SqueezeFieldElements(LongfellowTranscript transcript, LongfellowFieldProfile profile, Span<byte> destination, int count)
    {
        for(int i = 0; i < count; i++)
        {
            transcript.SqueezeFieldElement(profile, destination.Slice(i * ScalarSize, ScalarSize));
        }
    }


    //Folds the linear and quadratic constraints into A[nwqrow, w] (LigeroCommon::inner_product_vector).
    //The layout: the first nwrow rows are witness rows, then nqtriples x-routing rows, nqtriples
    //y-routing rows, nqtriples z-routing rows. A linear term adds k·alphal[c] to its witness column;
    //a quadratic constraint adds its three alphaq challenges to the routing rows and subtracts them
    //from the multiplicand witness columns.
    private static void BuildInnerProductVector(
        LongfellowLigeroParameters parameters,
        int linearConstraintCount,
        ReadOnlySpan<LigeroLinearConstraint> linearConstraints,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        ReadOnlySpan<byte> alphaLinear,
        ReadOnlySpan<byte> alphaQuadratic,
        Span<byte> matrix,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        int w = parameters.WitnessPerRow;
        int nwrow = parameters.WitnessRowCount;
        int nqtriples = parameters.QuadraticTripleCount;
        int witnessCount = parameters.WitnessCount;

        matrix.Clear();

        //Linear terms: A[term.w] += term.k · alphal[term.c]. A's flat index is the witness index,
        //because the witness rows store W[i*w + k] at flat position i*w + k = the witness index.
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        foreach(LigeroLinearConstraint term in linearConstraints)
        {
            if((uint)term.ConstraintIndex >= (uint)linearConstraintCount)
            {
                throw new ArgumentOutOfRangeException(nameof(linearConstraints), $"Linear term constraint index {term.ConstraintIndex} is outside [0, {linearConstraintCount}).");
            }

            if((uint)term.WitnessIndex >= (uint)witnessCount)
            {
                throw new ArgumentOutOfRangeException(nameof(linearConstraints), $"Linear term witness index {term.WitnessIndex} is outside [0, {witnessCount}).");
            }

            multiply(term.Coefficient.Span, ScalarAt(alphaLinear, term.ConstraintIndex), product, curve);
            AddInPlace(ScalarAt(matrix, term.WitnessIndex), product, scratch, add, curve);
        }

        //Routing terms. Ax begins at flat offset nwrow*w, Ay at nwrow*w + nqtriples*w, Az after that.
        int axBase = nwrow * w;
        int ayBase = axBase + (nqtriples * w);
        int azBase = ayBase + (nqtriples * w);

        for(int i = 0; i < nqtriples; i++)
        {
            for(int j = 0; j < w; j++)
            {
                int constraintIndex = j + (i * w);
                if(constraintIndex >= parameters.QuadraticConstraintCount)
                {
                    break;
                }

                LigeroQuadraticConstraint constraint = quadraticConstraints[constraintIndex];
                ReadOnlySpan<byte> alphaX = ScalarAt(alphaQuadratic, 3 * constraintIndex);
                ReadOnlySpan<byte> alphaY = ScalarAt(alphaQuadratic, (3 * constraintIndex) + 1);
                ReadOnlySpan<byte> alphaZ = ScalarAt(alphaQuadratic, (3 * constraintIndex) + 2);

                AddInPlace(ScalarAt(matrix, axBase + constraintIndex), alphaX, scratch, add, curve);
                SubtractInPlace(ScalarAt(matrix, constraint.XIndex), alphaX, scratch, subtract, curve);

                AddInPlace(ScalarAt(matrix, ayBase + constraintIndex), alphaY, scratch, add, curve);
                SubtractInPlace(ScalarAt(matrix, constraint.YIndex), alphaY, scratch, subtract, curve);

                AddInPlace(ScalarAt(matrix, azBase + constraintIndex), alphaZ, scratch, add, curve);
                SubtractInPlace(ScalarAt(matrix, constraint.ZIndex), alphaZ, scratch, subtract, curve);
            }
        }
    }


    //Computes y_ldt, y_dot and y_quad into the packed response buffer
    //(y_ldt | y_dot | y_quad_0 | y_quad_2). The middle witness block of y_quad must be zero.
    private static void ComputeResponses(
        LongfellowLigeroCommitment commitment,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> matrix,
        ReadOnlySpan<byte> uLowDegree,
        ReadOnlySpan<byte> uQuadratic,
        Span<byte> responses,
        LongfellowRowEncoderFactory encoderFactory,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;
        int nwqrow = parameters.WitnessQuadraticRowCount;
        int nqtriples = parameters.QuadraticTripleCount;
        int firstWitnessRow = LongfellowLigeroParameters.FirstWitnessRowIndex;

        Span<byte> yLowDegree = responses[..(block * ScalarSize)];
        Span<byte> yDot = responses.Slice(block * ScalarSize, dblock * ScalarSize);
        Span<byte> scratch = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];

        //y_ldt = ILDT[0..block) + Σ_i u_ldt[i] · row_{iw+i}[0..block).
        CopyRowPrefix(commitment, LongfellowLigeroParameters.LowDegreeRowIndex, block, yLowDegree);
        for(int i = 0; i < nwqrow; i++)
        {
            ReadOnlySpan<byte> coefficient = ScalarAt(uLowDegree, i);
            for(int k = 0; k < block; k++)
            {
                multiply(coefficient, commitment.ElementAt(firstWitnessRow + i, k), term, curve);
                AddInPlace(ScalarAt(yLowDegree, k), term, scratch, add, curve);
            }
        }

        //y_dot = IDOT[0..dblock) + Σ_i Aext_i ⊙ row_{iw+i}[0..dblock), where
        //Aext_i = [0^r | A[i,:]] RS-extended block -> dblock.
        CopyRowPrefix(commitment, LongfellowLigeroParameters.DotRowIndex, dblock, yDot);

        using LongfellowRowEncoder aextRs = encoderFactory(block, dblock);
        using IMemoryOwner<byte> aextOwner = pool.Rent(dblock * ScalarSize);
        Span<byte> aext = aextOwner.Memory.Span[..(dblock * ScalarSize)];
        try
        {
            for(int i = 0; i < nwqrow; i++)
            {
                //Aext message = [0^r | A[i,:]] over block columns; the rest of the dblock buffer is the
                //RS extension, filled in place.
                aext.Clear();
                matrix.Slice(i * w * ScalarSize, w * ScalarSize).CopyTo(aext.Slice(r * ScalarSize, w * ScalarSize));
                aextRs.Interpolate(aext);

                for(int k = 0; k < dblock; k++)
                {
                    multiply(ScalarAt(aext, k), commitment.ElementAt(firstWitnessRow + i, k), term, curve);
                    AddInPlace(ScalarAt(yDot, k), term, scratch, add, curve);
                }
            }
        }
        finally
        {
            aext.Clear();
        }

        //y_quad = IQUAD[0..dblock) + Σ_t u_quad[t] · (z_t[0..dblock) − x_t ⊙ y_t).
        using IMemoryOwner<byte> yQuadOwner = pool.Rent(dblock * ScalarSize);
        Span<byte> yQuad = yQuadOwner.Memory.Span[..(dblock * ScalarSize)];
        try
        {
            CopyRowPrefix(commitment, LongfellowLigeroParameters.QuadraticRowIndex, dblock, yQuad);

            Span<byte> difference = stackalloc byte[ScalarSize];
            for(int t = 0; t < nqtriples; t++)
            {
                int xRow = parameters.FirstQuadraticXRowIndex + t;
                int yRow = parameters.FirstQuadraticYRowIndex + t;
                int zRow = parameters.FirstQuadraticZRowIndex + t;
                ReadOnlySpan<byte> uQuad = ScalarAt(uQuadratic, t);

                for(int k = 0; k < dblock; k++)
                {
                    multiply(commitment.ElementAt(xRow, k), commitment.ElementAt(yRow, k), term, curve);
                    subtract(commitment.ElementAt(zRow, k), term, difference, curve);
                    multiply(uQuad, difference, term, curve);
                    AddInPlace(ScalarAt(yQuad, k), term, scratch, add, curve);
                }
            }

            //The witness block [r, block) of y_quad must be zero; transmit only the non-zero halves
            //y_quad_0 = [0, r) and y_quad_2 = [block, dblock).
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
        finally
        {
            yQuad.Clear();
        }
    }


    //Gathers the opened columns req[nrow, nreq] (the tableau elements at columns dblock + idx[j]),
    //the per-leaf nonces and the compressed Merkle multi-proof into a proof. The column at draw
    //position j is the extension column dblock + idx[j]; its Merkle leaf index is idx[j].
    [SuppressMessage("Reliability", "CA2000", Justification = "The opened-column, nonce and path buffers transfer ownership to the returned LongfellowLigeroProof; on a fault they are released before rethrow.")]
    private static LongfellowLigeroProof OpenColumns(
        LongfellowLigeroCommitment commitment,
        LongfellowLigeroParameters parameters,
        IMemoryOwner<byte> indicesOwner,
        IMemoryOwner<byte> responseOwner,
        BaseMemoryPool pool)
    {
        int nreq = parameters.OpenedColumnCount;
        int rowCount = parameters.RowCount;
        int doubleBlock = parameters.DoubleBlock;
        int blockExtension = parameters.BlockExtension;
        ReadOnlySpan<int> indices = MemoryMarshal.Cast<byte, int>(indicesOwner.Memory.Span[..(nreq * sizeof(int))]);

        IMemoryOwner<byte> openedColumnsOwner = pool.Rent(rowCount * nreq * ScalarSize);
        IMemoryOwner<byte>? nonceOwner = null;
        IMemoryOwner<byte>? merklePathOwner = null;
        try
        {
            //req[i, j] = tableau[i, dblock + idx[j]] for every row i.
            Span<byte> openedColumns = openedColumnsOwner.Memory.Span[..(rowCount * nreq * ScalarSize)];
            for(int i = 0; i < rowCount; i++)
            {
                for(int j = 0; j < nreq; j++)
                {
                    ReadOnlySpan<byte> element = commitment.ElementAt(i, doubleBlock + indices[j]);
                    element.CopyTo(openedColumns.Slice(((i * nreq) + j) * ScalarSize, ScalarSize));
                }
            }

            //The per-leaf nonces of the opened columns, pulled from the commitment's retained nonces.
            nonceOwner = pool.Rent(nreq * NonceLength);
            Span<byte> nonces = nonceOwner.Memory.Span[..(nreq * NonceLength)];
            ReadOnlySpan<byte> commitmentNonces = commitment.Nonces;
            for(int j = 0; j < nreq; j++)
            {
                commitmentNonces.Slice(indices[j] * NonceLength, NonceLength).CopyTo(nonces.Slice(j * NonceLength, NonceLength));
            }

            //The compressed Merkle multi-proof over the opened leaf positions, in selection order.
            int pathLength = LongfellowMerkleTree.CompressedProofLength(blockExtension, indices, pool);
            merklePathOwner = pool.Rent(Math.Max(pathLength, 1) * DigestLength);
            int written = commitment.Tree.GenerateCompressedProof(indices, merklePathOwner.Memory.Span, pool);
            if(written != pathLength)
            {
                throw new InvalidOperationException($"The compressed Merkle proof wrote {written} digests; the pre-count expected {pathLength}.");
            }

            return new LongfellowLigeroProof(parameters, responseOwner, openedColumnsOwner, indicesOwner, nonceOwner, merklePathOwner, pathLength);
        }
        catch
        {
            if(merklePathOwner is not null)
            {
                merklePathOwner.Memory.Span.Clear();
                merklePathOwner.Dispose();
            }

            if(nonceOwner is not null)
            {
                nonceOwner.Memory.Span[..(nreq * NonceLength)].Clear();
                nonceOwner.Dispose();
            }

            openedColumnsOwner.Memory.Span[..(rowCount * nreq * ScalarSize)].Clear();
            openedColumnsOwner.Dispose();
            indicesOwner.Memory.Span[..(nreq * sizeof(int))].Clear();
            indicesOwner.Dispose();
            throw;
        }
    }


    //Copies the first `length` canonical scalars of tableau row `rowIndex` into `destination`.
    private static void CopyRowPrefix(LongfellowLigeroCommitment commitment, int rowIndex, int length, Span<byte> destination)
    {
        for(int k = 0; k < length; k++)
        {
            commitment.ElementAt(rowIndex, k).CopyTo(destination.Slice(k * ScalarSize, ScalarSize));
        }
    }


    //destination += addend, in place, via a scratch the caller owns.
    private static void AddInPlace(Span<byte> destination, ReadOnlySpan<byte> addend, Span<byte> scratch, ScalarAddDelegate add, CurveParameterSet curve)
    {
        add(destination, addend, scratch, curve);
        scratch.CopyTo(destination);
    }


    //destination -= subtrahend, in place, via a scratch the caller owns.
    private static void SubtractInPlace(Span<byte> destination, ReadOnlySpan<byte> subtrahend, Span<byte> scratch, ScalarSubtractDelegate subtract, CurveParameterSet curve)
    {
        subtract(destination, subtrahend, scratch, curve);
        scratch.CopyTo(destination);
    }


    private static ReadOnlySpan<byte> ScalarAt(ReadOnlySpan<byte> buffer, int index) => buffer.Slice(index * ScalarSize, ScalarSize);

    private static Span<byte> ScalarAt(Span<byte> buffer, int index) => buffer.Slice(index * ScalarSize, ScalarSize);


    //A canonical scalar is the field's zero exactly when every byte is zero.
    private static bool IsZeroScalar(ReadOnlySpan<byte> scalar) => scalar.IndexOfAnyExcept((byte)0) < 0;
}
