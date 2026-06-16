using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The wire-format-conformant Ligero verify flow, a faithful port of google/longfellow-zk's
/// <c>LigeroVerifier::verify</c> (<c>lib/ligero/ligero_verifier.h</c>). It consumes a
/// <see cref="LongfellowLigeroProof"/> by its wire fields alone — the response rows, the opened
/// columns, the per-leaf nonces and the compressed Merkle path — replays the Fiat–Shamir transcript to
/// re-derive every challenge (in particular the opened-column indices, which the reference re-derives
/// rather than trusting the proof's copy), and runs the four checks the reference runs, byte for byte:
/// the Merkle opening, the low-degree test, the dot-product (linear) test together with its
/// inner-product value check, and the quadratic test.
/// </summary>
/// <remarks>
/// <para>
/// The transcript replay, byte-precise (the commitment root is absorbed by the caller before this runs,
/// exactly as the reference's <c>receive_commitment</c> does its <c>write_commitment</c>):
/// </para>
/// <list type="number">
///   <item><description>absorb <c>hash_of_llterm</c> (the theorem statement), 32 bytes through the byte-string write.</description></item>
///   <item><description>squeeze <c>u_ldt</c> (<c>nwqrow</c>), <c>alphal</c> (<c>nl</c>), <c>alphaq</c> (<c>3·nq</c>), <c>u_quad</c> (<c>nqtriples</c>).</description></item>
///   <item><description>absorb the four response rows out of the proof (<c>y_ldt</c>, <c>y_dot</c>, <c>y_quad_0</c>, <c>y_quad_2</c>) as field-element arrays.</description></item>
///   <item><description>squeeze <c>idx</c> (<c>nreq</c> distinct columns in <c>[0, block_ext)</c>).</description></item>
/// </list>
/// <para>
/// The four checks (the reference returns a <c>why</c> string on failure; this port returns
/// <see langword="false"/> and sets <see cref="LongfellowLigeroVerificationResult"/> to the matching
/// cause):
/// </para>
/// <list type="bullet">
///   <item><description><b>Merkle.</b> Reconstruct each opened leaf as <c>SHA256(nonce[r] ‖ to_bytes_field(req[*,r]))</c> over all <c>nrow</c> rows, then recompute the root from the leaves plus the compressed path and compare to the absorbed root. The opened leaf positions are <c>idx</c> directly (the column at draw <c>r</c> is the extension column <c>dblock + idx[r]</c>, whose Merkle leaf index is <c>idx[r]</c>).</description></item>
///   <item><description><b>Low degree.</b> Form the expected column values <c>yc[r] = req[ildt,r] + Σ_i u_ldt[i]·req[iw+i,r]</c>, RS-interpolate the response <c>y_ldt</c> (length <c>block</c>) to <c>block_enc</c> and gather it at the extension columns <c>dblock + idx[r]</c>, and require the two agree. This is the Reed–Solomon consistency relation: the ILDT blinding row plus the <c>u_ldt</c>-folded witness/quadratic rows form a single codeword whose message is <c>y_ldt</c>.</description></item>
///   <item><description><b>Dot (linear).</b> Build the inner-product vector <c>A[nwqrow, w]</c> from the constraints and their challenges (<c>LigeroCommon::inner_product_vector</c>); form <c>yc[r] = req[idot,r] + Σ_i Aext_i(dblock+idx[r])·req[iw+i,r]</c> where <c>Aext_i = [0^r | A[i,:]]</c> RS-extended <c>block→block_enc</c>; RS-interpolate <c>y_dot</c> (length <c>dblock</c>) and gather; require agreement. Then the value check: the expected inner product <c>want_dot = Σ_c b[c]·alphal[c]</c> must equal <c>proof_dot = Σ_{k=0}^{w-1} y_dot[r+k]</c> (the sum of the witness block of <c>y_dot</c>).</description></item>
///   <item><description><b>Quadratic.</b> Form <c>yc[r] = req[iquad,r] + Σ_t u_quad[t]·(req[iqz+t,r] − req[iqx+t,r]·req[iqy+t,r])</c>; reconstruct the full <c>y_quad = [y_quad_0 | 0^w | y_quad_2]</c> (the provably-zero witness window is not transmitted), RS-interpolate (length <c>dblock</c>) and gather; require agreement.</description></item>
/// </list>
/// <para>
/// The verifier never sees the witness — only the response rows and the opened columns. It is
/// stateless: it takes the proof, the public constraints and their targets, and the prepared transcript,
/// and returns a verdict. The Reed–Solomon interpolation, the field arithmetic, the Merkle node hash and
/// the leaf hash are delegate-injected so the port stays consistent with the library's primitive-agnostic
/// commitment infrastructure (they must be the LCH14 encoder, the GF(2^128) backend and SHA-256 to match
/// the reference).
/// </para>
/// </remarks>
internal static class LongfellowLigeroVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The reference's Digest::kLength and MerkleNonce::kLength: nonce and digest are 32 bytes each.
    private const int NonceLength = 32;
    private const int DigestLength = 32;


    /// <summary>
    /// Verifies <paramref name="proof"/> against <paramref name="root"/> and the public constraints,
    /// replaying <paramref name="transcript"/> to re-derive the challenges and running the four Ligero
    /// checks. The reference's <c>LigeroVerifier::verify</c>; the commitment root must already be absorbed
    /// into the transcript by the caller (the reference's <c>receive_commitment</c>).
    /// </summary>
    /// <param name="parameters">The wire-format tableau layout the proof was produced for.</param>
    /// <param name="proof">The proof to verify; consumed by its wire fields only.</param>
    /// <param name="root">The 32-byte commitment root the Merkle check verifies against — the value the caller absorbed, not a field of the proof.</param>
    /// <param name="transcript">The transcript, already seeded and with the commitment root absorbed; this flow drives it from the theorem-statement absorb onward.</param>
    /// <param name="theoremStatementHash">The 32-byte <c>hash_of_llterm</c> absorbed before any challenge.</param>
    /// <param name="linearConstraintCount">The number of linear constraints <c>nl</c>.</param>
    /// <param name="linearConstraints">The linear terms; each contributes <c>coefficient · W[witnessIndex]</c> to its constraint.</param>
    /// <param name="linearTargets">The linear-constraint targets <c>b[c]</c>; exactly <paramref name="linearConstraintCount"/> canonical scalars, the public inputs the dot value-check folds with <c>alphal</c>.</param>
    /// <param name="quadraticConstraints">The multiplication constraints; exactly <see cref="LongfellowLigeroParameters.QuadraticConstraintCount"/> of them.</param>
    /// <param name="encoderFactory">Builds the systematic Reed–Solomon row encoder per shape (the response and Aext interpolations): binary LCH14 or prime FFT-convolution.</param>
    /// <param name="profile">The field profile: the on-wire element width and the <c>to_bytes_field</c> / <c>of_bytes_field</c> framing.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> Merkle compression for the recomputed inner nodes.</param>
    /// <param name="leafHash">The one-shot SHA-256 over a single contiguous input span (a nonce followed by the column bytes).</param>
    /// <param name="hashAlgorithm">The canonical hash-function name (SHA-256) the leaf and node hashes implement.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent working buffers from.</param>
    /// <param name="failureCause">On a rejected proof, the check that caught it; <see cref="LongfellowLigeroVerificationResult.Accepted"/> on success.</param>
    /// <returns><see langword="true"/> when every check passes, <see langword="false"/> otherwise.</returns>
    /// <exception cref="ArgumentNullException">When a backend, the proof, the transcript or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the layout.</exception>
    public static bool Verify(
        LongfellowLigeroParameters parameters,
        LongfellowLigeroProof proof,
        ReadOnlySpan<byte> root,
        LongfellowTranscript transcript,
        ReadOnlySpan<byte> theoremStatementHash,
        int linearConstraintCount,
        ReadOnlySpan<LigeroLinearConstraint> linearConstraints,
        ReadOnlySpan<byte> linearTargets,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        out LongfellowLigeroVerificationResult failureCause)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(encoderFactory);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(add);

        //The proof's wire-field accessors slice by the layout it was produced for; the checks index
        //by the layout passed here. A mismatch indexes inconsistently instead of rejecting cleanly,
        //so the two must be the same layout.
        if(!ReferenceEquals(proof.Parameters, parameters))
        {
            throw new ArgumentException("The proof was produced for a different parameter layout than the one being verified against.", nameof(proof));
        }

        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(pool);

        failureCause = LongfellowLigeroVerificationResult.Accepted;

        if(theoremStatementHash.Length != DigestLength)
        {
            throw new ArgumentException($"The theorem statement hash is {DigestLength} bytes; received {theoremStatementHash.Length}.", nameof(theoremStatementHash));
        }

        if(root.Length != DigestLength)
        {
            throw new ArgumentException($"The commitment root is {DigestLength} bytes; received {root.Length}.", nameof(root));
        }

        if(linearTargets.Length != linearConstraintCount * ScalarSize)
        {
            throw new ArgumentException($"The linear targets must be {linearConstraintCount * ScalarSize} bytes; received {linearTargets.Length}.", nameof(linearTargets));
        }

        if(quadraticConstraints.Length != parameters.QuadraticConstraintCount)
        {
            throw new ArgumentException($"Expected {parameters.QuadraticConstraintCount} quadratic constraints; received {quadraticConstraints.Length}.", nameof(quadraticConstraints));
        }

        int nwqrow = parameters.WitnessQuadraticRowCount;
        int nq = parameters.QuadraticConstraintCount;
        int nqtriples = parameters.QuadraticTripleCount;
        int nreq = parameters.OpenedColumnCount;

        //Replay the protocol to compute the challenges. idx in particular must be re-derived before any
        //check, so the verifier opens the columns the transcript names rather than the proof's copy.
        transcript.AbsorbByteString(theoremStatementHash);

        int challengeCount = nwqrow + linearConstraintCount + (3 * nq) + nqtriples;
        using IMemoryOwner<byte> challengesOwner = pool.Rent(challengeCount * ScalarSize);
        Span<byte> challenges = challengesOwner.Memory.Span[..(challengeCount * ScalarSize)];
        Span<byte> uLowDegree = challenges[..(nwqrow * ScalarSize)];
        Span<byte> alphaLinear = challenges.Slice(nwqrow * ScalarSize, linearConstraintCount * ScalarSize);
        Span<byte> alphaQuadratic = challenges.Slice((nwqrow + linearConstraintCount) * ScalarSize, 3 * nq * ScalarSize);
        Span<byte> uQuadratic = challenges.Slice((nwqrow + linearConstraintCount + (3 * nq)) * ScalarSize, nqtriples * ScalarSize);

        try
        {
            SqueezeFieldElements(transcript, profile, uLowDegree, nwqrow);
            SqueezeFieldElements(transcript, profile, alphaLinear, linearConstraintCount);
            SqueezeFieldElements(transcript, profile, alphaQuadratic, 3 * nq);
            SqueezeFieldElements(transcript, profile, uQuadratic, nqtriples);

            AbsorbResponses(transcript, parameters, profile, proof, pool);

            using IMemoryOwner<byte> indicesOwner = pool.Rent(nreq * sizeof(int));
            Span<int> indices = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, int>(indicesOwner.Memory.Span[..(nreq * sizeof(int))]);
            try
            {
                transcript.SqueezeIndexSubset(parameters.BlockExtension, nreq, indices);

                if(!MerkleCheck(parameters, proof, root, indices, profile, merkleHash, leafHash, hashAlgorithm, pool))
                {
                    failureCause = LongfellowLigeroVerificationResult.MerkleCheckFailed;

                    return false;
                }

                if(!LowDegreeCheck(parameters, proof, indices, uLowDegree, encoderFactory, add, multiply, curve, pool))
                {
                    failureCause = LongfellowLigeroVerificationResult.LowDegreeCheckFailed;

                    return false;
                }

                if(!DotCheck(parameters, proof, indices, linearConstraintCount, linearConstraints, alphaLinear, alphaQuadratic, quadraticConstraints, encoderFactory, add, subtract, multiply, curve, pool))
                {
                    failureCause = LongfellowLigeroVerificationResult.DotCheckFailed;

                    return false;
                }

                if(!DotValueCheck(parameters, proof, linearConstraintCount, linearTargets, alphaLinear, add, multiply, curve))
                {
                    failureCause = LongfellowLigeroVerificationResult.WrongDotProduct;

                    return false;
                }

                if(!QuadraticCheck(parameters, proof, indices, uQuadratic, nqtriples, encoderFactory, add, subtract, multiply, curve, pool))
                {
                    failureCause = LongfellowLigeroVerificationResult.QuadraticCheckFailed;

                    return false;
                }

                return true;
            }
            finally
            {
                indices.Clear();
            }
        }
        finally
        {
            challenges.Clear();
        }
    }


    //Absorbs the four response rows out of the proof, exactly as the prover absorbed them: each row
    //converted to the field's little-endian to_bytes_field framing and written as one element array.
    private static void AbsorbResponses(LongfellowTranscript transcript, LongfellowLigeroParameters parameters, LongfellowFieldProfile profile, LongfellowLigeroProof proof, BaseMemoryPool pool)
    {
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int quadHigh = dblock - block;

        AbsorbElementArray(transcript, profile, proof.LowDegreeResponse, block, pool);
        AbsorbElementArray(transcript, profile, proof.DotResponse, dblock, pool);
        AbsorbElementArray(transcript, profile, proof.QuadraticResponseLow, r, pool);
        AbsorbElementArray(transcript, profile, proof.QuadraticResponseHigh, quadHigh, pool);
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


    //Squeezes `count` challenge field elements through the field's sample loop (gen_uldt etc., each a
    //tsv.elt(Elt[], n, F)). GF(2^128) is one 16-byte draw per element; the Fp256 profile reject-redraws.
    private static void SqueezeFieldElements(LongfellowTranscript transcript, LongfellowFieldProfile profile, Span<byte> destination, int count)
    {
        for(int i = 0; i < count; i++)
        {
            transcript.SqueezeFieldElement(profile, destination.Slice(i * ScalarSize, ScalarSize));
        }
    }


    //Merkle check: reconstruct each opened leaf as SHA256(nonce[r] || to_bytes_field(req[*,r])) over all
    //nrow rows, then recompute the root from the leaves plus the compressed path and compare. The opened
    //leaf positions are idx[r] (the column at draw r is extension column dblock+idx[r]; its leaf is idx[r]).
    private static bool MerkleCheck(
        LongfellowLigeroParameters parameters,
        LongfellowLigeroProof proof,
        ReadOnlySpan<byte> root,
        ReadOnlySpan<int> indices,
        LongfellowFieldProfile profile,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        BaseMemoryPool pool)
    {
        int nreq = parameters.OpenedColumnCount;
        int rowCount = parameters.RowCount;
        int blockExtension = parameters.BlockExtension;
        int elementBytes = profile.ElementBytes;

        //The leaf hash input: a 32-byte nonce followed by ElementBytes little-endian element bytes per row.
        int leafInputBytes = NonceLength + (rowCount * elementBytes);
        using IMemoryOwner<byte> leafInputOwner = pool.Rent(leafInputBytes);
        Span<byte> leafInput = leafInputOwner.Memory.Span[..leafInputBytes];

        using IMemoryOwner<byte> leavesOwner = pool.Rent(nreq * DigestLength);
        Span<byte> leaves = leavesOwner.Memory.Span[..(nreq * DigestLength)];
        try
        {
            for(int r = 0; r < nreq; r++)
            {
                proof.Nonce(r).CopyTo(leafInput[..NonceLength]);
                for(int rowIndex = 0; rowIndex < rowCount; rowIndex++)
                {
                    profile.ToBytesField(proof.OpenedColumnElement(rowIndex, r), leafInput.Slice(NonceLength + (rowIndex * elementBytes), elementBytes));
                }

                leafHash(leafInput, leaves.Slice(r * DigestLength, DigestLength), hashAlgorithm);
            }

            return LongfellowMerkleTree.VerifyCompressedProof(blockExtension, root, leaves, indices, proof.MerklePath, proof.MerklePathLength, merkleHash, pool);
        }
        finally
        {
            leafInput.Clear();
            leaves.Clear();
        }
    }


    //Low-degree check: yc[r] = req[ildt,r] + sum_i u_ldt[i]*req[iw+i,r]; interpolate y_ldt (length block)
    //to block_enc, gather at dblock+idx[r], require yp == yc.
    private static bool LowDegreeCheck(
        LongfellowLigeroParameters parameters,
        LongfellowLigeroProof proof,
        ReadOnlySpan<int> indices,
        ReadOnlySpan<byte> uLowDegree,
        LongfellowRowEncoderFactory encoderFactory,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int nreq = parameters.OpenedColumnCount;
        int nwqrow = parameters.WitnessQuadraticRowCount;
        int firstWitnessRow = LongfellowLigeroParameters.FirstWitnessRowIndex;

        using IMemoryOwner<byte> ycOwner = pool.Rent(nreq * ScalarSize);
        using IMemoryOwner<byte> ypOwner = pool.Rent(nreq * ScalarSize);
        Span<byte> yc = ycOwner.Memory.Span[..(nreq * ScalarSize)];
        Span<byte> yp = ypOwner.Memory.Span[..(nreq * ScalarSize)];
        try
        {
            //The ILDT blinding row with coefficient 1, plus all witness/quadratic rows with u_ldt[i].
            Span<byte> scratch = stackalloc byte[ScalarSize];
            Span<byte> term = stackalloc byte[ScalarSize];
            for(int r = 0; r < nreq; r++)
            {
                proof.OpenedColumnElement(LongfellowLigeroParameters.LowDegreeRowIndex, r).CopyTo(ScalarAt(yc, r));
            }

            for(int i = 0; i < nwqrow; i++)
            {
                ReadOnlySpan<byte> coefficient = ScalarAt(uLowDegree, i);
                for(int r = 0; r < nreq; r++)
                {
                    multiply(coefficient, proof.OpenedColumnElement(firstWitnessRow + i, r), term, curve);
                    AddInPlace(ScalarAt(yc, r), term, scratch, add, curve);
                }
            }

            InterpolateRequestColumns(parameters, parameters.Block, proof.LowDegreeResponse, indices, yp, encoderFactory, pool);

            return ColumnsEqual(yc, yp, nreq);
        }
        finally
        {
            yc.Clear();
            yp.Clear();
        }
    }


    //Dot (linear) check: build A[nwqrow, w] from the constraints, then
    //yc[r] = req[idot,r] + sum_i Aext_i(dblock+idx[r])*req[iw+i,r] with Aext_i = [0^r | A[i,:]] RS-extended
    //block->block_enc; interpolate y_dot (length dblock), gather, require yp == yc.
    private static bool DotCheck(
        LongfellowLigeroParameters parameters,
        LongfellowLigeroProof proof,
        ReadOnlySpan<int> indices,
        int linearConstraintCount,
        ReadOnlySpan<LigeroLinearConstraint> linearConstraints,
        ReadOnlySpan<byte> alphaLinear,
        ReadOnlySpan<byte> alphaQuadratic,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        LongfellowRowEncoderFactory encoderFactory,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int nreq = parameters.OpenedColumnCount;
        int nwqrow = parameters.WitnessQuadraticRowCount;
        int w = parameters.WitnessPerRow;
        int r = parameters.RandomCount;
        int block = parameters.Block;
        int blockEncoded = parameters.BlockEncoded;
        int doubleBlock = parameters.DoubleBlock;
        int firstWitnessRow = LongfellowLigeroParameters.FirstWitnessRowIndex;

        using IMemoryOwner<byte> matrixOwner = pool.Rent(nwqrow * w * ScalarSize);
        Span<byte> matrix = matrixOwner.Memory.Span[..(nwqrow * w * ScalarSize)];
        BuildInnerProductVector(parameters, linearConstraintCount, linearConstraints, quadraticConstraints, alphaLinear, alphaQuadratic, matrix, add, subtract, multiply, curve);

        using IMemoryOwner<byte> ycOwner = pool.Rent(nreq * ScalarSize);
        using IMemoryOwner<byte> ypOwner = pool.Rent(nreq * ScalarSize);
        using IMemoryOwner<byte> aextOwner = pool.Rent(blockEncoded * ScalarSize);
        Span<byte> yc = ycOwner.Memory.Span[..(nreq * ScalarSize)];
        Span<byte> yp = ypOwner.Memory.Span[..(nreq * ScalarSize)];
        Span<byte> aext = aextOwner.Memory.Span[..(blockEncoded * ScalarSize)];

        using LongfellowRowEncoder aextRs = encoderFactory(block, blockEncoded);
        try
        {
            //The IDOT blinding row with coefficient 1.
            for(int j = 0; j < nreq; j++)
            {
                proof.OpenedColumnElement(LongfellowLigeroParameters.DotRowIndex, j).CopyTo(ScalarAt(yc, j));
            }

            Span<byte> scratch = stackalloc byte[ScalarSize];
            Span<byte> term = stackalloc byte[ScalarSize];
            for(int i = 0; i < nwqrow; i++)
            {
                //Aext message = [0^r | A[i,:]] over block columns; extend block -> block_enc in place.
                aext.Clear();
                matrix.Slice(i * w * ScalarSize, w * ScalarSize).CopyTo(aext.Slice(r * ScalarSize, w * ScalarSize));
                aextRs.Interpolate(aext);

                for(int j = 0; j < nreq; j++)
                {
                    ReadOnlySpan<byte> aextColumn = ScalarAt(aext, doubleBlock + indices[j]);
                    multiply(aextColumn, proof.OpenedColumnElement(firstWitnessRow + i, j), term, curve);
                    AddInPlace(ScalarAt(yc, j), term, scratch, add, curve);
                }
            }

            InterpolateRequestColumns(parameters, doubleBlock, proof.DotResponse, indices, yp, encoderFactory, pool);

            return ColumnsEqual(yc, yp, nreq);
        }
        finally
        {
            yc.Clear();
            yp.Clear();
            aext.Clear();
            matrix.Clear();
        }
    }


    //Dot value check: want_dot = sum_c b[c]*alphal[c] must equal proof_dot = sum_{k=0}^{w-1} y_dot[r+k].
    private static bool DotValueCheck(
        LongfellowLigeroParameters parameters,
        LongfellowLigeroProof proof,
        int linearConstraintCount,
        ReadOnlySpan<byte> linearTargets,
        ReadOnlySpan<byte> alphaLinear,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;

        Span<byte> wantDot = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        wantDot.Clear();
        for(int c = 0; c < linearConstraintCount; c++)
        {
            multiply(ScalarAt(linearTargets, c), ScalarAt(alphaLinear, c), term, curve);
            AddInPlace(wantDot, term, scratch, add, curve);
        }

        //proof_dot = sum of the w witness-block elements of y_dot, starting at offset r.
        ReadOnlySpan<byte> yDot = proof.DotResponse;
        Span<byte> proofDot = stackalloc byte[ScalarSize];
        proofDot.Clear();
        for(int k = 0; k < w; k++)
        {
            AddInPlace(proofDot, ScalarAt(yDot, r + k), scratch, add, curve);
        }

        return wantDot.SequenceEqual(proofDot);
    }


    //Quadratic check: yc[r] = req[iquad,r] + sum_t u_quad[t]*(req[iqz+t,r] - req[iqx+t,r]*req[iqy+t,r]);
    //reconstruct y_quad = [y_quad_0 | 0^w | y_quad_2], interpolate (length dblock), gather, require yp == yc.
    private static bool QuadraticCheck(
        LongfellowLigeroParameters parameters,
        LongfellowLigeroProof proof,
        ReadOnlySpan<int> indices,
        ReadOnlySpan<byte> uQuadratic,
        int nqtriples,
        LongfellowRowEncoderFactory encoderFactory,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int nreq = parameters.OpenedColumnCount;
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;
        int iqx = parameters.FirstQuadraticXRowIndex;
        int iqy = parameters.FirstQuadraticYRowIndex;
        int iqz = parameters.FirstQuadraticZRowIndex;

        using IMemoryOwner<byte> ycOwner = pool.Rent(nreq * ScalarSize);
        using IMemoryOwner<byte> ypOwner = pool.Rent(nreq * ScalarSize);
        using IMemoryOwner<byte> yQuadOwner = pool.Rent(dblock * ScalarSize);
        Span<byte> yc = ycOwner.Memory.Span[..(nreq * ScalarSize)];
        Span<byte> yp = ypOwner.Memory.Span[..(nreq * ScalarSize)];
        Span<byte> yQuad = yQuadOwner.Memory.Span[..(dblock * ScalarSize)];
        try
        {
            //The IQUAD blinding row with coefficient 1.
            for(int j = 0; j < nreq; j++)
            {
                proof.OpenedColumnElement(LongfellowLigeroParameters.QuadraticRowIndex, j).CopyTo(ScalarAt(yc, j));
            }

            Span<byte> scratch = stackalloc byte[ScalarSize];
            Span<byte> term = stackalloc byte[ScalarSize];
            Span<byte> difference = stackalloc byte[ScalarSize];
            for(int t = 0; t < nqtriples; t++)
            {
                ReadOnlySpan<byte> uQuad = ScalarAt(uQuadratic, t);
                for(int j = 0; j < nreq; j++)
                {
                    //tmp = req[iqz+t,j] - req[iqx+t,j]*req[iqy+t,j]; yc += u_quad[t]*tmp.
                    multiply(proof.OpenedColumnElement(iqx + t, j), proof.OpenedColumnElement(iqy + t, j), term, curve);
                    subtract(proof.OpenedColumnElement(iqz + t, j), term, difference, curve);
                    multiply(uQuad, difference, term, curve);
                    AddInPlace(ScalarAt(yc, j), term, scratch, add, curve);
                }
            }

            //Reconstruct y_quad from the two transmitted parts: [y_quad_0 (r) | 0^w | y_quad_2 (dblock-block)].
            yQuad.Clear();
            proof.QuadraticResponseLow.CopyTo(yQuad[..(r * ScalarSize)]);
            proof.QuadraticResponseHigh.CopyTo(yQuad[(block * ScalarSize)..]);

            InterpolateRequestColumns(parameters, dblock, yQuad, indices, yp, encoderFactory, pool);

            return ColumnsEqual(yc, yp, nreq);
        }
        finally
        {
            yc.Clear();
            yp.Clear();
            yQuad.Clear();
        }
    }


    //RS-interpolate the response y (length ylen) to block_enc, then gather it at the extension columns
    //dblock+idx[r] into `gathered` (nreq scalars). The reference's interpolate_req_columns.
    private static void InterpolateRequestColumns(
        LongfellowLigeroParameters parameters,
        int responseLength,
        ReadOnlySpan<byte> response,
        ReadOnlySpan<int> indices,
        Span<byte> gathered,
        LongfellowRowEncoderFactory encoderFactory,
        BaseMemoryPool pool)
    {
        int blockEncoded = parameters.BlockEncoded;
        int doubleBlock = parameters.DoubleBlock;
        int nreq = parameters.OpenedColumnCount;

        using LongfellowRowEncoder rs = encoderFactory(responseLength, blockEncoded);

        using IMemoryOwner<byte> extendedOwner = pool.Rent(blockEncoded * ScalarSize);
        Span<byte> extended = extendedOwner.Memory.Span[..(blockEncoded * ScalarSize)];
        try
        {
            extended.Clear();
            response[..(responseLength * ScalarSize)].CopyTo(extended[..(responseLength * ScalarSize)]);
            rs.Interpolate(extended);

            for(int j = 0; j < nreq; j++)
            {
                ScalarAt(extended, doubleBlock + indices[j]).CopyTo(ScalarAt(gathered, j));
            }
        }
        finally
        {
            extended.Clear();
        }
    }


    //Folds the linear and quadratic constraints into A[nwqrow, w] (LigeroCommon::inner_product_vector).
    //Identical to the prover's build; kept local to the verifier so it consumes only public inputs.
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

        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        foreach(LigeroLinearConstraint linearTerm in linearConstraints)
        {
            if((uint)linearTerm.ConstraintIndex >= (uint)linearConstraintCount)
            {
                throw new ArgumentOutOfRangeException(nameof(linearConstraints), $"Linear term constraint index {linearTerm.ConstraintIndex} is outside [0, {linearConstraintCount}).");
            }

            if((uint)linearTerm.WitnessIndex >= (uint)witnessCount)
            {
                throw new ArgumentOutOfRangeException(nameof(linearConstraints), $"Linear term witness index {linearTerm.WitnessIndex} is outside [0, {witnessCount}).");
            }

            multiply(linearTerm.Coefficient.Span, ScalarAt(alphaLinear, linearTerm.ConstraintIndex), product, curve);
            AddInPlace(ScalarAt(matrix, linearTerm.WitnessIndex), product, scratch, add, curve);
        }

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


    //Two nreq-length column-value runs are equal exactly when every scalar matches.
    private static bool ColumnsEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, int count) =>
        left[..(count * ScalarSize)].SequenceEqual(right[..(count * ScalarSize)]);


    private static ReadOnlySpan<byte> ScalarAt(ReadOnlySpan<byte> buffer, int index) => buffer.Slice(index * ScalarSize, ScalarSize);

    private static Span<byte> ScalarAt(Span<byte> buffer, int index) => buffer.Slice(index * ScalarSize, ScalarSize);
}
