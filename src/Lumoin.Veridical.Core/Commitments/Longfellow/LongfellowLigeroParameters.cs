using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The wire-format-conformant Ligero tableau dimensions and row layout, a faithful port of
/// google/longfellow-zk's <c>lib/ligero/ligero_param.h</c> <c>LigeroParam</c> including the
/// <c>layout()</c> <c>block_enc</c> optimizer. This is the parameter derivation the deployed
/// Longfellow proof commits over, so the derived sizes (<see cref="BlockEncoded"/> chief among them)
/// are part of the wire format: the prover and verifier must agree on them bit for bit.
/// </summary>
/// <remarks>
/// <para>
/// This is the conformance sibling of <see cref="Ligero.LigeroParameters"/>, kept parallel to it
/// rather than merged: the existing engine derives <c>block_enc</c> from a directly supplied
/// <c>block</c>, whereas the reference <em>optimizes</em> <c>block_enc</c> to minimize an estimated
/// proof size, then back-solves <c>block</c> from it. The two derivations produce different layouts
/// for the same user parameters, so the wire-format port carries its own.
/// </para>
/// <para>
/// The tableau is a <see cref="RowCount"/> × <see cref="BlockEncoded"/> matrix. Each row has the form
/// <c>[X XD XEXT]</c>: <c>X</c> is the <see cref="Block"/>-element block (the Reed–Solomon message),
/// <c>XD</c> is <see cref="Block"/>−1 elements completing the double block <c>DBLOCK = 2·BLOCK−1</c>
/// (so products of two block-degree polynomials fit), and <c>XEXT</c> is <see cref="BlockExtension"/>
/// elements, the codeword extension. The <see cref="BlockExtension"/> extension columns are the
/// Merkle leaves. A witness block is <c>[RANDOM[R] WITNESS[W]]</c> with <c>R + W = BLOCK</c> and
/// <c>W ≥ R</c>. The first three rows are the ILDT/IDOT/IQUAD zero-knowledge blinding rows; the next
/// <see cref="WitnessRowCount"/> are witness rows; the last <c>3·</c><see cref="QuadraticTripleCount"/>
/// are the quadratic-check rows.
/// </para>
/// <para>
/// The optimizer: for each power-of-two candidate <c>e = block_enc</c> from 1 up to 2^28, compute the
/// layout and the estimated proof size, and keep the <c>e</c> that minimizes it. The candidate is
/// rejected (treated as infinite proof size) when it does not fit the subfield (<c>block_enc &lt;
/// 2^subfieldBits</c> is required), when the dimensions overflow, when <c>block &lt; R</c> (so
/// <c>W ≥ 0</c>) or <c>W &lt; R</c>, or when the tableau would not fit in 2^28 elements. The proof-size
/// estimate breaks the abstraction to the Merkle commitment and serialization sizes exactly as the
/// reference does — it is a heuristic the reference admits is a wart, but it IS the wire format, so it
/// is ported verbatim.
/// </para>
/// </remarks>
internal sealed class LongfellowLigeroParameters
{
    //The reference caps every dimension to 2^28 (max_lg_size = 28): 32-bit-machine paranoia. A
    //candidate block_enc past this — or any derived dimension past it — is rejected.
    private const int MaxLogSize = 28;
    private const long MaxSize = 1L << MaxLogSize;

    //The reference's Digest::kLength and MerkleNonce::kLength: SHA-256 output and nonce are 32 bytes.
    private const long DigestLength = 32;
    private const long MerkleNonceLength = 32;

    //The three zero-knowledge blinding rows sit at fixed positions in every tableau (protocol
    //invariants, not per-instance layout): ILDT = 0, IDOT = 1, IQUAD = 2, first witness row = 3.
    /// <summary>The low-degree-test blinding row index (<c>ILDT = 0</c>).</summary>
    public const int LowDegreeRowIndex = 0;

    /// <summary>The dot-product (linear) test blinding row index (<c>IDOT = 1</c>).</summary>
    public const int DotRowIndex = 1;

    /// <summary>The quadratic-test blinding row index (<c>IQUAD = 2</c>).</summary>
    public const int QuadraticRowIndex = 2;

    /// <summary>The first witness row index (<c>IW = 3</c>).</summary>
    public const int FirstWitnessRowIndex = 3;

    /// <summary>The total number of witnesses (<c>nw</c>).</summary>
    public int WitnessCount { get; }

    /// <summary>The total number of quadratic constraints <c>W[x]·W[y] = W[z]</c> (<c>nq</c>).</summary>
    public int QuadraticConstraintCount { get; }

    /// <summary>The inverse rate of the Reed–Solomon code (<c>rateinv</c>); at least 1.</summary>
    public int InverseRate { get; }

    /// <summary>The number of columns opened on challenge (<c>nreq</c>); also <c>r</c>, the random count per block.</summary>
    public int OpenedColumnCount { get; }

    /// <summary>The total number of elements per row (<c>block_enc</c>), the optimizer's chosen value.</summary>
    public int BlockEncoded { get; }

    /// <summary>The block size (<c>block</c>) — the Reed–Solomon message length of a witness row.</summary>
    public int Block { get; }

    /// <summary><c>DBLOCK = 2·block − 1</c>: the degree bound of a product of two block-degree polynomials.</summary>
    public int DoubleBlock { get; }

    /// <summary><c>BLOCK_EXT = block_enc − dblock</c>: the number of Merkle leaves (extension columns).</summary>
    public int BlockExtension { get; }

    /// <summary>The number of random blinding entries in a witness block (<c>r = nreq</c>).</summary>
    public int RandomCount { get; }

    /// <summary>The number of witness entries in a block (<c>w = block − r</c>).</summary>
    public int WitnessPerRow { get; }

    /// <summary>The number of witness rows (<c>nwrow = ceil(nw / w)</c>).</summary>
    public int WitnessRowCount { get; }

    /// <summary>The number of quadratic-constraint row triples (<c>nqtriples = ceil(nq / w)</c>).</summary>
    public int QuadraticTripleCount { get; }

    /// <summary>The number of witness-and-quadratic rows (<c>nwqrow = nwrow + 3·nqtriples</c>).</summary>
    public int WitnessQuadraticRowCount { get; }

    /// <summary>The total number of rows (<c>nrow = nwqrow + 3 blinding rows</c>).</summary>
    public int RowCount { get; }

    /// <summary>The first quadratic row index (<c>IQ = FirstWitnessRowIndex + nwrow</c>).</summary>
    public int FirstQuadraticRowIndex => FirstWitnessRowIndex + WitnessRowCount;

    /// <summary>The first quadratic <c>x</c>-operand row.</summary>
    public int FirstQuadraticXRowIndex => FirstQuadraticRowIndex;

    /// <summary>The first quadratic <c>y</c>-operand row.</summary>
    public int FirstQuadraticYRowIndex => FirstQuadraticRowIndex + QuadraticTripleCount;

    /// <summary>The first quadratic <c>z</c>-product row.</summary>
    public int FirstQuadraticZRowIndex => FirstQuadraticRowIndex + (2 * QuadraticTripleCount);


    /// <summary>
    /// Derives the layout by running the reference's <c>block_enc</c> optimizer for the given user
    /// parameters and field byte sizes.
    /// </summary>
    /// <param name="witnessCount">The number of witnesses (≥ 0); the reference's <c>nw</c>.</param>
    /// <param name="quadraticConstraintCount">The number of quadratic constraints (≥ 0); <c>nq</c>.</param>
    /// <param name="inverseRate">The inverse code rate (≥ 1); <c>rateinv</c>.</param>
    /// <param name="openedColumnCount">The number of opened columns (≥ 1); <c>nreq</c>, also <c>r</c>.</param>
    /// <param name="fieldBytes">The full-field element byte size (<c>Field::kBytes</c>, 16 for GF(2^128)); used by the proof-size estimate.</param>
    /// <param name="subFieldBytes">The subfield element byte size (<c>Field::kSubFieldBytes</c>, 2 for GF(2^16), 4 for GF(2^32)); caps <c>block_enc &lt; 2^(8·subFieldBytes)</c>.</param>
    /// <exception cref="ArgumentOutOfRangeException">When a parameter is out of range.</exception>
    /// <exception cref="InvalidOperationException">When no valid <c>block_enc</c> exists for these parameters.</exception>
    public LongfellowLigeroParameters(
        int witnessCount,
        int quadraticConstraintCount,
        int inverseRate,
        int openedColumnCount,
        int fieldBytes,
        int subFieldBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(witnessCount);
        ArgumentOutOfRangeException.ThrowIfNegative(quadraticConstraintCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(inverseRate, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(openedColumnCount, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(fieldBytes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(subFieldBytes, 1);

        WitnessCount = witnessCount;
        QuadraticConstraintCount = quadraticConstraintCount;
        InverseRate = inverseRate;
        OpenedColumnCount = openedColumnCount;
        RandomCount = openedColumnCount;

        //The reference's optimizer: try each power-of-two block_enc and keep the one minimizing the
        //estimated proof size. The candidate stride 1, 2, 4, ..., 2^28.
        long minProofSize = long.MaxValue;
        int bestBlockEncoded = 1;
        for(int candidate = 1; candidate <= (1 << MaxLogSize); candidate <<= 1)
        {
            long proofSize = EstimateProofSize(candidate, witnessCount, quadraticConstraintCount, inverseRate, openedColumnCount, fieldBytes, subFieldBytes, out _);
            if(proofSize < minProofSize)
            {
                minProofSize = proofSize;
                bestBlockEncoded = candidate;
            }
        }

        if(minProofSize == long.MaxValue)
        {
            throw new InvalidOperationException($"No valid block_enc exists for nw={witnessCount}, nq={quadraticConstraintCount}, rateinv={inverseRate}, nreq={openedColumnCount}.");
        }

        //Recompute the derived sizes for the winning candidate.
        long finalSize = EstimateProofSize(bestBlockEncoded, witnessCount, quadraticConstraintCount, inverseRate, openedColumnCount, fieldBytes, subFieldBytes, out LayoutFields layout);

        BlockEncoded = bestBlockEncoded;
        Block = layout.Block;
        DoubleBlock = layout.DoubleBlock;
        BlockExtension = layout.BlockExtension;
        WitnessPerRow = layout.WitnessPerRow;
        WitnessRowCount = layout.WitnessRowCount;
        QuadraticTripleCount = layout.QuadraticTripleCount;
        WitnessQuadraticRowCount = layout.WitnessQuadraticRowCount;
        RowCount = layout.RowCount;

        Sanity(finalSize);
    }


    /// <summary>
    /// Derives the layout from a <em>pre-computed</em> <c>block_enc</c> instead of running the optimizer,
    /// a faithful port of the reference's pre-computed-<c>block_enc</c> <c>LigeroParam(nw, nq, rateinv,
    /// nreq, be)</c> constructor (<c>ligero_param.h:172-178</c>): it sets <see cref="BlockEncoded"/> to the
    /// given value, runs <c>layout(block_enc)</c> once (the reference's
    /// <c>check(layout(block_enc) &lt; SIZE_MAX)</c>), then asserts the layout invariants.
    /// </summary>
    /// <remarks>
    /// This is the deployed v7 path: the reference no longer optimizes <c>block_enc</c> online but stores
    /// it in the <c>ZkSpecStruct</c> (<c>block_enc_hash</c> / <c>block_enc_sig</c>) and feeds it to both
    /// <c>ZkProof</c> and <c>ZkVerifier</c> (<c>mdoc_zk.cc:615-616, 659-662</c>). Because <c>block_enc</c>
    /// is part of the wire format, the prover and verifier must agree on it bit for bit; deriving it from
    /// the optimizer can choose a different candidate than the deployed spec, so the verifier reading a
    /// real-credential envelope must use the pinned value.
    /// </remarks>
    /// <param name="witnessCount">The number of witnesses (≥ 0); the reference's <c>nw</c>.</param>
    /// <param name="quadraticConstraintCount">The number of quadratic constraints (≥ 0); <c>nq</c>.</param>
    /// <param name="inverseRate">The inverse code rate (≥ 1); <c>rateinv</c>.</param>
    /// <param name="openedColumnCount">The number of opened columns (≥ 1); <c>nreq</c>, also <c>r</c>.</param>
    /// <param name="fieldBytes">The full-field element byte size (<c>Field::kBytes</c>, 16 for GF(2^128)).</param>
    /// <param name="subFieldBytes">The subfield element byte size (<c>Field::kSubFieldBytes</c>, 2 for GF(2^16), 4 for GF(2^32)); caps <c>block_enc &lt; 2^(8·subFieldBytes)</c>.</param>
    /// <param name="blockEncoded">The pinned <c>block_enc</c> (≥ 1) from the <c>ZkSpecStruct</c>.</param>
    /// <exception cref="ArgumentOutOfRangeException">When a parameter is out of range.</exception>
    /// <exception cref="InvalidOperationException">When the pinned <c>block_enc</c> is infeasible for these parameters.</exception>
    public LongfellowLigeroParameters(
        int witnessCount,
        int quadraticConstraintCount,
        int inverseRate,
        int openedColumnCount,
        int fieldBytes,
        int subFieldBytes,
        int blockEncoded)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(witnessCount);
        ArgumentOutOfRangeException.ThrowIfNegative(quadraticConstraintCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(inverseRate, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(openedColumnCount, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(fieldBytes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(subFieldBytes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(blockEncoded, 1);

        WitnessCount = witnessCount;
        QuadraticConstraintCount = quadraticConstraintCount;
        InverseRate = inverseRate;
        OpenedColumnCount = openedColumnCount;
        RandomCount = openedColumnCount;

        //The reference's check(layout(block_enc) < SIZE_MAX): run the layout once for the pinned candidate
        //and reject (rather than optimize) if it is infeasible.
        long finalSize = EstimateProofSize(blockEncoded, witnessCount, quadraticConstraintCount, inverseRate, openedColumnCount, fieldBytes, subFieldBytes, out LayoutFields layout);
        if(finalSize == long.MaxValue)
        {
            throw new InvalidOperationException($"The pinned block_enc={blockEncoded} is infeasible for nw={witnessCount}, nq={quadraticConstraintCount}, rateinv={inverseRate}, nreq={openedColumnCount}.");
        }

        BlockEncoded = blockEncoded;
        Block = layout.Block;
        DoubleBlock = layout.DoubleBlock;
        BlockExtension = layout.BlockExtension;
        WitnessPerRow = layout.WitnessPerRow;
        WitnessRowCount = layout.WitnessRowCount;
        QuadraticTripleCount = layout.QuadraticTripleCount;
        WitnessQuadraticRowCount = layout.WitnessQuadraticRowCount;
        RowCount = layout.RowCount;

        Sanity(finalSize);
    }


    //The reference's layout(e): derive every dimension for candidate block_enc = e and return the
    //estimated proof size, or long.MaxValue (= SIZE_MAX) if the candidate is infeasible. The derived
    //fields are returned through `fields` only when feasible. Mirrors ligero_param.h::layout.
    private static long EstimateProofSize(
        int blockEncoded,
        int witnessCount,
        int quadraticConstraintCount,
        int inverseRate,
        int openedColumnCount,
        int fieldBytes,
        int subFieldBytes,
        out LayoutFields fields)
    {
        fields = default;
        int r = openedColumnCount;

        //block_enc must fit in the subfield: block_enc < 2^(8·subFieldBytes) when that bound is
        //within the 2^28 paranoia range.
        int subfieldBits = 8 * subFieldBytes;
        if(subfieldBits <= MaxLogSize && blockEncoded >= (1 << subfieldBits))
        {
            return long.MaxValue;
        }

        //Limit block_enc and rateinv to avoid overflow; (block_enc + 1) must reach (2 + rateinv).
        if(blockEncoded > MaxSize || inverseRate > MaxSize || (blockEncoded + 1) < (2 + inverseRate))
        {
            return long.MaxValue;
        }

        int block = (blockEncoded + 1) / (2 + inverseRate);

        //Ensure block = r + w (block >= r) and w >= r (witness block at least half full).
        if(block < r)
        {
            return long.MaxValue;
        }

        int w = block - r;
        if(w < r)
        {
            return long.MaxValue;
        }

        int dblock = (2 * block) - 1;

        //block_enc must be at least dblock so block_ext >= 0.
        if(blockEncoded < dblock)
        {
            return long.MaxValue;
        }

        int blockExtension = blockEncoded - dblock;

        int witnessRowCount = CeilingDivide(witnessCount, w);
        int quadraticTripleCount = CeilingDivide(quadraticConstraintCount, w);
        int witnessQuadraticRowCount = witnessRowCount + (3 * quadraticTripleCount);
        int rowCount = witnessQuadraticRowCount + 3;

        //The whole tableau (nrow · block_enc) must fit in 2^28 elements.
        if(rowCount >= MaxSize / blockEncoded)
        {
            return long.MaxValue;
        }

        fields = new LayoutFields(block, dblock, blockExtension, w, witnessRowCount, quadraticTripleCount, witnessQuadraticRowCount, rowCount);

        //The proof-size estimate. Breaks abstraction to the Merkle commitment and serialization sizes
        //exactly as the reference does; it is a heuristic but it IS the wire-format selector.
        long mcPathLength = MerkleTreeLength(blockExtension);
        long size = 0;

        //commitment digest
        size += DigestLength;

        //Merkle openings (approximated; the exact leaf count depends on the random coins).
        size += mcPathLength / 2 * openedColumnCount * DigestLength;

        //y_ldt (block elements), y_dot (dblock elements), y_quad (dblock - w elements transmitted).
        size += (long)block * fieldBytes;
        size += (long)dblock * fieldBytes;
        size += (long)(dblock - w) * fieldBytes;

        //nonces
        size += (long)openedColumnCount * MerkleNonceLength;

        //req (optimistically all in the subfield)
        size += (long)rowCount * openedColumnCount * subFieldBytes;

        return Math.Min(size, long.MaxValue);
    }


    //The reference's merkle_tree_len(n): mimics generate_proof's path-length count without computing
    //the proof. Returns the length of a Merkle proof for n leaves. The arithmetic is unsigned and
    //mirrors the reference exactly, including n = 0, where (n − 1) wraps and the loop yields 64 —
    //that value feeds the proof-size estimate the layout optimizer minimizes, so reproducing it is
    //part of the parameter derivation's conformance.
    private static long MerkleTreeLength(int leafCount)
    {
        long result = 1;
        ulong position = unchecked((ulong)((long)leafCount - 1)) + (ulong)leafCount;
        for(; position > 1; position >>= 1)
        {
            ++result;
        }

        return result;
    }


    //The reference asserts block_enc > block and the quadratic rows fill the row count exactly.
    private void Sanity(long finalSize)
    {
        if(finalSize == long.MaxValue)
        {
            throw new InvalidOperationException("The winning block_enc became infeasible on recomputation.");
        }

        if(BlockEncoded <= Block)
        {
            throw new InvalidOperationException("Ligero layout invariant violated: block_enc must exceed block.");
        }

        if(RowCount != FirstQuadraticRowIndex + (3 * QuadraticTripleCount))
        {
            throw new InvalidOperationException("Ligero row layout is inconsistent.");
        }
    }


    private static int CeilingDivide(int numerator, int denominator) => (numerator + denominator - 1) / denominator;


    //The derived layout fields for one feasible block_enc candidate.
    private readonly record struct LayoutFields(
        int Block,
        int DoubleBlock,
        int BlockExtension,
        int WitnessPerRow,
        int WitnessRowCount,
        int QuadraticTripleCount,
        int WitnessQuadraticRowCount,
        int RowCount);
}
