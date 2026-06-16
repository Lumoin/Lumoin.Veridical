using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// A standing wire-format-conformant Ligero commitment, a faithful port of the prover state
/// google/longfellow-zk's <c>LigeroProver</c> retains across <c>commit()</c> and <c>prove()</c>
/// (its <c>tableau_</c>, <c>mc_</c> and <c>nonce_</c> members). It holds the RS-extended tableau, the
/// <see cref="LongfellowMerkleTree"/> over the extension columns and the per-leaf nonces, so the
/// commit and the prove can be separate steps: a commit-then-challenge protocol absorbs
/// <see cref="CopyRoot"/> first and proves constraints that depend on later challenges from the same
/// tableau, without rebuilding and re-encoding it.
/// </summary>
/// <remarks>
/// <para>
/// This mirrors the existing engine's <see cref="Ligero.LigeroCommitment"/> idiom (a disposable
/// object the prover commits into and proves out of), specialized to the Longfellow wire format: the
/// tableau is laid out exactly as <c>LigeroProver::layout</c>, every row is RS-extended with the
/// field's systematic Reed–Solomon row encoder supplied through <see cref="LongfellowRowEncoderFactory"/>
/// (the binary LCH14 additive-FFT encoder for the hash circuit, the prime FFT-convolution encoder for the
/// signature circuit), each Merkle leaf is framed <c>SHA256(nonce ‖ to_bytes_field(column))</c> with the
/// field's little-endian elements (16 bytes for GF(2^128), 32 for the P-256 base field), and the Merkle
/// heap is the reference's non-padded <c>2·n</c> form.
/// </para>
/// <para>
/// The leaf framing, byte for byte: leaf <c>j</c> covers extension column <c>dblock + j</c> across all
/// <see cref="LongfellowLigeroParameters.RowCount"/> rows. Its digest is the SHA-256 of a 32-byte
/// nonce followed by, for each row top to bottom, the field's little-endian element bytes of that row's
/// element in the column (<c>to_bytes_field</c>, least-significant byte first). The canonical scalars this
/// library carries are 32-byte big-endian, so the framing reverses the low element bytes of each scalar
/// into the SHA input through <see cref="LongfellowFieldProfile.ToBytesField"/>.
/// </para>
/// <para>
/// Randomness enters through <see cref="LongfellowRandomByteSource"/> in the reference's exact order —
/// blinding rows (ILDT block, IDOT dblock, IQUAD dblock with the witness columns not drawn), witness
/// rows (R padding each, subfield-sampled), quadratic triples (3·R padding each), then one 32-byte
/// nonce per leaf. A field element is drawn as <c>Field::kBytes</c> raw bytes interpreted little-endian;
/// a subfield element is drawn as <c>kSubFieldBytes</c> raw bytes interpreted little-endian and mapped
/// through <c>of_scalar</c> (<see cref="LongfellowFieldProfile.OfScalar"/>). A caller that fixes the
/// stream gets a deterministic root.
/// </para>
/// <para>
/// Disposable and sensitive: the tableau holds the witness values and the prover's blinding
/// randomness, and the commitment retains the per-leaf nonces (the prove step opens them), so
/// <see cref="Dispose"/> clears and releases all of it together with the Merkle tree.
/// </para>
/// </remarks>
internal sealed class LongfellowLigeroCommitment: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The reference's Digest::kLength and MerkleNonce::kLength: SHA-256 and the per-leaf nonce are 32.
    private const int DigestLength = 32;
    private const int NonceLength = 32;

    private IMemoryOwner<byte>? tableauOwner;
    private IMemoryOwner<byte>? nonceOwner;
    private LongfellowMerkleTree? tree;
    private readonly int rowStrideBytes;


    /// <summary>The layout the tableau was built to.</summary>
    public LongfellowLigeroParameters Parameters { get; }


    private LongfellowLigeroCommitment(
        LongfellowLigeroParameters parameters,
        IMemoryOwner<byte> tableauOwner,
        IMemoryOwner<byte> nonceOwner,
        LongfellowMerkleTree tree,
        int rowStrideBytes)
    {
        Parameters = parameters;
        this.tableauOwner = tableauOwner;
        this.nonceOwner = nonceOwner;
        this.tree = tree;
        this.rowStrideBytes = rowStrideBytes;
    }


    /// <summary>The full RS-extended tableau, row-major <c>[RowCount, BlockEncoded]</c> canonical scalars.</summary>
    internal ReadOnlySpan<byte> Tableau =>
        (tableauOwner ?? throw new ObjectDisposedException(nameof(LongfellowLigeroCommitment))).Memory.Span[..(Parameters.RowCount * rowStrideBytes)];

    /// <summary>The per-leaf nonces, concatenated 32 bytes each, one per extension column (<c>block_ext</c> of them).</summary>
    internal ReadOnlySpan<byte> Nonces =>
        (nonceOwner ?? throw new ObjectDisposedException(nameof(LongfellowLigeroCommitment))).Memory.Span[..(Parameters.BlockExtension * NonceLength)];

    /// <summary>The Merkle tree over the extension columns.</summary>
    internal LongfellowMerkleTree Tree =>
        tree ?? throw new ObjectDisposedException(nameof(LongfellowLigeroCommitment));


    /// <summary>The byte stride of one tableau row (<c>BlockEncoded · 32</c>).</summary>
    internal int RowStrideBytes => rowStrideBytes;


    /// <summary>
    /// Returns the canonical scalar at tableau row <paramref name="rowIndex"/>, column
    /// <paramref name="columnIndex"/>.
    /// </summary>
    internal ReadOnlySpan<byte> ElementAt(int rowIndex, int columnIndex) =>
        Tableau.Slice((rowIndex * rowStrideBytes) + (columnIndex * ScalarSize), ScalarSize);


    /// <summary>Copies the 32-byte commitment root (Merkle node 1) into <paramref name="destination"/>.</summary>
    /// <param name="destination">Receives the 32-byte root.</param>
    public void CopyRoot(Span<byte> destination) => Tree.CopyRoot(destination);


    /// <summary>
    /// Builds the tableau over <paramref name="witnesses"/> and <paramref name="quadraticConstraints"/>
    /// and Merkle-commits the extension columns, returning a standing commitment that retains the
    /// tableau, the tree and the per-leaf nonces. The reference's <c>LigeroProver::commit</c> minus the
    /// transcript absorb (the caller absorbs <see cref="CopyRoot"/> at its layer).
    /// </summary>
    /// <param name="parameters">The wire-format tableau layout.</param>
    /// <param name="witnesses">The witness vector; exactly <see cref="LongfellowLigeroParameters.WitnessCount"/> · 32 canonical bytes.</param>
    /// <param name="quadraticConstraints">One entry per multiplication constraint; exactly <see cref="LongfellowLigeroParameters.QuadraticConstraintCount"/> of them.</param>
    /// <param name="subFieldBytes">The subfield element byte size (2 for GF(2^16), 4 for GF(2^32)); the byte count a subfield random draw consumes.</param>
    /// <param name="subfieldBoundary">The reference's <c>subfield_boundary</c>: witness rows whose elements are all below this index draw subfield padding; the rest draw full-field padding. The production wiring sets it to <see cref="LongfellowLigeroParameters.WitnessCount"/>; <c>0</c> trivially makes every row full-field.</param>
    /// <param name="random">The raw-byte entropy source, consumed in the reference's fixed order.</param>
    /// <param name="encoderFactory">Builds the systematic Reed–Solomon row encoder per shape (binary LCH14 or prime FFT-convolution).</param>
    /// <param name="profile">The field profile: element width, the <c>to_bytes_field</c> framing, and the subfield <c>of_scalar</c> the padding draws map through.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> Merkle compression.</param>
    /// <param name="leafHash">The one-shot SHA-256 over a single contiguous input span (nonce followed by the column bytes).</param>
    /// <param name="hashAlgorithm">The canonical hash-function name (SHA-256) the leaf and node hashes implement.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent the tableau, leaf and column buffers from.</param>
    /// <returns>The standing commitment; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a backend, the parameters or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the layout.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The tableau, nonce and tree buffers transfer ownership to the returned LongfellowLigeroCommitment, which releases them through its own Dispose; on a fault they are released before rethrow. The block/double-block encoders are disposed in the finally.")]
    public static LongfellowLigeroCommitment Commit(
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> witnesses,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        int subFieldBytes,
        int subfieldBoundary,
        LongfellowRandomByteSource random,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(encoderFactory);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(pool);

        if(witnesses.Length != parameters.WitnessCount * ScalarSize)
        {
            throw new ArgumentException($"Witnesses must be {parameters.WitnessCount * ScalarSize} bytes; received {witnesses.Length}.", nameof(witnesses));
        }

        if(quadraticConstraints.Length != parameters.QuadraticConstraintCount)
        {
            throw new ArgumentException($"Expected {parameters.QuadraticConstraintCount} quadratic constraints; received {quadraticConstraints.Length}.", nameof(quadraticConstraints));
        }

        int rowStrideBytes = parameters.BlockEncoded * ScalarSize;
        IMemoryOwner<byte>? tableauOwner = null;
        IMemoryOwner<byte>? nonceOwner = null;
        LongfellowMerkleTree? tree = null;
        LongfellowRowEncoder? blockRs = null;
        LongfellowRowEncoder? doubleBlockRs = null;
        try
        {
            //The tableau holds the witness, blinding, and RS-extension rows — secret, long-lived (it backs the
            //commitment through prove), and too large for the locked native tier; pin it so it is never
            //GC-relocated and the clear-on-dispose actually wipes the witness bytes.
            tableauOwner = pool.Rent(parameters.RowCount * rowStrideBytes, AllocationKind.Pinned);

            //The two RS instances the reference's interpolators cover: block→block_enc (witness and
            //quadratic rows, plus ILDT) and dblock→block_enc (the IDOT/IQUAD blinding rows). Encoders
            //may own pooled precompute, so they are built inside the cleanup scope.
            blockRs = encoderFactory(parameters.Block, parameters.BlockEncoded);
            doubleBlockRs = encoderFactory(parameters.DoubleBlock, parameters.BlockEncoded);

            Span<byte> tableau = tableauOwner.Memory.Span[..(parameters.RowCount * rowStrideBytes)];
            tableau.Clear();

            FillBlindingRows(tableau, parameters, rowStrideBytes, random, profile, add, subtract, blockRs, doubleBlockRs, curve);
            FillWitnessRows(tableau, parameters, rowStrideBytes, subFieldBytes, subfieldBoundary, witnesses, random, profile, blockRs);
            FillQuadraticRows(tableau, parameters, rowStrideBytes, witnesses, quadraticConstraints, random, profile, multiply, blockRs, curve);

            //The per-leaf Merkle nonces are prover blinding randomness retained with the commitment (revealing
            //the unopened ones would break hiding); pin them alongside the tableau.
            nonceOwner = pool.Rent(parameters.BlockExtension * NonceLength, AllocationKind.Pinned);
            tree = CommitColumns(tableau, parameters, rowStrideBytes, random, profile, merkleHash, leafHash, hashAlgorithm, nonceOwner.Memory.Span[..(parameters.BlockExtension * NonceLength)], pool);

            return new LongfellowLigeroCommitment(parameters, tableauOwner, nonceOwner, tree, rowStrideBytes);
        }
        catch
        {
            tree?.Dispose();
            if(nonceOwner is not null)
            {
                nonceOwner.Memory.Span[..(parameters.BlockExtension * NonceLength)].Clear();
                nonceOwner.Dispose();
            }

            if(tableauOwner is not null)
            {
                tableauOwner.Memory.Span[..(parameters.RowCount * rowStrideBytes)].Clear();
                tableauOwner.Dispose();
            }

            throw;
        }
        finally
        {
            blockRs?.Dispose();
            doubleBlockRs?.Dispose();
        }
    }


    /// <summary>
    /// Builds the tableau, commits, and writes the 32-byte Merkle root into <paramref name="root"/> in
    /// one shot, releasing the commitment immediately. The thin facade the commit-only conformance gate
    /// (C.2) drives; the prove flow uses the object-returning <see cref="Commit"/> instead.
    /// </summary>
    /// <param name="root">Receives the 32-byte commitment root.</param>
    /// <inheritdoc cref="Commit(LongfellowLigeroParameters, ReadOnlySpan{byte}, ReadOnlySpan{LigeroQuadraticConstraint}, int, int, LongfellowRandomByteSource, LongfellowRowEncoderFactory, LongfellowFieldProfile, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, MerkleHashDelegate, FiatShamirHashDelegate, string, CurveParameterSet, BaseMemoryPool)"/>
    public static void Commit(
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> witnesses,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        int subFieldBytes,
        int subfieldBoundary,
        LongfellowRandomByteSource random,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        CurveParameterSet curve,
        Span<byte> root,
        BaseMemoryPool pool)
    {
        if(root.Length != DigestLength)
        {
            throw new ArgumentException($"The root is {DigestLength} bytes; received {root.Length}.", nameof(root));
        }

        using LongfellowLigeroCommitment commitment = Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, subfieldBoundary, random, encoderFactory, profile,
            add, subtract, multiply, merkleHash, leafHash, hashAlgorithm, curve, pool);
        commitment.CopyRoot(root);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        LongfellowMerkleTree? localTree = tree;
        if(localTree is not null)
        {
            tree = null;
            localTree.Dispose();
        }

        IMemoryOwner<byte>? localNonce = nonceOwner;
        if(localNonce is not null)
        {
            nonceOwner = null;
            localNonce.Memory.Span[..(Parameters.BlockExtension * NonceLength)].Clear();
            localNonce.Dispose();
        }

        IMemoryOwner<byte>? localTableau = tableauOwner;
        if(localTableau is not null)
        {
            tableauOwner = null;
            localTableau.Memory.Span[..(Parameters.RowCount * rowStrideBytes)].Clear();
            localTableau.Dispose();
        }
    }


    //ILDT: block random field elements. IDOT: dblock random field elements with the witness block
    //forced to sum to zero. IQUAD: dblock random field elements with the witness columns left zero
    //(and so not drawn from the stream). Each is RS-extended to block_enc.
    private static void FillBlindingRows(
        Span<byte> tableau,
        LongfellowLigeroParameters parameters,
        int rowStrideBytes,
        LongfellowRandomByteSource random,
        LongfellowFieldProfile profile,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        LongfellowRowEncoder blockRs,
        LongfellowRowEncoder doubleBlockRs,
        CurveParameterSet curve)
    {
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;

        //ILDT: block random message entries, extend block -> block_enc.
        Span<byte> lowDegreeRow = RowSpan(tableau, rowStrideBytes, LongfellowLigeroParameters.LowDegreeRowIndex);
        for(int j = 0; j < block; j++)
        {
            DrawFieldElement(random, profile, ScalarAt(lowDegreeRow, j));
        }

        ExtendRow(lowDegreeRow, parameters.BlockEncoded, blockRs);

        //IDOT: dblock random entries; subtract the whole witness-block sum from column r so [r, r+w)
        //sums to zero. Extend dblock -> block_enc.
        Span<byte> dotRow = RowSpan(tableau, rowStrideBytes, LongfellowLigeroParameters.DotRowIndex);
        for(int j = 0; j < dblock; j++)
        {
            DrawFieldElement(random, profile, ScalarAt(dotRow, j));
        }

        ZeroWitnessBlockSum(dotRow, r, w, add, subtract, curve);
        ExtendRow(dotRow, parameters.BlockEncoded, doubleBlockRs);

        //IQUAD: draw the whole dblock of random entries (so the random stream advances by dblock),
        //THEN zero the witness columns [r, r+w). The reference draws all dblock and clears w
        //afterwards, so the byte consumption is dblock field elements, not dblock − w. Extend
        //dblock -> block_enc.
        Span<byte> quadraticRow = RowSpan(tableau, rowStrideBytes, LongfellowLigeroParameters.QuadraticRowIndex);
        for(int j = 0; j < dblock; j++)
        {
            DrawFieldElement(random, profile, ScalarAt(quadraticRow, j));
        }

        for(int j = r; j < r + w; j++)
        {
            ScalarAt(quadraticRow, j).Clear();
        }

        ExtendRow(quadraticRow, parameters.BlockEncoded, doubleBlockRs);
    }


    //Witness rows: each carries R subfield padding entries then up to W witnesses (subfield_boundary
    //= nw, so the padding is subfield-sampled). The trailing row zero-pads past the witness count.
    private static void FillWitnessRows(
        Span<byte> tableau,
        LongfellowLigeroParameters parameters,
        int rowStrideBytes,
        int subFieldBytes,
        int subfieldBoundary,
        ReadOnlySpan<byte> witnesses,
        LongfellowRandomByteSource random,
        LongfellowFieldProfile profile,
        LongfellowRowEncoder blockRs)
    {
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;
        int witnessCount = parameters.WitnessCount;

        for(int i = 0; i < parameters.WitnessRowCount; i++)
        {
            Span<byte> row = RowSpan(tableau, rowStrideBytes, LongfellowLigeroParameters.FirstWitnessRowIndex + i);

            //subfield_only when the entire row's witness range is below the subfield boundary; only
            //then is the R padding drawn from the subfield (shorter draws). Otherwise full-field.
            bool subfieldOnly = ((i + 1) * w) <= subfieldBoundary;
            for(int j = 0; j < r; j++)
            {
                if(subfieldOnly)
                {
                    DrawSubfieldElement(random, profile, subFieldBytes, ScalarAt(row, j));
                }
                else
                {
                    DrawFieldElement(random, profile, ScalarAt(row, j));
                }
            }

            for(int k = 0; k < w; k++)
            {
                int witnessIndex = (i * w) + k;
                if(witnessIndex < witnessCount)
                {
                    witnesses.Slice(witnessIndex * ScalarSize, ScalarSize).CopyTo(ScalarAt(row, r + k));
                }
            }

            ExtendRow(row, parameters.BlockEncoded, blockRs);
        }
    }


    //Quadratic-constraint rows: three rows per triple. Each row draws 3·R worth of field padding
    //(R per x/y/z row) then the x/y/z operands of up to W constraints; the prover asserts each triple
    //satisfies W[z] = W[x]·W[y].
    private static void FillQuadraticRows(
        Span<byte> tableau,
        LongfellowLigeroParameters parameters,
        int rowStrideBytes,
        ReadOnlySpan<byte> witnesses,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        LongfellowRandomByteSource random,
        LongfellowFieldProfile profile,
        ScalarMultiplyDelegate multiply,
        LongfellowRowEncoder blockRs,
        CurveParameterSet curve)
    {
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;
        int witnessCount = parameters.WitnessCount;
        int quadraticConstraintCount = parameters.QuadraticConstraintCount;

        Span<byte> product = stackalloc byte[ScalarSize];
        for(int i = 0; i < parameters.QuadraticTripleCount; i++)
        {
            Span<byte> xRow = RowSpan(tableau, rowStrideBytes, parameters.FirstQuadraticXRowIndex + i);
            Span<byte> yRow = RowSpan(tableau, rowStrideBytes, parameters.FirstQuadraticYRowIndex + i);
            Span<byte> zRow = RowSpan(tableau, rowStrideBytes, parameters.FirstQuadraticZRowIndex + i);

            for(int j = 0; j < r; j++)
            {
                DrawFieldElement(random, profile, ScalarAt(xRow, j));
            }

            for(int j = 0; j < r; j++)
            {
                DrawFieldElement(random, profile, ScalarAt(yRow, j));
            }

            for(int j = 0; j < r; j++)
            {
                DrawFieldElement(random, profile, ScalarAt(zRow, j));
            }

            for(int k = 0; k < w; k++)
            {
                int constraintIndex = (i * w) + k;
                if(constraintIndex >= quadraticConstraintCount)
                {
                    break;
                }

                LigeroQuadraticConstraint constraint = quadraticConstraints[constraintIndex];
                ReadOnlySpan<byte> x = WitnessAt(witnesses, constraint.XIndex, witnessCount);
                ReadOnlySpan<byte> y = WitnessAt(witnesses, constraint.YIndex, witnessCount);
                ReadOnlySpan<byte> z = WitnessAt(witnesses, constraint.ZIndex, witnessCount);

                multiply(x, y, product, curve);
                if(!product.SequenceEqual(z))
                {
                    throw new InvalidOperationException($"Quadratic constraint {constraintIndex} is unsatisfied: W[{constraint.ZIndex}] != W[{constraint.XIndex}]·W[{constraint.YIndex}].");
                }

                x.CopyTo(ScalarAt(xRow, r + k));
                y.CopyTo(ScalarAt(yRow, r + k));
                z.CopyTo(ScalarAt(zRow, r + k));
            }

            ExtendRow(xRow, parameters.BlockEncoded, blockRs);
            ExtendRow(yRow, parameters.BlockEncoded, blockRs);
            ExtendRow(zRow, parameters.BlockEncoded, blockRs);
        }
    }


    //Merkle-commit the extension columns. Leaf j (j in [0, block_ext)) draws a 32-byte nonce then
    //hashes SHA256(nonce || to_bytes_field of column dblock+j over all nrow rows). The nonces are
    //drawn from the same stream, after all the tableau randomness, and retained in `nonces`.
    [SuppressMessage("Reliability", "CA2000", Justification = "The returned tree owns its heap buffer; the caller (Commit) transfers it into the commitment, which disposes it.")]
    private static LongfellowMerkleTree CommitColumns(
        Span<byte> tableau,
        LongfellowLigeroParameters parameters,
        int rowStrideBytes,
        LongfellowRandomByteSource random,
        LongfellowFieldProfile profile,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        Span<byte> nonces,
        BaseMemoryPool pool)
    {
        int blockExtension = parameters.BlockExtension;
        int doubleBlock = parameters.DoubleBlock;
        int rowCount = parameters.RowCount;
        int elementBytes = profile.ElementBytes;

        using IMemoryOwner<byte> leavesOwner = pool.Rent(blockExtension * DigestLength);
        Span<byte> leaves = leavesOwner.Memory.Span[..(blockExtension * DigestLength)];

        //The leaf hash input: a 32-byte nonce followed by elementBytes little-endian element bytes per row.
        int leafInputBytes = NonceLength + (rowCount * elementBytes);
        using IMemoryOwner<byte> leafInputOwner = pool.Rent(leafInputBytes);
        Span<byte> leafInput = leafInputOwner.Memory.Span[..leafInputBytes];

        try
        {
            for(int j = 0; j < blockExtension; j++)
            {
                Span<byte> nonce = nonces.Slice(j * NonceLength, NonceLength);
                random(nonce);
                nonce.CopyTo(leafInput[..NonceLength]);

                int columnIndex = doubleBlock + j;
                for(int rowIndex = 0; rowIndex < rowCount; rowIndex++)
                {
                    ReadOnlySpan<byte> element = ScalarAt(RowSpan(tableau, rowStrideBytes, rowIndex), columnIndex);
                    profile.ToBytesField(element, leafInput.Slice(NonceLength + (rowIndex * elementBytes), elementBytes));
                }

                leafHash(leafInput, leaves.Slice(j * DigestLength, DigestLength), hashAlgorithm);
            }

            return LongfellowMerkleTree.Build(leaves, blockExtension, merkleHash, pool);
        }
        finally
        {
            leaves.Clear();
            leafInput.Clear();
        }
    }


    //Draws one field element through the field's sample mask-then-reject loop, the reference's rng.elt(F)
    //(random.h:39-41). GF(2^128) is one 16-byte draw (never rejects); the Fp256 profile redraws a fresh
    //32-byte block until one is below the modulus. The canonical scalar is 32-byte big-endian with the
    //element in its low bytes.
    private static void DrawFieldElement(LongfellowRandomByteSource random, LongfellowFieldProfile profile, Span<byte> destination)
    {
        profile.SampleElement(random, destination);
    }


    //Draws one subfield element: kSubFieldBytes raw little-endian bytes interpreted as a coordinate
    //integer u, mapped through of_scalar(u) (the binary basis combination over GF, the integer u mod p
    //over Fp256).
    private static void DrawSubfieldElement(LongfellowRandomByteSource random, LongfellowFieldProfile profile, int subFieldBytes, Span<byte> destination)
    {
        //The coordinate accumulator is 32 bits; a wider subfield draw would silently drop the high bytes.
        if(subFieldBytes > sizeof(uint))
        {
            throw new ArgumentOutOfRangeException(nameof(subFieldBytes), subFieldBytes, $"Subfield draws wider than {sizeof(uint)} bytes are not supported.");
        }

        Span<byte> rawBytes = stackalloc byte[ScalarSize];
        random(rawBytes[..subFieldBytes]);

        uint coordinate = 0;
        for(int i = subFieldBytes - 1; i >= 0; i--)
        {
            coordinate = (coordinate << 8) | rawBytes[i];
        }

        profile.OfScalar(coordinate, destination);
    }


    //Subtracts the sum of the witness block [r, r+w) from column r so the block sums to zero.
    private static void ZeroWitnessBlockSum(Span<byte> row, int r, int w, ScalarAddDelegate add, ScalarSubtractDelegate subtract, CurveParameterSet curve)
    {
        Span<byte> sum = stackalloc byte[ScalarSize];
        sum.Clear();
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        for(int k = 0; k < w; k++)
        {
            add(sum, ScalarAt(row, r + k), accumulator, curve);
            accumulator.CopyTo(sum);
        }

        subtract(ScalarAt(row, r), sum, accumulator, curve);
        accumulator.CopyTo(ScalarAt(row, r));
    }


    //RS-extends the row's message prefix to the full block_enc codeword in place. The row encoder carries
    //the message length and the block-encoded length; it reads the message from the row's prefix and
    //fills the rest.
    private static void ExtendRow(Span<byte> row, int blockEncoded, LongfellowRowEncoder rs)
    {
        rs.Interpolate(row[..(blockEncoded * ScalarSize)]);
    }


    private static Span<byte> RowSpan(Span<byte> tableau, int rowStrideBytes, int rowIndex) =>
        tableau.Slice(rowIndex * rowStrideBytes, rowStrideBytes);


    private static Span<byte> ScalarAt(Span<byte> row, int columnIndex) =>
        row.Slice(columnIndex * ScalarSize, ScalarSize);


    private static ReadOnlySpan<byte> WitnessAt(ReadOnlySpan<byte> witnesses, int index, int witnessCount)
    {
        if((uint)index >= (uint)witnessCount)
        {
            throw new ArgumentOutOfRangeException(nameof(index), $"Witness index {index} is outside the {witnessCount}-element witness vector.");
        }

        return witnesses.Slice(index * ScalarSize, ScalarSize);
    }
}
