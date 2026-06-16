using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// A built Ligero tableau: the <see cref="LigeroParameters.RowCount"/> ×
/// <see cref="LigeroParameters.BlockEncoded"/> matrix of field elements whose
/// every row is a systematic Reed–Solomon codeword, laid out row-major in one
/// pooled buffer. The three blinding rows, the witness rows and the
/// quadratic-constraint rows are filled per the layout of
/// <see cref="LigeroParameters"/>, then each row is RS-extended to
/// <see cref="LigeroParameters.BlockEncoded"/> columns by
/// <see cref="LigeroReedSolomonEncoder"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the prover-side commitment object: build the tableau over the
/// witness vector and the multiplication constraints, then
/// <see cref="CommitColumns"/> to obtain the Merkle commitment over the
/// extension columns. The later protocol responses (low-degree, dot-product and
/// quadratic tests) read the committed rows and columns back out through
/// <see cref="GetColumn"/> and <see cref="GetRowSpan"/>.
/// </para>
/// <para>
/// Disposable and sensitive: the buffer holds the witness values and the
/// prover's blinding randomness, so <see cref="Dispose"/> clears it before
/// returning it to the pool. The Merkle root is copied out of the tree before
/// the tableau is disposed.
/// </para>
/// <para>
/// Follows the layout of "Ligero: Lightweight Sublinear Arguments Without a
/// Trusted Setup" (Ames, Hazay, Ishai, Venkitasubramaniam, IACR ePrint
/// 2022/1608) — structural reference only, no code dependency.
/// </para>
/// </remarks>
[DebuggerDisplay("LigeroTableau (RowCount = {Parameters.RowCount}, BlockEncoded = {Parameters.BlockEncoded})")]
public sealed class LigeroTableau: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private IMemoryOwner<byte>? buffer;

    //The byte length of one row: BlockEncoded field elements. Cached so the
    //row/column accessors do not recompute it per call.
    private readonly int rowStrideBytes;


    /// <summary>The layout the tableau was built to.</summary>
    public LigeroParameters Parameters { get; }


    private LigeroTableau(IMemoryOwner<byte> buffer, LigeroParameters parameters, int rowStrideBytes)
    {
        this.buffer = buffer;
        this.rowStrideBytes = rowStrideBytes;
        Parameters = parameters;
    }


    /// <summary>
    /// Builds the tableau over <paramref name="witnesses"/> and
    /// <paramref name="quadraticConstraints"/>: lays out the blinding, witness
    /// and quadratic rows and RS-extends each to
    /// <see cref="LigeroParameters.BlockEncoded"/> columns.
    /// </summary>
    /// <param name="parameters">The tableau layout.</param>
    /// <param name="witnesses">The witness vector; exactly <c>WitnessCount · 32</c> canonical bytes.</param>
    /// <param name="quadraticConstraints">One entry per multiplication constraint <c>W[z] = W[x]·W[y]</c>; exactly <see cref="LigeroParameters.QuadraticConstraintCount"/> of them.</param>
    /// <param name="random">The prover-randomness backend filling the blinding entries and per-row padding.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent the tableau buffer and encoding scratch from.</param>
    /// <returns>The built tableau; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a backend, the parameters or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the layout.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a constraint names a witness index outside the vector.</exception>
    /// <exception cref="InvalidOperationException">When a constraint's witness values do not satisfy <c>W[z] = W[x]·W[y]</c>.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The tableau buffer transfers ownership to the returned LigeroTableau, which releases it through its own Dispose.")]
    public static LigeroTableau Build(
        LigeroParameters parameters,
        ReadOnlySpan<byte> witnesses,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        ScalarRandomDelegate random,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);

        int witnessCount = parameters.WitnessCount;
        if(witnesses.Length != witnessCount * ScalarSize)
        {
            throw new ArgumentException($"Witnesses must be {witnessCount * ScalarSize} bytes; received {witnesses.Length}.", nameof(witnesses));
        }

        if(quadraticConstraints.Length != parameters.QuadraticConstraintCount)
        {
            throw new ArgumentException($"Expected {parameters.QuadraticConstraintCount} quadratic constraints; received {quadraticConstraints.Length}.", nameof(quadraticConstraints));
        }

        int blockEncoded = parameters.BlockEncoded;
        int rowStrideBytes = blockEncoded * ScalarSize;

        //The tableau stores the produced random bytes verbatim and discards the
        //per-scalar provenance tag the backend returns, so the inbound tag is
        //ceremonial; an empty tag keeps Build curve-agnostic (it must serve the
        //small test field and P-256, neither of which has a cached scalar tag).
        Tag scalarTag = Tag.Empty;

        //The tableau holds the witness rows, the prover's blinding rows, and the RS extension derived from them
        //— secret, long-lived (it backs the commitment through prove), and too large for the locked native
        //tier. Pin it (pinned-object heap) so it is never GC-relocated and the clear-on-dispose actually wipes
        //the bytes that held the witness. The churny per-step scratch elsewhere stays on the managed tier.
        IMemoryOwner<byte> owner = pool.Rent(parameters.RowCount * rowStrideBytes, AllocationKind.Pinned);
        try
        {
            Span<byte> tableau = owner.Memory.Span[..(parameters.RowCount * rowStrideBytes)];
            tableau.Clear();

            //The barycentric weights depend only on the domain and the message length, so the
            //two lengths every row uses — block and dblock — are computed once for the whole
            //build instead of per row (the binary-field weights are quadratic to compute).
            using IMemoryOwner<byte> weightsOwner = pool.Rent((parameters.Block + parameters.DoubleBlock) * ScalarSize);
            Span<byte> blockWeights = weightsOwner.Memory.Span[..(parameters.Block * ScalarSize)];
            Span<byte> doubleBlockWeights = weightsOwner.Memory.Span.Slice(parameters.Block * ScalarSize, parameters.DoubleBlock * ScalarSize);
            LigeroReedSolomonEncoder.ComputeWeights(parameters.Block, parameters.NodeDomain, blockWeights, subtract, multiply, invert, curve, pool);
            LigeroReedSolomonEncoder.ComputeWeights(parameters.DoubleBlock, parameters.NodeDomain, doubleBlockWeights, subtract, multiply, invert, curve, pool);

            FillBlindingRows(tableau, parameters, rowStrideBytes, blockWeights, doubleBlockWeights, scalarTag, random, add, subtract, multiply, invert, curve, pool);
            FillWitnessRows(tableau, parameters, rowStrideBytes, blockWeights, witnesses, scalarTag, random, add, subtract, multiply, invert, curve, pool);
            FillQuadraticRows(tableau, parameters, rowStrideBytes, blockWeights, witnesses, quadraticConstraints, scalarTag, random, add, subtract, multiply, invert, curve, pool);
        }
        catch
        {
            //A satisfaction failure (or any fill fault) leaves a half-built buffer
            //holding witness material; clear and return it before propagating.
            owner.Memory.Span[..(parameters.RowCount * rowStrideBytes)].Clear();
            owner.Dispose();
            throw;
        }

        return new LigeroTableau(owner, parameters, rowStrideBytes);
    }


    //The three ZK blinding rows: ILDT carries block random message entries;
    //IDOT carries dblock random entries adjusted so its witness-block sums to
    //zero; IQUAD carries dblock random entries with the witness block zeroed.
    private static void FillBlindingRows(
        Span<byte> tableau,
        LigeroParameters parameters,
        int rowStrideBytes,
        ReadOnlySpan<byte> blockWeights,
        ReadOnlySpan<byte> doubleBlockWeights,
        Tag scalarTag,
        ScalarRandomDelegate random,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int blockEncoded = parameters.BlockEncoded;
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;

        //ILDT: block random message entries, extend block -> blockEnc.
        Span<byte> lowDegreeRow = RowSpan(tableau, rowStrideBytes, LigeroParameters.LowDegreeRowIndex);
        FillRandomScalars(lowDegreeRow, 0, block, random, curve, scalarTag);
        EncodeRow(lowDegreeRow, block, blockEncoded, parameters.NodeDomain, blockWeights, add, subtract, multiply, invert, curve, pool);

        //IDOT: dblock random entries; then subtract the whole witness-block sum
        //from column r so the entries [r, r+w) sum to zero (the dot test's
        //blinding must not bias the linear-combination value). Extend dblock -> blockEnc.
        Span<byte> dotRow = RowSpan(tableau, rowStrideBytes, LigeroParameters.DotRowIndex);
        FillRandomScalars(dotRow, 0, dblock, random, curve, scalarTag);
        ZeroWitnessBlockSum(dotRow, r, w, add, subtract, curve);
        EncodeRow(dotRow, dblock, blockEncoded, parameters.NodeDomain, doubleBlockWeights, add, subtract, multiply, invert, curve, pool);

        //IQUAD: dblock random entries but the witness columns [r, r+w) zeroed
        //(left clear by the initial Clear). Extend dblock -> blockEnc.
        Span<byte> quadraticRow = RowSpan(tableau, rowStrideBytes, LigeroParameters.QuadraticRowIndex);
        FillRandomScalars(quadraticRow, 0, r, random, curve, scalarTag);
        FillRandomScalars(quadraticRow, r + w, dblock - (r + w), random, curve, scalarTag);
        EncodeRow(quadraticRow, dblock, blockEncoded, parameters.NodeDomain, doubleBlockWeights, add, subtract, multiply, invert, curve, pool);
    }


    //The witness rows: each carries r random padding entries then up to w
    //witness values (the trailing row zero-pads past the witness count).
    private static void FillWitnessRows(
        Span<byte> tableau,
        LigeroParameters parameters,
        int rowStrideBytes,
        ReadOnlySpan<byte> blockWeights,
        ReadOnlySpan<byte> witnesses,
        Tag scalarTag,
        ScalarRandomDelegate random,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int block = parameters.Block;
        int blockEncoded = parameters.BlockEncoded;
        int r = parameters.RandomCount;
        int w = parameters.WitnessPerRow;
        int witnessCount = parameters.WitnessCount;

        for(int i = 0; i < parameters.WitnessRowCount; i++)
        {
            Span<byte> row = RowSpan(tableau, rowStrideBytes, LigeroParameters.FirstWitnessRowIndex + i);
            FillRandomScalars(row, 0, r, random, curve, scalarTag);
            for(int k = 0; k < w; k++)
            {
                int witnessIndex = (i * w) + k;
                if(witnessIndex < witnessCount)
                {
                    witnesses.Slice(witnessIndex * ScalarSize, ScalarSize).CopyTo(ScalarAt(row, r + k));
                }
            }

            EncodeRow(row, block, blockEncoded, parameters.NodeDomain, blockWeights, add, subtract, multiply, invert, curve, pool);
        }
    }


    //The quadratic-constraint rows: three rows per triple holding the x, y and
    //z operands of up to w constraints. The prover asserts each operand triple
    //satisfies W[z] = W[x]·W[y] before committing.
    private static void FillQuadraticRows(
        Span<byte> tableau,
        LigeroParameters parameters,
        int rowStrideBytes,
        ReadOnlySpan<byte> blockWeights,
        ReadOnlySpan<byte> witnesses,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        Tag scalarTag,
        ScalarRandomDelegate random,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int block = parameters.Block;
        int blockEncoded = parameters.BlockEncoded;
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

            FillRandomScalars(xRow, 0, r, random, curve, scalarTag);
            FillRandomScalars(yRow, 0, r, random, curve, scalarTag);
            FillRandomScalars(zRow, 0, r, random, curve, scalarTag);

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

            EncodeRow(xRow, block, blockEncoded, parameters.NodeDomain, blockWeights, add, subtract, multiply, invert, curve, pool);
            EncodeRow(yRow, block, blockEncoded, parameters.NodeDomain, blockWeights, add, subtract, multiply, invert, curve, pool);
            EncodeRow(zRow, block, blockEncoded, parameters.NodeDomain, blockWeights, add, subtract, multiply, invert, curve, pool);
        }
    }


    /// <summary>
    /// Commits to the tableau by Merkle-hashing its extension columns: leaf
    /// <c>j</c> is <c>columnHash</c> of the column at position
    /// <c>DoubleBlock + j</c> (the <c>j</c>-th of the
    /// <see cref="LigeroParameters.BlockExtension"/> committed columns), and the
    /// leaves are padded with zero leaves up to the next power of two so the
    /// binary tree is well-formed. The verifier opens
    /// <see cref="LigeroParameters.OpenedColumnCount"/> of these columns by index.
    /// </summary>
    /// <param name="columnHash">A bytes-to-digest hash producing one 32-byte leaf from a whole column.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name <paramref name="columnHash"/> implements.</param>
    /// <param name="merkleHash">The two-to-one compression for the tree's internal nodes.</param>
    /// <param name="pool">Pool to rent the leaf buffer, the column scratch and the tree from.</param>
    /// <returns>The Merkle tree over the extension columns; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a hash backend or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">When the tableau has been disposed.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The returned MerkleTree owns its own buffers; the local leaf and column rentals are released by their using scopes.")]
    public MerkleTree CommitColumns(
        FiatShamirHashDelegate columnHash,
        string hashAlgorithm,
        MerkleHashDelegate merkleHash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(columnHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(pool);
        _ = buffer ?? throw new ObjectDisposedException(nameof(LigeroTableau));

        int blockExtension = Parameters.BlockExtension;
        int doubleBlock = Parameters.DoubleBlock;
        int rowCount = Parameters.RowCount;
        int paddedLeafCount = (int)BitOperations.RoundUpToPowerOf2((uint)blockExtension);

        using IMemoryOwner<byte> leavesOwner = pool.Rent(paddedLeafCount * ScalarSize);
        Span<byte> leaves = leavesOwner.Memory.Span[..(paddedLeafCount * ScalarSize)];
        leaves.Clear();

        using IMemoryOwner<byte> columnOwner = pool.Rent(rowCount * ScalarSize);
        Span<byte> column = columnOwner.Memory.Span[..(rowCount * ScalarSize)];

        for(int j = 0; j < blockExtension; j++)
        {
            GetColumn(doubleBlock + j, column);
            columnHash(column, leaves.Slice(j * ScalarSize, ScalarSize), hashAlgorithm);
        }

        return MerkleTree.Build(leaves, paddedLeafCount, merkleHash, pool);
    }


    /// <summary>
    /// Gathers the column at <paramref name="columnIndex"/> — one entry from
    /// every row, top to bottom — into <paramref name="destination"/>.
    /// </summary>
    /// <param name="columnIndex">The column index in <c>[0, BlockEncoded)</c>.</param>
    /// <param name="destination">Receives <see cref="LigeroParameters.RowCount"/> scalars (<c>RowCount · 32</c> bytes).</param>
    /// <exception cref="ObjectDisposedException">When the tableau has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="columnIndex"/> is out of range.</exception>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is the wrong length.</exception>
    public void GetColumn(int columnIndex, Span<byte> destination)
    {
        IMemoryOwner<byte> local = buffer ?? throw new ObjectDisposedException(nameof(LigeroTableau));
        ArgumentOutOfRangeException.ThrowIfNegative(columnIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(columnIndex, Parameters.BlockEncoded);
        if(destination.Length != Parameters.RowCount * ScalarSize)
        {
            throw new ArgumentException($"Destination must be {Parameters.RowCount * ScalarSize} bytes; received {destination.Length}.", nameof(destination));
        }

        Span<byte> tableau = local.Memory.Span;
        for(int rowIndex = 0; rowIndex < Parameters.RowCount; rowIndex++)
        {
            int offset = (rowIndex * rowStrideBytes) + (columnIndex * ScalarSize);
            tableau.Slice(offset, ScalarSize).CopyTo(destination.Slice(rowIndex * ScalarSize, ScalarSize));
        }
    }


    /// <summary>
    /// Returns the row at <paramref name="rowIndex"/> — all
    /// <see cref="LigeroParameters.BlockEncoded"/> codeword entries — for the
    /// protocol response that linearly combines rows.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the tableau has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="rowIndex"/> is out of range.</exception>
    internal ReadOnlySpan<byte> GetRowSpan(int rowIndex)
    {
        IMemoryOwner<byte> local = buffer ?? throw new ObjectDisposedException(nameof(LigeroTableau));
        ArgumentOutOfRangeException.ThrowIfNegative(rowIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(rowIndex, Parameters.RowCount);

        return local.Memory.Span.Slice(rowIndex * rowStrideBytes, rowStrideBytes);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = buffer;
        if(local is not null)
        {
            buffer = null;
            try
            {
                //The buffer holds witness values and prover blinding randomness;
                //clear before returning it to the pool.
                local.Memory.Span[..(Parameters.RowCount * rowStrideBytes)].Clear();
                local.Dispose();
            }
            catch
            {
                //Disposal must not throw; an orphaned buffer is preferable to a crash.
            }
        }
    }


    //Returns the writable span of the whole row at the given index.
    private static Span<byte> RowSpan(Span<byte> tableau, int rowStrideBytes, int rowIndex) =>
        tableau.Slice(rowIndex * rowStrideBytes, rowStrideBytes);


    //Returns the writable span of the single scalar at the given column within a row.
    private static Span<byte> ScalarAt(Span<byte> row, int columnIndex) =>
        row.Slice(columnIndex * ScalarSize, ScalarSize);


    //Returns the witness at the given index, bounds-checked against the vector.
    private static ReadOnlySpan<byte> WitnessAt(ReadOnlySpan<byte> witnesses, int index, int witnessCount)
    {
        if((uint)index >= (uint)witnessCount)
        {
            throw new ArgumentOutOfRangeException(nameof(index), $"Witness index {index} is outside the {witnessCount}-element witness vector.");
        }

        return witnesses.Slice(index * ScalarSize, ScalarSize);
    }


    //Fills count consecutive scalars of the row, starting at firstColumn, with
    //fresh prover randomness.
    private static void FillRandomScalars(Span<byte> row, int firstColumn, int count, ScalarRandomDelegate random, CurveParameterSet curve, Tag scalarTag)
    {
        for(int k = 0; k < count; k++)
        {
            _ = random(ScalarAt(row, firstColumn + k), curve, scalarTag);
        }
    }


    //Subtracts the sum of the witness block [r, r+w) from column r so that the
    //block sums to the field's zero.
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


    //RS-extends the row's first messageLength entries to the full blockEnc
    //codeword in place. The message is the row's own prefix, so the encoder's
    //systematic copy is an identity copy of that region.
    private static void EncodeRow(
        Span<byte> row,
        int messageLength,
        int blockEncoded,
        LigeroNodeDomain nodeDomain,
        ReadOnlySpan<byte> weights,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        LigeroReedSolomonEncoder.Encode(
            row[..(messageLength * ScalarSize)],
            messageLength,
            row,
            blockEncoded,
            nodeDomain,
            weights,
            add,
            subtract,
            multiply,
            invert,
            curve,
            pool);
    }
}
