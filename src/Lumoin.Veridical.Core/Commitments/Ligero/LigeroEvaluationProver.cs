using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The Ligero polynomial-commitment prover: commits to a multilinear
/// polynomial's evaluation matrix (RS-encode each row, Merkle-commit the
/// extension columns) and answers an evaluation query with a proximity
/// row-combination, the evaluation row-combination, and the opened columns with
/// their Merkle paths.
/// </summary>
/// <remarks>
/// The opening is serialized into one flat buffer in the layout
/// <c>[u | v | per-query(column | path)]</c>, fully determined by the
/// <see cref="LigeroEvaluationDimensions"/> and the digest size, so the verifier
/// parses it without any length prefixes. Structural reference: "Ligero" (Ames,
/// Hazay, Ishai, Venkitasubramaniam, IACR ePrint 2022/1608) and the Brakedown
/// tensor-query evaluation argument; no code dependency.
/// </remarks>
internal static class LigeroEvaluationProver
{
    /// <summary>The byte width of one scalar in this prover's evaluation matrix and opening buffers, matching the library-wide scalar size.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>The serialized opening length for the given dimensions and digest size.</summary>
    public static int OpeningLengthBytes(LigeroEvaluationDimensions dimensions, int digestSizeBytes) =>
        (2 * dimensions.ColumnCount * ScalarSize)
        + (dimensions.OpenedColumnCount * ((dimensions.RowCount * ScalarSize) + (dimensions.PathDepth * digestSizeBytes)));


    /// <summary>
    /// Commits to the evaluation matrix and returns the column Merkle tree; the
    /// caller copies out <see cref="MerkleTree.Root"/> and disposes the tree.
    /// </summary>
    /// <param name="evaluations">The polynomial's evaluation matrix, row-major; exactly <c>RowCount · ColumnCount · 32</c> bytes.</param>
    /// <param name="dimensions">The matrix and code shape.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="columnHash">The one-shot bytes-to-digest hash producing a Merkle leaf from a whole column; must write exactly the output span's length.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name.</param>
    /// <param name="merkleParameters">The Merkle compression paired with the node width it produces.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent working buffers from.</param>
    /// <param name="rowExtenderFactory">Optional row-extension source consulted once for the matrix's single row shape, in place of the barycentric path; <see langword="null"/> (the default) uses the barycentric encode.</param>
    public static MerkleTree Commit(
        ReadOnlySpan<byte> evaluations,
        LigeroEvaluationDimensions dimensions,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        FiatShamirHashDelegate columnHash,
        string hashAlgorithm,
        MerkleCommitmentParameters merkleParameters,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        LigeroRowExtenderFactory? rowExtenderFactory = null)
    {
        //Every row of the matrix shares one (ColumnCount, CodewordLength) shape, so the
        //extender is resolved once here, before the per-row loop inside EncodeMatrix.
        LigeroRowExtender? rowExtender = ResolveRowExtender(rowExtenderFactory, dimensions.ColumnCount, dimensions.CodewordLength);
        using IMemoryOwner<byte> encodedOwner = EncodeMatrix(evaluations, dimensions, add, subtract, multiply, invert, curve, pool, rowExtender);
        return CommitColumns(encodedOwner.Memory.Span[..(dimensions.RowCount * dimensions.CodewordLength * ScalarSize)], dimensions, columnHash, hashAlgorithm, merkleParameters, pool);
    }


    /// <summary>
    /// Produces the evaluation opening into <paramref name="openingDestination"/>
    /// (length <see cref="OpeningLengthBytes"/>) and writes the claimed value
    /// <c>p(point) = ⟨v, R⟩</c> into <paramref name="claimedValueDestination"/>
    /// (one scalar). Runs the full Fiat-Shamir schedule against
    /// <paramref name="transcript"/>.
    /// </summary>
    /// <param name="evaluations">The polynomial's evaluation matrix, row-major; exactly <c>RowCount · ColumnCount · 32</c> bytes.</param>
    /// <param name="evaluationPoint">The multilinear evaluation point; exactly <c>ColumnVariableCount + RowVariableCount</c> scalars.</param>
    /// <param name="dimensions">The matrix and code shape.</param>
    /// <param name="openingDestination">Receives the serialized opening; exactly <see cref="OpeningLengthBytes"/> bytes.</param>
    /// <param name="claimedValueDestination">Receives the claimed evaluation <c>p(point)</c>; one scalar.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="reduce">Scalar-reduce backend for the challenge squeeze.</param>
    /// <param name="hash">The fixed-output transcript hash backend.</param>
    /// <param name="squeeze">The transcript XOF backend.</param>
    /// <param name="columnHash">The one-shot bytes-to-digest hash producing a Merkle leaf from a whole column; must write exactly the output span's length.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name.</param>
    /// <param name="merkleParameters">The Merkle compression paired with the node width it produces; the width also prices the opening's authentication paths.</param>
    /// <param name="transcript">The Fiat-Shamir transcript to absorb into and squeeze from.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent working buffers from.</param>
    /// <param name="rowExtenderFactory">Optional row-extension source consulted once for the matrix's single row shape, in place of the barycentric path; <see langword="null"/> (the default) uses the barycentric encode.</param>
    public static void Prove(
        ReadOnlySpan<byte> evaluations,
        ReadOnlySpan<Scalar> evaluationPoint,
        LigeroEvaluationDimensions dimensions,
        Span<byte> openingDestination,
        Span<byte> claimedValueDestination,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate columnHash,
        string hashAlgorithm,
        MerkleCommitmentParameters merkleParameters,
        FiatShamirTranscript transcript,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        LigeroRowExtenderFactory? rowExtenderFactory = null)
    {
        int digestSizeBytes = merkleParameters.NodeSizeBytes;
        int rowCount = dimensions.RowCount;
        int columnCount = dimensions.ColumnCount;
        int codewordLength = dimensions.CodewordLength;
        int openedColumnCount = dimensions.OpenedColumnCount;

        //Every row of the matrix shares one (ColumnCount, CodewordLength) shape, so the
        //extender is resolved once here, before the per-row loop inside EncodeMatrix.
        LigeroRowExtender? rowExtender = ResolveRowExtender(rowExtenderFactory, columnCount, codewordLength);
        using IMemoryOwner<byte> encodedOwner = EncodeMatrix(evaluations, dimensions, add, subtract, multiply, invert, curve, pool, rowExtender);
        Span<byte> encoded = encodedOwner.Memory.Span[..(rowCount * codewordLength * ScalarSize)];

        using MerkleTree tree = CommitColumns(encoded, dimensions, columnHash, hashAlgorithm, merkleParameters, pool);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroEvaluationLabels.CommitmentRoot), tree.Root.AsReadOnlySpan(), hash);

        //Proximity coefficients γ (one per row), squeezed from the commitment.
        using IMemoryOwner<byte> gammaOwner = pool.Rent(rowCount * ScalarSize);
        Span<byte> gamma = gammaOwner.Memory.Span[..(rowCount * ScalarSize)];
        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroEvaluationLabels.ProximityChallenge), rowCount, gamma, squeeze, hash, reduce, curve, pool);

        //The public evaluation tensors: R over the lower (column) variables, L over the upper (row) variables.
        using IMemoryOwner<byte> rTensorOwner = pool.Rent(columnCount * ScalarSize);
        Span<byte> rTensor = rTensorOwner.Memory.Span[..(columnCount * ScalarSize)];
        LigeroEvaluationTensor.ComputeEqualityWeights(evaluationPoint, 0, dimensions.ColumnVariableCount, rTensor, subtract, multiply, curve, pool);

        using IMemoryOwner<byte> lTensorOwner = pool.Rent(rowCount * ScalarSize);
        Span<byte> lTensor = lTensorOwner.Memory.Span[..(rowCount * ScalarSize)];
        LigeroEvaluationTensor.ComputeEqualityWeights(evaluationPoint, dimensions.ColumnVariableCount, dimensions.RowVariableCount, lTensor, subtract, multiply, curve, pool);

        //u = γ·M (proximity), v = L·M (evaluation), written into the opening prefix.
        Span<byte> u = openingDestination[..(columnCount * ScalarSize)];
        Span<byte> v = openingDestination.Slice(columnCount * ScalarSize, columnCount * ScalarSize);
        LigeroEvaluationTensor.CombineRows(gamma, evaluations, rowCount, columnCount, u, add, multiply, curve);
        LigeroEvaluationTensor.CombineRows(lTensor, evaluations, rowCount, columnCount, v, add, multiply, curve);

        //claimedValue = ⟨v, R⟩ = p(point).
        LigeroEvaluationTensor.InnerProduct(v, rTensor, columnCount, claimedValueDestination, add, multiply, curve);

        //Absorb both responses, then draw the opened-column indices.
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroEvaluationLabels.ProximityResponse), u, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroEvaluationLabels.EvaluationResponse), v, hash);

        Span<int> indices = stackalloc int[openedColumnCount];
        transcript.SqueezeLigeroDistinctColumnIndices(dimensions.ExtensionWidth, openedColumnCount, indices, squeeze, hash);

        //Open each drawn column (encoded-matrix column at node ColumnCount + idx) with its Merkle path.
        int perQueryBytes = (rowCount * ScalarSize) + (dimensions.PathDepth * digestSizeBytes);
        int queryBase = 2 * columnCount * ScalarSize;
        for(int q = 0; q < openedColumnCount; q++)
        {
            Span<byte> columnDestination = openingDestination.Slice(queryBase + (q * perQueryBytes), rowCount * ScalarSize);
            GatherColumn(encoded, dimensions, columnCount + indices[q], columnDestination);

            using MerkleAuthenticationPath path = tree.BuildPath(indices[q], pool);
            ReadOnlySpan<byte> pathBytes = path.AsReadOnlySpan();

            //The path must fill exactly the slot the length arithmetic priced:
            //a shorter path would leave a tail the reader parses as path
            //material, and the length check on the way back in prices the
            //sections the same way and cannot see the difference. The tree and
            //the pricing share one node width by construction, so a mismatch
            //here can only mean the dimensions' path depth and the tree's
            //actual depth drifted apart.
            if(pathBytes.Length != dimensions.PathDepth * digestSizeBytes)
            {
                throw new ArgumentException(
                    $"The authentication path carries {pathBytes.Length} bytes where the opening prices {dimensions.PathDepth * digestSizeBytes}. The dimensions' path depth and the tree's depth must agree.",
                    nameof(dimensions));
            }

            pathBytes.CopyTo(openingDestination.Slice(queryBase + (q * perQueryBytes) + (rowCount * ScalarSize), dimensions.PathDepth * digestSizeBytes));
        }
    }


    /// <summary>
    /// RS-encodes each of the RowCount message rows (ColumnCount -&gt; CodewordLength) into a freshly
    /// rented row-major encoded matrix. Message and codeword are separate buffers here (unlike
    /// <see cref="LigeroTableau"/>'s in-place rows), so the extender path first copies the message
    /// into the codeword's prefix, then runs the extender over the whole codeword. The barycentric
    /// fallback computes its weights once for the shape shared by every row, rather than per row.
    /// </summary>
    private static IMemoryOwner<byte> EncodeMatrix(
        ReadOnlySpan<byte> evaluations,
        LigeroEvaluationDimensions dimensions,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        LigeroRowExtender? rowExtender = null)
    {
        int rowCount = dimensions.RowCount;
        int columnCount = dimensions.ColumnCount;
        int codewordLength = dimensions.CodewordLength;

        if(evaluations.Length != rowCount * columnCount * ScalarSize)
        {
            throw new ArgumentException($"Evaluations must be {rowCount * columnCount * ScalarSize} bytes; received {evaluations.Length}.", nameof(evaluations));
        }

        IMemoryOwner<byte> owner = pool.Rent(rowCount * codewordLength * ScalarSize);
        try
        {
            Span<byte> encoded = owner.Memory.Span[..(rowCount * codewordLength * ScalarSize)];
            if(rowExtender is not null)
            {
                for(int i = 0; i < rowCount; i++)
                {
                    ReadOnlySpan<byte> message = evaluations.Slice(i * columnCount * ScalarSize, columnCount * ScalarSize);
                    Span<byte> codeword = encoded.Slice(i * codewordLength * ScalarSize, codewordLength * ScalarSize);
                    message.CopyTo(codeword[..(columnCount * ScalarSize)]);
                    rowExtender(codeword);
                }

                return owner;
            }

            using IMemoryOwner<byte> weightsOwner = pool.Rent(columnCount * ScalarSize);
            Span<byte> weights = weightsOwner.Memory.Span[..(columnCount * ScalarSize)];
            LigeroReedSolomonEncoder.ComputeWeights(columnCount, LigeroNodeDomain.ConsecutiveIntegers, weights, subtract, multiply, invert, curve, pool);
            for(int i = 0; i < rowCount; i++)
            {
                ReadOnlySpan<byte> message = evaluations.Slice(i * columnCount * ScalarSize, columnCount * ScalarSize);
                Span<byte> codeword = encoded.Slice(i * codewordLength * ScalarSize, codewordLength * ScalarSize);
                LigeroReedSolomonEncoder.Encode(message, columnCount, codeword, codewordLength, LigeroNodeDomain.ConsecutiveIntegers, weights, add, subtract, multiply, invert, curve, pool);
            }

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Merkle-commits the extension columns <c>[ColumnCount, CodewordLength)</c>:
    /// leaf <c>j</c> is <paramref name="columnHash"/> of the <c>j</c>-th
    /// extension column (<c>RowCount</c> entries) written at node width — the
    /// column hash is Ligero's leaf commitment and must honour the output
    /// span's length — padded with all-zero node-wide leaves up to
    /// <c>PaddedLeafCount</c>.
    /// </summary>
    /// <param name="encoded">The row-major encoded matrix.</param>
    /// <param name="dimensions">The matrix and code shape.</param>
    /// <param name="columnHash">The one-shot bytes-to-digest hash producing a node-wide Merkle leaf from a whole column.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name.</param>
    /// <param name="merkleParameters">The Merkle compression paired with the node width it produces.</param>
    /// <param name="pool">Pool to rent working buffers from.</param>
    private static MerkleTree CommitColumns(
        ReadOnlySpan<byte> encoded,
        LigeroEvaluationDimensions dimensions,
        FiatShamirHashDelegate columnHash,
        string hashAlgorithm,
        MerkleCommitmentParameters merkleParameters,
        BaseMemoryPool pool)
    {
        int rowCount = dimensions.RowCount;
        int columnCount = dimensions.ColumnCount;
        int paddedLeafCount = dimensions.PaddedLeafCount;
        int nodeSize = merkleParameters.NodeSizeBytes;

        using IMemoryOwner<byte> leavesOwner = pool.Rent(paddedLeafCount * nodeSize);
        Span<byte> leaves = leavesOwner.Memory.Span[..(paddedLeafCount * nodeSize)];
        leaves.Clear();

        using IMemoryOwner<byte> columnOwner = pool.Rent(rowCount * ScalarSize);
        Span<byte> column = columnOwner.Memory.Span[..(rowCount * ScalarSize)];

        for(int j = 0; j < dimensions.ExtensionWidth; j++)
        {
            GatherColumn(encoded, dimensions, columnCount + j, column);
            columnHash(column, leaves.Slice(j * nodeSize, nodeSize), hashAlgorithm);
        }

        return MerkleTree.Build(leaves, paddedLeafCount, merkleParameters, pool);
    }


    /// <summary>
    /// Consults the factory for the matrix's row shape. <see cref="EncodeMatrix"/> passes
    /// <see cref="LigeroNodeDomain.ConsecutiveIntegers"/> explicitly at both of its encode call sites,
    /// so this PCS path never runs the BinaryField domain and needs no domain argument to gate on,
    /// unlike <see cref="LigeroTableau"/>'s build.
    /// </summary>
    private static LigeroRowExtender? ResolveRowExtender(LigeroRowExtenderFactory? factory, int messageLength, int codewordLength)
    {
        if(factory is null)
        {
            return null;
        }

        return factory(messageLength, codewordLength);
    }


    /// <summary>Gathers the encoded-matrix column at the given codeword node into <paramref name="destination"/> (one entry per row, top to bottom).</summary>
    private static void GatherColumn(ReadOnlySpan<byte> encoded, LigeroEvaluationDimensions dimensions, int node, Span<byte> destination)
    {
        int codewordLength = dimensions.CodewordLength;
        for(int i = 0; i < dimensions.RowCount; i++)
        {
            encoded.Slice(((i * codewordLength) + node) * ScalarSize, ScalarSize).CopyTo(destination.Slice(i * ScalarSize, ScalarSize));
        }
    }
}
