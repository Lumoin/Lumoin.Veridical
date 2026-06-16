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
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>The serialized opening length for the given dimensions and digest size.</summary>
    public static int OpeningLengthBytes(LigeroEvaluationDimensions dimensions, int digestSizeBytes) =>
        (2 * dimensions.ColumnCount * ScalarSize)
        + (dimensions.OpenedColumnCount * ((dimensions.RowCount * ScalarSize) + (dimensions.PathDepth * digestSizeBytes)));


    /// <summary>
    /// Commits to the evaluation matrix and returns the column Merkle tree; the
    /// caller copies out <see cref="MerkleTree.Root"/> and disposes the tree.
    /// </summary>
    public static MerkleTree Commit(
        ReadOnlySpan<byte> evaluations,
        LigeroEvaluationDimensions dimensions,
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
        using IMemoryOwner<byte> encodedOwner = EncodeMatrix(evaluations, dimensions, add, subtract, multiply, invert, curve, pool);
        return CommitColumns(encodedOwner.Memory.Span[..(dimensions.RowCount * dimensions.CodewordLength * ScalarSize)], dimensions, columnHash, hashAlgorithm, merkleHash, pool);
    }


    /// <summary>
    /// Produces the evaluation opening into <paramref name="openingDestination"/>
    /// (length <see cref="OpeningLengthBytes"/>) and writes the claimed value
    /// <c>p(point) = ⟨v, R⟩</c> into <paramref name="claimedValueDestination"/>
    /// (one scalar). Runs the full Fiat-Shamir schedule against
    /// <paramref name="transcript"/>.
    /// </summary>
    public static void Prove(
        ReadOnlySpan<byte> evaluations,
        ReadOnlySpan<Scalar> evaluationPoint,
        LigeroEvaluationDimensions dimensions,
        int digestSizeBytes,
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
        MerkleHashDelegate merkleHash,
        FiatShamirTranscript transcript,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int rowCount = dimensions.RowCount;
        int columnCount = dimensions.ColumnCount;
        int codewordLength = dimensions.CodewordLength;
        int openedColumnCount = dimensions.OpenedColumnCount;

        using IMemoryOwner<byte> encodedOwner = EncodeMatrix(evaluations, dimensions, add, subtract, multiply, invert, curve, pool);
        Span<byte> encoded = encodedOwner.Memory.Span[..(rowCount * codewordLength * ScalarSize)];

        using MerkleTree tree = CommitColumns(encoded, dimensions, columnHash, hashAlgorithm, merkleHash, pool);

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
            path.AsReadOnlySpan().CopyTo(openingDestination.Slice(queryBase + (q * perQueryBytes) + (rowCount * ScalarSize), dimensions.PathDepth * digestSizeBytes));
        }
    }


    //RS-encodes each of the RowCount message rows (ColumnCount -> CodewordLength)
    //into a freshly rented row-major encoded matrix.
    private static IMemoryOwner<byte> EncodeMatrix(
        ReadOnlySpan<byte> evaluations,
        LigeroEvaluationDimensions dimensions,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
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
            for(int i = 0; i < rowCount; i++)
            {
                ReadOnlySpan<byte> message = evaluations.Slice(i * columnCount * ScalarSize, columnCount * ScalarSize);
                Span<byte> codeword = encoded.Slice(i * codewordLength * ScalarSize, codewordLength * ScalarSize);
                LigeroReedSolomonEncoder.Encode(message, columnCount, codeword, codewordLength, add, subtract, multiply, invert, curve, pool);
            }

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    //Merkle-commits the extension columns [ColumnCount, CodewordLength): leaf j is
    //columnHash of the j-th extension column (RowCount entries), padded with zero
    //leaves up to PaddedLeafCount.
    private static MerkleTree CommitColumns(
        ReadOnlySpan<byte> encoded,
        LigeroEvaluationDimensions dimensions,
        FiatShamirHashDelegate columnHash,
        string hashAlgorithm,
        MerkleHashDelegate merkleHash,
        BaseMemoryPool pool)
    {
        int rowCount = dimensions.RowCount;
        int columnCount = dimensions.ColumnCount;
        int paddedLeafCount = dimensions.PaddedLeafCount;

        using IMemoryOwner<byte> leavesOwner = pool.Rent(paddedLeafCount * ScalarSize);
        Span<byte> leaves = leavesOwner.Memory.Span[..(paddedLeafCount * ScalarSize)];
        leaves.Clear();

        using IMemoryOwner<byte> columnOwner = pool.Rent(rowCount * ScalarSize);
        Span<byte> column = columnOwner.Memory.Span[..(rowCount * ScalarSize)];

        for(int j = 0; j < dimensions.ExtensionWidth; j++)
        {
            GatherColumn(encoded, dimensions, columnCount + j, column);
            columnHash(column, leaves.Slice(j * ScalarSize, ScalarSize), hashAlgorithm);
        }

        return MerkleTree.Build(leaves, paddedLeafCount, merkleHash, pool);
    }


    //Gathers the encoded-matrix column at the given codeword node into destination
    //(one entry per row, top to bottom).
    private static void GatherColumn(ReadOnlySpan<byte> encoded, LigeroEvaluationDimensions dimensions, int node, Span<byte> destination)
    {
        int codewordLength = dimensions.CodewordLength;
        for(int i = 0; i < dimensions.RowCount; i++)
        {
            encoded.Slice(((i * codewordLength) + node) * ScalarSize, ScalarSize).CopyTo(destination.Slice(i * ScalarSize, ScalarSize));
        }
    }
}
