using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The Ligero polynomial-commitment verifier: replays the prover's Fiat-Shamir
/// schedule against the committed root, then checks each opened column
/// authenticates against the root and is consistent with both the proximity
/// response <c>u</c> and the evaluation response <c>v</c>, and that
/// <c>⟨v, R⟩</c> equals the claimed value.
/// </summary>
internal static class LigeroEvaluationVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Verifies an opening of <paramref name="commitmentRoot"/> at
    /// <paramref name="evaluationPoint"/> against <paramref name="claimedValue"/>.
    /// Returns <see langword="false"/> on any malformed input or failed check.
    /// </summary>
    public static bool Verify(
        ReadOnlySpan<byte> commitmentRoot,
        ReadOnlySpan<Scalar> evaluationPoint,
        ReadOnlySpan<byte> claimedValue,
        ReadOnlySpan<byte> opening,
        LigeroEvaluationDimensions dimensions,
        int digestSizeBytes,
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
        int openedColumnCount = dimensions.OpenedColumnCount;
        int pathBytes = dimensions.PathDepth * digestSizeBytes;
        int perQueryBytes = (rowCount * ScalarSize) + pathBytes;
        int queryBase = 2 * columnCount * ScalarSize;

        if(opening.Length != LigeroEvaluationProver.OpeningLengthBytes(dimensions, digestSizeBytes)
            || claimedValue.Length != ScalarSize
            || commitmentRoot.Length != digestSizeBytes)
        {
            return false;
        }

        ReadOnlySpan<byte> u = opening[..(columnCount * ScalarSize)];
        ReadOnlySpan<byte> v = opening.Slice(columnCount * ScalarSize, columnCount * ScalarSize);

        //Replay the schedule: absorb root, squeeze γ, absorb u and v, draw indices.
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroEvaluationLabels.CommitmentRoot), commitmentRoot, hash);

        using IMemoryOwner<byte> gammaOwner = pool.Rent(rowCount * ScalarSize);
        Span<byte> gamma = gammaOwner.Memory.Span[..(rowCount * ScalarSize)];
        transcript.SqueezeLigeroChallengeScalars(new FiatShamirOperationLabel(WellKnownLigeroEvaluationLabels.ProximityChallenge), rowCount, gamma, squeeze, hash, reduce, curve, pool);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroEvaluationLabels.ProximityResponse), u, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLigeroEvaluationLabels.EvaluationResponse), v, hash);

        Span<int> indices = stackalloc int[openedColumnCount];
        transcript.SqueezeLigeroDistinctColumnIndices(dimensions.ExtensionWidth, openedColumnCount, indices, squeeze, hash);

        //Public evaluation tensors.
        using IMemoryOwner<byte> rTensorOwner = pool.Rent(columnCount * ScalarSize);
        Span<byte> rTensor = rTensorOwner.Memory.Span[..(columnCount * ScalarSize)];
        LigeroEvaluationTensor.ComputeEqualityWeights(evaluationPoint, 0, dimensions.ColumnVariableCount, rTensor, subtract, multiply, curve, pool);

        using IMemoryOwner<byte> lTensorOwner = pool.Rent(rowCount * ScalarSize);
        Span<byte> lTensor = lTensorOwner.Memory.Span[..(rowCount * ScalarSize)];
        LigeroEvaluationTensor.ComputeEqualityWeights(evaluationPoint, dimensions.ColumnVariableCount, dimensions.RowVariableCount, lTensor, subtract, multiply, curve, pool);

        //RS weights for evaluating u, v at the opened nodes.
        using IMemoryOwner<byte> weightsOwner = pool.Rent(columnCount * ScalarSize);
        Span<byte> weights = weightsOwner.Memory.Span[..(columnCount * ScalarSize)];
        BarycentricInterpolation.ComputeConsecutiveNodeWeights(columnCount, weights, subtract, multiply, invert, curve, pool);

        using MerkleRoot root = MerkleRoot.FromBytes(commitmentRoot, pool);

        Span<byte> leaf = stackalloc byte[digestSizeBytes];
        Span<byte> encodedAtNode = stackalloc byte[ScalarSize];
        Span<byte> combined = stackalloc byte[ScalarSize];
        Span<int> singlePoint = stackalloc int[1];
        for(int q = 0; q < openedColumnCount; q++)
        {
            int idx = indices[q];
            ReadOnlySpan<byte> column = opening.Slice(queryBase + (q * perQueryBytes), rowCount * ScalarSize);
            ReadOnlySpan<byte> pathSpan = opening.Slice(queryBase + (q * perQueryBytes) + (rowCount * ScalarSize), pathBytes);

            //(a) Merkle authentication of the opened column against the root.
            columnHash(column, leaf, hashAlgorithm);
            if(!AuthenticatePath(pathSpan, digestSizeBytes, root, idx, leaf, merkleHash, pool))
            {
                return false;
            }

            singlePoint[0] = columnCount + idx;

            //(b) encode(u)[c] == Σ_i γ[i]·column[i] and encode(v)[c] == Σ_i L[i]·column[i].
            BarycentricInterpolation.EvaluateAtPoints(u, weights, columnCount, singlePoint, encodedAtNode, add, subtract, multiply, invert, curve, pool);
            LigeroEvaluationTensor.InnerProduct(gamma, column, rowCount, combined, add, multiply, curve);
            if(!encodedAtNode.SequenceEqual(combined))
            {
                return false;
            }

            BarycentricInterpolation.EvaluateAtPoints(v, weights, columnCount, singlePoint, encodedAtNode, add, subtract, multiply, invert, curve, pool);
            LigeroEvaluationTensor.InnerProduct(lTensor, column, rowCount, combined, add, multiply, curve);
            if(!encodedAtNode.SequenceEqual(combined))
            {
                return false;
            }
        }

        //The value check: ⟨v, R⟩ must equal the claimed evaluation.
        LigeroEvaluationTensor.InnerProduct(v, rTensor, columnCount, combined, add, multiply, curve);

        return combined.SequenceEqual(claimedValue);
    }


    //Reconstructs the authentication path from its serialized siblings and checks
    //it against the root (precedent: BaseFoldEvaluationProofSerialization.ReadPath).
    private static bool AuthenticatePath(
        ReadOnlySpan<byte> pathSpan,
        int digestSizeBytes,
        MerkleRoot root,
        int leafIndex,
        ReadOnlySpan<byte> leaf,
        MerkleHashDelegate merkleHash,
        BaseMemoryPool pool)
    {
        IMemoryOwner<byte> pathOwner = pool.Rent(Math.Max(1, pathSpan.Length));
        pathSpan.CopyTo(pathOwner.Memory.Span[..pathSpan.Length]);
        using MerkleAuthenticationPath path = MerkleAuthenticationPath.Create(pathOwner, pathSpan.Length, digestSizeBytes);

        return path.Verify(root, leafIndex, leaf, merkleHash);
    }
}
