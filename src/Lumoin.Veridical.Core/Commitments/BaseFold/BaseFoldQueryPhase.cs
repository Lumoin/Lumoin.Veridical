using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The BaseFold IOPP query phase, shared by the standalone proximity IOPP
/// (<see cref="BaseFoldIoppProver"/> / <see cref="BaseFoldIoppVerifier"/>) and
/// the evaluation protocol (<see cref="BaseFoldEvaluationProver"/> /
/// <see cref="BaseFoldEvaluationVerifier"/>). Both protocols commit and fold a
/// codeword identically; they differ only in where the per-round fold
/// challenges come from (squeezed alone for the IOPP, shared with the sumcheck
/// for the evaluation protocol). The query openings and their verification are
/// therefore the same, and live here once.
/// </summary>
/// <remarks>
/// Fold pairs follow the paper's Type-2 ordering (partners a half-layer apart),
/// matching <see cref="FoldableCodeExtensions"/>. The verifier derives every
/// leaf index itself from the squeezed query index, so nothing index-related is
/// trusted from the proof.
/// </remarks>
internal static class BaseFoldQueryPhase
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Reveals, for one query index <paramref name="j0"/>, the fold pair (and
    /// Merkle paths) at every layer from <paramref name="d"/> down to 1,
    /// tracking the position as it folds toward the base.
    /// </summary>
    internal static BaseFoldQueryStep[] BuildOpening(
        MerkleTree?[] trees,
        IMemoryOwner<byte>?[] codewords,
        int baseUnit,
        int d,
        int j0,
        BaseMemoryPool pool,
        IMemoryOwner<byte>?[]? saltsByLayer = null)
    {
        var steps = new BaseFoldQueryStep[d];
        int position = j0;

        for(int level = d; level >= 1; level--)
        {
            int lowerLength = LayerLength(baseUnit, level - 1);
            int firstIndex = position;
            int secondIndex = position + lowerLength;

            ReadOnlySpan<byte> layer = codewords[level]!.Memory.Span[..(LayerLength(baseUnit, level) * ScalarSize)];
            ReadOnlySpan<byte> first = layer.Slice(firstIndex * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> second = layer.Slice(secondIndex * ScalarSize, ScalarSize);

            MerkleAuthenticationPath firstPath = trees[level]!.BuildPath(firstIndex, pool);
            MerkleAuthenticationPath secondPath = trees[level]!.BuildPath(secondIndex, pool);

            if(saltsByLayer is null)
            {
                steps[d - level] = BaseFoldQueryStep.Create(level, first, second, firstPath, secondPath, pool);
            }
            else
            {
                //Hiding: the authenticated leaf at each position is
                //hash(value ‖ salt); the verifier needs the salt to recompute it.
                ReadOnlySpan<byte> saltLayer = saltsByLayer[level]!.Memory.Span[..(LayerLength(baseUnit, level) * ScalarSize)];
                ReadOnlySpan<byte> firstSalt = saltLayer.Slice(firstIndex * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> secondSalt = saltLayer.Slice(secondIndex * ScalarSize, ScalarSize);
                steps[d - level] = BaseFoldQueryStep.CreateSalted(level, first, second, firstSalt, secondSalt, firstPath, secondPath, pool);
            }

            //The folded value lands at position in π_{level-1}; the next layer's
            //fold pair is taken modulo the next lower-layer length.
            if(level - 1 >= 1)
            {
                position %= LayerLength(baseUnit, level - 2);
            }
        }

        return steps;
    }


    /// <summary>
    /// Verifies one query's per-layer openings: each revealed fold pair must
    /// authenticate against its layer root, and folding it under the round
    /// challenge must equal the entry the next layer down carries (or, at
    /// layer 1, the cleartext base entry). The fold challenge for layer
    /// <c>level</c> is <c>challengesForLevel[level]</c>.
    /// </summary>
    internal static bool VerifyQuery(
        FoldableCode code,
        MerkleRoot commitment,
        IReadOnlyList<MerkleRoot> foldRoots,
        IReadOnlyList<BaseFoldQueryStep> steps,
        ReadOnlySpan<byte> finalOracle,
        int baseUnit,
        int d,
        int j0,
        Scalar[] challengesForLevel,
        MerkleHashDelegate merkleHash,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert)
    {
        if(steps.Count != d)
        {
            return false;
        }

        int position = j0;
        Span<byte> folded = stackalloc byte[ScalarSize];

        for(int level = d; level >= 1; level--)
        {
            BaseFoldQueryStep step = steps[d - level];
            if(step.Level != level)
            {
                return false;
            }

            int lowerLength = LayerLength(baseUnit, level - 1);
            int firstIndex = position;
            int secondIndex = position + lowerLength;

            //The root for this layer: the commitment for the top layer, else the
            //in-proof fold root (commit order maps root_level to index d-1-level).
            MerkleRoot layerRoot = level == d ? commitment : foldRoots[d - 1 - level];

            if(!AuthenticateLeaf(step, step.FirstPath, layerRoot, firstIndex, step.First, isFirst: true, merkleHash)
                || !AuthenticateLeaf(step, step.SecondPath, layerRoot, secondIndex, step.Second, isFirst: false, merkleHash))
            {
                return false;
            }

            //Recompute the single-position fold; it must equal the entry the
            //next layer down carries (or the cleartext base entry at level 1).
            FoldableCodeExtensions.FoldPosition(code, level, position, step.First, step.Second, challengesForLevel[level].AsReadOnlySpan(), folded, add, subtract, multiply, invert);

            if(level > 1)
            {
                int nextLowerLength = LayerLength(baseUnit, level - 2);
                int nextPosition = position % nextLowerLength;
                BaseFoldQueryStep nextStep = steps[d - (level - 1)];

                //π_{level-1}[position] is the first of the next pair when
                //position < n_{level-2}, else the second.
                ReadOnlySpan<byte> expected = position < nextLowerLength ? nextStep.First : nextStep.Second;
                if(!folded.SequenceEqual(expected))
                {
                    return false;
                }

                position = nextPosition;
            }
            else
            {
                //Level 1: the fold lands in the cleartext base codeword π_0.
                ReadOnlySpan<byte> expected = finalOracle.Slice(position * ScalarSize, ScalarSize);
                if(!folded.SequenceEqual(expected))
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>
    /// Checks that <paramref name="finalOracle"/> is a valid base-code word.
    /// For the wired <c>k0 = 1</c> code the base code is the <c>[c, 1, c]</c>
    /// repetition code, so a valid base codeword repeats its single element
    /// across all <c>n_0 = c</c> positions.
    /// </summary>
    internal static bool FinalOracleIsValidBaseCodeword(ReadOnlySpan<byte> finalOracle, int baseUnit)
    {
        ReadOnlySpan<byte> first = finalOracle[..ScalarSize];
        for(int i = 1; i < baseUnit; i++)
        {
            if(!finalOracle.Slice(i * ScalarSize, ScalarSize).SequenceEqual(first))
            {
                return false;
            }
        }

        return true;
    }


    //Authenticates one fold-pair entry against its layer root. For a plain
    //(non-hiding) step the leaf is the value verbatim; for a salted (hiding)
    //step the leaf is hash(value ‖ salt), which is recomputed here from the
    //revealed pair so the verifier never trusts a precomputed leaf digest.
    private static bool AuthenticateLeaf(
        BaseFoldQueryStep step,
        MerkleAuthenticationPath path,
        MerkleRoot layerRoot,
        int leafIndex,
        ReadOnlySpan<byte> value,
        bool isFirst,
        MerkleHashDelegate merkleHash)
    {
        if(!step.IsSalted)
        {
            return path.Verify(layerRoot, leafIndex, value, merkleHash);
        }

        int digestSize = layerRoot.Length;
        Span<byte> leaf = stackalloc byte[WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
        leaf = leaf[..digestSize];
        merkleHash(value, isFirst ? step.FirstSalt : step.SecondSalt, leaf);

        return path.Verify(layerRoot, leafIndex, leaf, merkleHash);
    }


    internal static int LayerLength(int baseUnit, int level)
    {
        return baseUnit << level;
    }
}
