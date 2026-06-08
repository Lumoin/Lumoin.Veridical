using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The BaseFold IOPP prover: given a codeword to prove proximity for, runs the
/// commit phase (Merkle-committing each fold layer and folding under the
/// transcript's challenges down to the base codeword) and the query phase
/// (revealing, for each squeezed query index, the fold pair and Merkle paths at
/// every layer). Produces a <see cref="BaseFoldIoppProof"/>.
/// </summary>
/// <remarks>
/// <para>
/// Implements the prover side of the BaseFold IOPP (Zeilberger, Chen, Fisch,
/// CRYPTO 2024, IACR ePrint 2023/1705, Section 4, Protocols 2 and 3),
/// standalone — without the sumcheck interleaving the evaluation protocol adds.
/// Structural inspiration only, no code dependency. Fold pairs follow the
/// paper's Type-2 ordering (partners a half-layer apart), matching
/// <see cref="FoldableCodeExtensions"/>; this differs from reference
/// implementations that bit-reverse into adjacent pairs.
/// </para>
/// <para>
/// The Merkle root of the input codeword is the public commitment: the prover
/// absorbs it as the first transcript operation, and the verifier must be given
/// the same root. It is not carried in the proof.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BaseFoldIoppProver
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Produces a proximity proof for <paramref name="inputCodeword"/> (the
    /// layer-<c>d</c> codeword <c>π_d</c>) under the foldable
    /// <paramref name="code"/>, performing <paramref name="queryCount"/>
    /// independent queries.
    /// </summary>
    /// <param name="code">The foldable code; reconstructed from the same seed the verifier uses.</param>
    /// <param name="inputCodeword">The codeword to prove proximity for; <c>CodewordLength · 32</c> bytes.</param>
    /// <param name="queryCount">The number of query repetitions (see <see cref="WellKnownBaseFoldIoppParameters"/>).</param>
    /// <param name="transcript">The Fiat-Shamir transcript, already initialised with the protocol's public context.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for deriving fold challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="pool">The pool to rent working and proof buffers from.</param>
    /// <returns>The proximity proof; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="queryCount"/> is non-positive or the code has no foldable layers.</exception>
    /// <exception cref="ArgumentException">When <paramref name="inputCodeword"/> length does not match the code.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Working codewords and trees are disposed in the finally block; the buffers the proof keeps are copied into the returned proof, which owns them.")]
    public static BaseFoldIoppProof Prove(
        FoldableCode code,
        ReadOnlySpan<byte> inputCodeword,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);

        FoldableCodeParameters parameters = code.Parameters;
        int d = parameters.LayerCount;
        ArgumentOutOfRangeException.ThrowIfLessThan(d, 1);

        CurveParameterSet curve = parameters.Curve;
        int baseUnit = parameters.InverseRate * parameters.BaseDimension;
        int expectedCodeword = parameters.CodewordLength * ScalarSize;
        if(inputCodeword.Length != expectedCodeword)
        {
            throw new ArgumentException($"Input codeword must be {expectedCodeword} bytes; received {inputCodeword.Length}.", nameof(inputCodeword));
        }

        //Working storage: codewords[ℓ] holds π_ℓ (n_ℓ scalars) for ℓ in [0, d];
        //trees[ℓ] is the Merkle tree over π_ℓ for ℓ in [1, d] (π_0 is cleartext).
        var codewords = new IMemoryOwner<byte>?[d + 1];
        var trees = new MerkleTree?[d + 1];
        var disposables = new List<IDisposable>();

        try
        {
            //π_d = the input codeword.
            int topLength = LayerLength(baseUnit, d);
            codewords[d] = RentCopy(inputCodeword, pool, disposables);
            trees[d] = BuildTree(codewords[d]!, topLength, merkleHash, pool, disposables);

            //Commit phase: for ℓ = d downto 1, absorb root_ℓ, squeeze α_{ℓ-1},
            //fold π_ℓ → π_{ℓ-1}, and commit π_{ℓ-1} (unless it is the base π_0).
            for(int level = d; level >= 1; level--)
            {
                transcript.AbsorbBaseFoldFoldRoot(trees[level]!.Root, hash);

                using Scalar challenge = transcript.SqueezeBaseFoldFoldChallenge(squeeze, hash, reduce, curve, pool);

                int lowerLength = LayerLength(baseUnit, level - 1);
                codewords[level - 1] = pool.Rent(lowerLength * ScalarSize);
                disposables.Add(codewords[level - 1]!);
                Span<byte> lower = codewords[level - 1]!.Memory.Span[..(lowerLength * ScalarSize)];

                code.Fold(
                    codewords[level]!.Memory.Span[..(LayerLength(baseUnit, level) * ScalarSize)],
                    level,
                    challenge.AsReadOnlySpan(),
                    lower,
                    add,
                    subtract,
                    multiply,
                    invert);

                if(level - 1 >= 1)
                {
                    trees[level - 1] = BuildTree(codewords[level - 1]!, lowerLength, merkleHash, pool, disposables);
                }
            }

            //Absorb the cleartext base codeword π_0 before squeezing queries.
            int finalLength = LayerLength(baseUnit, 0) * ScalarSize;
            ReadOnlySpan<byte> finalOracleSpan = codewords[0]!.Memory.Span[..finalLength];
            transcript.AbsorbBaseFoldFinalOracle(finalOracleSpan, hash);

            //Query phase: squeeze queryCount indices over [0, n_{d-1}) and, for
            //each, reveal the fold pair and its Merkle paths at every layer.
            int queryDomainSize = LayerLength(baseUnit, d - 1);
            var openings = new BaseFoldQueryStep[queryCount][];
            for(int q = 0; q < queryCount; q++)
            {
                int j0 = transcript.SqueezeBaseFoldQueryIndex(queryDomainSize, squeeze, hash);
                openings[q] = BaseFoldQueryPhase.BuildOpening(trees, codewords, baseUnit, d, j0, pool);
            }

            //Copy the fold roots π_{d-1} … π_1 (commit order) and the final
            //oracle into proof-owned buffers, then release the working storage.
            MerkleRoot[] foldRoots = CopyFoldRoots(trees, d, pool);
            IMemoryOwner<byte> finalOracle = RentCopy(finalOracleSpan, pool, null);

            return new BaseFoldIoppProof(parameters, queryCount, foldRoots, finalOracle, finalLength, openings);
        }
        finally
        {
            //Trees and working codewords are scratch; dispose in reverse order.
            for(int i = disposables.Count - 1; i >= 0; i--)
            {
                disposables[i].Dispose();
            }
        }
    }


    //Copies the fold-layer roots π_{d-1} … π_1 (commit order) into standalone
    //proof-owned roots, so the working trees can be disposed.
    [SuppressMessage("Reliability", "CA2000", Justification = "Each copied root transfers ownership to the returned array, which the proof owns and disposes.")]
    private static MerkleRoot[] CopyFoldRoots(MerkleTree?[] trees, int d, SensitiveMemoryPool<byte> pool)
    {
        var foldRoots = new MerkleRoot[d - 1];
        for(int i = 0; i < d - 1; i++)
        {
            //Commit order: index 0 is π_{d-1}, last is π_1.
            int level = d - 1 - i;
            foldRoots[i] = MerkleRoot.FromBytes(trees[level]!.Root.AsReadOnlySpan(), pool);
        }

        return foldRoots;
    }


    private static int LayerLength(int baseUnit, int level)
    {
        return baseUnit << level;
    }


    private static IMemoryOwner<byte> RentCopy(ReadOnlySpan<byte> source, SensitiveMemoryPool<byte> pool, List<IDisposable>? track)
    {
        IMemoryOwner<byte> owner = pool.Rent(source.Length);
        source.CopyTo(owner.Memory.Span[..source.Length]);
        track?.Add(owner);

        return owner;
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The tree is tracked in the disposables list and released in the prover's finally block.")]
    private static MerkleTree BuildTree(
        IMemoryOwner<byte> codeword,
        int leafCount,
        MerkleHashDelegate merkleHash,
        SensitiveMemoryPool<byte> pool,
        List<IDisposable> disposables)
    {
        MerkleTree tree = MerkleTree.Build(codeword.Memory.Span[..(leafCount * ScalarSize)], leafCount, merkleHash, pool);
        disposables.Add(tree);

        return tree;
    }
}
