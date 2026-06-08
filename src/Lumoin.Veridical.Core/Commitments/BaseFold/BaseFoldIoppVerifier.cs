using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The BaseFold IOPP verifier: replays the commit-phase transcript to recover
/// the fold challenges, re-derives the same query indices, and for each query
/// walks the layers checking that the revealed fold pairs authenticate against
/// the committed roots and that each layer's fold is consistent with the next.
/// Finally checks the cleartext base codeword is a valid base-code word.
/// </summary>
/// <remarks>
/// <para>
/// Implements the verifier side of the standalone BaseFold IOPP (Zeilberger,
/// Chen, Fisch, CRYPTO 2024, IACR ePrint 2023/1705, Section 4, Protocol 3),
/// without the sumcheck interleaving. The verifier reconstructs the same
/// foldable code from the shared seed and derives every query index itself, so
/// nothing index-related is trusted from the proof. Verification is
/// exception-safe against adversarial proofs: a structurally malformed proof or
/// any failed check returns <see langword="false"/> rather than throwing; only
/// <see langword="null"/> arguments (a caller fault) throw.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BaseFoldIoppVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Verifies a BaseFold IOPP proof of proximity for the codeword committed
    /// by <paramref name="commitment"/> (the Merkle root of <c>π_d</c>) under
    /// the foldable <paramref name="code"/>.
    /// </summary>
    /// <param name="code">The foldable code, reconstructed from the same seed the prover used.</param>
    /// <param name="commitment">The public commitment: the Merkle root of the codeword being tested.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="queryCount">The protocol's query repetition count; must match the proof.</param>
    /// <param name="transcript">The Fiat-Shamir transcript, initialised identically to the prover's.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for re-deriving fold challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="pool">The pool to rent scratch buffers from.</param>
    /// <returns><see langword="true"/> iff the proof verifies.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    public static bool Verify(
        FoldableCode code,
        MerkleRoot commitment,
        BaseFoldIoppProof proof,
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
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(proof);
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
        if(d < 1)
        {
            return false;
        }

        CurveParameterSet curve = parameters.Curve;
        int baseUnit = parameters.InverseRate * parameters.BaseDimension;

        //Structural checks: a malformed proof is rejected, not thrown on.
        if(proof.QueryCount != queryCount
            || proof.Parameters != parameters
            || proof.FoldRoots.Count != d - 1
            || proof.FinalOracle.Length != LayerLength(baseUnit, 0) * ScalarSize
            || proof.Openings.Count != queryCount)
        {
            return false;
        }

        //Replay the commit phase: absorb the commitment, then alternately
        //squeeze a fold challenge and absorb the next fold root. Challenges are
        //indexed by the layer they fold from: challengesForLevel[level] = α_{level-1}.
        var challengesForLevel = new Scalar[d + 1];
        try
        {
            transcript.AbsorbBaseFoldFoldRoot(commitment, hash);

            for(int level = d; level >= 1; level--)
            {
                challengesForLevel[level] = transcript.SqueezeBaseFoldFoldChallenge(squeeze, hash, reduce, curve, pool);

                //After folding π_level → π_{level-1}, absorb root_{level-1}
                //unless that is the cleartext base π_0.
                if(level - 1 >= 1)
                {
                    //Commit order: FoldRoots[0] = root_{d-1}, …; root_{level-1} is at index d-1-(level-1) = d-level.
                    MerkleRoot nextRoot = proof.FoldRoots[d - level];
                    transcript.AbsorbBaseFoldFoldRoot(nextRoot, hash);
                }
            }

            transcript.AbsorbBaseFoldFinalOracle(proof.FinalOracle, hash);

            int queryDomainSize = LayerLength(baseUnit, d - 1);
            for(int q = 0; q < queryCount; q++)
            {
                int j0 = transcript.SqueezeBaseFoldQueryIndex(queryDomainSize, squeeze, hash);

                if(!BaseFoldQueryPhase.VerifyQuery(code, commitment, proof.FoldRoots, proof.Openings[q], proof.FinalOracle, baseUnit, d, j0, challengesForLevel, merkleHash, add, subtract, multiply, invert))
                {
                    return false;
                }
            }

            //The base codeword must be a valid base-code word. For the wired
            //k0 = 1 repetition code that means all n_0 entries are equal.
            return BaseFoldQueryPhase.FinalOracleIsValidBaseCodeword(proof.FinalOracle, baseUnit);
        }
        finally
        {
            foreach(Scalar challenge in challengesForLevel)
            {
                challenge?.Dispose();
            }
        }
    }


    private static int LayerLength(int baseUnit, int level)
    {
        return baseUnit << level;
    }
}
