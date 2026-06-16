using Lumoin.Veridical.Core.Commitments.BaseFold;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The native Poseidon permutation and hash (Grassi et al, USENIX Security
/// 2021), circomlib-compatible: <c>x^5</c> S-box, <c>R_F/2</c> full rounds,
/// <c>R_P</c> partial rounds (S-box on lane 0 only), <c>R_F/2</c> full
/// rounds, each round adding its constants before the S-box and mixing
/// through the MDS matrix after. The hash of <c>k</c> inputs runs one
/// permutation over <c>t = k + 1</c> lanes with state
/// <c>(0, in_1 … in_k)</c> and emits lane 0 — circomlib's construction, so
/// digests agree byte-for-byte with circomlib circuits over BN254 (gated by
/// the known-answer tests against the committed Poseidon fixture).
/// </summary>
/// <remarks>
/// This is the algebraic, in-circuit-friendly hash the ZK seam needs: a
/// Poseidon two-to-one <see cref="MerkleHashDelegate"/>
/// (<see cref="GetMerkleHash"/>) makes <c>MerkleSetCommitment</c> shadow
/// roots whose membership proofs are cheap inside an R1CS circuit, where
/// BLAKE3 is expensive. All arithmetic flows through the scalar delegate
/// backends; correctness-first reference pace.
/// </remarks>
public static class PoseidonPermutation
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Applies the permutation to <paramref name="state"/> in place
    /// (<c>StateWidth</c> concatenated canonical scalars).
    /// </summary>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the state is not <c>StateWidth</c> scalars wide.</exception>
    public static void Permute(
        PoseidonParameters parameters,
        Span<byte> state,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);

        int t = parameters.StateWidth;
        if(state.Length != t * ScalarSize)
        {
            throw new ArgumentException($"The state must be exactly {t} scalars ({t * ScalarSize} bytes); received {state.Length}.", nameof(state));
        }

        CurveParameterSet curve = parameters.Curve;
        int totalRounds = parameters.FullRounds + parameters.PartialRounds;
        int halfFull = parameters.FullRounds / 2;

        //Mix scratch: the next state, built lane by lane.
        Span<byte> mixed = stackalloc byte[WellKnownPoseidonScratch.MaximumStateBytes];
        Span<byte> term = stackalloc byte[ScalarSize];
        if(state.Length > mixed.Length)
        {
            throw new ArgumentException($"The state width {t} exceeds the supported maximum.", nameof(state));
        }

        mixed = mixed[..state.Length];

        for(int round = 0; round < totalRounds; round++)
        {
            //Add the round constants.
            for(int lane = 0; lane < t; lane++)
            {
                Span<byte> slot = state.Slice(lane * ScalarSize, ScalarSize);
                add(slot, parameters.GetRoundConstant(round, lane), slot, curve);
            }

            //The S-box: x^5 on every lane in a full round, on lane 0 only in a
            //partial round.
            bool fullRound = round < halfFull || round >= halfFull + parameters.PartialRounds;
            int sboxLanes = fullRound ? t : 1;
            for(int lane = 0; lane < sboxLanes; lane++)
            {
                Span<byte> slot = state.Slice(lane * ScalarSize, ScalarSize);
                multiply(slot, slot, term, curve);     //x²
                multiply(term, term, term, curve);     //x⁴
                multiply(slot, term, slot, curve);     //x⁵
            }

            //The MDS mix: new[i] = Σ_j M[i][j]·state[j]. The orientation is
            //material (Grain-sampled Cauchy points are not symmetric) and
            //pinned by the known-answer tests.
            for(int row = 0; row < t; row++)
            {
                Span<byte> slot = mixed.Slice(row * ScalarSize, ScalarSize);
                slot.Clear();
                for(int column = 0; column < t; column++)
                {
                    multiply(parameters.GetMdsEntry(row, column), state.Slice(column * ScalarSize, ScalarSize), term, curve);
                    add(slot, term, slot, curve);
                }
            }

            mixed.CopyTo(state);
        }
    }


    /// <summary>
    /// The circomlib Poseidon hash: one permutation over
    /// <c>t = inputCount + 1</c> lanes with state <c>(0, inputs…)</c>,
    /// emitting lane 0.
    /// </summary>
    /// <param name="parameters">Parameters whose <c>StateWidth</c> is the input count plus one.</param>
    /// <param name="inputs">The concatenated canonical scalar inputs.</param>
    /// <param name="digest">Receives the digest; one scalar wide.</param>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span argument does not match the parameter shape.</exception>
    public static void Hash(
        PoseidonParameters parameters,
        ReadOnlySpan<byte> inputs,
        Span<byte> digest,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        int t = parameters.StateWidth;
        if(inputs.Length != (t - 1) * ScalarSize)
        {
            throw new ArgumentException($"The inputs must be exactly {t - 1} scalars; received {inputs.Length} bytes.", nameof(inputs));
        }

        if(digest.Length != ScalarSize)
        {
            throw new ArgumentException($"The digest must be exactly {ScalarSize} bytes; received {digest.Length}.", nameof(digest));
        }

        Span<byte> state = stackalloc byte[WellKnownPoseidonScratch.MaximumStateBytes];
        if(t * ScalarSize > state.Length)
        {
            throw new ArgumentException($"The state width {t} exceeds the supported maximum.", nameof(parameters));
        }

        state = state[..(t * ScalarSize)];
        state[..ScalarSize].Clear();
        inputs.CopyTo(state[ScalarSize..]);

        Permute(parameters, state, add, multiply);

        state[..ScalarSize].CopyTo(digest);
    }


    /// <summary>
    /// Returns a Poseidon two-to-one <see cref="MerkleHashDelegate"/> over
    /// two-input parameters — the in-circuit-friendly compression for
    /// <c>MerkleTree</c>/<c>MerkleSetCommitment</c> shadow roots. The
    /// returned delegate captures the parameters and backends; node digests
    /// are canonical 32-byte field elements.
    /// </summary>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the parameters are not two-input (<c>StateWidth ≠ 3</c>).</exception>
    public static MerkleHashDelegate GetMerkleHash(
        PoseidonParameters parameters,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        if(parameters.StateWidth != 3)
        {
            throw new ArgumentException(
                $"A two-to-one Merkle compression needs two-input parameters (StateWidth = 3); received {parameters.StateWidth}.",
                nameof(parameters));
        }

        return (left, right, output) =>
        {
            Span<byte> inputs = stackalloc byte[2 * ScalarSize];
            left.CopyTo(inputs[..ScalarSize]);
            right.CopyTo(inputs.Slice(ScalarSize, ScalarSize));
            Hash(parameters, inputs, output, add, multiply);
        };
    }
}
