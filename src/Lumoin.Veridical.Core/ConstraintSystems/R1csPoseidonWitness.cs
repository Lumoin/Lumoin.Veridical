using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Computes the auxiliary input bindings the Poseidon gadgets
/// (<see cref="R1csCircuitBuilderPoseidonGadget"/>) need — the mirror of
/// <see cref="R1csPredicateWitness"/> for the hash and Merkle-membership
/// generators. It reruns the Poseidon permutation in
/// <see cref="BigInteger"/> arithmetic modulo the curve's scalar field,
/// recording each S-box's intermediate wires, each Merkle swap wire, and each
/// materialised digest under the same derived names the gadget declares.
/// </summary>
/// <remarks>
/// The trace follows <see cref="PoseidonPermutation.Permute"/> lane for lane, so
/// the digest it binds equals <see cref="PoseidonPermutation.Hash"/> for the
/// same inputs — the property the tests gate, which transitively binds the
/// gadget to circomlib (the plaintext hash is byte-compatible with circomlib
/// over BN254). Values are reduced modulo the field, matching what
/// <c>Compile</c> does when it evaluates the constraints.
/// </remarks>
public static class R1csPoseidonWitness
{
    //A Merkle two-to-one compression hashes two inputs (state width three).
    private const int MerkleStateWidth = 3;


    /// <summary>
    /// Adds the auxiliary bindings for
    /// <see cref="R1csCircuitBuilderPoseidonGadget.AssertPoseidonHash"/>: every
    /// S-box's <c>{name}_r{round}_l{lane}_x2 / _x4 / _x5</c> and the
    /// <c>{name}_digest</c> wire. Returns the digest value so a caller chaining
    /// hashes (a Merkle path) can carry it forward.
    /// </summary>
    /// <param name="bindings">The bindings dictionary being assembled for compilation.</param>
    /// <param name="name">The same name prefix passed to the gadget.</param>
    /// <param name="inputs">The hash inputs; exactly <c>StateWidth - 1</c> values.</param>
    /// <param name="parameters">The Poseidon parameters.</param>
    /// <returns>The Poseidon digest, reduced modulo the scalar field.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the input count does not match the parameter shape.</exception>
    public static BigInteger AddPoseidonHashWitness(
        IDictionary<string, BigInteger> bindings,
        string name,
        ReadOnlySpan<BigInteger> inputs,
        PoseidonParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(parameters);

        int t = parameters.StateWidth;
        if(inputs.Length != t - 1)
        {
            throw new ArgumentException(
                $"A Poseidon hash over state width {t} takes exactly {t - 1} inputs; received {inputs.Length}.",
                nameof(inputs));
        }

        BigInteger order = WellKnownCurves.GetScalarFieldOrder(parameters.Curve);

        var state = new BigInteger[t];
        state[0] = BigInteger.Zero;
        for(int lane = 1; lane < t; lane++)
        {
            state[lane] = Reduce(inputs[lane - 1], order);
        }

        int totalRounds = parameters.FullRounds + parameters.PartialRounds;
        int halfFull = parameters.FullRounds / 2;
        var sboxOut = new BigInteger[t];

        for(int round = 0; round < totalRounds; round++)
        {
            for(int lane = 0; lane < t; lane++)
            {
                state[lane] = Reduce(state[lane] + ToFieldElement(parameters.GetRoundConstant(round, lane)), order);
            }

            bool fullRound = round < halfFull || round >= halfFull + parameters.PartialRounds;
            int sboxLanes = fullRound ? t : 1;
            for(int lane = 0; lane < t; lane++)
            {
                sboxOut[lane] = lane < sboxLanes
                    ? AppendSBoxWitness(bindings, $"{name}_r{round}_l{lane}", state[lane], order)
                    : state[lane];
            }

            for(int row = 0; row < t; row++)
            {
                BigInteger mixed = BigInteger.Zero;
                for(int column = 0; column < t; column++)
                {
                    mixed += ToFieldElement(parameters.GetMdsEntry(row, column)) * sboxOut[column];
                }

                state[row] = Reduce(mixed, order);
            }
        }

        BigInteger digest = state[0];
        bindings[$"{name}_digest"] = digest;

        return digest;
    }


    /// <summary>
    /// Adds the auxiliary bindings for
    /// <see cref="R1csCircuitBuilderPoseidonGadget.AssertMerkleMembership"/>:
    /// each level's <c>{name}_swap_{level}</c> wire and every per-level Poseidon
    /// auxiliary (through <see cref="AddPoseidonHashWitness"/>). The caller binds
    /// the leaf, sibling, and path-bit variables it declared. Returns the
    /// recomputed root so the caller can bind it (or check it against the known
    /// commitment).
    /// </summary>
    /// <param name="bindings">The bindings dictionary being assembled for compilation.</param>
    /// <param name="name">The same name prefix passed to the gadget.</param>
    /// <param name="leafValue">The claimed leaf digest value.</param>
    /// <param name="pathBits">The direction bit (0 or 1) at each level, bottom-up — bit <c>level</c> of the leaf index.</param>
    /// <param name="siblingValues">The sibling digest value at each level, bottom-up.</param>
    /// <param name="twoToOneParameters">Two-input Poseidon parameters (<c>StateWidth = 3</c>).</param>
    /// <returns>The recomputed root, reduced modulo the scalar field.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the parameters are not two-input, the counts differ, the path is empty, or a path bit is not 0 or 1.</exception>
    public static BigInteger AddMerkleMembershipWitness(
        IDictionary<string, BigInteger> bindings,
        string name,
        BigInteger leafValue,
        ReadOnlySpan<int> pathBits,
        ReadOnlySpan<BigInteger> siblingValues,
        PoseidonParameters twoToOneParameters)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(twoToOneParameters);

        if(twoToOneParameters.StateWidth != MerkleStateWidth)
        {
            throw new ArgumentException(
                $"A Merkle two-to-one compression needs two-input Poseidon parameters (StateWidth = {MerkleStateWidth}); received {twoToOneParameters.StateWidth}.",
                nameof(twoToOneParameters));
        }

        if(pathBits.Length != siblingValues.Length)
        {
            throw new ArgumentException(
                $"The path must have one bit per sibling; received {pathBits.Length} bits and {siblingValues.Length} siblings.",
                nameof(pathBits));
        }

        if(pathBits.Length == 0)
        {
            throw new ArgumentException("The Merkle path must have at least one level.", nameof(pathBits));
        }

        BigInteger order = WellKnownCurves.GetScalarFieldOrder(twoToOneParameters.Curve);
        BigInteger current = Reduce(leafValue, order);

        for(int level = 0; level < pathBits.Length; level++)
        {
            int bit = pathBits[level];
            if(bit is not 0 and not 1)
            {
                throw new ArgumentException($"Path bit {level} must be 0 or 1; received {bit}.", nameof(pathBits));
            }

            BigInteger sibling = Reduce(siblingValues[level], order);
            BigInteger difference = Reduce(sibling - current, order);

            //swap = bit·(sibling − current): zero for a left turn, the difference
            //for a right turn.
            BigInteger swap = bit == 1 ? difference : BigInteger.Zero;
            bindings[$"{name}_swap_{level}"] = swap;

            BigInteger left = Reduce(current + swap, order);
            BigInteger right = Reduce(sibling - swap, order);

            current = AddPoseidonHashWitness(bindings, $"{name}_level_{level}", [left, right], twoToOneParameters);
        }

        return current;
    }


    //The x^5 S-box trace: bind x2, x4, x5 and return x5.
    private static BigInteger AppendSBoxWitness(IDictionary<string, BigInteger> bindings, string name, BigInteger x, BigInteger order)
    {
        BigInteger x2 = Reduce(x * x, order);
        BigInteger x4 = Reduce(x2 * x2, order);
        BigInteger x5 = Reduce(x4 * x, order);

        bindings[$"{name}_x2"] = x2;
        bindings[$"{name}_x4"] = x4;
        bindings[$"{name}_x5"] = x5;

        return x5;
    }


    private static BigInteger ToFieldElement(ReadOnlySpan<byte> canonicalBigEndian) =>
        new(canonicalBigEndian, isUnsigned: true, isBigEndian: true);


    private static BigInteger Reduce(BigInteger value, BigInteger order)
    {
        BigInteger remainder = value % order;
        return remainder.Sign < 0 ? remainder + order : remainder;
    }
}
