using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// In-circuit Poseidon gadgets for <see cref="R1csCircuitBuilder"/>: the
/// Poseidon permutation as R1CS constraints (<see cref="AssertPoseidonHash"/>)
/// and a Merkle-path membership proof over a two-to-one Poseidon compression
/// (<see cref="AssertMerkleMembership"/>). Both are generators built from the
/// existing op set — <c>AddConstraint</c> plus intermediate variables — so a
/// prover can show, in zero knowledge, that a hidden leaf is a member of a
/// committed <c>MerkleSetCommitment</c> whose shadow root uses the Poseidon
/// <c>MerkleHashDelegate</c>.
/// </summary>
/// <remarks>
/// <para>
/// The permutation's linear layers are free in R1CS: adding a round constant is
/// a constant term on a linear combination, and the MDS mix
/// <c>new[i] = Σ_j M[i][j]·state[j]</c> is a linear combination of the previous
/// lanes. Only the degree-five S-box <c>x^5</c> costs constraints, through the
/// minimal addition chain <c>x2 = x·x</c>, <c>x4 = x2·x2</c>, <c>x5 = x4·x</c>
/// (three constraints, three intermediate wires). The gadget carries the state
/// as an array of <see cref="R1csLinearCombination"/> and folds the rounds
/// exactly as the plaintext <see cref="PoseidonPermutation.Permute"/> does; the
/// witness auxiliaries come from <see cref="R1csPoseidonWitness"/>, whose trace
/// is gated equal to <see cref="PoseidonPermutation.Hash"/>.
/// </para>
/// <para>
/// Because only S-boxes are materialised, a partial round's non-S-boxed lane
/// linear combinations accrete one term per partial round, so the longest
/// constraint row is bounded by <c>t + R_P</c> terms. This is the standard
/// efficient Poseidon R1CS shape; the sumcheck handles arbitrary sparse rows,
/// and correctness-first defers any row-length optimisation.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class R1csCircuitBuilderPoseidonGadget
{
    //A Merkle two-to-one compression hashes two inputs, so its Poseidon state
    //is three lanes wide (two inputs plus the capacity lane).
    private const int MerkleStateWidth = 3;


    extension(R1csCircuitBuilder builder)
    {
        /// <summary>
        /// Emits the constraints computing the circomlib Poseidon hash of
        /// <paramref name="inputs"/> under <paramref name="parameters"/> — one
        /// permutation over <c>t = inputs.Length + 1</c> lanes with initial state
        /// <c>(0, inputs…)</c>, emitting lane 0 — and returns the materialised
        /// digest wire <c>{name}_digest</c>. Each S-box introduces three
        /// intermediate wires <c>{name}_r{round}_l{lane}_x2 / _x4 / _x5</c>; the
        /// caller binds them (and the digest) with
        /// <see cref="R1csPoseidonWitness.AddPoseidonHashWitness"/>.
        /// </summary>
        /// <param name="inputs">The input linear combinations; exactly <c>StateWidth - 1</c> of them.</param>
        /// <param name="parameters">The Poseidon parameters; their curve must match the builder's.</param>
        /// <param name="name">The unique name prefix for this hash's auxiliary variables.</param>
        /// <returns>The digest wire index.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the input count does not match the parameter shape, or the curves differ.</exception>
        public R1csVariableIndex AssertPoseidonHash(
            ReadOnlySpan<R1csLinearCombination> inputs,
            PoseidonParameters parameters,
            string name)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(parameters);
            ArgumentException.ThrowIfNullOrEmpty(name);

            int t = parameters.StateWidth;
            if(inputs.Length != t - 1)
            {
                throw new ArgumentException(
                    $"A Poseidon hash over state width {t} takes exactly {t - 1} inputs; received {inputs.Length}.",
                    nameof(inputs));
            }

            if(parameters.Curve.Code != builder.Curve.Code)
            {
                throw new ArgumentException(
                    $"The Poseidon parameters are over curve '{parameters.Curve}', but the builder constructs over '{builder.Curve}'.",
                    nameof(parameters));
            }

            //Initial state: the capacity lane at 0, then the inputs.
            var state = new R1csLinearCombination[t];
            state[0] = R1csLinearCombination.Zero;
            for(int lane = 1; lane < t; lane++)
            {
                R1csLinearCombination input = inputs[lane - 1];
                ArgumentNullException.ThrowIfNull(input);
                state[lane] = input;
            }

            int totalRounds = parameters.FullRounds + parameters.PartialRounds;
            int halfFull = parameters.FullRounds / 2;
            var sboxOut = new R1csLinearCombination[t];

            for(int round = 0; round < totalRounds; round++)
            {
                //Add the round constants (a constant term per lane; free).
                for(int lane = 0; lane < t; lane++)
                {
                    state[lane] += R1csLinearCombination.FromConstant(ToFieldElement(parameters.GetRoundConstant(round, lane)));
                }

                //The S-box acts on every lane in a full round, on lane 0 only in
                //a partial round; a non-S-boxed lane carries its value forward.
                bool fullRound = round < halfFull || round >= halfFull + parameters.PartialRounds;
                int sboxLanes = fullRound ? t : 1;
                for(int lane = 0; lane < t; lane++)
                {
                    sboxOut[lane] = lane < sboxLanes
                        ? AppendSBox(builder, state[lane], $"{name}_r{round}_l{lane}")
                        : state[lane];
                }

                //The MDS mix (a linear combination of the S-box outputs; free).
                //Reads sboxOut and writes state, so overwriting state in place is
                //safe.
                for(int row = 0; row < t; row++)
                {
                    R1csLinearCombination mixed = R1csLinearCombination.Zero;
                    for(int column = 0; column < t; column++)
                    {
                        mixed += ToFieldElement(parameters.GetMdsEntry(row, column)) * sboxOut[column];
                    }

                    state[row] = mixed;
                }
            }

            //Materialise lane 0 (an accumulated linear combination) into a single
            //digest wire, so the gadget's contract is "inputs to one wire".
            R1csVariableIndex digest = builder.DeclareIntermediateVariable($"{name}_digest");
            builder.AddConstraint(state[0], One, R1csLinearCombination.From(digest));

            return digest;
        }


        /// <summary>
        /// Emits the constraints authenticating <paramref name="leaf"/> against
        /// <paramref name="root"/> through a binary Merkle path — the in-circuit
        /// form of <c>MerkleAuthenticationPath.Verify</c> under a two-to-one
        /// Poseidon compression. At each level the boolean
        /// <paramref name="pathBits"/> entry selects whether the running node is
        /// the left child (0, <c>hash(current, sibling)</c>) or the right child
        /// (1, <c>hash(sibling, current)</c>), matching the out-of-circuit
        /// convention where that bit is bit <c>level</c> of the leaf index. The
        /// gadget introduces one swap wire <c>{name}_swap_{level}</c> per level
        /// plus each level's Poseidon auxiliaries; the caller binds them with
        /// <see cref="R1csPoseidonWitness.AddMerkleMembershipWitness"/>.
        /// </summary>
        /// <remarks>
        /// This proves <em>set membership</em>: that <paramref name="leaf"/> sits
        /// at some position of the tree committed by <paramref name="root"/>. The
        /// direction bits are free boolean witnesses the prover supplies, so the
        /// gadget does not by itself bind the leaf to a specific index — unlike
        /// the out-of-circuit <c>MerkleAuthenticationPath.Verify</c>, whose integer
        /// index carries an explicit position-binding range guard. That guard has
        /// no in-circuit analogue to omit: there is exactly one boolean bit per
        /// level, so no out-of-range position is expressible and nothing aliases.
        /// An application that needs membership <em>at a committed index</em>
        /// constrains the bits to a decomposition of that index separately.
        /// </remarks>
        /// <param name="leaf">The claimed leaf digest (a witness value).</param>
        /// <param name="pathBits">One boolean witness variable per level, bottom-up.</param>
        /// <param name="siblings">One sibling witness variable per level, bottom-up.</param>
        /// <param name="root">The committed root (typically a public input).</param>
        /// <param name="twoToOneParameters">Two-input Poseidon parameters (<c>StateWidth = 3</c>).</param>
        /// <param name="name">The unique name prefix for this proof's auxiliary variables.</param>
        /// <returns>The builder, for chaining.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the parameters are not two-input, or the path and sibling counts differ, or the path is empty.</exception>
        public R1csCircuitBuilder AssertMerkleMembership(
            R1csLinearCombination leaf,
            ReadOnlySpan<R1csVariableIndex> pathBits,
            ReadOnlySpan<R1csVariableIndex> siblings,
            R1csLinearCombination root,
            PoseidonParameters twoToOneParameters,
            string name)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(leaf);
            ArgumentNullException.ThrowIfNull(root);
            ArgumentNullException.ThrowIfNull(twoToOneParameters);
            ArgumentException.ThrowIfNullOrEmpty(name);

            if(twoToOneParameters.StateWidth != MerkleStateWidth)
            {
                throw new ArgumentException(
                    $"A Merkle two-to-one compression needs two-input Poseidon parameters (StateWidth = {MerkleStateWidth}); received {twoToOneParameters.StateWidth}.",
                    nameof(twoToOneParameters));
            }

            if(pathBits.Length != siblings.Length)
            {
                throw new ArgumentException(
                    $"The path must have one bit per sibling; received {pathBits.Length} bits and {siblings.Length} siblings.",
                    nameof(pathBits));
            }

            if(pathBits.Length == 0)
            {
                throw new ArgumentException("The Merkle path must have at least one level.", nameof(pathBits));
            }

            R1csLinearCombination current = leaf;
            for(int level = 0; level < pathBits.Length; level++)
            {
                //The direction bit is boolean, and the swap is a conditional
                //select realised with a single multiplication:
                //  swap = bit·(sibling − current)
                //  left  = current + swap    (current if bit = 0, sibling if bit = 1)
                //  right = sibling − swap    (sibling if bit = 0, current if bit = 1)
                R1csLinearCombination bit = R1csLinearCombination.From(pathBits[level]);
                builder.AssertBoolean(bit);

                R1csLinearCombination sibling = R1csLinearCombination.From(siblings[level]);
                R1csLinearCombination difference = sibling - current;

                R1csVariableIndex swap = builder.DeclareIntermediateVariable($"{name}_swap_{level}");
                builder.AddConstraint(bit, difference, R1csLinearCombination.From(swap));

                R1csLinearCombination left = current + R1csLinearCombination.From(swap);
                R1csLinearCombination right = sibling - R1csLinearCombination.From(swap);

                R1csVariableIndex parent = builder.AssertPoseidonHash(
                    [left, right], twoToOneParameters, $"{name}_level_{level}");
                current = R1csLinearCombination.From(parent);
            }

            //The recomputed root must equal the committed root.
            return builder.AssertEqual(current, root);
        }
    }


    //The x^5 S-box as three multiplication constraints over intermediate wires,
    //returning the output as a single-wire linear combination.
    private static R1csLinearCombination AppendSBox(R1csCircuitBuilder builder, R1csLinearCombination x, string name)
    {
        R1csVariableIndex x2 = builder.DeclareIntermediateVariable($"{name}_x2");
        builder.AddConstraint(x, x, R1csLinearCombination.From(x2));

        R1csVariableIndex x4 = builder.DeclareIntermediateVariable($"{name}_x4");
        builder.AddConstraint(R1csLinearCombination.From(x2), R1csLinearCombination.From(x2), R1csLinearCombination.From(x4));

        R1csVariableIndex x5 = builder.DeclareIntermediateVariable($"{name}_x5");
        builder.AddConstraint(R1csLinearCombination.From(x4), x, R1csLinearCombination.From(x5));

        return R1csLinearCombination.From(x5);
    }


    private static BigInteger ToFieldElement(ReadOnlySpan<byte> canonicalBigEndian) =>
        new(canonicalBigEndian, isUnsigned: true, isBigEndian: true);


    private static R1csLinearCombination One => R1csLinearCombination.FromConstant(BigInteger.One);
}
