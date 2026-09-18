using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Compile-level gates for the in-circuit Poseidon gadgets. The load-bearing
/// property is native ↔ in-circuit agreement: the gadget's constraints, bound by
/// <see cref="R1csPoseidonWitness"/>, compile and satisfy exactly when the
/// claimed digest equals the plaintext <see cref="PoseidonPermutation.Hash"/>
/// (itself KAT-bound to circomlib), and a wrong digest, leaf, sibling, root,
/// direction bit, or under-constrained intermediate is rejected at
/// <c>Compile</c>. The membership case runs against a real
/// <see cref="MerkleSetCommitment"/> under the Poseidon shadow root, so the
/// in-circuit path authenticates the same commitment the out-of-circuit verifier
/// accepts.
/// </summary>
[TestClass]
internal sealed class R1csPoseidonGadgetTests
{
    /// <summary>The byte width of a canonical scalar in the curve's field.</summary>
    private const int ScalarSize = 32;
    /// <summary>The number of key/value entries the Merkle fixture commits.</summary>
    private const int EntryCount = 5;

    /// <summary>The shared memory pool these tests compile and check circuits with.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The BN254 scalar addition delegate.</summary>
    private static ScalarAddDelegate Bn254Add { get; } = Bn254BigIntegerScalarReference.GetAdd();
    /// <summary>The BN254 scalar multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Bn254Multiply { get; } = Bn254BigIntegerScalarReference.GetMultiply();
    /// <summary>The BN254 scalar inversion delegate.</summary>
    private static ScalarInvertDelegate Bn254Invert { get; } = Bn254BigIntegerScalarReference.GetInvert();
    /// <summary>The BN254 scalar reduction delegate.</summary>
    private static ScalarReduceDelegate Bn254Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    /// <summary>The BLS12-381 scalar addition delegate.</summary>
    private static ScalarAddDelegate BlsAdd { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    /// <summary>The BLS12-381 scalar multiplication delegate.</summary>
    private static ScalarMultiplyDelegate BlsMultiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    /// <summary>The BLS12-381 scalar inversion delegate.</summary>
    private static ScalarInvertDelegate BlsInvert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();


    /// <summary>Checks that BN254 Poseidon hash gadget matches plaintext.</summary>
    [TestMethod]
    public void Bn254PoseidonHashGadgetMatchesPlaintext()
    {
        AssertHashGadgetMatchesPlaintext(BaseMemoryPool.Shared, CurveParameterSet.Bn254, inputCount: 2, Bn254Add, Bn254Multiply, Bn254Invert, [7, 11]);
    }


    /// <summary>Checks that BLS12-381 Poseidon hash gadget matches plaintext.</summary>
    [TestMethod]
    public void Bls12Curve381PoseidonHashGadgetMatchesPlaintext()
    {
        AssertHashGadgetMatchesPlaintext(BaseMemoryPool.Shared, CurveParameterSet.Bls12Curve381, inputCount: 2, BlsAdd, BlsMultiply, BlsInvert, [7, 11]);
    }


    /// <summary>Checks that Poseidon hash gadget matches plaintext across arities.</summary>
    [TestMethod]
    public void PoseidonHashGadgetMatchesPlaintextAcrossArities()
    {
        AssertHashGadgetMatchesPlaintext(BaseMemoryPool.Shared, CurveParameterSet.Bn254, inputCount: 1, Bn254Add, Bn254Multiply, Bn254Invert, [42]);
        AssertHashGadgetMatchesPlaintext(BaseMemoryPool.Shared, CurveParameterSet.Bn254, inputCount: 4, Bn254Add, Bn254Multiply, Bn254Invert, [1, 2, 3, 4]);
        AssertHashGadgetMatchesPlaintext(BaseMemoryPool.Shared, CurveParameterSet.Bn254, inputCount: 8, Bn254Add, Bn254Multiply, Bn254Invert, [3, 5, 8, 13, 21, 34, 55, 89]);
    }


    /// <summary>Checks that Poseidon hash gadget rejects wrong digest.</summary>
    [TestMethod]
    public void PoseidonHashGadgetRejectsWrongDigest()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert, BaseMemoryPool.Shared);
        R1csCircuit circuit = BuildHashCircuit(CurveParameterSet.Bn254, 2, parameters);

        BigInteger[] inputs = [7, 11];
        BigInteger correct = PlaintextHash(parameters, inputs, Bn254Add, Bn254Multiply);

        Dictionary<string, BigInteger> bindings = HashBindings(parameters, inputs, claimedDigest: correct + 1);
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    /// <summary>Checks that Poseidon hash gadget rejects under constrained sbox intermediate.</summary>
    [TestMethod]
    public void PoseidonHashGadgetRejectsUnderConstrainedSBoxIntermediate()
    {
        //The first S-box's x2 wire is bound by x·x = x2. Tampering it (leaving the
        //rest of the honest trace intact) must be caught at compile — proof that
        //the intermediate is genuinely constrained, not free.
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert, BaseMemoryPool.Shared);
        R1csCircuit circuit = BuildHashCircuit(CurveParameterSet.Bn254, 2, parameters);

        BigInteger[] inputs = [7, 11];
        BigInteger correct = PlaintextHash(parameters, inputs, Bn254Add, Bn254Multiply);
        Dictionary<string, BigInteger> bindings = HashBindings(parameters, inputs, claimedDigest: correct);
        bindings["h_r0_l0_x2"] = bindings["h_r0_l0_x2"] + 1;

        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    /// <summary>Checks that Poseidon hash witness reproduces plaintext hash.</summary>
    [TestMethod]
    public void PoseidonHashWitnessReproducesPlaintextHash()
    {
        //The witness trace is an independent third implementation of the
        //permutation; it must reproduce the plaintext hash bit for bit on both
        //curves, which is what transitively binds the gadget to circomlib.
        AssertWitnessReproducesPlaintext(BaseMemoryPool.Shared, CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, [7, 11]);
        AssertWitnessReproducesPlaintext(BaseMemoryPool.Shared, CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, [0, 0]);
        AssertWitnessReproducesPlaintext(BaseMemoryPool.Shared, CurveParameterSet.Bls12Curve381, BlsAdd, BlsMultiply, BlsInvert, [123456789, 987654321]);
    }


    /// <summary>Checks that Poseidon hash gadget rejects wrong input count.</summary>
    [TestMethod]
    public void PoseidonHashGadgetRejectsWrongInputCount()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert, BaseMemoryPool.Shared);
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bn254);
        R1csVariableIndex only = builder.DeclareWitnessVariable("only");

        //Two-input parameters, one input supplied.
        Assert.ThrowsExactly<ArgumentException>(
            () => builder.AssertPoseidonHash([R1csLinearCombination.From(only)], parameters, "h"));
    }


    /// <summary>Checks that BN254 Merkle membership gadget authenticates the shadow root.</summary>
    [TestMethod]
    public void Bn254MerkleMembershipGadgetAuthenticatesTheShadowRoot()
    {
        MerkleFixture fixture = BuildMerkleFixture(BaseMemoryPool.Shared, CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        Dictionary<string, BigInteger> bindings = MerkleBindings(fixture);
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(new R1csCircuitInputs(bindings), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Bn254Add, Bn254Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, "the in-circuit Merkle path authenticates the Poseidon shadow root");
    }


    /// <summary>Checks that BLS12-381 Merkle membership gadget authenticates the shadow root.</summary>
    [TestMethod]
    public void Bls12Curve381MerkleMembershipGadgetAuthenticatesTheShadowRoot()
    {
        MerkleFixture fixture = BuildMerkleFixture(BaseMemoryPool.Shared, CurveParameterSet.Bls12Curve381, BlsAdd, BlsMultiply, BlsInvert, Bls12Curve381BigIntegerScalarReference.GetReduce(), entryIndex: 2);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        Dictionary<string, BigInteger> bindings = MerkleBindings(fixture);
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(new R1csCircuitInputs(bindings), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, BlsAdd, BlsMultiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    /// <summary>Checks that Merkle membership gadget rejects wrong leaf.</summary>
    [TestMethod]
    public void MerkleMembershipGadgetRejectsWrongLeaf()
    {
        MerkleFixture fixture = BuildMerkleFixture(BaseMemoryPool.Shared, CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        Dictionary<string, BigInteger> bindings = MerkleBindings(fixture);
        bindings["leaf"] = bindings["leaf"] + 1;
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    /// <summary>Checks that Merkle membership gadget rejects wrong sibling.</summary>
    [TestMethod]
    public void MerkleMembershipGadgetRejectsWrongSibling()
    {
        MerkleFixture fixture = BuildMerkleFixture(BaseMemoryPool.Shared, CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        //A tampered sibling: the whole trace is recomputed from it, so the
        //recomputed root diverges from the committed (public) root.
        var tampered = (BigInteger[])fixture.SiblingValues.Clone();
        tampered[0] += 1;
        MerkleFixture wrong = fixture with { SiblingValues = tampered };

        Dictionary<string, BigInteger> bindings = MerkleBindings(wrong);
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    /// <summary>Checks that Merkle membership gadget rejects wrong root.</summary>
    [TestMethod]
    public void MerkleMembershipGadgetRejectsWrongRoot()
    {
        MerkleFixture fixture = BuildMerkleFixture(BaseMemoryPool.Shared, CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        Dictionary<string, BigInteger> bindings = MerkleBindings(fixture);
        bindings["root"] = bindings["root"] + 1;
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    /// <summary>Checks that Merkle membership gadget rejects wrong direction bit.</summary>
    [TestMethod]
    public void MerkleMembershipGadgetRejectsWrongDirectionBit()
    {
        //Claiming a different index (flip the lowest direction bit) turns the
        //authentication toward the wrong subtree: the recomputed root no longer
        //equals the committed root. This is the in-circuit position binding.
        MerkleFixture fixture = BuildMerkleFixture(BaseMemoryPool.Shared, CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        var flipped = (int[])fixture.PathBits.Clone();
        flipped[0] ^= 1;
        MerkleFixture wrong = fixture with { PathBits = flipped };

        Dictionary<string, BigInteger> bindings = MerkleBindings(wrong);
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    /// <summary>Compiles the Poseidon hash gadget for the given curve, input count, and backends, then asserts that its in-circuit digest equals the plaintext <see cref="PoseidonPermutation.Hash"/> over the given inputs.</summary>
    /// <param name="pool">The pool used to compile and check the circuit.</param>
    /// <param name="curve">The scalar field identifying the fixture.</param>
    /// <param name="inputCount">The number of hash inputs.</param>
    /// <param name="add">The scalar addition backend.</param>
    /// <param name="multiply">The scalar multiplication backend.</param>
    /// <param name="invert">The scalar inversion backend.</param>
    /// <param name="inputs">The plaintext inputs.</param>
    private static void AssertHashGadgetMatchesPlaintext(
        BaseMemoryPool pool,
        CurveParameterSet curve, int inputCount, ScalarAddDelegate add, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, BigInteger[] inputs)
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(inputCount, curve, add, invert, pool);
        R1csCircuit circuit = BuildHashCircuit(curve, inputCount, parameters);

        BigInteger digest = PlaintextHash(parameters, inputs, add, multiply);
        Dictionary<string, BigInteger> bindings = HashBindings(parameters, inputs, claimedDigest: digest);

        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(new R1csCircuitInputs(bindings), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, add, multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, $"the in-circuit Poseidon({inputCount}) digest equals the plaintext hash over {curve}");
    }


    /// <summary>Asserts that the Poseidon witness trace's digest for the given inputs equals the plaintext <see cref="PoseidonPermutation.Hash"/>, binding the witness generator to the same computation the gadget's constraints check.</summary>
    /// <param name="pool">The pool used to derive the Poseidon parameters.</param>
    /// <param name="curve">The scalar field identifying the fixture.</param>
    /// <param name="add">The scalar addition backend.</param>
    /// <param name="multiply">The scalar multiplication backend.</param>
    /// <param name="invert">The scalar inversion backend.</param>
    /// <param name="inputs">The plaintext inputs.</param>
    private static void AssertWitnessReproducesPlaintext(
        BaseMemoryPool pool,
        CurveParameterSet curve, ScalarAddDelegate add, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, BigInteger[] inputs)
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(inputs.Length, curve, add, invert, pool);
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        BigInteger traceDigest = R1csPoseidonWitness.AddPoseidonHashWitness(bindings, "h", inputs, parameters);
        BigInteger plaintext = PlaintextHash(parameters, inputs, add, multiply);

        Assert.AreEqual(plaintext, traceDigest, "the witness trace digest must equal the plaintext Poseidon hash");
    }


    /// <summary>Builds a circuit asserting that the Poseidon hash of <paramref name="inputCount"/> witness inputs equals a public expected digest.</summary>
    private static R1csCircuit BuildHashCircuit(CurveParameterSet curve, int inputCount, PoseidonParameters parameters)
    {
        var builder = new R1csCircuitBuilder(curve);
        R1csVariableIndex expected = builder.DeclarePublicInput("expected");

        var inputs = new R1csLinearCombination[inputCount];
        for(int i = 0; i < inputCount; i++)
        {
            inputs[i] = R1csLinearCombination.From(builder.DeclareWitnessVariable($"in_{i}"));
        }

        R1csVariableIndex digest = builder.AssertPoseidonHash(inputs, parameters, "h");
        builder.AssertEqual(R1csLinearCombination.From(digest), R1csLinearCombination.From(expected));

        return builder.Build();
    }


    /// <summary>Builds the variable bindings for <see cref="BuildHashCircuit"/>: the claimed digest, the plaintext inputs, and the witness trace <see cref="R1csPoseidonWitness.AddPoseidonHashWitness"/> derives from them.</summary>
    private static Dictionary<string, BigInteger> HashBindings(PoseidonParameters parameters, BigInteger[] inputs, BigInteger claimedDigest)
    {
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal)
        {
            ["expected"] = claimedDigest,
        };

        for(int i = 0; i < inputs.Length; i++)
        {
            bindings[$"in_{i}"] = inputs[i];
        }

        R1csPoseidonWitness.AddPoseidonHashWitness(bindings, "h", inputs, parameters);

        return bindings;
    }


    /// <summary>Builds a circuit asserting Merkle membership of a witnessed leaf against a public root, using <paramref name="fixture"/>'s depth and parameters.</summary>
    private static R1csCircuit BuildMerkleCircuit(MerkleFixture fixture)
    {
        var builder = new R1csCircuitBuilder(fixture.Parameters.Curve);
        R1csVariableIndex root = builder.DeclarePublicInput("root");
        R1csVariableIndex leaf = builder.DeclareWitnessVariable("leaf");

        int depth = fixture.SiblingValues.Length;
        var pathBits = new R1csVariableIndex[depth];
        var siblings = new R1csVariableIndex[depth];
        for(int level = 0; level < depth; level++)
        {
            pathBits[level] = builder.DeclareWitnessVariable($"bit_{level}");
            siblings[level] = builder.DeclareWitnessVariable($"sib_{level}");
        }

        builder.AssertMerkleMembership(
            R1csLinearCombination.From(leaf), pathBits, siblings, R1csLinearCombination.From(root), fixture.Parameters, "m");

        return builder.Build();
    }


    /// <summary>Builds the variable bindings for <see cref="BuildMerkleCircuit"/>: the root, leaf, path bits and siblings, and the witness trace <see cref="R1csPoseidonWitness.AddMerkleMembershipWitness"/> derives from them.</summary>
    private static Dictionary<string, BigInteger> MerkleBindings(MerkleFixture fixture)
    {
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal)
        {
            ["root"] = fixture.RootValue,
            ["leaf"] = fixture.LeafValue,
        };

        for(int level = 0; level < fixture.SiblingValues.Length; level++)
        {
            bindings[$"bit_{level}"] = fixture.PathBits[level];
            bindings[$"sib_{level}"] = fixture.SiblingValues[level];
        }

        R1csPoseidonWitness.AddMerkleMembershipWitness(
            bindings, "m", fixture.LeafValue, fixture.PathBits, fixture.SiblingValues, fixture.Parameters);

        return bindings;
    }


    /// <summary>Builds a Merkle-membership fixture: commits <see cref="EntryCount"/> key/value entries under the Poseidon shadow hash, opens the entry at <paramref name="entryIndex"/>, confirms the out-of-circuit membership proof verifies, and returns the leaf, root, path bits, and sibling values as field elements for the in-circuit gadget.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="curve">The scalar field identifying the fixture.</param>
    /// <param name="add">The scalar addition backend.</param>
    /// <param name="multiply">The scalar multiplication backend.</param>
    /// <param name="invert">The scalar inversion backend.</param>
    /// <param name="reduce">The scalar reduction backend.</param>
    /// <param name="entryIndex">The Merkle entry to open.</param>
    private static MerkleFixture BuildMerkleFixture(
        BaseMemoryPool pool,
        CurveParameterSet curve, ScalarAddDelegate add, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce, int entryIndex)
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, curve, add, invert, pool);
        MerkleHashDelegate poseidonHash = PoseidonPermutation.GetMerkleHash(parameters, add, multiply);

        Span<byte> entries = stackalloc byte[EntryCount * 2 * ScalarSize];
        Span<byte> material = stackalloc byte[ScalarSize];
        for(int i = 0; i < EntryCount; i++)
        {
            material.Clear();
            material[^1] = (byte)((i * 2) + 1);
            reduce(material, entries.Slice(i * 2 * ScalarSize, ScalarSize), curve);
            material[^1] = (byte)((i * 7) + 3);
            reduce(material, entries.Slice((i * 2 * ScalarSize) + ScalarSize, ScalarSize), curve);
        }

        using MerkleTree tree = MerkleSetCommitment.Commit(entries, EntryCount, ScalarSize, poseidonHash, Pool);
        using MerkleAuthenticationPath path = MerkleSetCommitment.ProveMembership(tree, entryIndex, Pool);

        ReadOnlySpan<byte> key = entries.Slice(entryIndex * 2 * ScalarSize, ScalarSize);
        ReadOnlySpan<byte> value = entries.Slice((entryIndex * 2 * ScalarSize) + ScalarSize, ScalarSize);

        Span<byte> leafBytes = stackalloc byte[ScalarSize];
        poseidonHash(key, value, leafBytes);

        //Guard: the fixture is only meaningful if the out-of-circuit verifier
        //accepts this leaf/path/root — the same commitment the gadget authenticates.
        Assert.IsTrue(
            MerkleSetCommitment.VerifyMembership(tree.Root, entryIndex, key, value, path, poseidonHash),
            "the out-of-circuit membership proof must verify before the in-circuit gate is meaningful");

        int depth = path.SiblingCount;
        var siblingValues = new BigInteger[depth];
        var pathBits = new int[depth];
        for(int level = 0; level < depth; level++)
        {
            siblingValues[level] = ToFieldElement(path.GetSibling(level));
            pathBits[level] = (entryIndex >> level) & 1;
        }

        return new MerkleFixture(
            parameters,
            ToFieldElement(leafBytes),
            ToFieldElement(tree.Root.AsReadOnlySpan()),
            pathBits,
            siblingValues);
    }


    /// <summary>Computes the plaintext Poseidon hash of <paramref name="inputs"/> as a field element, independent of the in-circuit gadget.</summary>
    private static BigInteger PlaintextHash(PoseidonParameters parameters, ReadOnlySpan<BigInteger> inputs, ScalarAddDelegate add, ScalarMultiplyDelegate multiply)
    {
        int count = inputs.Length;
        Span<byte> inputBytes = stackalloc byte[count * ScalarSize];
        for(int i = 0; i < count; i++)
        {
            WriteCanonical(inputs[i], inputBytes.Slice(i * ScalarSize, ScalarSize));
        }

        Span<byte> digest = stackalloc byte[ScalarSize];
        PoseidonPermutation.Hash(parameters, inputBytes, digest, add, multiply);

        return ToFieldElement(digest);
    }


    /// <summary>Reads <paramref name="canonicalBigEndian"/> as a field element.</summary>
    private static BigInteger ToFieldElement(ReadOnlySpan<byte> canonicalBigEndian) =>
        new(canonicalBigEndian, isUnsigned: true, isBigEndian: true);


    /// <summary>Writes <paramref name="value"/> to <paramref name="destination"/> as a canonical big-endian field element, zero-padded on the left.</summary>
    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Value does not fit a canonical field-element span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    /// <summary>One Merkle-membership fixture: the Poseidon parameters, the opened leaf and root, and the path bits and sibling values connecting them, all as field elements.</summary>
    /// <param name="Parameters">The Poseidon parameters the fixture's hashes were computed under.</param>
    /// <param name="LeafValue">The opened entry's leaf value.</param>
    /// <param name="RootValue">The commitment's root value.</param>
    /// <param name="PathBits">The opened entry's path bits, least significant first.</param>
    /// <param name="SiblingValues">The opened entry's sibling values, one per tree level.</param>
    private sealed record MerkleFixture(
        PoseidonParameters Parameters,
        BigInteger LeafValue,
        BigInteger RootValue,
        int[] PathBits,
        BigInteger[] SiblingValues);
}
