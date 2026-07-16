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
    private const int ScalarSize = 32;
    private const int EntryCount = 5;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static readonly ScalarAddDelegate Bn254Add = Bn254BigIntegerScalarReference.GetAdd();
    private static readonly ScalarMultiplyDelegate Bn254Multiply = Bn254BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarInvertDelegate Bn254Invert = Bn254BigIntegerScalarReference.GetInvert();
    private static readonly ScalarReduceDelegate Bn254Reduce = Bn254BigIntegerScalarReference.GetReduce();
    private static readonly ScalarAddDelegate BlsAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static readonly ScalarMultiplyDelegate BlsMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarInvertDelegate BlsInvert = Bls12Curve381BigIntegerScalarReference.GetInvert();


    [TestMethod]
    public void Bn254PoseidonHashGadgetMatchesPlaintext()
    {
        AssertHashGadgetMatchesPlaintext(CurveParameterSet.Bn254, inputCount: 2, Bn254Add, Bn254Multiply, Bn254Invert, [7, 11]);
    }


    [TestMethod]
    public void Bls12Curve381PoseidonHashGadgetMatchesPlaintext()
    {
        AssertHashGadgetMatchesPlaintext(CurveParameterSet.Bls12Curve381, inputCount: 2, BlsAdd, BlsMultiply, BlsInvert, [7, 11]);
    }


    [TestMethod]
    public void PoseidonHashGadgetMatchesPlaintextAcrossArities()
    {
        AssertHashGadgetMatchesPlaintext(CurveParameterSet.Bn254, inputCount: 1, Bn254Add, Bn254Multiply, Bn254Invert, [42]);
        AssertHashGadgetMatchesPlaintext(CurveParameterSet.Bn254, inputCount: 4, Bn254Add, Bn254Multiply, Bn254Invert, [1, 2, 3, 4]);
        AssertHashGadgetMatchesPlaintext(CurveParameterSet.Bn254, inputCount: 8, Bn254Add, Bn254Multiply, Bn254Invert, [3, 5, 8, 13, 21, 34, 55, 89]);
    }


    [TestMethod]
    public void PoseidonHashGadgetRejectsWrongDigest()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);
        R1csCircuit circuit = BuildHashCircuit(CurveParameterSet.Bn254, 2, parameters);

        BigInteger[] inputs = [7, 11];
        BigInteger correct = PlaintextHash(parameters, inputs, Bn254Add, Bn254Multiply);

        Dictionary<string, BigInteger> bindings = HashBindings(parameters, inputs, claimedDigest: correct + 1);
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    [TestMethod]
    public void PoseidonHashGadgetRejectsUnderConstrainedSBoxIntermediate()
    {
        //The first S-box's x2 wire is bound by x·x = x2. Tampering it (leaving the
        //rest of the honest trace intact) must be caught at compile — proof that
        //the intermediate is genuinely constrained, not free.
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);
        R1csCircuit circuit = BuildHashCircuit(CurveParameterSet.Bn254, 2, parameters);

        BigInteger[] inputs = [7, 11];
        BigInteger correct = PlaintextHash(parameters, inputs, Bn254Add, Bn254Multiply);
        Dictionary<string, BigInteger> bindings = HashBindings(parameters, inputs, claimedDigest: correct);
        bindings["h_r0_l0_x2"] = bindings["h_r0_l0_x2"] + 1;

        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    [TestMethod]
    public void PoseidonHashWitnessReproducesPlaintextHash()
    {
        //The witness trace is an independent third implementation of the
        //permutation; it must reproduce the plaintext hash bit for bit on both
        //curves, which is what transitively binds the gadget to circomlib.
        AssertWitnessReproducesPlaintext(CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, [7, 11]);
        AssertWitnessReproducesPlaintext(CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, [0, 0]);
        AssertWitnessReproducesPlaintext(CurveParameterSet.Bls12Curve381, BlsAdd, BlsMultiply, BlsInvert, [123456789, 987654321]);
    }


    [TestMethod]
    public void PoseidonHashGadgetRejectsWrongInputCount()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bn254);
        R1csVariableIndex only = builder.DeclareWitnessVariable("only");

        //Two-input parameters, one input supplied.
        Assert.ThrowsExactly<ArgumentException>(
            () => builder.AssertPoseidonHash([R1csLinearCombination.From(only)], parameters, "h"));
    }


    [TestMethod]
    public void Bn254MerkleMembershipGadgetAuthenticatesTheShadowRoot()
    {
        MerkleFixture fixture = BuildMerkleFixture(CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        Dictionary<string, BigInteger> bindings = MerkleBindings(fixture);
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(new R1csCircuitInputs(bindings), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Bn254Add, Bn254Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, "the in-circuit Merkle path authenticates the Poseidon shadow root");
    }


    [TestMethod]
    public void Bls12Curve381MerkleMembershipGadgetAuthenticatesTheShadowRoot()
    {
        MerkleFixture fixture = BuildMerkleFixture(CurveParameterSet.Bls12Curve381, BlsAdd, BlsMultiply, BlsInvert, Bls12Curve381BigIntegerScalarReference.GetReduce(), entryIndex: 2);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        Dictionary<string, BigInteger> bindings = MerkleBindings(fixture);
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(new R1csCircuitInputs(bindings), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, BlsAdd, BlsMultiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    [TestMethod]
    public void MerkleMembershipGadgetRejectsWrongLeaf()
    {
        MerkleFixture fixture = BuildMerkleFixture(CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        Dictionary<string, BigInteger> bindings = MerkleBindings(fixture);
        bindings["leaf"] = bindings["leaf"] + 1;
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    [TestMethod]
    public void MerkleMembershipGadgetRejectsWrongSibling()
    {
        MerkleFixture fixture = BuildMerkleFixture(CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        //A tampered sibling: the whole trace is recomputed from it, so the
        //recomputed root diverges from the committed (public) root.
        var tampered = (BigInteger[])fixture.SiblingValues.Clone();
        tampered[0] += 1;
        MerkleFixture wrong = fixture with { SiblingValues = tampered };

        Dictionary<string, BigInteger> bindings = MerkleBindings(wrong);
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    [TestMethod]
    public void MerkleMembershipGadgetRejectsWrongRoot()
    {
        MerkleFixture fixture = BuildMerkleFixture(CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        Dictionary<string, BigInteger> bindings = MerkleBindings(fixture);
        bindings["root"] = bindings["root"] + 1;
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    [TestMethod]
    public void MerkleMembershipGadgetRejectsWrongDirectionBit()
    {
        //Claiming a different index (flip the lowest direction bit) turns the
        //authentication toward the wrong subtree: the recomputed root no longer
        //equals the committed root. This is the in-circuit position binding.
        MerkleFixture fixture = BuildMerkleFixture(CurveParameterSet.Bn254, Bn254Add, Bn254Multiply, Bn254Invert, Bn254Reduce, entryIndex: 3);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);

        var flipped = (int[])fixture.PathBits.Clone();
        flipped[0] ^= 1;
        MerkleFixture wrong = fixture with { PathBits = flipped };

        Dictionary<string, BigInteger> bindings = MerkleBindings(wrong);
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }


    private static void AssertHashGadgetMatchesPlaintext(
        CurveParameterSet curve, int inputCount, ScalarAddDelegate add, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, BigInteger[] inputs)
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(inputCount, curve, add, invert);
        R1csCircuit circuit = BuildHashCircuit(curve, inputCount, parameters);

        BigInteger digest = PlaintextHash(parameters, inputs, add, multiply);
        Dictionary<string, BigInteger> bindings = HashBindings(parameters, inputs, claimedDigest: digest);

        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(new R1csCircuitInputs(bindings), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, add, multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, $"the in-circuit Poseidon({inputCount}) digest equals the plaintext hash over {curve}");
    }


    private static void AssertWitnessReproducesPlaintext(
        CurveParameterSet curve, ScalarAddDelegate add, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, BigInteger[] inputs)
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(inputs.Length, curve, add, invert);
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        BigInteger traceDigest = R1csPoseidonWitness.AddPoseidonHashWitness(bindings, "h", inputs, parameters);
        BigInteger plaintext = PlaintextHash(parameters, inputs, add, multiply);

        Assert.AreEqual(plaintext, traceDigest, "the witness trace digest must equal the plaintext Poseidon hash");
    }


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


    private static MerkleFixture BuildMerkleFixture(
        CurveParameterSet curve, ScalarAddDelegate add, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce, int entryIndex)
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, curve, add, invert);
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


    private static BigInteger ToFieldElement(ReadOnlySpan<byte> canonicalBigEndian) =>
        new(canonicalBigEndian, isUnsigned: true, isBigEndian: true);


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


    private sealed record MerkleFixture(
        PoseidonParameters Parameters,
        BigInteger LeafValue,
        BigInteger RootValue,
        int[] PathBits,
        BigInteger[] SiblingValues);
}
