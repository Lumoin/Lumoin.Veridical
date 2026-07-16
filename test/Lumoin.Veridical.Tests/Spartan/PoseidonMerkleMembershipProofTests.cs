using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end gate for the in-circuit Poseidon gadgets through the full
/// Spartan-over-Ligero pipeline: a Poseidon hash and a Merkle-membership proof
/// over a real <see cref="MerkleSetCommitment"/> (Poseidon shadow root) are
/// compiled, proven in zero knowledge, and verified. The flagship is the
/// membership case — the same commitment an out-of-circuit verifier accepts is
/// authenticated in circuit, so a holder can prove "this hidden leaf is a member
/// of that committed set" without revealing the leaf, the sibling path, or the
/// position.
/// </summary>
/// <remarks>
/// Backends mirror <see cref="LigeroAgeThresholdCredentialProofTests"/>: the
/// Spartan arithmetic runs over BLS12-381, the polynomial-commitment Merkle uses
/// BLAKE3, and the Poseidon parameters/plaintext oracle use the BigInteger
/// scalar references (as in the native Poseidon tests). The circuit is padded to
/// a power of two before proving.
/// </remarks>
[TestClass]
internal sealed class PoseidonMerkleMembershipProofTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
    private static MerkleHashDelegate PcsMerkle { get; } = HashTwoToOne;

    //Poseidon parameters and the plaintext oracle use the BigInteger references.
    private static ScalarAddDelegate PoseidonAdd { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarMultiplyDelegate PoseidonMultiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate PoseidonInvert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();
    private static ScalarReduceDelegate PoseidonReduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 8;
    private const int ScalarSize = 32;
    private const int EntryCount = 3;
    private const string TranscriptDomain = "veridical.wave3.poseidon.merkle.test.v1";

    private static readonly byte[] RandomSeed = System.Text.Encoding.UTF8.GetBytes("veridical.wave3.poseidon.merkle.rng.v1");
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [TestCategory("Slow")]
    public void PoseidonHashProvesInZeroKnowledge()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, Curve, PoseidonAdd, PoseidonInvert);
        BigInteger[] inputs = [7, 11];
        BigInteger digest = PlaintextHash(parameters, inputs);

        R1csCircuit circuit = BuildHashCircuit(parameters, inputs.Length);
        R1csCircuitInputs compiled = BuildHashInputs(circuit, parameters, inputs, digest);

        Assert.IsTrue(ProveAndVerify(circuit, compiled), "an honest Poseidon-hash statement must produce a verifying proof");
    }


    [TestMethod]
    [TestCategory("Slow")]
    public void MerkleMembershipProvesInZeroKnowledge()
    {
        MerkleFixture fixture = BuildMerkleFixture(entryIndex: 1);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);
        R1csCircuitInputs compiled = BuildMerkleInputs(circuit, fixture);

        Assert.IsTrue(ProveAndVerify(circuit, compiled), "an honest Merkle-membership statement must produce a verifying proof");
    }


    [TestMethod]
    [TestCategory("Slow")]
    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan prover/verifier own their keys and are disposed via using declarations.")]
    public void TamperedMembershipProofIsRejected()
    {
        MerkleFixture fixture = BuildMerkleFixture(entryIndex: 1);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);
        R1csCircuitInputs inputs = BuildMerkleInputs(circuit, fixture);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using var prover = new SpartanProver(new SpartanProvingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(inputs, pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();
        using LigeroSpartanProof proof = prover.ProveLigero(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);

        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[^1] ^= 0x01;

        using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) verifierCompiled = circuit.Compile(inputs, pool);
        using RawR1csInstance verifierInstance = verifierCompiled.Instance;
        using RawR1csWitness spareWitness = verifierCompiled.Witness;
        using FiatShamirTranscript verifierTranscript = FreshTranscript();

        bool verified = verifier.VerifyLigero(proof, verifierInstance, verifierTranscript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
        Assert.IsFalse(verified, "a tampered Merkle-membership proof must be rejected");
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Instances, witnesses, prover, verifier and transcripts are disposed via using declarations before the result is returned.")]
    private static bool ProveAndVerify(R1csCircuit circuit, R1csCircuitInputs inputs)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (RawR1csInstance Instance, RawR1csWitness Witness) proverCompiled = circuit.Compile(inputs, pool);
        using RawR1csInstance instance = proverCompiled.Instance;
        using RawR1csWitness witness = proverCompiled.Witness;

        using var prover = new SpartanProver(new SpartanProvingKey(BuildProvider()));
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();
        using LigeroSpartanProof proof = prover.ProveLigero(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);

        using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) verifierCompiled = circuit.Compile(inputs, pool);
        using RawR1csInstance verifierInstance = verifierCompiled.Instance;
        using RawR1csWitness spareWitness = verifierCompiled.Witness;
        using FiatShamirTranscript verifierTranscript = FreshTranscript();

        return verifier.VerifyLigero(proof, verifierInstance, verifierTranscript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
    }


    private static R1csCircuit BuildHashCircuit(PoseidonParameters parameters, int inputCount)
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex expected = builder.DeclarePublicInput("expected");

        var inputs = new R1csLinearCombination[inputCount];
        for(int i = 0; i < inputCount; i++)
        {
            inputs[i] = R1csLinearCombination.From(builder.DeclareWitnessVariable($"in_{i}"));
        }

        R1csVariableIndex digest = builder.AssertPoseidonHash(inputs, parameters, "h");
        builder.AssertEqual(R1csLinearCombination.From(digest), R1csLinearCombination.From(expected));

        return builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build();
    }


    private static R1csCircuitInputs BuildHashInputs(R1csCircuit circuit, PoseidonParameters parameters, BigInteger[] inputs, BigInteger digest)
    {
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal)
        {
            ["expected"] = digest,
        };

        for(int i = 0; i < inputs.Length; i++)
        {
            bindings[$"in_{i}"] = inputs[i];
        }

        R1csPoseidonWitness.AddPoseidonHashWitness(bindings, "h", inputs, parameters);
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        return new R1csCircuitInputs(bindings);
    }


    private static R1csCircuit BuildMerkleCircuit(MerkleFixture fixture)
    {
        var builder = new R1csCircuitBuilder(Curve);
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

        return builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build();
    }


    private static R1csCircuitInputs BuildMerkleInputs(R1csCircuit circuit, MerkleFixture fixture)
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
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        return new R1csCircuitInputs(bindings);
    }


    private static MerkleFixture BuildMerkleFixture(int entryIndex)
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, Curve, PoseidonAdd, PoseidonInvert);
        MerkleHashDelegate poseidonHash = PoseidonPermutation.GetMerkleHash(parameters, PoseidonAdd, PoseidonMultiply);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Span<byte> entries = stackalloc byte[EntryCount * 2 * ScalarSize];
        Span<byte> material = stackalloc byte[ScalarSize];
        for(int i = 0; i < EntryCount; i++)
        {
            material.Clear();
            material[^1] = (byte)((i * 2) + 1);
            PoseidonReduce(material, entries.Slice(i * 2 * ScalarSize, ScalarSize), Curve);
            material[^1] = (byte)((i * 7) + 3);
            PoseidonReduce(material, entries.Slice((i * 2 * ScalarSize) + ScalarSize, ScalarSize), Curve);
        }

        using MerkleTree tree = MerkleSetCommitment.Commit(entries, EntryCount, ScalarSize, poseidonHash, pool);
        using MerkleAuthenticationPath path = MerkleSetCommitment.ProveMembership(tree, entryIndex, pool);

        ReadOnlySpan<byte> key = entries.Slice(entryIndex * 2 * ScalarSize, ScalarSize);
        ReadOnlySpan<byte> value = entries.Slice((entryIndex * 2 * ScalarSize) + ScalarSize, ScalarSize);

        Span<byte> leafBytes = stackalloc byte[ScalarSize];
        poseidonHash(key, value, leafBytes);

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

        return new MerkleFixture(parameters, ToFieldElement(leafBytes), ToFieldElement(tree.Root.AsReadOnlySpan()), pathBits, siblingValues);
    }


    private static BigInteger PlaintextHash(PoseidonParameters parameters, ReadOnlySpan<BigInteger> inputs)
    {
        int count = inputs.Length;
        Span<byte> inputBytes = stackalloc byte[count * ScalarSize];
        for(int i = 0; i < count; i++)
        {
            WriteCanonical(inputs[i], inputBytes.Slice(i * ScalarSize, ScalarSize));
        }

        Span<byte> digest = stackalloc byte[ScalarSize];
        PoseidonPermutation.Hash(parameters, inputBytes, digest, PoseidonAdd, PoseidonMultiply);

        return ToFieldElement(digest);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce, Hash, Squeeze, Hash, PcsMerkle, WellKnownHashAlgorithms.Blake3, DigestSizeBytes);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
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
