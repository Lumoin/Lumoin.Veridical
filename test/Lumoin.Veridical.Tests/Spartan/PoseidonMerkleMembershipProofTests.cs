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
    /// <summary>The Fiat-Shamir hash delegate the Spartan transcript and Ligero commitment share.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The Fiat-Shamir squeeze delegate the Spartan transcript and Ligero commitment share.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The scalar-reduce delegate the Spartan pipeline uses over BLS12-381.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 scalar addition delegate the Spartan pipeline computes over.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar subtraction delegate the Spartan pipeline computes over.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar multiplication delegate the Spartan pipeline computes over.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar inversion delegate the Spartan pipeline computes over.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 G1 addition delegate the Spartan commitment scheme uses.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BLS12-381 G1 scalar-multiplication delegate the Spartan commitment scheme uses.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BLS12-381 G1 multi-scalar-multiplication delegate the Spartan commitment scheme uses.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The multilinear-extension evaluation delegate the Spartan sumcheck uses.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The multilinear-extension fold delegate the Spartan sumcheck uses.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    /// <summary>The Merkle two-to-one hash the Ligero polynomial commitment uses, backed by BLAKE3.</summary>
    private static MerkleHashDelegate PcsMerkle { get; } = HashTwoToOne;

    /// <summary>The Poseidon addition delegate; Poseidon parameters and the plaintext oracle use the BigInteger references.</summary>
    private static ScalarAddDelegate PoseidonAdd { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();

    /// <summary>The Poseidon multiplication delegate; Poseidon parameters and the plaintext oracle use the BigInteger references.</summary>
    private static ScalarMultiplyDelegate PoseidonMultiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();

    /// <summary>The Poseidon inversion delegate; Poseidon parameters and the plaintext oracle use the BigInteger references.</summary>
    private static ScalarInvertDelegate PoseidonInvert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();

    /// <summary>The Poseidon reduce delegate; Poseidon parameters and the plaintext oracle use the BigInteger references.</summary>
    private static ScalarReduceDelegate PoseidonReduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The Merkle digest width in bytes, taken from the library's default hash parameters.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The number of Ligero column queries the test polynomial-commitment provider opens.</summary>
    private const int TestQueryCount = 8;

    /// <summary>The byte width of one BLS12-381 scalar.</summary>
    private const int ScalarSize = 32;

    /// <summary>The number of key/value entries committed into the test Merkle set.</summary>
    private const int EntryCount = 3;

    /// <summary>The Fiat-Shamir domain label every transcript in this file is initialised with.</summary>
    private const string TranscriptDomain = "veridical.poseidon.merkle.test.v1";

    /// <summary>The fixed seed for every deterministic prover randomness source this file constructs.</summary>
    private static byte[] RandomSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.poseidon.merkle.rng.v1");

    /// <summary>The BLS12-381 curve tag every delegate call in this file routes over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>
    /// Verifies that an honest Poseidon-hash statement — a circuit asserting a witness input's
    /// Poseidon digest equals a declared public expected value — produces a Spartan-over-Ligero
    /// proof that verifies.
    /// </summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void PoseidonHashProvesInZeroKnowledge()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, Curve, PoseidonAdd, PoseidonInvert, BaseMemoryPool.Shared);
        BigInteger[] inputs = [7, 11];
        BigInteger digest = PlaintextHash(parameters, inputs);

        R1csCircuit circuit = BuildHashCircuit(parameters, inputs.Length);
        R1csCircuitInputs compiled = BuildHashInputs(circuit, parameters, inputs, digest);

        Assert.IsTrue(ProveAndVerify(circuit, compiled), "an honest Poseidon-hash statement must produce a verifying proof");
    }


    /// <summary>
    /// Verifies that an honest Merkle-membership statement — a circuit binding a hidden leaf,
    /// sibling path and position bits to a public committed root — produces a Spartan-over-Ligero
    /// proof that verifies.
    /// </summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void MerkleMembershipProvesInZeroKnowledge()
    {
        MerkleFixture fixture = BuildMerkleFixture(entryIndex: 1);
        R1csCircuit circuit = BuildMerkleCircuit(fixture);
        R1csCircuitInputs compiled = BuildMerkleInputs(circuit, fixture);

        Assert.IsTrue(ProveAndVerify(circuit, compiled), "an honest Merkle-membership statement must produce a verifying proof");
    }


    /// <summary>
    /// Verifies that flipping one bit of a genuine Merkle-membership proof's serialized bytes makes
    /// verification fail.
    /// </summary>
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
        using CommitmentSpartanProof proof = prover.ProveCommitted(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);

        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[^1] ^= 0x01;

        using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) verifierCompiled = circuit.Compile(inputs, pool);
        using RawR1csInstance verifierInstance = verifierCompiled.Instance;
        using RawR1csWitness spareWitness = verifierCompiled.Witness;
        using FiatShamirTranscript verifierTranscript = FreshTranscript();

        bool verified = verifier.VerifyCommitted(proof, verifierInstance, verifierTranscript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
        Assert.IsFalse(verified, "a tampered Merkle-membership proof must be rejected");
    }


    /// <summary>
    /// Compiles the circuit and inputs, proves the resulting instance/witness with Spartan-over-Ligero
    /// under a fresh transcript, then compiles again and verifies the proof under a second fresh
    /// transcript, returning whether verification accepted it.
    /// </summary>
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
        using CommitmentSpartanProof proof = prover.ProveCommitted(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);

        using var verifier = new SpartanVerifier(new SpartanVerifyingKey(BuildProvider()));
        (RawR1csInstance Instance, RawR1csWitness Witness) verifierCompiled = circuit.Compile(inputs, pool);
        using RawR1csInstance verifierInstance = verifierCompiled.Instance;
        using RawR1csWitness spareWitness = verifierCompiled.Witness;
        using FiatShamirTranscript verifierTranscript = FreshTranscript();

        return verifier.VerifyCommitted(proof, verifierInstance, verifierTranscript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
    }


    /// <summary>
    /// Builds a circuit that declares the given number of witness inputs and a public expected
    /// digest, then asserts the Poseidon hash of the inputs equals it, padded to a power of two.
    /// </summary>
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


    /// <summary>
    /// Builds the witness bindings for the hash circuit: the declared inputs and expected digest,
    /// the Poseidon gadget's own auxiliary witness, and the power-of-two padding bindings.
    /// </summary>
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


    /// <summary>
    /// Builds a circuit that declares a public root, a witness leaf, and per-level path-bit and
    /// sibling witnesses, then asserts Merkle membership of the leaf under the root, padded to a
    /// power of two.
    /// </summary>
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


    /// <summary>
    /// Builds the witness bindings for the Merkle circuit: the root, leaf, path bits and siblings
    /// from the fixture, the Merkle gadget's own auxiliary witness, and the power-of-two padding
    /// bindings.
    /// </summary>
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


    /// <summary>Builds the Poseidon Merkle membership fixture for the selected entry.</summary>
    private static MerkleFixture BuildMerkleFixture(int entryIndex)
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(2, Curve, PoseidonAdd, PoseidonInvert, BaseMemoryPool.Shared);
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


    /// <summary>Computes the out-of-circuit Poseidon hash of the given field-element inputs, as the plaintext oracle.</summary>
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


    /// <summary>Builds the Ligero polynomial-commitment provider the Spartan proving and verifying keys share.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce, Hash, Squeeze, Hash, PcsMerkle, WellKnownHashAlgorithms.Blake3, DigestSizeBytes);
    }


    /// <summary>Builds a fresh Fiat-Shamir transcript scoped to this file's fixed domain, with an empty initial absorb.</summary>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the two-to-one BLAKE3 compression the Merkle polynomial commitment uses, hashing the concatenation of the left and right inputs.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Interprets a canonical big-endian byte span as an unsigned field-element integer.</summary>
    private static BigInteger ToFieldElement(ReadOnlySpan<byte> canonicalBigEndian) =>
        new(canonicalBigEndian, isUnsigned: true, isBigEndian: true);


    /// <summary>Writes a non-negative field-element value as a canonical big-endian byte span, zero-padded on the left.</summary>
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


    /// <summary>
    /// The Poseidon Merkle-membership fixture: the hash parameters, the leaf and root field
    /// elements, and the per-level path-bit and sibling values the in-circuit gadget consumes.
    /// </summary>
    /// <param name="Parameters">The Poseidon hash parameters the tree and gadget share.</param>
    /// <param name="LeafValue">The disclosed leaf's field-element value.</param>
    /// <param name="RootValue">The committed tree's root, as a field element.</param>
    /// <param name="PathBits">The leaf's position bit at each level, least significant first.</param>
    /// <param name="SiblingValues">The sibling digest at each level, as field elements.</param>
    private sealed record MerkleFixture(
        PoseidonParameters Parameters,
        BigInteger LeafValue,
        BigInteger RootValue,
        int[] PathBits,
        BigInteger[] SiblingValues);
}
