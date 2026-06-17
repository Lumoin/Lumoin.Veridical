using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.Memory;
using System;
using System.IO;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The native Poseidon's correctness gates. BN254 is held to circomlib
/// byte-compatibility twice over, by independent sources: the pinned
/// well-known circomlib vector for <c>Poseidon(1, 2)</c>, and the committed
/// <c>poseidon2.wtns</c> fixture (a real circomlib evaluation produced by the
/// pinned toolchain — its inputs are exactly <c>(1, 2)</c>). BLS12-381 is the
/// <em>canonical</em> Grain instantiation over the 255-bit field — gated for
/// determinism, deliberately NOT against the BLS circom fixture, whose
/// constants are circomlib's BN254 decimal literals reduced mod the BLS prime
/// by the compiler (circom <c>--prime</c> semantics), not a generated BLS
/// parameter set.
/// </summary>
[TestClass]
internal sealed class PoseidonPermutationTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const string FixtureDirectoryRelative = "ConstraintSystems/Interop/Circom/Fixtures";

    //The well-known circomlib test vector: Poseidon(1, 2) over BN254.
    private const string CircomlibVectorHex = "115CC0F5E7D690413DF64C6B9662E9CF2A3617F2743245519E19607A4417189A";

    private static readonly ScalarAddDelegate Bn254Add = Bn254BigIntegerScalarReference.GetAdd();
    private static readonly ScalarMultiplyDelegate Bn254Multiply = Bn254BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarInvertDelegate Bn254Invert = Bn254BigIntegerScalarReference.GetInvert();
    private static readonly ScalarReduceDelegate Bn254Reduce = Bn254BigIntegerScalarReference.GetReduce();
    private static readonly ScalarAddDelegate BlsAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static readonly ScalarMultiplyDelegate BlsMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarInvertDelegate BlsInvert = Bls12Curve381BigIntegerScalarReference.GetInvert();


    [TestMethod]
    public void Bn254PoseidonMatchesTheCircomlibVector()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: 2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);

        Span<byte> inputs = stackalloc byte[2 * ScalarSize];
        inputs.Clear();
        inputs[ScalarSize - 1] = 0x01;
        inputs[(2 * ScalarSize) - 1] = 0x02;

        Span<byte> digest = stackalloc byte[ScalarSize];
        PoseidonPermutation.Hash(parameters, inputs, digest, Bn254Add, Bn254Multiply);

        Span<byte> expected = stackalloc byte[ScalarSize];
        Convert.FromHexString(CircomlibVectorHex).CopyTo(expected);

        Assert.IsTrue(
            digest.SequenceEqual(expected),
            $"Poseidon(1, 2) over BN254 must equal the circomlib vector; computed {Convert.ToHexString(digest)}.");
    }


    [TestMethod]
    public void Bn254PoseidonMatchesTheOwnedFixtureWitness()
    {
        //The committed wtns is ground truth from the pinned circom toolchain:
        //wires are (1, out, in0, in1) and the input.json pins (1, 2).
        byte[] wtnsBytes = LoadFixtureWitnessBytes("bn254");
        using RawR1csWitness witness = ParseWtns(wtnsBytes, CurveParameterSet.Bn254);

        ReadOnlySpan<byte> witnessScalars = witness.GetWitnessBytes();
        ReadOnlySpan<byte> fixtureDigest = witnessScalars[..ScalarSize];
        ReadOnlySpan<byte> firstInput = witnessScalars.Slice(ScalarSize, ScalarSize);
        ReadOnlySpan<byte> secondInput = witnessScalars.Slice(2 * ScalarSize, ScalarSize);

        //Sanity: the fixture's committed inputs are (1, 2).
        Assert.AreEqual(1, firstInput[^1], "The fixture's first input must be 1.");
        Assert.AreEqual(2, secondInput[^1], "The fixture's second input must be 2.");

        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: 2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);

        Span<byte> inputs = stackalloc byte[2 * ScalarSize];
        firstInput.CopyTo(inputs[..ScalarSize]);
        secondInput.CopyTo(inputs.Slice(ScalarSize, ScalarSize));

        Span<byte> digest = stackalloc byte[ScalarSize];
        PoseidonPermutation.Hash(parameters, inputs, digest, Bn254Add, Bn254Multiply);

        Assert.IsTrue(
            digest.SequenceEqual(fixtureDigest),
            $"The native Poseidon must reproduce the committed circomlib witness output; computed {Convert.ToHexString(digest)}, fixture {Convert.ToHexString(fixtureDigest)}.");
    }


    [TestMethod]
    public void Bls12Curve381GenerationIsDeterministicAndPermutes()
    {
        //The canonical Grain instantiation over the 255-bit field: identical
        //regenerations, and a hash that moves the state.
        PoseidonParameters first = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: 2, CurveParameterSet.Bls12Curve381, BlsAdd, BlsInvert);
        PoseidonParameters second = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: 2, CurveParameterSet.Bls12Curve381, BlsAdd, BlsInvert);

        Assert.IsTrue(
            first.GetRoundConstant(0, 0).SequenceEqual(second.GetRoundConstant(0, 0))
            && first.GetRoundConstant(64, 2).SequenceEqual(second.GetRoundConstant(64, 2)),
            "Parameter generation must be deterministic.");

        Span<byte> inputs = stackalloc byte[2 * ScalarSize];
        inputs.Clear();
        inputs[ScalarSize - 1] = 0x01;
        inputs[(2 * ScalarSize) - 1] = 0x02;

        Span<byte> digest = stackalloc byte[ScalarSize];
        Span<byte> repeat = stackalloc byte[ScalarSize];
        PoseidonPermutation.Hash(first, inputs, digest, BlsAdd, BlsMultiply);
        PoseidonPermutation.Hash(second, inputs, repeat, BlsAdd, BlsMultiply);

        Assert.IsTrue(digest.SequenceEqual(repeat), "The hash must be deterministic across regenerated parameters.");
        Assert.IsFalse(digest.SequenceEqual(inputs[..ScalarSize]), "The digest must not be the input.");
    }


    [TestMethod]
    public void PoseidonMerkleDelegateDrivesTheSetCommitment()
    {
        //The shadow-root story end-to-end: the same MerkleSetCommitment
        //convention under the Poseidon two-to-one delegate — the in-circuit-
        //friendly shadow root. Entry keys/values must be canonical field
        //elements, so the raw test material is reduced first.
        const int EntryCount = 5;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: 2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);
        MerkleHashDelegate poseidonHash = PoseidonPermutation.GetMerkleHash(parameters, Bn254Add, Bn254Multiply);

        Span<byte> entries = stackalloc byte[EntryCount * 2 * ScalarSize];
        Span<byte> material = stackalloc byte[ScalarSize];
        for(int i = 0; i < EntryCount; i++)
        {
            material.Clear();
            material[^1] = (byte)((i * 2) + 1);
            Bn254Reduce(material, entries.Slice(i * 2 * ScalarSize, ScalarSize), CurveParameterSet.Bn254);
            material[^1] = (byte)((i * 7) + 3);
            Bn254Reduce(material, entries.Slice((i * 2 * ScalarSize) + ScalarSize, ScalarSize), CurveParameterSet.Bn254);
        }

        using MerkleTree tree = MerkleSetCommitment.Commit(entries, EntryCount, ScalarSize, poseidonHash, pool);

        const int EntryIndex = 3;
        using MerkleAuthenticationPath path = MerkleSetCommitment.ProveMembership(tree, EntryIndex, pool);
        ReadOnlySpan<byte> key = entries.Slice(EntryIndex * 2 * ScalarSize, ScalarSize);
        ReadOnlySpan<byte> value = entries.Slice((EntryIndex * 2 * ScalarSize) + ScalarSize, ScalarSize);

        Assert.IsTrue(
            MerkleSetCommitment.VerifyMembership(tree.Root, EntryIndex, key, value, path, poseidonHash),
            "Membership under the Poseidon shadow root must verify.");

        Span<byte> wrongValue = stackalloc byte[ScalarSize];
        value.CopyTo(wrongValue);
        wrongValue[^1] ^= 0x01;
        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(tree.Root, EntryIndex, key, wrongValue, path, poseidonHash),
            "A wrong value must be rejected under the Poseidon shadow root.");
    }


    [TestMethod]
    public void ExternallyConstructedParametersDriveTheSamePermutation()
    {
        //The data-level convention seam: a parameter set rebuilt through the
        //public constructor from another producer's values is interchangeable
        //with the generated one — and the constructor rejects shape
        //mismatches.
        PoseidonParameters generated = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: 2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);

        int t = generated.StateWidth;
        int rounds = generated.FullRounds + generated.PartialRounds;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var constantsOwner = pool.Rent(rounds * t * ScalarSize);
        using var mdsOwner = pool.Rent(t * t * ScalarSize);
        Span<byte> constants = constantsOwner.Memory.Span;
        Span<byte> mds = mdsOwner.Memory.Span;
        for(int round = 0; round < rounds; round++)
        {
            for(int lane = 0; lane < t; lane++)
            {
                generated.GetRoundConstant(round, lane).CopyTo(constants.Slice(((round * t) + lane) * ScalarSize, ScalarSize));
            }
        }

        for(int row = 0; row < t; row++)
        {
            for(int column = 0; column < t; column++)
            {
                generated.GetMdsEntry(row, column).CopyTo(mds.Slice(((row * t) + column) * ScalarSize, ScalarSize));
            }
        }

        var rebuilt = new PoseidonParameters(t, generated.FullRounds, generated.PartialRounds, constants, mds, CurveParameterSet.Bn254);

        Span<byte> inputs = stackalloc byte[2 * ScalarSize];
        inputs.Clear();
        inputs[ScalarSize - 1] = 0x01;
        inputs[(2 * ScalarSize) - 1] = 0x02;

        Span<byte> digest = stackalloc byte[ScalarSize];
        PoseidonPermutation.Hash(rebuilt, inputs, digest, Bn254Add, Bn254Multiply);

        Span<byte> expected = stackalloc byte[ScalarSize];
        Convert.FromHexString(CircomlibVectorHex).CopyTo(expected);
        Assert.IsTrue(digest.SequenceEqual(expected), "Externally constructed parameters must drive the identical permutation.");

        int fullRounds = generated.FullRounds;
        int partialRounds = generated.PartialRounds;
        _ = Assert.ThrowsExactly<ArgumentException>(
            () => new PoseidonParameters(3, fullRounds, partialRounds, constantsOwner.Memory.Span[..^ScalarSize], mdsOwner.Memory.Span, CurveParameterSet.Bn254));
    }


    private static byte[] LoadFixtureWitnessBytes(string curveDirectory)
    {
        string directory = Path.Combine(AppContext.BaseDirectory, FixtureDirectoryRelative, curveDirectory);
        if(!Directory.Exists(directory))
        {
            directory = Path.Combine(FixtureDirectoryRelative, curveDirectory);
        }

        string wtnsPath = Path.Combine(directory, "poseidon2.wtns");
        if(!File.Exists(wtnsPath))
        {
            Assert.Inconclusive($"Fixture file not found: {wtnsPath}. Regenerate per Fixtures/REGENERATE.md.");
        }

        return File.ReadAllBytes(wtnsPath);
    }


    private static RawR1csWitness ParseWtns(byte[] bytes, CurveParameterSet curve)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);

        return CircomWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomWitness,
            curve,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }
}
