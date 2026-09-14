using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Numerics;
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

    /// <summary>The input count of a two-to-one Poseidon hash, whose state is three lanes wide.</summary>
    private const int TwoInputCount = 2;

    /// <summary>The state width of a two-to-one Poseidon hash: its two input lanes plus the capacity lane.</summary>
    private const int TwoInputStateWidth = TwoInputCount + CapacityLanes;

    /// <summary>A state four scalars wide, one lane wider than the three-lane state a two-input parameter set declares.</summary>
    private const int ForeignStateScalars = 4;

    /// <summary>An input one scalar wide, one scalar short of what a two-input parameter set takes.</summary>
    private const int ShortInputScalars = 1;

    /// <summary>The width of a Poseidon digest in scalars.</summary>
    private const int DigestScalars = 1;

    /// <summary>A digest buffer two scalars wide, one scalar wider than the hash emits.</summary>
    private const int ForeignDigestScalars = 2;

    /// <summary>The capacity lanes of the hash state, which carry no input.</summary>
    private const int CapacityLanes = 1;

    /// <summary>The widest state the stack scratch holds: its 544 bytes are exactly 17 lanes.</summary>
    private const int WidestScratchStateWidth = WellKnownPoseidonScratch.MaximumStateBytes / ScalarSize;

    /// <summary>One lane past the widest state the stack scratch holds: 544 bytes are 17 lanes, so this is 18.</summary>
    private const int OversizedStateWidth = WidestScratchStateWidth + 1;

    /// <summary>The state width of a one-input hash, which the parameter constructor accepts but a two-to-one compression cannot use.</summary>
    private const int OneInputStateWidth = 2;

    /// <summary>The smallest full-round count the parameter constructor accepts: positive and even.</summary>
    private const int MinimalFullRounds = 2;

    /// <summary>The smallest partial-round count the parameter constructor accepts.</summary>
    private const int MinimalPartialRounds = 1;

    /// <summary>The fill salt of constructed round constants.</summary>
    private const int RoundConstantFillSalt = 1;

    /// <summary>The fill salt of constructed MDS entries.</summary>
    private const int MdsFillSalt = 2;

    /// <summary>The fill salt of a permutation state.</summary>
    private const int StateFillSalt = 3;

    /// <summary>The fill salt of hash inputs.</summary>
    private const int InputFillSalt = 4;

    /// <summary>The fill salt of a digest buffer, whose prior contents a refused hash never reads.</summary>
    private const int DigestFillSalt = 5;

    /// <summary>The parameter name both state guards of the permutation report.</summary>
    private const string StateParameterName = "state";

    /// <summary>The parameter name the input-arity guard of the hash reports.</summary>
    private const string InputsParameterName = "inputs";

    /// <summary>The parameter name the digest-width guard of the hash reports.</summary>
    private const string DigestParameterName = "digest";

    /// <summary>
    /// The parameter name the parameter-set null guards, the scratch-bound guard of the hash and the arity guard of
    /// the Merkle compression report.
    /// </summary>
    private const string ParametersParameterName = "parameters";

    /// <summary>The parameter name the addition-backend null guards of the permutation and the Merkle compression report.</summary>
    private const string AddParameterName = "add";

    /// <summary>The parameter name the multiplication-backend null guards of the permutation and the Merkle compression report.</summary>
    private const string MultiplyParameterName = "multiply";

    /// <summary>The wire-name prefix the independent modular trace binds its intermediate values under.</summary>
    private const string TraceName = "h";

    /// <summary>The state-width refusal for a four-scalar state against three lanes: three lanes are 96 bytes, and four scalars are 128.</summary>
    private const string WrongStateWidthMessage = "The state must be exactly 3 scalars (96 bytes); received 128.";

    /// <summary>The scratch-bound refusal for an 18-lane parameter set; the permutation and the hash word it identically and differ only in the parameter name.</summary>
    private const string ScratchBoundMessage = "The state width 18 exceeds the supported maximum.";

    /// <summary>The input-arity refusal for a one-scalar input against a two-input parameter set.</summary>
    private const string WrongInputArityMessage = "The inputs must be exactly 2 scalars; received 32 bytes.";

    /// <summary>The digest-width refusal for a two-scalar digest buffer.</summary>
    private const string WrongDigestWidthMessage = "The digest must be exactly 32 bytes; received 64.";

    /// <summary>The Merkle compression's refusal of a two-lane parameter set.</summary>
    private const string NotTwoInputMessage = "A two-to-one Merkle compression needs two-input parameters (StateWidth = 3); received 2.";

    private static ScalarAddDelegate Bn254Add { get; } = Bn254BigIntegerScalarReference.GetAdd();
    private static ScalarMultiplyDelegate Bn254Multiply { get; } = Bn254BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate Bn254Invert { get; } = Bn254BigIntegerScalarReference.GetInvert();
    private static ScalarReduceDelegate Bn254Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate BlsAdd { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarMultiplyDelegate BlsMultiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate BlsInvert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();

    /// <summary>The pooled rentals a test opened, released together in cleanup.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Disposes every rental the test opened.</summary>
    [TestCleanup]
    public void DisposeRentals()
    {
        foreach(IDisposable rental in Disposables)
        {
            rental.Dispose();
        }

        Disposables.Clear();
    }


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


    /// <summary>
    /// The Poseidon compression admits exactly one node width — its digest is
    /// one canonical field element — so a set commitment stated at any other
    /// width is refused loudly at the first leaf hash instead of committing a
    /// tree the compression cannot honestly fill.
    /// </summary>
    [TestMethod]
    public void PoseidonSetCommitmentRefusesAForeignNodeWidth()
    {
        //One entry suffices: the refusal fires inside the first leaf hash,
        //before any tree is built.
        const int EntryCount = 1;
        const int ForeignDigestSizeBytes = 2 * ScalarSize;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: 2, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);
        MerkleHashDelegate poseidonHash = PoseidonPermutation.GetMerkleHash(parameters, Bn254Add, Bn254Multiply);

        //Entries shaped for the stated width, all zero: the width figure
        //itself is what the commitment trips on, not the entry content.
        using System.Buffers.IMemoryOwner<byte> entriesOwner = pool.Rent(EntryCount * 2 * ForeignDigestSizeBytes);
        Memory<byte> entries = entriesOwner.Memory[..(EntryCount * 2 * ForeignDigestSizeBytes)];
        entries.Span.Clear();

        Assert.ThrowsExactly<ArgumentException>(
            () => MerkleSetCommitment.Commit(entries.Span, EntryCount, ForeignDigestSizeBytes, poseidonHash, BaseMemoryPool.Shared).Dispose(),
            "A node width the Poseidon compression cannot produce must be refused, not committed.");
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


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Permute"/> refuses a state that is not exactly
    /// <see cref="PoseidonParameters.StateWidth"/> scalars wide with an <see cref="ArgumentException"/> that names
    /// <c>state</c> and states the expected lane count, the expected byte count and the received length, instead of
    /// permuting only the lanes the parameters declare and overwriting the extra lane with the unwritten, zeroed scratch
    /// lane. The parameters are a generated three-lane set and the state is four canonical scalars, so every reference
    /// argument is non-null and the state fits the stack scratch; the scratch-bound guard, which also names
    /// <c>state</c>, words its refusal differently.
    /// </summary>
    [TestMethod]
    public void PermuteRejectsAStateOfTheWrongWidth()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: TwoInputCount, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);
        Memory<byte> state = RentCanonicalScalars(ForeignStateScalars, StateFillSalt);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => PoseidonPermutation.Permute(parameters, state.Span, Bn254Add, Bn254Multiply),
            "A state that is not StateWidth scalars wide must be refused.");

        Assert.AreEqual(StateParameterName, exception.ParamName, "The refusal must name the state parameter.");
        Assert.Contains(WrongStateWidthMessage, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Permute"/> refuses parameters wider than its stack scratch holds with an
    /// <see cref="ArgumentException"/> that names <c>state</c> and states the offending width, rather than faulting on
    /// the undersized scratch with an <see cref="ArgumentOutOfRangeException"/>. The generated circomlib sets stop at 17
    /// lanes, but the public <see cref="PoseidonParameters"/> constructor bounds the width only from below, so an
    /// 18-lane set is constructible. The state is exactly 18 scalars, so the state-width guard passes, every reference
    /// argument is non-null, and the refusal comes before any round reads the constants.
    /// </summary>
    [TestMethod]
    public void PermuteRejectsAStateWiderThanTheScratchBound()
    {
        PoseidonParameters parameters = CreateMinimalParameters(OversizedStateWidth);
        Memory<byte> state = RentCanonicalScalars(OversizedStateWidth, StateFillSalt);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => PoseidonPermutation.Permute(parameters, state.Span, Bn254Add, Bn254Multiply),
            "A state wider than the stack scratch must be refused.");

        Assert.AreEqual(StateParameterName, exception.ParamName, "The refusal must name the state parameter.");
        Assert.Contains(ScratchBoundMessage, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Hash"/> refuses inputs that are not exactly <c>StateWidth - 1</c>
    /// scalars with an <see cref="ArgumentException"/> that names <c>inputs</c> and states the expected arity and the
    /// received length, instead of hashing a short input as if the missing lanes were zero. The input is one canonical
    /// scalar against a two-input parameter set; the digest is exactly one scalar wide and the three-lane state fits
    /// the stack scratch, so neither later guard can answer, and no other guard names <c>inputs</c>. A short input is
    /// the case only this guard stops: an oversized one would also fault when copied into the state.
    /// </summary>
    [TestMethod]
    public void HashRejectsInputsOfTheWrongArity()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: TwoInputCount, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);
        Memory<byte> inputs = RentCanonicalScalars(ShortInputScalars, InputFillSalt);
        Memory<byte> digest = RentCanonicalScalars(DigestScalars, DigestFillSalt);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => PoseidonPermutation.Hash(parameters, inputs.Span, digest.Span, Bn254Add, Bn254Multiply),
            "Inputs that are not StateWidth - 1 scalars must be refused.");

        Assert.AreEqual(InputsParameterName, exception.ParamName, "The refusal must name the inputs parameter.");
        Assert.Contains(WrongInputArityMessage, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Hash"/> refuses a digest buffer that is not exactly one scalar wide with
    /// an <see cref="ArgumentException"/> that names <c>digest</c> and states the required and received widths, instead
    /// of writing the digest into the first scalar of a wider buffer. The inputs are exactly two canonical scalars for a
    /// two-input parameter set, so the input guard passes, and no other guard names <c>digest</c>. A wider buffer is
    /// the case only this guard stops: a narrower one would also fault when the digest is copied out.
    /// </summary>
    [TestMethod]
    public void HashRejectsADigestOfTheWrongWidth()
    {
        PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(
            inputCount: TwoInputCount, CurveParameterSet.Bn254, Bn254Add, Bn254Invert);
        Memory<byte> inputs = RentCanonicalScalars(TwoInputCount, InputFillSalt);
        Memory<byte> digest = RentCanonicalScalars(ForeignDigestScalars, DigestFillSalt);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => PoseidonPermutation.Hash(parameters, inputs.Span, digest.Span, Bn254Add, Bn254Multiply),
            "A digest buffer that is not one scalar wide must be refused.");

        Assert.AreEqual(DigestParameterName, exception.ParamName, "The refusal must name the digest parameter.");
        Assert.Contains(WrongDigestWidthMessage, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Hash"/> refuses parameters wider than its stack scratch holds with an
    /// <see cref="ArgumentException"/> that names <c>parameters</c> and states the offending width, rather than
    /// faulting on the undersized scratch with an <see cref="ArgumentOutOfRangeException"/>. The 18-lane set comes from the
    /// public constructor, the inputs are exactly 17 canonical scalars and the digest is one scalar wide, so both span
    /// guards pass. <see cref="PoseidonPermutation.Permute"/> words its own scratch-bound refusal identically but names
    /// <c>state</c>, and the hash refuses before the permutation is reached.
    /// </summary>
    [TestMethod]
    public void HashRejectsParametersWiderThanTheScratchBound()
    {
        PoseidonParameters parameters = CreateMinimalParameters(OversizedStateWidth);
        Memory<byte> inputs = RentCanonicalScalars(OversizedStateWidth - CapacityLanes, InputFillSalt);
        Memory<byte> digest = RentCanonicalScalars(DigestScalars, DigestFillSalt);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => PoseidonPermutation.Hash(parameters, inputs.Span, digest.Span, Bn254Add, Bn254Multiply),
            "Parameters wider than the stack scratch must be refused.");

        Assert.AreEqual(ParametersParameterName, exception.ParamName, "The refusal must name the parameters parameter.");
        Assert.Contains(ScratchBoundMessage, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.GetMerkleHash"/> refuses parameters that are not two-input with an
    /// <see cref="ArgumentException"/> that names <c>parameters</c> and states the required and received state widths,
    /// when the compression is requested rather than at its first invocation. A two-lane set is legal for the public
    /// constructor, every delegate is non-null and the returned compression is never invoked, so no guard of the hash
    /// can answer in its place.
    /// </summary>
    [TestMethod]
    public void GetMerkleHashRejectsParametersThatAreNotTwoInput()
    {
        PoseidonParameters parameters = CreateMinimalParameters(OneInputStateWidth);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => _ = PoseidonPermutation.GetMerkleHash(parameters, Bn254Add, Bn254Multiply),
            "Parameters that are not two-input must be refused when the compression is requested.");

        Assert.AreEqual(ParametersParameterName, exception.ParamName, "The refusal must name the parameters parameter.");
        Assert.Contains(NotTwoInputMessage, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Permute"/> refuses a null parameter set with an
    /// <see cref="ArgumentNullException"/> that names <c>parameters</c>, instead of faulting with a
    /// <see cref="NullReferenceException"/> where the state width is read out of it. Both backends are non-null and the
    /// state is three canonical scalars, so this is the first guard the call meets and nothing else can answer in its
    /// place; the other refusals that name <c>parameters</c> are <see cref="ArgumentException"/>, which the exact-type
    /// assertion separates from this one.
    /// </summary>
    [TestMethod]
    public void PermuteRejectsNullParameters()
    {
        Memory<byte> state = RentCanonicalScalars(TwoInputStateWidth, StateFillSalt);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => PoseidonPermutation.Permute(null!, state.Span, Bn254Add, Bn254Multiply),
            "A null parameter set must be refused.");

        Assert.AreEqual(ParametersParameterName, exception.ParamName, "The refusal must name the parameters parameter.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Permute"/> refuses a null addition backend with an
    /// <see cref="ArgumentNullException"/> that names <c>add</c>, instead of invoking the missing delegate at the first
    /// round-constant addition and faulting with a <see cref="NullReferenceException"/>. The parameter set is a
    /// constructed three-lane set and the multiplication backend is non-null, and the state is exactly three canonical
    /// scalars, which is both the declared width and inside the scratch bound, so only this guard can fire and no other
    /// refusal names <c>add</c>.
    /// </summary>
    [TestMethod]
    public void PermuteRejectsANullAddition()
    {
        PoseidonParameters parameters = CreateMinimalParameters(TwoInputStateWidth);
        Memory<byte> state = RentCanonicalScalars(TwoInputStateWidth, StateFillSalt);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => PoseidonPermutation.Permute(parameters, state.Span, null!, Bn254Multiply),
            "A null addition backend must be refused.");

        Assert.AreEqual(AddParameterName, exception.ParamName, "The refusal must name the add parameter.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Permute"/> refuses a null multiplication backend with an
    /// <see cref="ArgumentNullException"/> that names <c>multiply</c>, instead of adding the first round's constants
    /// through the live addition backend and then faulting with a <see cref="NullReferenceException"/> at the first
    /// S-box squaring. The parameter set is a constructed three-lane set and the addition backend is non-null, and the
    /// state is exactly three canonical scalars, so only this guard can fire and no other refusal names
    /// <c>multiply</c>.
    /// </summary>
    [TestMethod]
    public void PermuteRejectsANullMultiplication()
    {
        PoseidonParameters parameters = CreateMinimalParameters(TwoInputStateWidth);
        Memory<byte> state = RentCanonicalScalars(TwoInputStateWidth, StateFillSalt);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => PoseidonPermutation.Permute(parameters, state.Span, Bn254Add, null!),
            "A null multiplication backend must be refused.");

        Assert.AreEqual(MultiplyParameterName, exception.ParamName, "The refusal must name the multiply parameter.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Hash"/> refuses a null parameter set with an
    /// <see cref="ArgumentNullException"/> that names <c>parameters</c>, instead of faulting with a
    /// <see cref="NullReferenceException"/> where the state width is read out of it. The inputs are two canonical
    /// scalars, the digest is one, and both backends are non-null, so this is the first guard the call meets; the
    /// permutation's own null guard is never reached, and the scratch-bound refusal that also names <c>parameters</c>
    /// is an <see cref="ArgumentException"/>.
    /// </summary>
    [TestMethod]
    public void HashRejectsNullParameters()
    {
        Memory<byte> inputs = RentCanonicalScalars(TwoInputCount, InputFillSalt);
        Memory<byte> digest = RentCanonicalScalars(DigestScalars, DigestFillSalt);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => PoseidonPermutation.Hash(null!, inputs.Span, digest.Span, Bn254Add, Bn254Multiply),
            "A null parameter set must be refused.");

        Assert.AreEqual(ParametersParameterName, exception.ParamName, "The refusal must name the parameters parameter.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.Hash"/> still hashes at the widest state the stack scratch holds,
    /// instead of refusing a width it can serve. The scratch is 544 bytes, which is exactly 17 lanes, and both
    /// scratch-bound guards compare the state length against that scratch, so 17 lanes is the single width at which an
    /// inclusive comparison refuses and the exclusive one admits; no narrower width the other tests use can tell the
    /// two apart. The digest is held to <see cref="R1csPoseidonWitness.AddPoseidonHashWitness"/>, which reruns the
    /// same schedule, MDS orientation and initial state in modular <see cref="BigInteger"/> arithmetic with neither a
    /// stack scratch nor a width bound, so the expected value is independent of the guards under test. The parameter
    /// set carries the smallest round shape the constructor accepts, which bounds the work to a few thousand field
    /// operations.
    /// </summary>
    [TestMethod]
    public void HashAtTheWidestScratchStateMatchesTheIndependentTrace()
    {
        const int WidestScratchInputCount = WidestScratchStateWidth - CapacityLanes;

        PoseidonParameters parameters = CreateMinimalParameters(WidestScratchStateWidth);
        Memory<byte> inputs = RentCanonicalScalars(WidestScratchInputCount, InputFillSalt);
        Memory<byte> digest = RentCanonicalScalars(DigestScalars, DigestFillSalt);

        PoseidonPermutation.Hash(parameters, inputs.Span, digest.Span, Bn254Add, Bn254Multiply);

        BigInteger[] traceInputs = new BigInteger[WidestScratchInputCount];
        for(int lane = 0; lane < WidestScratchInputCount; lane++)
        {
            traceInputs[lane] = ToFieldElement(inputs.Span.Slice(lane * ScalarSize, ScalarSize));
        }

        BigInteger expected = R1csPoseidonWitness.AddPoseidonHashWitness(
            new Dictionary<string, BigInteger>(StringComparer.Ordinal), TraceName, traceInputs, parameters);

        Assert.AreEqual(
            expected,
            ToFieldElement(digest.Span),
            "The digest at the widest state the scratch holds must equal the independent modular trace.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.GetMerkleHash"/> refuses a null parameter set with an
    /// <see cref="ArgumentNullException"/> that names <c>parameters</c>, instead of faulting with a
    /// <see cref="NullReferenceException"/> where the state width is read out of it. Both backends are non-null, so
    /// this is the first guard the call meets; the arity refusal also names <c>parameters</c> but is an
    /// <see cref="ArgumentException"/>, which the exact-type assertion separates from this one.
    /// </summary>
    [TestMethod]
    public void GetMerkleHashRejectsNullParameters()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => _ = PoseidonPermutation.GetMerkleHash(null!, Bn254Add, Bn254Multiply),
            "A null parameter set must be refused.");

        Assert.AreEqual(ParametersParameterName, exception.ParamName, "The refusal must name the parameters parameter.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.GetMerkleHash"/> refuses a null addition backend when the compression
    /// is requested, with an <see cref="ArgumentNullException"/> that names <c>add</c>, instead of handing back a
    /// compression that carries the missing backend and fails only at its first invocation. The parameter set is a
    /// constructed three-lane set, so the arity guard passes, and the multiplication backend is non-null. The returned
    /// compression is never invoked, so the permutation's own <c>add</c> guard cannot answer in its place.
    /// </summary>
    [TestMethod]
    public void GetMerkleHashRejectsANullAddition()
    {
        PoseidonParameters parameters = CreateMinimalParameters(TwoInputStateWidth);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => _ = PoseidonPermutation.GetMerkleHash(parameters, null!, Bn254Multiply),
            "A null addition backend must be refused when the compression is requested.");

        Assert.AreEqual(AddParameterName, exception.ParamName, "The refusal must name the add parameter.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonPermutation.GetMerkleHash"/> refuses a null multiplication backend when the
    /// compression is requested, with an <see cref="ArgumentNullException"/> that names <c>multiply</c>, instead of
    /// handing back a compression that carries the missing backend and fails only at its first invocation. The
    /// parameter set is a constructed three-lane set, so the arity guard passes, and the addition backend is non-null.
    /// The returned compression is never invoked, so the permutation's own <c>multiply</c> guard cannot answer in its
    /// place.
    /// </summary>
    [TestMethod]
    public void GetMerkleHashRejectsANullMultiplication()
    {
        PoseidonParameters parameters = CreateMinimalParameters(TwoInputStateWidth);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => _ = PoseidonPermutation.GetMerkleHash(parameters, Bn254Add, null!),
            "A null multiplication backend must be refused when the compression is requested.");

        Assert.AreEqual(MultiplyParameterName, exception.ParamName, "The refusal must name the multiply parameter.");
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
            Assert.Inconclusive($"Fixture file not found: {wtnsPath}. Restore the committed fixture bytes.");
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


    /// <summary>
    /// Rents <paramref name="scalarCount"/> scalars of pooled memory, tracks the rental for cleanup and fills it with
    /// deterministic canonical BN254 scalars. The buffer is sliced to exactly the requested width, because every guard
    /// under test compares lengths exactly, and it is returned as <see cref="Memory{T}"/> because the assertion lambdas
    /// capture it where they cannot capture a stack span.
    /// </summary>
    /// <param name="scalarCount">The buffer width in scalars.</param>
    /// <param name="salt">The fill stream selector.</param>
    /// <returns>The filled buffer, exactly <paramref name="scalarCount"/> scalars long.</returns>
    private Memory<byte> RentCanonicalScalars(int scalarCount, int salt)
    {
        int length = scalarCount * ScalarSize;
        System.Buffers.IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Disposables.Add(owner);

        Memory<byte> scalars = owner.Memory[..length];
        DeterministicScalarFill.FillCanonical(scalars.Span, salt, Bn254Reduce, CurveParameterSet.Bn254);

        return scalars;
    }


    /// <summary>
    /// Builds a BN254 parameter set of <paramref name="stateWidth"/> lanes through the public constructor, with the
    /// smallest round shape it accepts and deterministic canonical round constants and MDS entries. The constructor
    /// bounds the width only from below, so this reaches widths the generated circomlib sets never have. The values
    /// are not a vetted instantiation and carry no security claim; they are well-formed canonical field elements of
    /// the declared shape, which is all a width guard and a digest comparison against an independent trace need.
    /// </summary>
    /// <param name="stateWidth">The state width <c>t</c>; at least two.</param>
    /// <returns>The constructed parameter set.</returns>
    private PoseidonParameters CreateMinimalParameters(int stateWidth)
    {
        Memory<byte> roundConstants = RentCanonicalScalars((MinimalFullRounds + MinimalPartialRounds) * stateWidth, RoundConstantFillSalt);
        Memory<byte> mdsMatrix = RentCanonicalScalars(stateWidth * stateWidth, MdsFillSalt);

        return new PoseidonParameters(stateWidth, MinimalFullRounds, MinimalPartialRounds, roundConstants.Span, mdsMatrix.Span, CurveParameterSet.Bn254);
    }


    /// <summary>
    /// Reads a canonical big-endian scalar as the field element it encodes, which is the representation the modular
    /// trace states its values in. Every scalar the permutation emits is already reduced, so the reading is exact and
    /// needs no further reduction.
    /// </summary>
    /// <param name="canonicalBigEndian">The canonical scalar bytes.</param>
    /// <returns>The field element the bytes encode.</returns>
    private static BigInteger ToFieldElement(ReadOnlySpan<byte> canonicalBigEndian) =>
        new(canonicalBigEndian, isUnsigned: true, isBigEndian: true);
}
