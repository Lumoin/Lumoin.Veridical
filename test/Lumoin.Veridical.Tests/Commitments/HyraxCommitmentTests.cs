using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Tests for <see cref="HyraxCommitmentExtensions.CommitMultilinearExtension"/>:
/// commitment determinism under fixed randomness, divergence under
/// different MLEs, and basic shape invariants.
/// </summary>
[TestClass]
internal sealed class HyraxCommitmentTests
{
    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;


    [TestMethod]
    public void CommitmentShapeMatchesVariableCount()
    {
        const int VariableCount = 4;
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(4, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);
        using MultilinearExtension mle = BuildMle(VariableCount);

        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 17);

        var (commitment, witness) = key.CommitMultilinearExtension(mle, fixedRandom, G1Msm, BaseMemoryPool.Shared);
        using(commitment)
        using(witness)
        {
            Assert.AreEqual(4, commitment.RowCount, "n=4 → rows = 2^⌈n/2⌉ = 4");
            Assert.AreEqual(4, commitment.ColumnCount, "n=4 → cols = 2^⌊n/2⌋ = 4");
            Assert.AreEqual(VariableCount, commitment.VariableCount);
            Assert.AreEqual(commitment.RowCount, witness.RowCount);
        }
    }


    [TestMethod]
    public void CommitIsDeterministicGivenFixedRandomness()
    {
        const int VariableCount = 3;
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(4, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);
        using MultilinearExtension mle = BuildMle(VariableCount);

        ScalarRandomDelegate fixedRandom1 = MakeFixedRandom(seed: 42);
        ScalarRandomDelegate fixedRandom2 = MakeFixedRandom(seed: 42);

        var (commitmentA, witnessA) = key.CommitMultilinearExtension(mle, fixedRandom1, G1Msm, BaseMemoryPool.Shared);
        var (commitmentB, witnessB) = key.CommitMultilinearExtension(mle, fixedRandom2, G1Msm, BaseMemoryPool.Shared);

        using(commitmentA)
        using(commitmentB)
        using(witnessA)
        using(witnessB)
        {
            Assert.IsTrue(commitmentA.AsReadOnlySpan().SequenceEqual(commitmentB.AsReadOnlySpan()),
                "Two commits with the same MLE and same randomness sequence should produce identical row commitments.");
            Assert.IsTrue(witnessA.AsReadOnlySpan().SequenceEqual(witnessB.AsReadOnlySpan()),
                "Witness blindings should also be identical under the same randomness.");
        }
    }


    [TestMethod]
    public void DifferentMlesProduceDifferentCommitments()
    {
        const int VariableCount = 3;
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(4, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        using MultilinearExtension mleA = BuildMleWithValues(VariableCount, i => i + 1);
        using MultilinearExtension mleB = BuildMleWithValues(VariableCount, i => i + 100);

        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 7);
        ScalarRandomDelegate fixedRandomSameSequence = MakeFixedRandom(seed: 7);

        var (commitmentA, witnessA) = key.CommitMultilinearExtension(mleA, fixedRandom, G1Msm, BaseMemoryPool.Shared);
        var (commitmentB, witnessB) = key.CommitMultilinearExtension(mleB, fixedRandomSameSequence, G1Msm, BaseMemoryPool.Shared);

        using(commitmentA)
        using(commitmentB)
        using(witnessA)
        using(witnessB)
        {
            Assert.IsFalse(commitmentA.AsReadOnlySpan().SequenceEqual(commitmentB.AsReadOnlySpan()),
                "Different MLEs (even with identical blinding sequences) must produce different commitments.");
        }
    }


    [TestMethod]
    public void CommitRejectsForeignCurveMle()
    {
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(4, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        int elementSize = Scalar.SizeBytes;
        const int VariableCount = 2;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent((1 << VariableCount) * elementSize);
        owner.Memory.Span[..((1 << VariableCount) * elementSize)].Clear();
        Tag bn254Tag = Tag.Create(AlgebraicRole.MultilinearExtension)
            .With(CurveParameterSet.Bn254)
            .With(new MultilinearExtensionDimensions(VariableCount, 1 << VariableCount));
        using var foreignMle = new MultilinearExtension(owner, VariableCount, elementSize, CurveParameterSet.Bn254, bn254Tag);

        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 1);
        Assert.ThrowsExactly<ArgumentException>(() => key.CommitMultilinearExtension(foreignMle, fixedRandom, G1Msm, BaseMemoryPool.Shared));
    }


    private static MultilinearExtension BuildMle(int variableCount)
    {
        return BuildMleWithValues(variableCount, i => i + 1);
    }


    private static MultilinearExtension BuildMleWithValues(int variableCount, Func<int, int> valueAt)
    {
        int evalCount = 1 << variableCount;
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> bufOwner = BaseMemoryPool.Shared.Rent(evalCount * elementSize);
        Span<byte> buf = bufOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            WriteCanonical(new BigInteger(valueAt(i)), buf.Slice(i * elementSize, elementSize));
        }


        return MultilinearExtension.FromEvaluations(buf, variableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Returns a <see cref="ScalarRandomDelegate"/> backed by a fixed
    /// <c>ChaCha20</c>-shaped stream — the same seed produces the
    /// same sequence of "random" scalars, making tests reproducible.
    /// Implemented as SHA-256 of (seed counter) reduced into the field.
    /// </summary>
    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        Tag Sample(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            //Deterministic: SHA-256(seed_bytes || counter_bytes) → 32 bytes.
            //Reduce into the destination via the BigInteger scalar reduce
            //since the raw SHA-256 output may exceed r.
            Span<byte> hashInput = stackalloc byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[..4], seed);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[4..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[32];
            SHA256.HashData(hashInput, wide);
            ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
            reduce(wide, destination, curve);
            return inboundTag;
        }
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % r) + r) % r;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}