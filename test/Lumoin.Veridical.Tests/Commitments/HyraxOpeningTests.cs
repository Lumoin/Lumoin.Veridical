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
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// The load-bearing round-trip tests for Hyrax: commit, open, verify.
/// The round-trip must succeed for every meaningful variable count, and
/// verify must reject when the proof, point, or claimed value is
/// tampered with.
/// </summary>
[TestClass]
internal sealed class HyraxOpeningTests
{
    private const string TranscriptDomain = "veridical.test.hyrax.v1";

    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    private static ScalarAddDelegate ScalarAdd { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate ScalarSubtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate ScalarMul { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate ScalarInvert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static ScalarReduceDelegate ScalarReduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();


    [TestMethod]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    [DataRow(5)]
    public void OpenVerifyRoundtrip(int variableCount)
    {
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(variableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        using MultilinearExtension mle = BuildMle(variableCount);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 1234);

        var (commitment, witness) = key.CommitMultilinearExtension(mle, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        using(PointArray point = BuildPointArray(variableCount))
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (proof, claimedValue) = commitment.Open(
                witness, mle, point.AsSpan, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(proof)
            using(claimedValue)
            {
                bool ok = commitment.VerifyOpening(
                    point.AsSpan, claimedValue, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, BaseMemoryPool.Shared);

                Assert.IsTrue(ok, $"Open / Verify round-trip must succeed for n = {variableCount}.");
            }
        }
    }


    [TestMethod]
    public void VerifyWithWrongEvaluationFails()
    {
        const int VariableCount = 3;
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        using MultilinearExtension mle = BuildMle(VariableCount);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 2222);
        var (commitment, witness) = key.CommitMultilinearExtension(mle, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        using(PointArray point = BuildPointArray(VariableCount))
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (proof, claimedValue) = commitment.Open(
                witness, mle, point.AsSpan, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(proof)
            using(claimedValue)
            {
                //Wrong claimed value = claimed + 1.
                using Scalar one = MakeScalar(1);
                using Scalar wrong = claimedValue.Add(one, ScalarAdd, BaseMemoryPool.Shared);

                bool ok = commitment.VerifyOpening(
                    point.AsSpan, wrong, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, "Verify must reject when the claimed value differs from the actual evaluation.");
            }
        }
    }


    [TestMethod]
    public void VerifyWithSwappedEvaluationPointFails()
    {
        const int VariableCount = 3;
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        using MultilinearExtension mle = BuildMle(VariableCount);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 3333);
        var (commitment, witness) = key.CommitMultilinearExtension(mle, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        using(PointArray pointA = BuildPointArrayFromValues(VariableCount, i => i + 1))
        using(PointArray pointB = BuildPointArrayFromValues(VariableCount, i => i + 100))
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (proof, claimedValue) = commitment.Open(
                witness, mle, pointA.AsSpan, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(proof)
            using(claimedValue)
            {
                bool ok = commitment.VerifyOpening(
                    pointB.AsSpan, claimedValue, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, "Verify must reject when the evaluation point at verify differs from the point at open.");
            }
        }
    }


    [TestMethod]
    [DataRow(0)]   //First byte of C_f: a point slot, rejected by the subgroup screen before the algebraic check runs.
    [DataRow(50)]  //Inside the first IPA round's L point: a point slot, rejected by the subgroup screen before the algebraic check runs.
    [DataRow(100)] //Inside the first IPA round's R point: a point slot, rejected by the subgroup screen before the algebraic check runs.
    [DataRow(250)] //Inside the IPA's final scalar a': a scalar slot, so this still exercises the algebraic check.
    public void VerifyWithCorruptedProofFails(int byteOffset)
    {
        const int VariableCount = 4;
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        using MultilinearExtension mle = BuildMle(VariableCount);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 4444);
        var (commitment, witness) = key.CommitMultilinearExtension(mle, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        using(PointArray point = BuildPointArray(VariableCount))
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (proof, claimedValue) = commitment.Open(
                witness, mle, point.AsSpan, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(claimedValue)
            using(proof)
            {
                MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[byteOffset] ^= 0x01;

                bool ok = commitment.VerifyOpening(
                    point.AsSpan, claimedValue, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, $"Verify must reject after a bit-flip at byte offset {byteOffset} in the proof.");
            }
        }
    }


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static MultilinearExtension BuildMle(int variableCount)
    {
        int evalCount = 1 << variableCount;
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> bufOwner = BaseMemoryPool.Shared.Rent(evalCount * elementSize);
        Span<byte> buf = bufOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            WriteCanonical(new BigInteger((i * 13) + 7), buf.Slice(i * elementSize, elementSize));
        }


        return MultilinearExtension.FromEvaluations(buf, variableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static PointArray BuildPointArray(int variableCount) =>
        BuildPointArrayFromValues(variableCount, i => (i * 5) + 3);


    private static PointArray BuildPointArrayFromValues(int variableCount, Func<int, int> valueAt)
    {
        var scalars = new Scalar[variableCount];
        for(int i = 0; i < variableCount; i++)
        {
            scalars[i] = MakeScalar(valueAt(i));
        }


        return new PointArray(scalars);
    }


    private static Scalar MakeScalar(int value)
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        Span<byte> span = owner.Memory.Span[..Scalar.SizeBytes];
        WriteCanonical(new BigInteger(value), span);
        return Scalar.FromCanonical(span, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
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


    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        Tag Sample(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
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


    private readonly struct PointArray: IDisposable
    {
        private readonly Scalar[] scalars;

        public PointArray(Scalar[] scalars) { this.scalars = scalars; }

        public ReadOnlySpan<Scalar> AsSpan => scalars;

        public void Dispose()
        {
            if(scalars is null)
            {
                return;
            }

            foreach(Scalar s in scalars)
            {
                s?.Dispose();
            }
        }
    }
}