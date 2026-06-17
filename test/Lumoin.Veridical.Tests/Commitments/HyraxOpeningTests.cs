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
/// The load-bearing round-trip tests for Hyrax: commit, open, verify.
/// The round-trip must succeed for every meaningful variable count, and
/// verify must reject when the proof, point, or claimed value is
/// tampered with.
/// </summary>
[TestClass]
internal sealed class HyraxOpeningTests
{
    private const string TranscriptDomain = "veridical.test.hyrax.v1";

    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1AddDelegate G1Add = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static readonly G1ScalarMultiplyDelegate G1ScalarMul = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;
    private static readonly ScalarAddDelegate ScalarAdd = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate ScalarSubtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate ScalarMul = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate ScalarInvert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate ScalarReduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();


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
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

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
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

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
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, "Verify must reject when the evaluation point at verify differs from the point at open.");
            }
        }
    }


    [TestMethod]
    [DataRow(0)]   //First byte of C_f
    [DataRow(50)]  //Inside C_f bytes
    [DataRow(100)] //Inside IPA round pairs
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
                proof.AsSpan()[byteOffset] ^= 0x01;

                bool ok = commitment.VerifyOpening(
                    point.AsSpan, claimedValue, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

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