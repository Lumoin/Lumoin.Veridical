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
/// Round-trip and tamper tests for the Hyrax weighted opening: a single-row
/// vector commitment proving <c>⟨vector, W⟩</c> against a public weight
/// vector through the inner-product argument — the Pedersen/IPA analogue of
/// BaseFold's weighted opening (SM.1), and the binding the statistical-mask
/// construction uses over the Hyrax path.
/// </summary>
[TestClass]
internal sealed class HyraxWeightedOpeningTests
{
    private const string TranscriptDomain = "veridical.test.hyrax.weighted.v1";

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
    public void WeightedOpenVerifyRoundtrip(int variableCount)
    {
        int vectorLength = 1 << variableCount;
        using HyraxCommitmentKey key = DeriveKey(vectorLength);

        using MultilinearExtension vector = BuildVector(variableCount, i => (i * 13) + 7);
        using MultilinearExtension weights = BuildVector(variableCount, i => (i * 5) + 3);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 1234);

        var (commitment, witness) = key.CommitVector(vector, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (proof, claimedValue) = commitment.OpenWeightedSum(
                witness, vector, weights, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(proof)
            using(claimedValue)
            {
                using Scalar expected = ComputeDirectInnerProduct(vector, weights);
                Assert.IsTrue(expected.AsReadOnlySpan().SequenceEqual(claimedValue.AsReadOnlySpan()),
                    $"The claimed value must equal the directly computed inner product for n = {variableCount}.");

                bool ok = commitment.VerifyWeightedSum(
                    weights, claimedValue, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

                Assert.IsTrue(ok, $"Weighted open / verify round-trip must succeed for n = {variableCount}.");
            }
        }
    }


    [TestMethod]
    public void VerifyWithWrongClaimedValueFails()
    {
        const int VariableCount = 3;
        int vectorLength = 1 << VariableCount;
        using HyraxCommitmentKey key = DeriveKey(vectorLength);

        using MultilinearExtension vector = BuildVector(VariableCount, i => (i * 13) + 7);
        using MultilinearExtension weights = BuildVector(VariableCount, i => (i * 5) + 3);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 2222);

        var (commitment, witness) = key.CommitVector(vector, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (proof, claimedValue) = commitment.OpenWeightedSum(
                witness, vector, weights, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(proof)
            using(claimedValue)
            {
                using Scalar one = MakeScalar(1);
                using Scalar wrong = claimedValue.Add(one, ScalarAdd, BaseMemoryPool.Shared);

                bool ok = commitment.VerifyWeightedSum(
                    weights, wrong, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, "Verify must reject when the claimed value differs from the actual weighted sum.");
            }
        }
    }


    [TestMethod]
    public void VerifyWithDifferentWeightsFails()
    {
        const int VariableCount = 3;
        int vectorLength = 1 << VariableCount;
        using HyraxCommitmentKey key = DeriveKey(vectorLength);

        using MultilinearExtension vector = BuildVector(VariableCount, i => (i * 13) + 7);
        using MultilinearExtension weightsAtOpen = BuildVector(VariableCount, i => (i * 5) + 3);
        using MultilinearExtension weightsAtVerify = BuildVector(VariableCount, i => (i * 5) + 4);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 3333);

        var (commitment, witness) = key.CommitVector(vector, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (proof, claimedValue) = commitment.OpenWeightedSum(
                witness, vector, weightsAtOpen, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(proof)
            using(claimedValue)
            {
                bool ok = commitment.VerifyWeightedSum(
                    weightsAtVerify, claimedValue, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, "Verify must reject when the weight vector at verify differs from the one at open.");
            }
        }
    }


    [TestMethod]
    [DataRow(0)]   //First byte of C_f.
    [DataRow(50)]  //Inside C_f bytes.
    [DataRow(100)] //Inside IPA round pairs.
    public void VerifyWithCorruptedProofFails(int byteOffset)
    {
        const int VariableCount = 4;
        int vectorLength = 1 << VariableCount;
        using HyraxCommitmentKey key = DeriveKey(vectorLength);

        using MultilinearExtension vector = BuildVector(VariableCount, i => (i * 13) + 7);
        using MultilinearExtension weights = BuildVector(VariableCount, i => (i * 5) + 3);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 4444);

        var (commitment, witness) = key.CommitVector(vector, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (proof, claimedValue) = commitment.OpenWeightedSum(
                witness, vector, weights, key, proverTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(proof)
            using(claimedValue)
            {
                proof.AsSpan()[byteOffset] ^= 0x01;

                bool ok = commitment.VerifyWeightedSum(
                    weights, claimedValue, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, $"Verify must reject after a bit-flip at byte offset {byteOffset} in the proof.");
            }
        }
    }


    [TestMethod]
    public void TwoOpeningsOfSameStatementDiffer()
    {
        const int VariableCount = 3;
        int vectorLength = 1 << VariableCount;
        using HyraxCommitmentKey key = DeriveKey(vectorLength);

        using MultilinearExtension vector = BuildVector(VariableCount, i => (i * 13) + 7);
        using MultilinearExtension weights = BuildVector(VariableCount, i => (i * 5) + 3);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 5555);

        var (commitment, witness) = key.CommitVector(vector, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using(commitment)
        using(witness)
        using(FiatShamirTranscript firstTx = NewTranscript())
        using(FiatShamirTranscript secondTx = NewTranscript())
        {
            var (firstProof, firstClaim) = commitment.OpenWeightedSum(
                witness, vector, weights, key, firstTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            using(firstProof)
            using(firstClaim)
            {
                var (secondProof, secondClaim) = commitment.OpenWeightedSum(
                    witness, vector, weights, key, secondTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
                    G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

                using(secondProof)
                using(secondClaim)
                {
                    Assert.IsFalse(firstProof.AsReadOnlySpan().SequenceEqual(secondProof.AsReadOnlySpan()),
                        "Two openings of the same statement must differ (the fresh C_f blind randomises the proof bytes).");
                }
            }
        }
    }


    [TestMethod]
    public void CommitVectorWithTooFewGeneratorsThrows()
    {
        const int VariableCount = 3;
        //One generator short of the vector's coordinate count.
        int generatorCount = (1 << VariableCount) - 1;
        using HyraxCommitmentKey key = DeriveKey(generatorCount);

        using MultilinearExtension vector = BuildVector(VariableCount, i => i + 1);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed: 6666);

        Assert.ThrowsExactly<ArgumentException>(() => key.CommitVector(vector, fixedRandom, G1Msm, BaseMemoryPool.Shared));
    }


    private static HyraxCommitmentKey DeriveKey(int vectorLength) =>
        HyraxCommitmentKey.Derive(vectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static Scalar ComputeDirectInnerProduct(MultilinearExtension vector, MultilinearExtension weights)
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> sum = stackalloc byte[scalarSize];
        Span<byte> term = stackalloc byte[scalarSize];
        sum.Clear();

        ReadOnlySpan<byte> vectorBytes = vector.AsReadOnlySpan();
        ReadOnlySpan<byte> weightBytes = weights.AsReadOnlySpan();
        for(int i = 0; i < vector.EvaluationCount; i++)
        {
            ScalarMul(vectorBytes.Slice(i * scalarSize, scalarSize), weightBytes.Slice(i * scalarSize, scalarSize), term, CurveParameterSet.Bls12Curve381);
            ScalarAdd(sum, term, sum, CurveParameterSet.Bls12Curve381);
        }

        return Scalar.FromCanonical(sum, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static MultilinearExtension BuildVector(int variableCount, Func<int, int> valueAt)
    {
        int evaluationCount = 1 << variableCount;
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(evaluationCount * elementSize);
        Span<byte> buffer = bufferOwner.Memory.Span[..(evaluationCount * elementSize)];
        for(int i = 0; i < evaluationCount; i++)
        {
            WriteCanonical(new BigInteger(valueAt(i)), buffer.Slice(i * elementSize, elementSize));
        }

        return MultilinearExtension.FromEvaluations(buffer, variableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static Scalar MakeScalar(int value)
    {
        Span<byte> span = stackalloc byte[Scalar.SizeBytes];
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
}
