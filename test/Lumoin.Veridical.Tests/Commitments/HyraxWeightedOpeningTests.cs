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
/// Round-trip and tamper tests for the Hyrax weighted opening: a single-row
/// vector commitment proving <c>⟨vector, W⟩</c> against a public weight
/// vector through the inner-product argument — the Pedersen/IPA analogue of
/// BaseFold's weighted opening, and the binding the statistical-mask
/// construction uses over the Hyrax path.
/// </summary>
[TestClass]
internal sealed class HyraxWeightedOpeningTests
{
    /// <summary>The Fiat-Shamir domain label every transcript in this file is initialised with.</summary>
    private const string TranscriptDomain = "veridical.test.hyrax.weighted.v1";

    /// <summary>The BLS12-381 G1 hash-to-curve delegate used to derive the Hyrax commitment key's generators.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The BLS12-381 G1 addition delegate the Hyrax commitment and IPA use.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BLS12-381 G1 scalar-multiplication delegate the Hyrax commitment and IPA use.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BLS12-381 G1 multi-scalar-multiplication delegate the Hyrax commitment and IPA use.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The BLS12-381 G1 on-curve validation delegate the verifier uses to screen proof points.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>The BLS12-381 G1 prime-order-subgroup validation delegate the verifier uses to screen proof points.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    /// <summary>The BLS12-381 scalar addition delegate the weighted opening computes over.</summary>
    private static ScalarAddDelegate ScalarAdd { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar subtraction delegate the weighted opening computes over.</summary>
    private static ScalarSubtractDelegate ScalarSubtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar multiplication delegate the weighted opening computes over.</summary>
    private static ScalarMultiplyDelegate ScalarMul { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar inversion delegate the weighted opening computes over.</summary>
    private static ScalarInvertDelegate ScalarInvert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The delegate that reduces a wide byte buffer to a canonical BLS12-381 scalar.</summary>
    private static ScalarReduceDelegate ScalarReduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The Fiat-Shamir hash delegate every transcript in this file uses.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The Fiat-Shamir squeeze delegate every transcript in this file uses.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();


    /// <summary>
    /// Verifies that an honest Hyrax weighted-opening proof's claimed value equals the directly
    /// computed inner product of the vector and weights, and that the proof verifies, across
    /// several variable counts.
    /// </summary>
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
                    G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, BaseMemoryPool.Shared);

                Assert.IsTrue(ok, $"Weighted open / verify round-trip must succeed for n = {variableCount}.");
            }
        }
    }


    /// <summary>Verifies that verification rejects a genuine proof when paired with a claimed value one off from the true weighted sum.</summary>
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
                    G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, "Verify must reject when the claimed value differs from the actual weighted sum.");
            }
        }
    }


    /// <summary>Verifies that verification rejects a genuine proof when the verifier's weight vector differs from the one the prover opened against.</summary>
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
                    G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, "Verify must reject when the weight vector at verify differs from the one at open.");
            }
        }
    }


    /// <summary>
    /// Verifies that flipping one bit anywhere in a genuine proof's bytes makes verification fail,
    /// whether the flipped byte lands in a point slot (C_f, or an IPA round's L/R point, caught by
    /// the subgroup screen) or a scalar slot (the IPA's final a', caught by the algebraic check).
    /// Offset 0 is the first byte of C_f, 50 lies inside the first IPA round's L point, and 100
    /// lies inside its R point — all three are point slots rejected by the subgroup screen before
    /// the algebraic check runs; offset 440 lies inside the IPA's final scalar a', a scalar slot,
    /// so it exercises the algebraic check instead.
    /// </summary>
    [TestMethod]
    [DataRow(0)]
    [DataRow(50)]
    [DataRow(100)]
    [DataRow(440)]
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
                MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[byteOffset] ^= 0x01;

                bool ok = commitment.VerifyWeightedSum(
                    weights, claimedValue, proof, key, verifierTx,
                    Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
                    G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, BaseMemoryPool.Shared);

                Assert.IsFalse(ok, $"Verify must reject after a bit-flip at byte offset {byteOffset} in the proof.");
            }
        }
    }


    /// <summary>Verifies that two independent openings of the same commitment, vector and weights produce different proof bytes, since each draws a fresh C_f blind.</summary>
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


    /// <summary>Verifies that committing a vector throws when the key was derived with fewer generators than the vector's coordinate count.</summary>
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


    /// <summary>Derives a Hyrax commitment key with the given number of generators from the library's canonical seed.</summary>
    private static HyraxCommitmentKey DeriveKey(int vectorLength) =>
        HyraxCommitmentKey.Derive(vectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);


    /// <summary>Builds a fresh Fiat-Shamir transcript scoped to this file's fixed domain, with an empty initial absorb.</summary>
    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    /// <summary>Computes ⟨vector, weights⟩ directly over the scalar field, as the reference the claimed opening value is checked against.</summary>
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


    /// <summary>Builds a multilinear extension of the given variable count whose evaluations are the given function applied to each index.</summary>
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


    /// <summary>Builds a canonical scalar from a small integer value.</summary>
    private static Scalar MakeScalar(int value)
    {
        Span<byte> span = stackalloc byte[Scalar.SizeBytes];
        WriteCanonical(new BigInteger(value), span);

        return Scalar.FromCanonical(span, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>Reduces a possibly negative or oversized integer modulo the scalar field order and writes it as a canonical big-endian scalar.</summary>
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


    /// <summary>
    /// Builds a deterministic scalar randomness delegate: each call hashes the seed with an
    /// incrementing counter and reduces the digest to a scalar, so a fixed seed always replays the
    /// same sequence.
    /// </summary>
    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        //Produces the next scalar in this seed's deterministic sequence from SHA-256(seed, counter).
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
