using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// SM.1 — the weighted-opening BaseFold primitive
/// (<see cref="BaseFoldEvaluationProver.ProveWeightedSum"/> /
/// <see cref="BaseFoldEvaluationVerifier.VerifyWeightedSum"/>): the evaluation
/// protocol with the <c>eq_z</c> multiplier generalised to an arbitrary public
/// multiplier multilinear <c>W</c>, proving <c>Σ_b f(b)·W(b) = v</c>. An
/// evaluation opening is the special case <c>W = eq_z</c>, pinned here by a
/// byte-identity test so the generalisation provably did not move the existing
/// wire format. This is the binding primitive the statistical-mask construction
/// (<c>ZK-STATMASK-DESIGN.md</c> levels 2 and 3) opens its mask
/// coefficients with. Real BLS12-381 arithmetic and production BLAKE3.
/// </summary>
[TestClass]
internal sealed class BaseFoldWeightedSumTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static readonly ScalarRandomDelegate Random = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //A modest query count keeps the round-trip and tamper tests fast; protocol
    //correctness does not depend on the soundness-driven repetition count.
    private const int TestQueryCount = 12;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void HonestWeightedOpeningVerifiesAndClaimedValueMatchesDirectSum(int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        using MultilinearExtension mle = BuildRandomMle(variableCount, salt: 1, pool);
        using MultilinearExtension multiplier = BuildRandomMle(variableCount, salt: 2, pool);

        using FiatShamirTranscript proverTx = NewTranscript();
        (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveWeightedSum(
            code, mle, multiplier, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        using(proof)
        using(claimedValue)
        {
            //The claimed value must equal the directly computed Σ_b f(b)·W(b).
            using Scalar expected = DirectWeightedSum(mle, multiplier, pool);
            Assert.IsTrue(
                claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                $"Claimed value must equal Σ f·W for n = {variableCount}.");

            using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
            using FiatShamirTranscript verifierTx = NewTranscript();
            bool verified = BaseFoldEvaluationVerifier.VerifyWeightedSum(
                code, commitment, multiplier, claimedValue, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

            Assert.IsTrue(verified, $"An honest weighted opening must verify for n = {variableCount}.");
        }
    }


    [TestMethod]
    public void EqMultiplierWeightedOpeningIsByteIdenticalToEvaluationOpening()
    {
        //The generalisation gate: with W = eq_z the weighted opening must produce
        //the same claimed value and byte-identical proof and transcript as the
        //evaluation opening — proving the eq path did not move.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(VariableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, salt: 3, pool);
        Scalar[] point = BuildPoint(VariableCount, salt: 11, pool);

        try
        {
            using FiatShamirTranscript evaluationTx = NewTranscript();
            (BaseFoldEvaluationProof evaluationProof, Scalar evaluationValue) = BaseFoldEvaluationProver.Prove(
                code, mle, point, TestQueryCount, evaluationTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

            using MultilinearExtension eqMultiplier = SumcheckRoundComputation.BuildEqEvaluations(point, Subtract, Multiply, Curve, pool);
            using FiatShamirTranscript weightedTx = NewTranscript();
            (BaseFoldEvaluationProof weightedProof, Scalar weightedValue) = BaseFoldEvaluationProver.ProveWeightedSum(
                code, mle, eqMultiplier, TestQueryCount, weightedTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

            using(evaluationProof)
            using(evaluationValue)
            using(weightedProof)
            using(weightedValue)
            {
                Assert.IsTrue(
                    weightedValue.AsReadOnlySpan().SequenceEqual(evaluationValue.AsReadOnlySpan()),
                    "With W = eq_z the weighted claimed value must equal the evaluation's f(z).");

                (IMemoryOwner<byte> evaluationBytesOwner, int evaluationLength) = BaseFoldEvaluationProofSerialization.ToBytes(
                    evaluationProof, DigestSizeBytes, BaseFoldOpeningMode.Plain, pool);
                (IMemoryOwner<byte> weightedBytesOwner, int weightedLength) = BaseFoldEvaluationProofSerialization.ToBytes(
                    weightedProof, DigestSizeBytes, BaseFoldOpeningMode.Plain, pool);

                using(evaluationBytesOwner)
                using(weightedBytesOwner)
                {
                    Assert.AreEqual(evaluationLength, weightedLength, "The two openings must have identical lengths.");
                    Assert.IsTrue(
                        evaluationBytesOwner.Memory.Span[..evaluationLength].SequenceEqual(weightedBytesOwner.Memory.Span[..weightedLength]),
                        "With W = eq_z the weighted opening must be byte-identical to the evaluation opening.");
                }

                //Cross-acceptance: each verifier accepts the other entry's proof.
                using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
                using FiatShamirTranscript crossTx = NewTranscript();
                Assert.IsTrue(
                    BaseFoldEvaluationVerifier.VerifyWeightedSum(
                        code, commitment, eqMultiplier, evaluationValue, evaluationProof, TestQueryCount, crossTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool),
                    "VerifyWeightedSum with W = eq_z must accept the evaluation opening.");
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void HidingWeightedOpeningRoundTrips()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(VariableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);
        int codewordElements = parameters.CodewordLength;

        using MultilinearExtension mle = BuildRandomMle(VariableCount, salt: 4, pool);
        using MultilinearExtension multiplier = BuildRandomMle(VariableCount, salt: 5, pool);

        //Salted commitment: fresh top-layer salts fix the public root, replayed
        //into the hiding open exactly as the ZK provider's blind does.
        using IMemoryOwner<byte> saltsOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> salts = saltsOwner.Memory.Span[..(codewordElements * ScalarSize)];
        for(int i = 0; i < codewordElements; i++)
        {
            _ = Random(salts.Slice(i * ScalarSize, ScalarSize), Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        using MerkleRoot commitment = ComputeSaltedCommitment(code, mle, salts, pool);

        using FiatShamirTranscript proverTx = NewTranscript();
        (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveWeightedSumHiding(
            code, mle, multiplier, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, salts, Random, pool);

        using(proof)
        using(claimedValue)
        {
            using Scalar expected = DirectWeightedSum(mle, multiplier, pool);
            Assert.IsTrue(
                claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                "The hiding weighted opening must still prove the true Σ f·W.");

            using FiatShamirTranscript verifierTx = NewTranscript();
            Assert.IsTrue(
                BaseFoldEvaluationVerifier.VerifyWeightedSum(
                    code, commitment, multiplier, claimedValue, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool),
                "An honest hiding weighted opening must verify against the salted commitment.");
        }
    }


    [TestMethod]
    public void WrongClaimedValueIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(VariableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, salt: 6, pool);
        using MultilinearExtension multiplier = BuildRandomMle(VariableCount, salt: 7, pool);

        using FiatShamirTranscript proverTx = NewTranscript();
        (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveWeightedSum(
            code, mle, multiplier, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        using(proof)
        using(claimedValue)
        {
            using Scalar wrongValue = AddOne(claimedValue, pool);
            using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
            using FiatShamirTranscript verifierTx = NewTranscript();
            Assert.IsFalse(
                BaseFoldEvaluationVerifier.VerifyWeightedSum(
                    code, commitment, multiplier, wrongValue, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool),
                "A wrong claimed weighted sum must be rejected.");
        }
    }


    [TestMethod]
    public void DifferentMultiplierIsRejected()
    {
        //The multiplier is part of the statement: verifying the same proof and
        //claim against a different public W must fail the terminal tie.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(VariableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, salt: 8, pool);
        using MultilinearExtension multiplier = BuildRandomMle(VariableCount, salt: 9, pool);
        using MultilinearExtension otherMultiplier = BuildRandomMle(VariableCount, salt: 10, pool);

        using FiatShamirTranscript proverTx = NewTranscript();
        (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveWeightedSum(
            code, mle, multiplier, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        using(proof)
        using(claimedValue)
        {
            using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
            using FiatShamirTranscript verifierTx = NewTranscript();
            Assert.IsFalse(
                BaseFoldEvaluationVerifier.VerifyWeightedSum(
                    code, commitment, otherMultiplier, claimedValue, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool),
                "Verifying against a different multiplier must be rejected.");
        }
    }


    [TestMethod]
    public void TamperedFoldRootIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(VariableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, salt: 12, pool);
        using MultilinearExtension multiplier = BuildRandomMle(VariableCount, salt: 13, pool);

        using FiatShamirTranscript proverTx = NewTranscript();
        (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveWeightedSum(
            code, mle, multiplier, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

        using(proof)
        using(claimedValue)
        {
            //Round-trip through serialization with a flipped byte in the first
            //fold root: the rebuilt proof must be rejected.
            (IMemoryOwner<byte> bytesOwner, int length) = BaseFoldEvaluationProofSerialization.ToBytes(
                proof, DigestSizeBytes, BaseFoldOpeningMode.Plain, pool);
            using(bytesOwner)
            {
                Span<byte> bytes = bytesOwner.Memory.Span[..length];

                //The fold roots sit right after the d round polynomials.
                int foldRootOffset = VariableCount * 2 * ScalarSize;
                bytes[foldRootOffset] ^= 0x01;

                using BaseFoldEvaluationProof tampered = BaseFoldEvaluationProofSerialization.FromBytes(
                    bytes, parameters, TestQueryCount, DigestSizeBytes, BaseFoldOpeningMode.Plain, pool);

                using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
                using FiatShamirTranscript verifierTx = NewTranscript();
                Assert.IsFalse(
                    BaseFoldEvaluationVerifier.VerifyWeightedSum(
                        code, commitment, multiplier, claimedValue, tampered, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool),
                    "A tampered fold root must be rejected.");
            }
        }
    }


    //Σ_b f(b)·W(b) computed directly over the dense tables.
    private static Scalar DirectWeightedSum(MultilinearExtension mle, MultilinearExtension multiplier, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> f = mle.AsReadOnlySpan();
        ReadOnlySpan<byte> w = multiplier.AsReadOnlySpan();
        int count = mle.EvaluationCount;

        IMemoryOwner<byte> sumOwner = pool.Rent(ScalarSize);
        Span<byte> sum = sumOwner.Memory.Span[..ScalarSize];
        sum.Clear();

        Span<byte> product = stackalloc byte[ScalarSize];
        for(int i = 0; i < count; i++)
        {
            Multiply(f.Slice(i * ScalarSize, ScalarSize), w.Slice(i * ScalarSize, ScalarSize), product, Curve);
            Add(sum, product, sum, Curve);
        }

        return new Scalar(sumOwner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    private static MerkleRoot ComputeCommitment(FoldableCode code, MultilinearExtension mle, BaseMemoryPool pool)
    {
        FoldableCodeParameters parameters = code.Parameters;
        int messageElements = parameters.MessageLength;
        int codewordElements = parameters.CodewordLength;

        using IMemoryOwner<byte> coeffsOwner = pool.Rent(messageElements * ScalarSize);
        Span<byte> coeffs = coeffsOwner.Memory.Span[..(messageElements * ScalarSize)];
        mle.InterpolateToCoefficients(coeffs, Subtract);

        using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        code.Encode(coeffs, codeword, Add, Subtract, Multiply, pool);

        using MerkleTree tree = MerkleTree.Build(codeword, codewordElements, Merkle, pool);

        return MerkleRoot.FromBytes(tree.Root.AsReadOnlySpan(), pool);
    }


    private static MerkleRoot ComputeSaltedCommitment(FoldableCode code, MultilinearExtension mle, ReadOnlySpan<byte> salts, BaseMemoryPool pool)
    {
        FoldableCodeParameters parameters = code.Parameters;
        int messageElements = parameters.MessageLength;
        int codewordElements = parameters.CodewordLength;

        using IMemoryOwner<byte> coeffsOwner = pool.Rent(messageElements * ScalarSize);
        Span<byte> coeffs = coeffsOwner.Memory.Span[..(messageElements * ScalarSize)];
        mle.InterpolateToCoefficients(coeffs, Subtract);

        using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        code.Encode(coeffs, codeword, Add, Subtract, Multiply, pool);

        using MerkleTree tree = MerkleTree.BuildSalted(codeword, salts, codewordElements, Merkle, pool);

        return MerkleRoot.FromBytes(tree.Root.AsReadOnlySpan(), pool);
    }


    private static MultilinearExtension BuildRandomMle(int variableCount, int salt, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evals = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < evaluationCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 131) + (i * 17) + 1);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 13) + (i * 29) + 3);
            Reduce(wide, evals.Slice(i * ScalarSize, ScalarSize), Curve);
        }

        return MultilinearExtension.FromEvaluations(evals, variableCount, Curve, pool);
    }


    private static Scalar[] BuildPoint(int variableCount, int salt, BaseMemoryPool pool)
    {
        var point = new Scalar[variableCount];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < variableCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 53) + (i * 19) + 2);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 23) + (i * 41) + 5);
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            Reduce(wide, owner.Memory.Span[..ScalarSize], Curve);
            point[i] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        return point;
    }


    private static Scalar AddOne(Scalar value, BaseMemoryPool pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
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


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.WeightedSum.Test"u8;
}
