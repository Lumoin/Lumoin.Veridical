using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Tests for the BaseFold evaluation protocol (AB.4): the multilinear PCS
/// open/verify that interleaves a sumcheck for <c>Σ_b f(b)·eq_z(b) = y</c> with
/// the BaseFold IOPP. The round-trip tests confirm an honest opening verifies
/// and that the prover's claimed value equals an independent MLE evaluation —
/// the end-to-end tie that pins the interpolation ordering, the high-bit-first
/// sumcheck, and the codeword fold against one another. Negative tests confirm a
/// wrong claimed value, a tampered fold root, and a wrong evaluation point are
/// rejected. Real BLS12-381 arithmetic and production BLAKE3 throughout.
/// </summary>
[TestClass]
internal sealed class BaseFoldEvaluationTests
{
    //Scalar field ops come from the environment-aware bundle (SIMD when the host
    //supports it, BigInteger otherwise) — byte-identical to the reference, so this
    //exercises the SIMD path end-to-end through BaseFold without changing results.
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static readonly MleEvaluateDelegate MleEvaluate = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //A modest query count keeps the round-trip and tamper tests fast; protocol
    //correctness does not depend on the soundness-driven repetition count.
    private const int TestQueryCount = 12;
    private const int IterationCount = 12;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    [DataRow(5)]
    public void HonestEvaluationVerifiesAndClaimedValueMatches(int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        using MultilinearExtension mle = BuildRandomMle(variableCount, 1, pool);
        Scalar[] point = BuildPoint(variableCount, 7, pool);

        try
        {
            using FiatShamirTranscript proverTx = NewTranscript();
            (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.Prove(
                code, mle, point, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

            using(proof)
            using(claimedValue)
            {
                //The claimed value must equal an independent MLE evaluation.
                using Scalar expected = mle.Evaluate(point, MleEvaluate, pool);
                Assert.IsTrue(
                    claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                    $"Claimed value must equal f(z) for n = {variableCount}.");

                using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
                using FiatShamirTranscript verifierTx = NewTranscript();
                bool verified = BaseFoldEvaluationVerifier.Verify(
                    code, commitment, point, claimedValue, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

                Assert.IsTrue(verified, $"An honest evaluation opening must verify for n = {variableCount}.");
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void RandomHonestEvaluationsAlwaysVerify()
    {
        Gen.Int[1, 5]
            .SelectMany(variableCount =>
                Gen.Select(
                    Gen.Const(variableCount),
                    Gen.Byte.Array[(1 << variableCount) * ScalarSize],
                    Gen.Byte.Array[variableCount * ScalarSize]))
            .Sample((variableCount, evalBytes, pointBytes) =>
            {
                BaseMemoryPool pool = BaseMemoryPool.Shared;
                FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, Curve);
                using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

                using MultilinearExtension mle = MleFromBytes(evalBytes, variableCount, pool);
                Scalar[] point = PointFromBytes(pointBytes, variableCount, pool);

                try
                {
                    using FiatShamirTranscript proverTx = NewTranscript();
                    (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.Prove(
                        code, mle, point, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

                    using(proof)
                    using(claimedValue)
                    {
                        using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
                        using FiatShamirTranscript verifierTx = NewTranscript();
                        return BaseFoldEvaluationVerifier.Verify(
                            code, commitment, point, claimedValue, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);
                    }
                }
                finally
                {
                    DisposePoint(point);
                }
            }, iter: IterationCount);
    }


    [TestMethod]
    public void WrongClaimedValueIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(VariableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 2, pool);
        Scalar[] point = BuildPoint(VariableCount, 9, pool);

        try
        {
            using FiatShamirTranscript proverTx = NewTranscript();
            (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.Prove(
                code, mle, point, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

            using(proof)
            using(claimedValue)
            {
                //Perturb the claimed value by adding one.
                using Scalar wrongValue = AddOne(claimedValue, pool);

                using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
                using FiatShamirTranscript verifierTx = NewTranscript();
                bool verified = BaseFoldEvaluationVerifier.Verify(
                    code, commitment, point, wrongValue, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

                Assert.IsFalse(verified, "A wrong claimed value must be rejected.");
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void TamperedFoldRootIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(VariableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 3, pool);
        Scalar[] point = BuildPoint(VariableCount, 11, pool);

        try
        {
            using FiatShamirTranscript proverTx = NewTranscript();
            (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.Prove(
                code, mle, point, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

            using(proof)
            using(claimedValue)
            {
                proof.FoldRoots[0].AsSpan()[0] ^= 0x01;

                using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
                using FiatShamirTranscript verifierTx = NewTranscript();
                bool verified = BaseFoldEvaluationVerifier.Verify(
                    code, commitment, point, claimedValue, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

                Assert.IsFalse(verified, "A tampered fold-layer root must break verification.");
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void WrongEvaluationPointIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(VariableCount, Curve);
        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 4, pool);
        Scalar[] point = BuildPoint(VariableCount, 13, pool);
        Scalar[] otherPoint = BuildPoint(VariableCount, 14, pool);

        try
        {
            using FiatShamirTranscript proverTx = NewTranscript();
            (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.Prove(
                code, mle, point, TestQueryCount, proverTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

            using(proof)
            using(claimedValue)
            {
                using MerkleRoot commitment = ComputeCommitment(code, mle, pool);
                using FiatShamirTranscript verifierTx = NewTranscript();
                bool verified = BaseFoldEvaluationVerifier.Verify(
                    code, commitment, otherPoint, claimedValue, proof, TestQueryCount, verifierTx, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

                Assert.IsFalse(verified, "Verifying at a different point than the prover opened must be rejected.");
            }
        }
        finally
        {
            DisposePoint(point);
            DisposePoint(otherPoint);
        }
    }


    //Computes the public commitment the verifier needs: the Merkle root of
    //Enc_d(coeffs), where coeffs is the interpolation of the MLE. Mirrors what
    //the commit operation produces.
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
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 7) + (i * 29) + 3);
            Reduce(wide, evals.Slice(i * ScalarSize, ScalarSize), Curve);
        }

        return MultilinearExtension.FromEvaluations(evals, variableCount, Curve, pool);
    }


    private static MultilinearExtension MleFromBytes(byte[] evalBytes, int variableCount, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evals = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        for(int i = 0; i < evaluationCount; i++)
        {
            Reduce(evalBytes.AsSpan(i * ScalarSize, ScalarSize), evals.Slice(i * ScalarSize, ScalarSize), Curve);
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


    private static Scalar[] PointFromBytes(byte[] pointBytes, int variableCount, BaseMemoryPool pool)
    {
        var point = new Scalar[variableCount];
        for(int i = 0; i < variableCount; i++)
        {
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            Reduce(pointBytes.AsSpan(i * ScalarSize, ScalarSize), owner.Memory.Span[..ScalarSize], Curve);
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


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.AB4.Eval.Test"u8;
}
