using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Tests for the BaseFold evaluation protocol: the multilinear PCS
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
    /// <summary>The BLS12-381 scalar field addition delegate, from the environment-aware bundle (SIMD when the host supports it, BigInteger otherwise) — byte-identical to the reference, so this exercises the SIMD path end-to-end through BaseFold without changing results.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar field subtraction delegate, from the same environment-aware bundle as <see cref="Add"/>.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar field multiplication delegate, from the same environment-aware bundle as <see cref="Add"/>.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar field inversion delegate, from the same environment-aware bundle as <see cref="Add"/>.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 scalar reduction delegate (wide bytes to a canonical scalar), from the BigInteger reference.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 hash-to-scalar delegate deriving the foldable code's basis, from the BigInteger reference.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The independent BigInteger-reference multilinear-extension evaluator, used to cross-check the prover's claimed value.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF (squeeze) backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The Merkle two-to-one compression this test's trees use, <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The compression paired with the node width it produces.</summary>
    private static MerkleCommitmentParameters TreeParameters { get; } = new(Merkle, ScalarSize);

    /// <summary>The width in bytes of one BLS12-381 scalar in its canonical representation.</summary>
    private const int ScalarSize = 32;

    /// <summary>The Merkle tree's node/digest width in bytes.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The IOPP query-repetition count these tests use: a modest count keeps the round-trip and tamper tests fast, since protocol correctness does not depend on the soundness-driven repetition count.</summary>
    private const int TestQueryCount = 12;

    /// <summary>The number of random samples <see cref="RandomHonestEvaluationsAlwaysVerify"/> draws.</summary>
    private const int IterationCount = 12;

    /// <summary>The curve every gate in this file runs over: BLS12-381.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies, for variable counts one through five, that the prover's claimed value equals an independent MLE evaluation at the same point, and that the honest evaluation proof verifies.</summary>
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
                code, mle, point, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

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


    /// <summary>Verifies, over randomly generated variable counts, evaluation tables and points, that an honest evaluation proof always verifies.</summary>
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
                        code, mle, point, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

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


    /// <summary>Verifies that perturbing the honestly proved claimed value by one, before verification, is rejected.</summary>
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
                code, mle, point, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

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


    /// <summary>Verifies that flipping one byte of the first proof-carried fold-layer root is rejected.</summary>
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
                code, mle, point, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

            using(proof)
            using(claimedValue)
            {
                MemoryMarshal.AsMemory(proof.FoldRoots[0].AsReadOnlyMemory()).Span[0] ^= 0x01;

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


    /// <summary>Verifies that verifying a proof against a different evaluation point than the one the prover opened at is rejected.</summary>
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
                code, mle, point, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

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


    /// <summary>Computes the public commitment the verifier needs: the Merkle root of <c>Enc_d(coeffs)</c>, where <c>coeffs</c> is the interpolation of the MLE. Mirrors what the commit operation produces.</summary>
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

        using MerkleTree tree = MerkleTree.Build(codeword, codewordElements, new MerkleCommitmentParameters(Merkle, ScalarSize), pool);
        return MerkleRoot.FromBytes(tree.Root.AsReadOnlySpan(), pool);
    }


    /// <summary>Builds a deterministic pseudo-random multilinear extension of <paramref name="variableCount"/> variables, varied by <paramref name="salt"/> so distinct call sites get distinct evaluation tables.</summary>
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


    /// <summary>Builds a multilinear extension of <paramref name="variableCount"/> variables by reducing each generated evaluation-table slice of <paramref name="evalBytes"/> to a canonical scalar.</summary>
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


    /// <summary>Builds a deterministic pseudo-random evaluation point of <paramref name="variableCount"/> scalars, varied by <paramref name="salt"/> so distinct call sites get distinct points.</summary>
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


    /// <summary>Builds an evaluation point of <paramref name="variableCount"/> scalars by reducing each generated slice of <paramref name="pointBytes"/> to a canonical scalar.</summary>
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


    /// <summary>Adds the field one to <paramref name="value"/>, returning a fresh <see cref="Scalar"/> distinct from any correct claimed value derived from a well-formed evaluation.</summary>
    private static Scalar AddOne(Scalar value, BaseMemoryPool pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    /// <summary>Disposes every coordinate scalar of a point built by <see cref="BuildPoint"/> or <see cref="PointFromBytes"/>.</summary>
    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    /// <summary>Creates a fresh transcript under this file's fixed domain label, seeded with no extra context bytes.</summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the two-to-one BLAKE3 compression of <paramref name="left"/> concatenated with <paramref name="right"/> into <paramref name="output"/>, this file's Merkle node hash.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The fixed domain-separation seed the foldable code is derived from in every gate.</summary>
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.Eval.Test"u8;
}
