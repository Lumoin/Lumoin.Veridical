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
/// The weighted-opening BaseFold primitive
/// (<see cref="BaseFoldEvaluationProver.ProveWeightedSum"/> /
/// <see cref="BaseFoldEvaluationVerifier.VerifyWeightedSum"/>): the evaluation
/// protocol with the <c>eq_z</c> multiplier generalised to an arbitrary public
/// multiplier multilinear <c>W</c>, proving <c>Σ_b f(b)·W(b) = v</c>. An
/// evaluation opening is the special case <c>W = eq_z</c>, pinned here by a
/// byte-identity test so the generalisation provably did not move the existing
/// wire format. This is the binding primitive the statistical-mask construction
/// opens its mask coefficients with, at both the quadratic degree BaseFold's
/// <c>f·eq_z</c> sumcheck uses and the cubic degree the Spartan outer sumcheck
/// uses. Real BLS12-381 arithmetic and production BLAKE3.
/// </summary>
[TestClass]
internal sealed class BaseFoldWeightedSumTests
{
    /// <summary>The BLS12-381 scalar field addition delegate, from the reference backend.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar field subtraction delegate, from the reference backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar field multiplication delegate, from the reference backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar field inversion delegate, from the reference backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 scalar reduction delegate (wide bytes to a canonical scalar), from the BigInteger reference.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 hash-to-scalar delegate deriving the foldable code's basis, from the BigInteger reference.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The BLS12-381 scalar sampler the hiding opening's fresh salts are drawn from, from the BigInteger reference.</summary>
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();

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

    /// <summary>The curve every gate in this file runs over: BLS12-381.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies, for variable counts one through four, that the weighted opening's claimed value equals the directly computed <c>Σ_b f(b)·W(b)</c>, and that the honest weighted opening verifies.</summary>
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
            code, mle, multiplier, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

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


    /// <summary>Verifies that opening with the multiplier <c>W = eq_z</c> produces the same claimed value and a byte-identical serialized proof as the plain evaluation opening at the same point, and that each verifier accepts the other's proof.</summary>
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
                code, mle, point, TestQueryCount, evaluationTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

            using MultilinearExtension eqMultiplier = SumcheckRoundComputation.BuildEqEvaluations(point, Subtract, Multiply, Curve, pool);
            using FiatShamirTranscript weightedTx = NewTranscript();
            (BaseFoldEvaluationProof weightedProof, Scalar weightedValue) = BaseFoldEvaluationProver.ProveWeightedSum(
                code, mle, eqMultiplier, TestQueryCount, weightedTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

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


    /// <summary>Verifies that a hiding (salted-Merkle) weighted opening still proves the true <c>Σ f·W</c> and verifies against the salted commitment built from the same top-layer salts.</summary>
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
            code, mle, multiplier, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, salts, Random, pool);

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


    /// <summary>Verifies that perturbing the honestly proved weighted-sum claim by one, before verification, is rejected.</summary>
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
            code, mle, multiplier, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

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


    /// <summary>Verifies that verifying a weighted proof and its correct claim against a different public multiplier than the one it was opened with is rejected.</summary>
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
            code, mle, multiplier, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

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


    /// <summary>Verifies that flipping one byte of the first fold-layer root, after round-tripping the weighted proof through serialization, is rejected.</summary>
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
            code, mle, multiplier, TestQueryCount, proverTx, TreeParameters, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);

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


    /// <summary>Computes <c>Σ_b f(b)·W(b)</c> directly over the dense tables, the value a correct weighted opening's claim must equal.</summary>
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


    /// <summary>Computes the public commitment the verifier needs: the Merkle root of <c>Enc_d(coeffs)</c>, where <c>coeffs</c> is the interpolation of the MLE.</summary>
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

        using MerkleTree tree = MerkleTree.Build(codeword, codewordElements, TreeParameters, pool);

        return MerkleRoot.FromBytes(tree.Root.AsReadOnlySpan(), pool);
    }


    /// <summary>Computes the public hiding commitment the verifier needs: the salted Merkle root of <c>Enc_d(coeffs)</c> over <paramref name="salts"/>, where <c>coeffs</c> is the interpolation of the MLE.</summary>
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

        using MerkleTree tree = MerkleTree.BuildSalted(codeword, salts, codewordElements, TreeParameters, pool);

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
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 13) + (i * 29) + 3);
            Reduce(wide, evals.Slice(i * ScalarSize, ScalarSize), Curve);
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


    /// <summary>Adds the field one to <paramref name="value"/>, returning a fresh <see cref="Scalar"/> distinct from any correct claimed value derived from a well-formed weighted opening.</summary>
    private static Scalar AddOne(Scalar value, BaseMemoryPool pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    /// <summary>Disposes every coordinate scalar of a point built by <see cref="BuildPoint"/>.</summary>
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
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.WeightedSum.Test"u8;
}
