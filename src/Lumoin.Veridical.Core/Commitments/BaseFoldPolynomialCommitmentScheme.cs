using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Adapts the BaseFold multilinear polynomial commitment to the
/// scheme-agnostic <see cref="PolynomialCommitmentProvider"/> surface. The
/// factory captures the code seed, the curve, the query count, the digest size,
/// and the algebraic / transcript / Merkle backends once; the three returned
/// operations close over them, so Spartan supplies only the per-call arguments
/// (polynomial, point, transcript) and never names a BaseFold type.
/// </summary>
/// <remarks>
/// <para>
/// BaseFold is a transparent, hash-based, post-quantum-resistant commitment: it
/// has no structured reference string and no group operations, only a random
/// foldable code (derived deterministically from the captured seed and the
/// committed polynomial's variable count), Merkle commitments, and field
/// arithmetic. It is the post-quantum sibling of the pairing-based Hyrax
/// provider behind the same surface.
/// </para>
/// <para>
/// BaseFold is <em>not hiding</em>: the commitment is a Merkle root over the
/// codeword and carries no blinding randomness. The blind on the surface is
/// therefore a placeholder (no secret state); the open operation re-derives the
/// codeword from the polynomial it is given again, exactly as the commit did.
/// </para>
/// <para>
/// The foldable code is reconstructed per call from the seed and variable
/// count, matching the correctness-first stance — caching the derived code per
/// size is a later performance refinement, not a correctness concern.
/// </para>
/// </remarks>
public static class BaseFoldPolynomialCommitmentScheme
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The blind a BaseFold commitment carries: a single zero byte. BaseFold has
    //no hiding randomness, but the surface's blind must be non-empty, so this
    //is a placeholder the open operation never reads.
    private const int PlaceholderBlindLengthBytes = 1;


    /// <summary>
    /// Builds a BaseFold-backed provider over the code derived from
    /// <paramref name="seed"/>. The returned provider's
    /// <see cref="CommitmentScheme"/> is <see cref="CommitmentScheme.BaseFold"/>
    /// and its curve is <paramref name="curve"/>.
    /// </summary>
    /// <param name="seed">The seed binding the random foldable code; the same seed reproduces the same code, so commit, open, and verify must share it.</param>
    /// <param name="curve">The curve every produced artifact is tagged with.</param>
    /// <param name="queryCount">The IOPP query repetition count (see <see cref="WellKnownBaseFoldIoppParameters.ClassicalSecurityDefaultQueryCount"/>).</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">Fiat-Shamir absorb backend.</param>
    /// <param name="squeeze">Fiat-Shamir squeeze backend.</param>
    /// <param name="reduce">Scalar reduction backend.</param>
    /// <param name="add">Scalar addition backend.</param>
    /// <param name="subtract">Scalar subtraction backend.</param>
    /// <param name="multiply">Scalar multiplication backend.</param>
    /// <param name="invert">Scalar inversion backend.</param>
    /// <param name="hashToScalar">Hash-to-scalar backend the code derivation uses for its diagonal entries.</param>
    /// <param name="digestSizeBytes">The Merkle node digest size <paramref name="merkleHash"/> produces; defaults to <see cref="WellKnownMerkleHashParameters.DefaultDigestSizeBytes"/>.</param>
    /// <returns>A provider whose commit / open / verify route to the BaseFold evaluation protocol.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="queryCount"/> or <paramref name="digestSizeBytes"/> is non-positive.</exception>
    public static PolynomialCommitmentProvider Create(
        ReadOnlySpan<byte> seed,
        CurveParameterSet curve,
        int queryCount,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarHashToScalarDelegate hashToScalar,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        //Copy the seed: the closures outlive the caller's span.
        byte[] seedCopy = seed.ToArray();

        FoldableCode DeriveCode(int variableCount, SensitiveMemoryPool<byte> pool)
        {
            FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, curve);
            return FoldableCode.Derive(parameters, seedCopy, hashToScalar, pool);
        }

        PolynomialCommitDelegate commit = (polynomial, pool) =>
        {
            using FoldableCode code = DeriveCode(polynomial.VariableCount, pool);
            FoldableCodeParameters parameters = code.Parameters;

            int messageElements = parameters.MessageLength;
            int codewordElements = parameters.CodewordLength;

            using IMemoryOwner<byte> coeffsOwner = pool.Rent(messageElements * ScalarSize);
            Span<byte> coeffs = coeffsOwner.Memory.Span[..(messageElements * ScalarSize)];
            polynomial.InterpolateToCoefficients(coeffs, subtract);

            using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
            Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
            code.Encode(coeffs, codeword, add, subtract, multiply, pool, batch);

            using MerkleTree tree = MerkleTree.Build(codeword, codewordElements, merkleHash, pool);

            PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
                tree.Root.AsReadOnlySpan(), curve, CommitmentScheme.BaseFold, pool);
            PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.CreateZero(
                PlaceholderBlindLengthBytes, curve, CommitmentScheme.BaseFold, pool);

            return (commitment, blind);
        };

        PolynomialOpenDelegate open = (commitment, blind, polynomial, evaluationPoint, transcript, pool) =>
        {
            using FoldableCode code = DeriveCode(polynomial.VariableCount, pool);

            (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.Prove(
                code,
                polynomial,
                evaluationPoint,
                queryCount,
                transcript,
                merkleHash,
                hash,
                squeeze,
                reduce,
                add,
                subtract,
                multiply,
                invert,
                pool,
                batch);

            using(proof)
            {
                (IMemoryOwner<byte> bytesOwner, int length) = BaseFoldEvaluationProofSerialization.ToBytes(proof, digestSizeBytes, BaseFoldOpeningMode.Plain, pool);
                using(bytesOwner)
                {
                    PolynomialOpening opening = PolynomialOpening.FromBytes(
                        bytesOwner.Memory.Span[..length], curve, CommitmentScheme.BaseFold, pool);

                    return (opening, claimedValue);
                }
            }
        };

        PolynomialVerifyEvaluationDelegate verifyEvaluation = (commitment, evaluationPoint, claimedValue, opening, transcript, pool) =>
        {
            using FoldableCode code = DeriveCode(evaluationPoint.Length, pool);

            BaseFoldEvaluationProof? proof = null;
            try
            {
                proof = BaseFoldEvaluationProofSerialization.FromBytes(
                    opening.AsReadOnlySpan(), code.Parameters, queryCount, digestSizeBytes, BaseFoldOpeningMode.Plain, pool);
            }
            catch(ArgumentException)
            {
                //Malformed opening bytes are a rejection, not a fault.
                return false;
            }

            using(proof)
            using(MerkleRoot commitmentRoot = MerkleRoot.FromBytes(commitment.AsReadOnlySpan(), pool))
            {
                return BaseFoldEvaluationVerifier.Verify(
                    code,
                    commitmentRoot,
                    evaluationPoint,
                    claimedValue,
                    proof,
                    queryCount,
                    transcript,
                    merkleHash,
                    hash,
                    squeeze,
                    reduce,
                    add,
                    subtract,
                    multiply,
                    invert,
                    pool);
            }
        };

        //The weighted-opening path (the statistical sumcheck mask's binding,
        //SM.7b): the vector commit is the ordinary Merkle commit of the
        //vector's MLE, and the weighted opening is the SM.1 multiplier-generic
        //evaluation protocol.
        PolynomialOpenWeightedSumDelegate openWeightedSum = (commitment, blind, vector, weights, transcript, pool) =>
        {
            using FoldableCode code = DeriveCode(vector.VariableCount, pool);

            (BaseFoldEvaluationProof proof, Scalar claimedValue) = BaseFoldEvaluationProver.ProveWeightedSum(
                code,
                vector,
                weights,
                queryCount,
                transcript,
                merkleHash,
                hash,
                squeeze,
                reduce,
                add,
                subtract,
                multiply,
                invert,
                pool,
                batch);

            using(proof)
            {
                (IMemoryOwner<byte> bytesOwner, int length) = BaseFoldEvaluationProofSerialization.ToBytes(proof, digestSizeBytes, BaseFoldOpeningMode.Plain, pool);
                using(bytesOwner)
                {
                    PolynomialOpening opening = PolynomialOpening.FromBytes(
                        bytesOwner.Memory.Span[..length], curve, CommitmentScheme.BaseFold, pool);

                    return (opening, claimedValue);
                }
            }
        };

        PolynomialVerifyWeightedSumDelegate verifyWeightedSum = (commitment, weights, claimedValue, opening, transcript, pool) =>
        {
            using FoldableCode code = DeriveCode(weights.VariableCount, pool);

            BaseFoldEvaluationProof? proof = null;
            try
            {
                proof = BaseFoldEvaluationProofSerialization.FromBytes(
                    opening.AsReadOnlySpan(), code.Parameters, queryCount, digestSizeBytes, BaseFoldOpeningMode.Plain, pool);
            }
            catch(ArgumentException)
            {
                //Malformed opening bytes are a rejection, not a fault.
                return false;
            }

            using(proof)
            using(MerkleRoot commitmentRoot = MerkleRoot.FromBytes(commitment.AsReadOnlySpan(), pool))
            {
                return BaseFoldEvaluationVerifier.VerifyWeightedSum(
                    code,
                    commitmentRoot,
                    weights,
                    claimedValue,
                    proof,
                    queryCount,
                    transcript,
                    merkleHash,
                    hash,
                    squeeze,
                    reduce,
                    add,
                    subtract,
                    multiply,
                    invert,
                    pool);
            }
        };

        return new PolynomialCommitmentProvider(
            CommitmentScheme.BaseFold, curve, commit, open, verifyEvaluation,
            ownedResource: null, queryCount: queryCount, digestSizeBytes: digestSizeBytes,
            //BaseFold's commitment is a Merkle root over the codeword — binding
            //but not additively homomorphic, so it cannot back Nova-style folding;
            //and not hiding (the root is a deterministic fingerprint of the witness,
            //the opening reveals queried codeword positions). The salted/masked ZK
            //variant (ZkBaseFoldPolynomialCommitmentScheme) is the hiding sibling.
            isAdditivelyHomomorphic: false, isHiding: false,
            //The vector commit is the ordinary commit; the unlifted Pedersen/IPA
            //mask shape is reused because the sound-only path makes no hiding
            //claim — the filler is inert structure shared with the hiding paths.
            extraVariableCount: null, commitVector: commit, openWeightedSum, verifyWeightedSum,
            resolveStatisticalMaskShape: static (d, degree) => WellKnownStatisticalMaskParameters.CreatePedersenIpa(d, degree));
    }


    /// <summary>
    /// Returns the byte size of the serialized BaseFold evaluation proof (the
    /// opening) for a multilinear polynomial in <paramref name="variableCount"/>
    /// variables, under the wired classical-security code shape, the given query
    /// count, and digest size. A consumer that embeds BaseFold openings in a
    /// larger proof (the Spartan integration) uses this to lay out and recover
    /// the variable-length opening sections without naming the internal
    /// serializer.
    /// </summary>
    /// <param name="variableCount">The committed polynomial's variable count (= the code's layer count).</param>
    /// <param name="curve">The curve the code is over.</param>
    /// <param name="queryCount">The IOPP query repetition count the provider was built with.</param>
    /// <param name="digestSizeBytes">The Merkle digest size the provider was built with.</param>
    /// <returns>The opening's serialized byte length.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is non-positive or negative.</exception>
    public static int GetEvaluationProofSizeBytes(int variableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, curve);
        return BaseFoldEvaluationProofSerialization.ComputeLength(parameters, queryCount, digestSizeBytes, BaseFoldOpeningMode.Plain);
    }
}
