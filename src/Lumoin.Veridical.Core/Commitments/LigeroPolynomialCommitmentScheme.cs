using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The Ligero scheme behind the scheme-agnostic
/// <see cref="PolynomialCommitmentProvider"/> surface Spartan operates against:
/// a transparent, hash-based multilinear polynomial commitment built from
/// interleaved Reed-Solomon codes with a tensor-query evaluation argument. It
/// commits a polynomial's evaluation matrix (RS-encode each row, Merkle-commit
/// the extension columns) and opens at a point with a proximity row-combination,
/// the evaluation row-combination, and the opened columns with their Merkle
/// paths.
/// </summary>
/// <remarks>
/// <para>
/// Like plain BaseFold, the commitment is a deterministic Merkle root and the
/// opening reveals queried codeword positions, so the scheme is binding but not
/// hiding and not additively homomorphic. It needs no trusted setup and, because
/// the encoder is the NTT-free barycentric one, runs over any prime field
/// (multilinear extensions are wired for BLS12-381 and BN254).
/// </para>
/// <para>
/// Structural reference: "Ligero" (Ames, Hazay, Ishai, Venkitasubramaniam, IACR
/// ePrint 2022/1608) and the Brakedown tensor-query evaluation argument; no code
/// dependency.
/// </para>
/// </remarks>
public static class LigeroPolynomialCommitmentScheme
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The inverse code rate is fixed so the opening size is a pure function of
    //(variableCount, queryCount, digest) — which lets the Spartan proof carrier
    //size openings from the provider's metadata alone, as for BaseFold. The rate,
    //its per-opened-column soundness (rate 1/4 gives ≈ 2 bits/column) and the
    //128-bit query-count derivation live in WellKnownLigeroParameters; the soundness
    //level is scaled by the query count, not the rate.
    private const int InverseRate = WellKnownLigeroParameters.DefaultInverseRate;


    /// <summary>
    /// Builds a Ligero provider over <paramref name="curve"/> with the supplied
    /// algebraic, hashing and Merkle backends.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the polynomial lives in (BLS12-381 or BN254).</param>
    /// <param name="queryCount">The number of opened columns (the soundness query count); use <see cref="Ligero.WellKnownLigeroParameters.ClassicalSecurityDefaultQueryCount"/> for the 128-bit-classical target. Clamped per-polynomial to the available extension width, so for a small polynomial check the clamped count against <see cref="Ligero.WellKnownLigeroParameters.EffectiveSecurityBits"/>.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="reduce">Scalar-reduce backend for the challenge squeeze.</param>
    /// <param name="hash">The fixed-output transcript hash backend.</param>
    /// <param name="squeeze">The transcript XOF backend.</param>
    /// <param name="columnHash">The one-shot bytes-to-digest hash producing a Merkle leaf from a whole column.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <returns>The provider; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a backend or the hash-algorithm name is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="queryCount"/> or <paramref name="digestSizeBytes"/> is non-positive.</exception>
    public static PolynomialCommitmentProvider Create(
        CurveParameterSet curve,
        int queryCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate columnHash,
        MerkleHashDelegate merkleHash,
        string hashAlgorithm,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(columnHash);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        PolynomialCommitDelegate commit = (polynomial, pool) =>
        {
            ArgumentNullException.ThrowIfNull(polynomial);
            ArgumentNullException.ThrowIfNull(pool);

            LigeroEvaluationDimensions dimensions = LigeroEvaluationDimensions.ForVariableCount(polynomial.VariableCount, InverseRate, queryCount);
            using MerkleTree tree = LigeroEvaluationProver.Commit(
                polynomial.AsReadOnlySpan(), dimensions, add, subtract, multiply, invert, columnHash, hashAlgorithm, merkleHash, curve, pool);

            PolynomialCommitment commitment = PolynomialCommitment.FromBytes(tree.Root.AsReadOnlySpan(), curve, CommitmentScheme.Ligero, pool);
            PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.CreateZero(ScalarSize, curve, CommitmentScheme.Ligero, pool);

            return (commitment, blind);
        };

        PolynomialOpenDelegate open = (commitment, blind, polynomial, evaluationPoint, transcript, pool) =>
        {
            ArgumentNullException.ThrowIfNull(commitment);
            ArgumentNullException.ThrowIfNull(polynomial);
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(pool);

            LigeroEvaluationDimensions dimensions = LigeroEvaluationDimensions.ForVariableCount(polynomial.VariableCount, InverseRate, queryCount);
            int openingLength = LigeroEvaluationProver.OpeningLengthBytes(dimensions, digestSizeBytes);

            using IMemoryOwner<byte> openingOwner = pool.Rent(openingLength);
            Span<byte> openingSpan = openingOwner.Memory.Span[..openingLength];
            Span<byte> claimedValue = stackalloc byte[ScalarSize];

            LigeroEvaluationProver.Prove(
                polynomial.AsReadOnlySpan(), evaluationPoint, dimensions, digestSizeBytes,
                openingSpan, claimedValue,
                add, subtract, multiply, invert, reduce, hash, squeeze, columnHash, hashAlgorithm, merkleHash, transcript, curve, pool);

            PolynomialOpening opening = PolynomialOpening.FromBytes(openingSpan, curve, CommitmentScheme.Ligero, pool);
            Scalar claimed = Scalar.FromCanonical(claimedValue, curve, pool);

            return (opening, claimed);
        };

        PolynomialVerifyEvaluationDelegate verifyEvaluation = (commitment, evaluationPoint, claimedValue, opening, transcript, pool) =>
        {
            ArgumentNullException.ThrowIfNull(commitment);
            ArgumentNullException.ThrowIfNull(claimedValue);
            ArgumentNullException.ThrowIfNull(opening);
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(pool);

            LigeroEvaluationDimensions dimensions = LigeroEvaluationDimensions.ForVariableCount(evaluationPoint.Length, InverseRate, queryCount);

            try
            {
                return LigeroEvaluationVerifier.Verify(
                    commitment.AsReadOnlySpan(), evaluationPoint, claimedValue.AsReadOnlySpan(), opening.AsReadOnlySpan(),
                    dimensions, digestSizeBytes,
                    add, subtract, multiply, invert, reduce, hash, squeeze, columnHash, hashAlgorithm, merkleHash, transcript, curve, pool);
            }
            catch(ArgumentException)
            {
                //A malformed opening (wrong length, bad path shape) is a rejection,
                //not a caller fault.
                return false;
            }
        };

        return new PolynomialCommitmentProvider(
            CommitmentScheme.Ligero,
            curve,
            commit,
            open,
            verifyEvaluation,
            ownedResource: null,
            queryCount: queryCount,
            digestSizeBytes: digestSizeBytes,
            isAdditivelyHomomorphic: false,
            isHiding: false);
    }


    /// <summary>
    /// The deterministic serialized length of a Ligero evaluation opening for a
    /// <paramref name="variableCount"/>-variable polynomial under the given query
    /// count and digest size — what the Spartan proof carrier uses to size the
    /// embedded openings.
    /// </summary>
    /// <param name="variableCount">The polynomial's variable count.</param>
    /// <param name="curve">The curve (carried for signature parity with other schemes; the size is curve-independent).</param>
    /// <param name="queryCount">The provider's query count.</param>
    /// <param name="digestSizeBytes">The Merkle digest size.</param>
    public static int GetEvaluationProofSizeBytes(int variableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes)
    {
        _ = curve;
        LigeroEvaluationDimensions dimensions = LigeroEvaluationDimensions.ForVariableCount(variableCount, InverseRate, queryCount);

        return LigeroEvaluationProver.OpeningLengthBytes(dimensions, digestSizeBytes);
    }
}
