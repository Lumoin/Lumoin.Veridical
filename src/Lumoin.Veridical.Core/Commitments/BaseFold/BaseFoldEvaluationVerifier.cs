using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The BaseFold evaluation-protocol verifier: checks a
/// <see cref="BaseFoldEvaluationProof"/> attesting that the committed
/// multilinear polynomial evaluates to a claimed value at a point. It replays
/// the interleaved sumcheck-and-IOPP transcript, chaining the sumcheck claim
/// through the per-round polynomials, then checks the IOPP query openings and
/// the tie between the sumcheck's final claim and the cleartext base codeword.
/// </summary>
/// <remarks>
/// <para>
/// Implements the verifier side of Protocol 4 / Fig. 3 (Zeilberger, Chen,
/// Fisch, CRYPTO 2024, IACR ePrint 2023/1705). The three acceptance conditions
/// are: every IOPP query opening authenticates and folds consistently; the
/// sumcheck claim chains through <c>h_d, …, h_1</c> (each round polynomial's
/// missing linear term is reconstructed from the running claim, which bakes in
/// <c>h_i(0)+h_i(1) = claim_i</c>); and the base codeword <c>π_0</c> is a valid
/// repetition word whose value <c>w</c> satisfies
/// <c>w · eq_z(r) = h_1(r_0)</c> — equivalently
/// <c>Enc_0(h_1(r_0)/eq_z(r)) = π_0</c> without an inversion.
/// </para>
/// <para>
/// Verification is exception-safe against adversarial proofs: a structurally
/// malformed proof or any failed check returns <see langword="false"/> rather
/// than throwing; only <see langword="null"/> arguments (a caller fault) throw.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BaseFoldEvaluationVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int RoundPolynomialDegree = 2;


    /// <summary>
    /// Verifies that <paramref name="commitment"/> (the Merkle root of
    /// <c>π_d</c>) opens to <paramref name="claimedValue"/> at
    /// <paramref name="evaluationPoint"/> under <paramref name="proof"/> and the
    /// foldable <paramref name="code"/>.
    /// </summary>
    /// <param name="code">The foldable code, reconstructed from the same seed the prover used.</param>
    /// <param name="commitment">The public commitment: the Merkle root of the committed codeword <c>π_d</c>.</param>
    /// <param name="evaluationPoint">The point <c>z</c>; one scalar per variable, matching the prover's.</param>
    /// <param name="claimedValue">The claimed evaluation <c>y</c>.</param>
    /// <param name="proof">The evaluation proof.</param>
    /// <param name="queryCount">The IOPP query repetition count; must match the proof.</param>
    /// <param name="transcript">The live Fiat-Shamir transcript, replayed identically to the prover's.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for re-deriving challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend (the per-query fold uses it).</param>
    /// <param name="pool">The pool to rent scratch buffers from.</param>
    /// <returns><see langword="true"/> iff the proof verifies.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    public static bool Verify(
        FoldableCode code,
        MerkleRoot commitment,
        ReadOnlySpan<Scalar> evaluationPoint,
        Scalar claimedValue,
        BaseFoldEvaluationProof proof,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        SensitiveMemoryPool<byte> pool)
    {
        return VerifyCore(code, commitment, evaluationPoint, multiplier: null, claimedValue, proof, queryCount, transcript, merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, pool);
    }


    /// <summary>
    /// Verifies a weighted-sum opening
    /// (<see cref="BaseFoldEvaluationProver.ProveWeightedSum"/> or its hiding
    /// sibling): that <paramref name="commitment"/> opens to
    /// <paramref name="claimedValue"/> <c>= Σ_b f(b)·W(b)</c> against the public
    /// multiplier multilinear <paramref name="multiplier"/>. The transcript and
    /// proof layout are exactly the evaluation protocol's; only the terminal tie
    /// multiplies the base oracle's value by <c>W(r)</c> — evaluated here by
    /// folding the public multiplier table under the squeezed challenges, the
    /// same collapse the prover's tables undergo — instead of <c>eq_z(r)</c>.
    /// </summary>
    /// <param name="multiplier">The public multiplier multilinear <c>W</c>; its variable count must equal the code's layer count.</param>
    /// <inheritdoc cref="Verify"/>
    public static bool VerifyWeightedSum(
        FoldableCode code,
        MerkleRoot commitment,
        MultilinearExtension multiplier,
        Scalar claimedValue,
        BaseFoldEvaluationProof proof,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(multiplier);

        return VerifyCore(code, commitment, evaluationPoint: default, multiplier, claimedValue, proof, queryCount, transcript, merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, pool);
    }


    private static bool VerifyCore(
        FoldableCode code,
        MerkleRoot commitment,
        ReadOnlySpan<Scalar> evaluationPoint,
        MultilinearExtension? multiplier,
        Scalar claimedValue,
        BaseFoldEvaluationProof proof,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(claimedValue);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);

        FoldableCodeParameters parameters = code.Parameters;
        int d = parameters.LayerCount;
        if(d < 1)
        {
            return false;
        }

        //An evaluation opening carries the point (eq_z is derived from it); a
        //weighted opening carries the public multiplier and no point.
        CurveParameterSet curve = parameters.Curve;
        if(!IsCurveWired(curve)
            || (multiplier is null && evaluationPoint.Length != d)
            || (multiplier is not null && multiplier.VariableCount != d))
        {
            return false;
        }

        int baseUnit = parameters.InverseRate * parameters.BaseDimension;

        //Structural checks: a malformed proof is rejected, not thrown on.
        if(proof.QueryCount != queryCount
            || proof.Parameters != parameters
            || proof.RoundPolynomials.Count != d
            || proof.FoldRoots.Count != d - 1
            || proof.FinalOracle.Length != BaseFoldQueryPhase.LayerLength(baseUnit, 0) * ScalarSize
            || proof.Openings.Count != queryCount)
        {
            return false;
        }

        //challengesForLevel[level] = r_{level-1}, the challenge that folds
        //π_level → π_{level-1} and binds variable X_level. The per-query IOPP
        //check indexes the fold challenge by level.
        var challengesForLevel = new Scalar[d + 1];
        var scratch = new List<IDisposable>();

        try
        {
            //Replay the commit phase: absorb the commitment and h_d, then chain
            //the sumcheck claim while absorbing each fold root and round polynomial.
            transcript.AbsorbBaseFoldFoldRoot(commitment, hash);

            if(!RoundPolynomialDegreeMatches(proof.RoundPolynomials[0]))
            {
                return false;
            }

            transcript.AbsorbRoundPolynomial(RoundPolynomialLabel, proof.RoundPolynomials[0], hash);

            //claim starts at y; poly = decompressed h_d. Decompression sets the
            //elided linear term so h_d(0)+h_d(1) = claim by construction.
            Scalar claim = claimedValue;
            Polynomial poly = proof.RoundPolynomials[0].Decompress(claim, subtract, pool);
            scratch.Add(poly);

            for(int level = d; level >= 1; level--)
            {
                Scalar challenge = transcript.SqueezeBaseFoldFoldChallenge(squeeze, hash, reduce, curve, pool);
                challengesForLevel[level] = challenge;
                scratch.Add(challenge);

                //claim ← h_level(r_{level-1}).
                Scalar nextClaim = EvaluateDegree2(poly.AsReadOnlySpan(), challenge.AsReadOnlySpan(), add, multiply, curve, pool);
                scratch.Add(nextClaim);
                claim = nextClaim;

                if(level - 1 >= 1)
                {
                    MerkleRoot nextRoot = proof.FoldRoots[d - level];
                    transcript.AbsorbBaseFoldFoldRoot(nextRoot, hash);

                    CompressedRoundPolynomial nextRoundPolynomial = proof.RoundPolynomials[d - level + 1];
                    if(!RoundPolynomialDegreeMatches(nextRoundPolynomial))
                    {
                        return false;
                    }

                    transcript.AbsorbRoundPolynomial(RoundPolynomialLabel, nextRoundPolynomial, hash);

                    poly = nextRoundPolynomial.Decompress(claim, subtract, pool);
                    scratch.Add(poly);
                }
                else
                {
                    transcript.AbsorbBaseFoldFinalOracle(proof.FinalOracle, hash);
                }
            }

            //Final sumcheck claim is h_1(r_0). Tie it to the base codeword:
            //π_0 must be a valid repetition word, and its value w must satisfy
            //w · M(r) = h_1(r_0), where M is eq_z for an evaluation opening and
            //the public multiplier W for a weighted one.
            if(!BaseFoldQueryPhase.FinalOracleIsValidBaseCodeword(proof.FinalOracle, baseUnit))
            {
                return false;
            }

            Span<byte> multiplierEvaluation = stackalloc byte[ScalarSize];
            if(multiplier is null)
            {
                ComputeEqEvaluation(evaluationPoint, challengesForLevel, d, add, subtract, multiply, curve, multiplierEvaluation);
            }
            else
            {
                ComputeMultiplierEvaluation(multiplier, challengesForLevel, d, add, subtract, multiply, curve, multiplierEvaluation, pool);
            }

            Span<byte> tie = stackalloc byte[ScalarSize];
            ReadOnlySpan<byte> baseValue = proof.FinalOracle[..ScalarSize];
            multiply(baseValue, multiplierEvaluation, tie, curve);
            if(!tie.SequenceEqual(claim.AsReadOnlySpan()))
            {
                return false;
            }

            //IOPP query checks.
            int queryDomainSize = BaseFoldQueryPhase.LayerLength(baseUnit, d - 1);
            for(int q = 0; q < queryCount; q++)
            {
                int j0 = transcript.SqueezeBaseFoldQueryIndex(queryDomainSize, squeeze, hash);
                if(!BaseFoldQueryPhase.VerifyQuery(code, commitment, proof.FoldRoots, proof.Openings[q], proof.FinalOracle, baseUnit, d, j0, challengesForLevel, merkleHash, add, subtract, multiply, invert))
                {
                    return false;
                }
            }

            return true;
        }
        catch(ArgumentException)
        {
            //A structurally malformed proof (for example a round polynomial that
            //decompresses inconsistently) is a rejection, not a fault.
            return false;
        }
        finally
        {
            foreach(IDisposable disposable in scratch)
            {
                disposable.Dispose();
            }
        }
    }


    /// <summary>
    /// Verifies a statistically zero-knowledge BaseFold evaluation opening
    /// (<see cref="BaseFoldEvaluationProver.ProveZeroKnowledge"/>, design doc
    /// <c>ZK-STATMASK-DESIGN.md</c> §2 v3): replays the masked
    /// transcript, chains the blended claim, derives the mask evaluation from
    /// the terminal (<c>s(r) = (claim − f(r)·eq_z(r))·ρ⁻¹</c>), and checks the
    /// nested weighted opening of the mask's coefficient commitment against the
    /// derived claim <c>s(r) + σ_F</c> under publicly derived weights.
    /// </summary>
    /// <param name="commitment">The public commitment: the Merkle root of the committed witness codeword <c>π_d</c>.</param>
    /// <param name="maskCommitmentCode">The foldable code the mask's coefficient commitment lives under, derived from the same seed at the deterministic lifted layer count (must mirror the prover's).</param>
    /// <inheritdoc cref="Verify"/>
    public static bool VerifyZeroKnowledge(
        FoldableCode code,
        MerkleRoot commitment,
        ReadOnlySpan<Scalar> evaluationPoint,
        Scalar claimedValue,
        BaseFoldEvaluationProof proof,
        int queryCount,
        FiatShamirTranscript transcript,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        FoldableCode maskCommitmentCode,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(claimedValue);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(maskCommitmentCode);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);

        FoldableCodeParameters parameters = code.Parameters;
        int d = parameters.LayerCount;
        if(d < 1)
        {
            return false;
        }

        CurveParameterSet curve = parameters.Curve;
        if(!IsCurveWired(curve) || evaluationPoint.Length != d)
        {
            return false;
        }

        int baseUnit = parameters.InverseRate * parameters.BaseDimension;
        int finalOracleLength = BaseFoldQueryPhase.LayerLength(baseUnit, 0) * ScalarSize;

        //The mask-commitment code must match the deterministic policy shape for
        //this protocol — a mismatch is a configuration fault on the honest path
        //and a rejection on the adversarial one.
        StatisticalMaskParameters maskParameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(d, curve, queryCount);
        if(maskCommitmentCode.Parameters != WellKnownFoldableCodeParameters.CreateClassicalSecurity(maskParameters.LiftedVariableCount, curve))
        {
            return false;
        }

        //Structural checks: a malformed proof is rejected, not thrown on.
        BaseFoldMaskOpening? mask = proof.Mask;
        if(proof.QueryCount != queryCount
            || proof.Parameters != parameters
            || proof.RoundPolynomials.Count != d
            || proof.FoldRoots.Count != d - 1
            || proof.FinalOracle.Length != finalOracleLength
            || proof.Openings.Count != queryCount
            || mask is null
            || mask.Sigma.Length != ScalarSize
            || mask.FillerSum.Length != ScalarSize)
        {
            return false;
        }

        var challengesForLevel = new Scalar[d + 1];
        var scratch = new List<IDisposable>();

        try
        {
            //Replay the commit phase: absorb the witness commitment, com(C*), σ,
            //and σ_F, then squeeze the blend scalar ρ — mirroring the prover.
            transcript.AbsorbBaseFoldFoldRoot(commitment, hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBaseFoldEvaluationParameters.MaskCommitmentRoot), mask.CommitmentRoot.AsReadOnlySpan(), hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBaseFoldEvaluationParameters.MaskSum), mask.Sigma, hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBaseFoldEvaluationParameters.MaskFillerSum), mask.FillerSum, hash);
            Scalar rho = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBaseFoldEvaluationParameters.MaskBlendChallenge), squeeze, hash, reduce, curve, pool);
            scratch.Add(rho);

            //A zero blend challenge would make ρ⁻¹ undefined; rejecting keeps the
            //terminal derivation total (probability 1/|F| on an honest run).
            if(IsZeroScalar(rho.AsReadOnlySpan()))
            {
                return false;
            }

            if(!RoundPolynomialDegreeMatches(proof.RoundPolynomials[0]))
            {
                return false;
            }

            transcript.AbsorbRoundPolynomial(RoundPolynomialLabel, proof.RoundPolynomials[0], hash);

            //The masked sumcheck's initial claim is y + ρ·σ; the chain otherwise
            //runs exactly as the plain protocol (each round polynomial's elided
            //linear term is reconstructed from this running claim, which already
            //absorbs the ρ·s blend).
            Scalar initialClaim = ComputeBlendedClaim(claimedValue, rho, mask.Sigma, add, multiply, curve, pool);
            scratch.Add(initialClaim);

            Scalar claim = initialClaim;
            Polynomial poly = proof.RoundPolynomials[0].Decompress(claim, subtract, pool);
            scratch.Add(poly);

            for(int level = d; level >= 1; level--)
            {
                Scalar challenge = transcript.SqueezeBaseFoldFoldChallenge(squeeze, hash, reduce, curve, pool);
                challengesForLevel[level] = challenge;
                scratch.Add(challenge);

                Scalar nextClaim = EvaluateDegree2(poly.AsReadOnlySpan(), challenge.AsReadOnlySpan(), add, multiply, curve, pool);
                scratch.Add(nextClaim);
                claim = nextClaim;

                if(level - 1 >= 1)
                {
                    MerkleRoot nextRoot = proof.FoldRoots[d - level];
                    transcript.AbsorbBaseFoldFoldRoot(nextRoot, hash);

                    CompressedRoundPolynomial nextRoundPolynomial = proof.RoundPolynomials[d - level + 1];
                    if(!RoundPolynomialDegreeMatches(nextRoundPolynomial))
                    {
                        return false;
                    }

                    transcript.AbsorbRoundPolynomial(RoundPolynomialLabel, nextRoundPolynomial, hash);

                    poly = nextRoundPolynomial.Decompress(claim, subtract, pool);
                    scratch.Add(poly);
                }
                else
                {
                    transcript.AbsorbBaseFoldFinalOracle(proof.FinalOracle, hash);
                }
            }

            //The witness base oracle must be a valid repetition word; its value
            //is f(r). The masked final claim is f(r)·eq_z(r) + ρ·s(r), so the
            //mask evaluation the weighted opening must bind is
            //s(r) = (claim − f(r)·eq_z(r))·ρ⁻¹, and the weighted claim adds the
            //precommitted filler sum.
            if(!BaseFoldQueryPhase.FinalOracleIsValidBaseCodeword(proof.FinalOracle, baseUnit))
            {
                return false;
            }

            Span<byte> eqEvaluation = stackalloc byte[ScalarSize];
            ComputeEqEvaluation(evaluationPoint, challengesForLevel, d, add, subtract, multiply, curve, eqEvaluation);

            Span<byte> weightedClaim = stackalloc byte[ScalarSize];
            multiply(proof.FinalOracle[..ScalarSize], eqEvaluation, weightedClaim, curve);
            subtract(claim.AsReadOnlySpan(), weightedClaim, weightedClaim, curve);

            Span<byte> rhoInverse = stackalloc byte[ScalarSize];
            invert(rho.AsReadOnlySpan(), rhoInverse, curve);
            multiply(weightedClaim, rhoInverse, weightedClaim, curve);
            add(weightedClaim, mask.FillerSum, weightedClaim, curve);

            //IOPP query checks over the witness codeword.
            int queryDomainSize = BaseFoldQueryPhase.LayerLength(baseUnit, d - 1);
            for(int q = 0; q < queryCount; q++)
            {
                int j0 = transcript.SqueezeBaseFoldQueryIndex(queryDomainSize, squeeze, hash);
                if(!BaseFoldQueryPhase.VerifyQuery(code, commitment, proof.FoldRoots, proof.Openings[q], proof.FinalOracle, baseUnit, d, j0, challengesForLevel, merkleHash, add, subtract, multiply, invert))
                {
                    return false;
                }
            }

            //The nested weighted opening binds ⟨C*, w⁺⟩ = s(r) + σ_F: the weights
            //are the mask basis's monomials at the bound challenges, field one on
            //every filler coordinate, zero on the lift block.
            MonomialBasis maskBasis = MonomialBasis.SumOfUnivariatesWithPad(d, padPairCount: 0);
            ReadOnlySpan<Scalar> terminalPoint = challengesForLevel.AsSpan(1, d);

            int liftedEvaluations = 1 << maskParameters.LiftedVariableCount;
            using IMemoryOwner<byte> weightsOwner = pool.Rent(liftedEvaluations * ScalarSize);
            Span<byte> weights = weightsOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
            MonomialBasisMask.BuildWeightVector(maskBasis, terminalPoint, weights, multiply, curve);
            for(int i = maskParameters.MaskCoefficientCount; i < maskParameters.CoefficientCount; i++)
            {
                Span<byte> weight = weights.Slice(i * ScalarSize, ScalarSize);
                weight.Clear();
                weight[ScalarSize - 1] = 0x01;
            }

            using MultilinearExtension weightsMle = MultilinearExtension.FromEvaluations(weights, maskParameters.LiftedVariableCount, curve, pool);

            IMemoryOwner<byte> weightedClaimOwner = pool.Rent(ScalarSize);
            weightedClaim.CopyTo(weightedClaimOwner.Memory.Span[..ScalarSize]);
            using var weightedClaimScalar = new Scalar(weightedClaimOwner, curve, WellKnownAlgebraicTags.ScalarFor(curve));

            return VerifyWeightedSum(
                maskCommitmentCode, mask.CommitmentRoot, weightsMle, weightedClaimScalar, mask.WeightedOpening,
                queryCount, transcript, merkleHash, hash, squeeze, reduce, add, subtract, multiply, invert, pool);
        }
        catch(ArgumentException)
        {
            return false;
        }
        finally
        {
            foreach(IDisposable disposable in scratch)
            {
                disposable.Dispose();
            }
        }
    }


    //True when the canonical big-endian scalar is the field zero.
    private static bool IsZeroScalar(ReadOnlySpan<byte> value)
    {
        for(int i = 0; i < value.Length; i++)
        {
            if(value[i] != 0)
            {
                return false;
            }
        }

        return true;
    }


    //The masked sumcheck's initial running claim y + ρ·σ.
    [SuppressMessage("Reliability", "CA2000", Justification = "The returned scalar transfers ownership to the caller (added to the verifier's scratch list and disposed there).")]
    private static Scalar ComputeBlendedClaim(
        Scalar claimedValue,
        Scalar rho,
        ReadOnlySpan<byte> sigma,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Span<byte> buffer = owner.Memory.Span[..ScalarSize];
        multiply(rho.AsReadOnlySpan(), sigma, buffer, curve);
        add(claimedValue.AsReadOnlySpan(), buffer, buffer, curve);

        return new Scalar(owner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }


    //W(r) for a general public multiplier: folds a working copy of W's dense
    //evaluation table on the high bit by each squeezed challenge in fold order
    //(level d down to 1) — exactly the collapse the prover's multiplier table
    //undergoes — leaving W(r) in the first slot. O(2^d) multiplies; the weighted
    //openings' consumers are small (the statistical-mask levels), so the product
    //shortcut eq_z enjoys is not needed here.
    private static void ComputeMultiplierEvaluation(
        MultilinearExtension multiplier,
        Scalar[] challengesForLevel,
        int d,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        Span<byte> result,
        SensitiveMemoryPool<byte> pool)
    {
        int evaluationCount = multiplier.EvaluationCount;
        using IMemoryOwner<byte> tableOwner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> table = tableOwner.Memory.Span[..(evaluationCount * ScalarSize)];
        multiplier.AsReadOnlySpan().CopyTo(table);

        int currentSize = evaluationCount;
        for(int level = d; level >= 1; level--)
        {
            BaseFoldEvaluationProver.FoldHighBitInPlace(table, currentSize, challengesForLevel[level].AsReadOnlySpan(), add, subtract, multiply, curve);
            currentSize >>= 1;
        }

        table[..ScalarSize].CopyTo(result);
        table.Clear();
    }


    //eq_z(r) = Π_{i=1}^d [z_i·v_i + (1−z_i)(1−v_i)] where z_i = evaluationPoint[i-1]
    //and v_i = challengesForLevel[i] (the challenge that bound variable X_i).
    //Each factor is 1 − z − v + 2zv.
    private static void ComputeEqEvaluation(
        ReadOnlySpan<Scalar> evaluationPoint,
        Scalar[] challengesForLevel,
        int d,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        Span<byte> result)
    {
        //Field one, big-endian canonical.
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        //Accumulator starts at the field one.
        one.CopyTo(result);

        Span<byte> factor = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        for(int i = 1; i <= d; i++)
        {
            ReadOnlySpan<byte> z = evaluationPoint[i - 1].AsReadOnlySpan();
            ReadOnlySpan<byte> v = challengesForLevel[i].AsReadOnlySpan();

            //product = z·v.
            multiply(z, v, product, curve);

            //factor = 1 − z − v + 2·(z·v).
            one.CopyTo(factor);
            subtract(factor, z, factor, curve);
            subtract(factor, v, factor, curve);
            add(factor, product, factor, curve);
            add(factor, product, factor, curve);

            //result *= factor.
            multiply(result, factor, result, curve);
        }
    }


    //Evaluates a degree-2 polynomial in coefficient form (c_0, c_1, c_2) at
    //point r by Horner: ((c_2·r) + c_1)·r + c_0.
    private static Scalar EvaluateDegree2(
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> r,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> c0 = coefficients[..ScalarSize];
        ReadOnlySpan<byte> c1 = coefficients.Slice(ScalarSize, ScalarSize);
        ReadOnlySpan<byte> c2 = coefficients.Slice(2 * ScalarSize, ScalarSize);

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Span<byte> accumulator = owner.Memory.Span[..ScalarSize];

        //acc = c2·r + c1.
        multiply(c2, r, accumulator, curve);
        add(accumulator, c1, accumulator, curve);

        //acc = acc·r + c0.
        multiply(accumulator, r, accumulator, curve);
        add(accumulator, c0, accumulator, curve);

        return new Scalar(owner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }


    private static bool RoundPolynomialDegreeMatches(CompressedRoundPolynomial polynomial)
    {
        return polynomial.Degree == RoundPolynomialDegree;
    }


    private static bool IsCurveWired(CurveParameterSet curve)
    {
        return curve.Code == CurveParameterSet.Bls12Curve381.Code || curve.Code == CurveParameterSet.Bn254.Code;
    }


    private static FiatShamirOperationLabel RoundPolynomialLabel =>
        new(WellKnownBaseFoldEvaluationParameters.RoundPolynomial);
}
