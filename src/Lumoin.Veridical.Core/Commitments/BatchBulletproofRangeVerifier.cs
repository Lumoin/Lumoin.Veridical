using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Batch verification of independent single-value Bulletproofs range proofs
/// sharing one <see cref="RangeProofKey"/> (Bünz et al, IEEE S&amp;P 2018,
/// §6.1): rather than verifying each proof with its own
/// <c>O(n)</c>-point-fold inner-product check, every proof is collapsed to
/// its single-multiexponentiation form and the forms are combined by a fresh
/// random weight per proof into one multiexponentiation. The shared
/// generators (<c>g, h, U</c> and the <c>2n</c> bit generators) appear once
/// with accumulated coefficients, so a batch of <c>m</c> proofs costs one MSM
/// of <c>3 + 2n + m·(5 + 2·log₂n)</c> operands instead of <c>m</c> full
/// verifications.
/// </summary>
/// <remarks>
/// <para>
/// Each proof yields two point identities that must each equal the group
/// identity: the <c>t̂</c> consistency equation and the inner-product
/// equation rewritten as a single multiexponentiation through the IPA
/// <em>s-vector</em> (<c>s_i = ∏_j w_j^{±1}</c> by the bit pattern of
/// <c>i</c>, the closed form of the folded final generators). A random
/// linear combination of identities is the identity exactly when all of them
/// are, except on a weight set of measure <c>≤ 2m/|F|</c> (Schwartz-Zippel) —
/// so a forged proof survives the batch only with negligible probability.
/// The random weights are squeezed from the post-replay transcript state, so
/// they bind every proof's challenges and need no verifier-held randomness.
/// </para>
/// <para>
/// The combined equation is gated against the per-proof
/// <see cref="BulletproofRangeVerifier"/> by construction: a single-proof
/// batch must accept exactly what the fold-based verifier accepts, which the
/// tests pin and which would break immediately on a wrong s-vector
/// orientation.
/// </para>
/// </remarks>
public static class BatchBulletproofRangeVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;

    //Label for the per-proof batch weights, squeezed after every proof's
    //challenges have been replayed into the transcript.
    private const string BatchWeightLabelPrefix = "veridical.bulletproofs.range.batch.weight";


    /// <summary>
    /// Verifies that every <paramref name="valueCommitmentsConcatenated"/>
    /// entry commits a value in <c>[0, 2^BitWidth)</c> under the
    /// corresponding proof in <paramref name="proofs"/>. Each proof gets its
    /// own fresh transcript from <paramref name="newTranscript"/>, bound to
    /// the same statement context the prover used, replayed in proof order.
    /// </summary>
    /// <param name="key">The shared range-proof key.</param>
    /// <param name="valueCommitmentsConcatenated">The value commitments, one compressed G1 point per proof, in proof order.</param>
    /// <param name="proofs">The proofs to batch; all single-value over <paramref name="key"/>'s width.</param>
    /// <param name="batchTranscript">The transcript the per-proof batch weights are squeezed from; bound to the batch's statement context by the caller.</param>
    /// <param name="newTranscript">Factory for each proof's verification transcript (the caller binds the statement context inside).</param>
    /// <returns><see langword="true"/> iff every proof verifies.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the counts or shapes do not line up.</exception>
    public static bool Verify(
        RangeProofKey key,
        ReadOnlySpan<byte> valueCommitmentsConcatenated,
        IReadOnlyList<RangeProof> proofs,
        FiatShamirTranscript batchTranscript,
        Func<FiatShamirTranscript> newTranscript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        G1MultiScalarMultiplyDelegate g1Msm,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(proofs);
        ArgumentNullException.ThrowIfNull(batchTranscript);
        ArgumentNullException.ThrowIfNull(newTranscript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(g1Msm);
        ArgumentNullException.ThrowIfNull(pool);

        int m = proofs.Count;
        if(m == 0)
        {
            return true;
        }

        int n = key.BitWidth;
        CurveParameterSet curve = key.Curve;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int rounds = BitOperations.Log2((uint)n);
        if(valueCommitmentsConcatenated.Length != m * g1Size)
        {
            throw new ArgumentException(
                $"The commitments must be {m} compressed G1 points ({m * g1Size} bytes); received {valueCommitmentsConcatenated.Length}.",
                nameof(valueCommitmentsConcatenated));
        }

        for(int p = 0; p < m; p++)
        {
            if(proofs[p].BitWidth != n || proofs[p].Curve.Code != curve.Code)
            {
                throw new ArgumentException($"Proof {p} (width {proofs[p].BitWidth}, curve {proofs[p].Curve}) does not match the key (width {n}, curve {curve}).", nameof(proofs));
            }
        }

        try
        {
            return VerifyCore(key, valueCommitmentsConcatenated, proofs, batchTranscript, newTranscript, hash, squeeze, reduce, add, subtract, multiply, invert, g1Msm, pool, m, n, g1Size, rounds);
        }
        catch(InvalidOperationException)
        {
            return false;
        }
        catch(ArgumentException)
        {
            return false;
        }
    }


    private static bool VerifyCore(
        RangeProofKey key,
        ReadOnlySpan<byte> valueCommitmentsConcatenated,
        IReadOnlyList<RangeProof> proofs,
        FiatShamirTranscript batchTranscript,
        Func<FiatShamirTranscript> newTranscript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        G1MultiScalarMultiplyDelegate g1Msm,
        SensitiveMemoryPool<byte> pool,
        int m,
        int n,
        int g1Size,
        int rounds)
    {
        CurveParameterSet curve = key.Curve;

        //One MSM: 3 shared scalars (g, h, U) + 2n shared (G_i, H_i)
        //+ per proof (V, T1, T2, A, S) and its 2·rounds (L, R) round points.
        int sharedCount = 3 + (2 * n);
        int perProofCount = 5 + (2 * rounds);
        int operandCount = sharedCount + (m * perProofCount);

        using IMemoryOwner<byte> pointsOwner = pool.Rent(operandCount * g1Size);
        using IMemoryOwner<byte> scalarsOwner = pool.Rent(operandCount * ScalarSize);
        Span<byte> points = pointsOwner.Memory.Span[..(operandCount * g1Size)];
        Span<byte> scalars = scalarsOwner.Memory.Span[..(operandCount * ScalarSize)];
        scalars.Clear();

        //Shared generator layout: [0]=g (value gen), [1]=h (blinding gen),
        //[2]=U (inner-product gen), [3..3+n)=G_i, [3+n..3+2n)=H_i.
        const int IndexG = 0;
        const int IndexH = 1;
        const int IndexU = 2;
        int indexGFamily = 3;
        int indexHFamily = 3 + n;
        key.GetValueGenerator().CopyTo(points.Slice(IndexG * g1Size, g1Size));
        key.GetBlindingGenerator().CopyTo(points.Slice(IndexH * g1Size, g1Size));
        key.GetInnerProductGenerator().CopyTo(points.Slice(IndexU * g1Size, g1Size));
        for(int i = 0; i < n; i++)
        {
            key.GetGeneratorG(i).CopyTo(points.Slice((indexGFamily + i) * g1Size, g1Size));
            key.GetGeneratorH(i).CopyTo(points.Slice((indexHFamily + i) * g1Size, g1Size));
        }

        //Per-proof scratch.
        using IMemoryOwner<byte> challengeOwner = pool.Rent(rounds * ScalarSize);
        using IMemoryOwner<byte> sVectorOwner = pool.Rent(n * ScalarSize);
        using IMemoryOwner<byte> powersTwoOwner = pool.Rent(n * ScalarSize);
        using IMemoryOwner<byte> yInvPowersOwner = pool.Rent(n * ScalarSize);
        Span<byte> roundChallenges = challengeOwner.Memory.Span[..(rounds * ScalarSize)];
        Span<byte> sVector = sVectorOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> powersTwo = powersTwoOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> yInvPowers = yInvPowersOwner.Memory.Span[..(n * ScalarSize)];

        Span<byte> two = stackalloc byte[ScalarSize];
        two.Clear();
        two[^1] = 0x02;

        Span<byte> weight = stackalloc byte[ScalarSize];     //β_p, the IPA-equation weight.
        Span<byte> tWeight = stackalloc byte[ScalarSize];     //α_p, the t̂-equation weight.
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> term2 = stackalloc byte[ScalarSize];
        Span<byte> yBytes = stackalloc byte[ScalarSize];
        Span<byte> zBytes = stackalloc byte[ScalarSize];
        Span<byte> xBytes = stackalloc byte[ScalarSize];
        Span<byte> zSquared = stackalloc byte[ScalarSize];
        Span<byte> yInverse = stackalloc byte[ScalarSize];
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        Span<byte> delta = stackalloc byte[ScalarSize];
        Span<byte> xSquared = stackalloc byte[ScalarSize];
        Span<byte> sInv = stackalloc byte[ScalarSize];

        int perProofBase = sharedCount;
        for(int p = 0; p < m; p++)
        {
            RangeProof proof = proofs[p];
            ReadOnlySpan<byte> valueCommitment = valueCommitmentsConcatenated.Slice(p * g1Size, g1Size);

            using FiatShamirTranscript transcript = newTranscript();

            //Replay the §4.2 schedule to recover y, z, x and the IPA round
            //challenges; the batch weights bind all of them.
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ValueCommitment), valueCommitment, hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.BitCommitment), proof.GetABytes(), hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.BlindingCommitment), proof.GetSBytes(), hash);
            using(Scalar y = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ChallengeY), squeeze, hash, reduce, curve, pool))
            {
                y.AsReadOnlySpan().CopyTo(yBytes);
            }

            using(Scalar z = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ChallengeZ), squeeze, hash, reduce, curve, pool))
            {
                z.AsReadOnlySpan().CopyTo(zBytes);
            }

            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.PolynomialCommitmentT1), proof.GetT1Bytes(), hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.PolynomialCommitmentT2), proof.GetT2Bytes(), hash);
            using(Scalar x = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ChallengeX), squeeze, hash, reduce, curve, pool))
            {
                x.AsReadOnlySpan().CopyTo(xBytes);
            }
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.TauX), proof.GetTauXBytes(), hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.Mu), proof.GetMuBytes(), hash);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.THat), proof.GetTHatBytes(), hash);

            //IPA round challenges (the verifier absorbs L, R, squeezes w_j).
            for(int round = 0; round < rounds; round++)
            {
                string roundIndex = round.ToString(CultureInfo.InvariantCulture);
                transcript.AbsorbBytes(new FiatShamirOperationLabel($"{WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix}.{roundIndex}.l"), proof.GetIpaRoundPairBytes().Slice(round * 2 * g1Size, g1Size), hash);
                transcript.AbsorbBytes(new FiatShamirOperationLabel($"{WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix}.{roundIndex}.r"), proof.GetIpaRoundPairBytes().Slice((round * 2 * g1Size) + g1Size, g1Size), hash);
                using Scalar w = transcript.SqueezeScalar(new FiatShamirOperationLabel($"{WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix}.{roundIndex}.challenge"), squeeze, hash, reduce, curve, pool);
                w.AsReadOnlySpan().CopyTo(roundChallenges.Slice(round * ScalarSize, ScalarSize));
            }

            //Two independent batch weights for this proof, squeezed from the
            //now-fully-bound batch transcript: β_p for the IPA equation, α_p
            //for the t̂ equation.
            batchTranscript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.THat), proof.GetTHatBytes(), hash);
            string proofIndex = p.ToString(CultureInfo.InvariantCulture);
            using(Scalar beta = batchTranscript.SqueezeScalar(new FiatShamirOperationLabel($"{BatchWeightLabelPrefix}.{proofIndex}.ipa"), squeeze, hash, reduce, curve, pool))
            {
                beta.AsReadOnlySpan().CopyTo(weight);
            }

            using(Scalar alpha = batchTranscript.SqueezeScalar(new FiatShamirOperationLabel($"{BatchWeightLabelPrefix}.{proofIndex}.that"), squeeze, hash, reduce, curve, pool))
            {
                alpha.AsReadOnlySpan().CopyTo(tWeight);
            }

            multiply(zBytes, zBytes, zSquared, curve);

            BulletproofRangeComputation.BuildPowers(two, powersTwo, n, multiply, curve);
            invert(yBytes, yInverse, curve);
            BulletproofRangeComputation.BuildPowers(yInverse, yInvPowers, n, multiply, curve);

            ComputeSVector(roundChallenges, rounds, n, sVector, multiply, invert, curve);

            //--- The t̂ equation, weighted by α_p ---
            //(t̂ − δ)·g + τ_x·h − z²·V − x·T1 − x²·T2 == 0.
            ComputeDelta(yBytes, zBytes, zSquared, powersTwo, yInvPowers, n, delta, add, subtract, multiply, curve, pool);

            //g coefficient += α_p·(t̂ − δ).
            subtract(proof.GetTHatBytes(), delta, term, curve);
            AccumulateScalar(scalars, IndexG, tWeight, term, add, multiply, curve);
            //h coefficient += α_p·τ_x.
            AccumulateScalar(scalars, IndexH, tWeight, proof.GetTauXBytes(), add, multiply, curve);

            int proofBase = perProofBase + (p * perProofCount);
            //V_p: coefficient α_p·(−z²).
            valueCommitment.CopyTo(points.Slice(proofBase * g1Size, g1Size));
            subtract(zero, zSquared, term, curve);
            SetScalar(scalars, proofBase, tWeight, term, multiply, curve);
            //T1_p: α_p·(−x).
            proof.GetT1Bytes().CopyTo(points.Slice((proofBase + 1) * g1Size, g1Size));
            subtract(zero, xBytes, term, curve);
            SetScalar(scalars, proofBase + 1, tWeight, term, multiply, curve);
            //T2_p: α_p·(−x²).
            multiply(xBytes, xBytes, xSquared, curve);
            proof.GetT2Bytes().CopyTo(points.Slice((proofBase + 2) * g1Size, g1Size));
            subtract(zero, xSquared, term, curve);
            SetScalar(scalars, proofBase + 2, tWeight, term, multiply, curve);

            //--- The IPA equation, weighted by β_p ---
            //A: +1 ; S: +x ; G_i: −z − a·s_i ; H_i: w_i − b·s_i^{-1}·y^{-i} ;
            //h: −μ ; U: t̂ − a·b ; L_j: w_j² ; R_j: w_j^{-2}.
            //A_p.
            proof.GetABytes().CopyTo(points.Slice((proofBase + 3) * g1Size, g1Size));
            weight.CopyTo(scalars.Slice((proofBase + 3) * ScalarSize, ScalarSize));
            //S_p.
            proof.GetSBytes().CopyTo(points.Slice((proofBase + 4) * g1Size, g1Size));
            multiply(weight, xBytes, term, curve);
            term.CopyTo(scalars.Slice((proofBase + 4) * ScalarSize, ScalarSize));

            //h coefficient += β_p·(−μ).
            subtract(zero, proof.GetMuBytes(), term, curve);
            AccumulateScalar(scalars, IndexH, weight, term, add, multiply, curve);
            //U coefficient += β_p·(t̂ − a·b).
            ReadOnlySpan<byte> finalA = proof.GetIpaFinalABytes();
            ReadOnlySpan<byte> finalB = proof.GetIpaFinalBBytes();
            multiply(finalA, finalB, term, curve);
            subtract(proof.GetTHatBytes(), term, term, curve);
            AccumulateScalar(scalars, IndexU, weight, term, add, multiply, curve);

            //G_i coefficient += β_p·(−z − a·s_i).
            for(int i = 0; i < n; i++)
            {
                multiply(finalA, sVector.Slice(i * ScalarSize, ScalarSize), term, curve);
                add(term, zBytes, term, curve);
                subtract(zero, term, term, curve);
                AccumulateScalar(scalars, indexGFamily + i, weight, term, add, multiply, curve);
            }

            //H_i coefficient += β_p·(w_i − b·s_i^{-1}·y^{-i}), with the IPA's
            //H' basis: w_i = (z + z²·2^i·y^{-i}) is the range weight, the IPA
            //folds H' = y^{-i}·H so the s-vector term on H_i carries y^{-i}.
            for(int i = 0; i < n; i++)
            {
                //Range weight on H_i.
                multiply(zSquared, powersTwo.Slice(i * ScalarSize, ScalarSize), term, curve);
                multiply(term, yInvPowers.Slice(i * ScalarSize, ScalarSize), term, curve);
                add(term, zBytes, term, curve);
                //− b·s_i^{-1}·y^{-i}.
                invert(sVector.Slice(i * ScalarSize, ScalarSize), sInv, curve);
                multiply(finalB, sInv, term2, curve);
                multiply(term2, yInvPowers.Slice(i * ScalarSize, ScalarSize), term2, curve);
                subtract(term, term2, term, curve);
                AccumulateScalar(scalars, indexHFamily + i, weight, term, add, multiply, curve);
            }

            //L_j: β_p·w_j² ; R_j: β_p·w_j^{-2}.
            ReadOnlySpan<byte> roundPairs = proof.GetIpaRoundPairBytes();
            for(int round = 0; round < rounds; round++)
            {
                ReadOnlySpan<byte> w = roundChallenges.Slice(round * ScalarSize, ScalarSize);
                int lIndex = proofBase + 5 + (2 * round);
                int rIndex = lIndex + 1;
                roundPairs.Slice(round * 2 * g1Size, g1Size).CopyTo(points.Slice(lIndex * g1Size, g1Size));
                roundPairs.Slice((round * 2 * g1Size) + g1Size, g1Size).CopyTo(points.Slice(rIndex * g1Size, g1Size));

                multiply(w, w, term, curve);
                SetScalar(scalars, lIndex, weight, term, multiply, curve);
                invert(term, term2, curve);
                SetScalar(scalars, rIndex, weight, term2, multiply, curve);
            }
        }

        //The combined check: the whole multiexponentiation must be the group
        //identity. Compare against the encoded identity rather than a fixed
        //all-zero buffer so the curve's canonical infinity encoding is used.
        Span<byte> resultBytes = stackalloc byte[64];
        Span<byte> result = resultBytes[..g1Size];
        g1Msm(points, scalars, operandCount, result, curve);

        Span<byte> identityBytes = stackalloc byte[64];
        Span<byte> identity = identityBytes[..g1Size];
        EncodeIdentity(key, identity, g1Msm, curve, pool);


        return result.SequenceEqual(identity);
    }


    //s_i = ∏_{j=0}^{rounds-1} w_j^{ bit_{(rounds-1-j)}(i) ? +1 : −1 } — the
    //closed form of the IPA's folded final G generator coefficients (round 0
    //splits the top bit; G folds low·w^{-1} + high·w).
    internal static void ComputeSVector(
        ReadOnlySpan<byte> roundChallenges,
        int rounds,
        int n,
        Span<byte> sVector,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve)
    {
        Span<byte> inverses = stackalloc byte[16 * ScalarSize];     //rounds ≤ log2(4096) = 12.
        for(int j = 0; j < rounds; j++)
        {
            invert(roundChallenges.Slice(j * ScalarSize, ScalarSize), inverses.Slice(j * ScalarSize, ScalarSize), curve);
        }

        for(int i = 0; i < n; i++)
        {
            Span<byte> s = sVector.Slice(i * ScalarSize, ScalarSize);
            s.Clear();
            s[^1] = 0x01;
            for(int j = 0; j < rounds; j++)
            {
                bool bitSet = ((i >> (rounds - 1 - j)) & 1) == 1;
                ReadOnlySpan<byte> factor = bitSet
                    ? roundChallenges.Slice(j * ScalarSize, ScalarSize)
                    : inverses.Slice(j * ScalarSize, ScalarSize);
                multiply(s, factor, s, curve);
            }
        }
    }


    private static void ComputeDelta(
        ReadOnlySpan<byte> y,
        ReadOnlySpan<byte> z,
        ReadOnlySpan<byte> zSquared,
        ReadOnlySpan<byte> powersTwo,
        ReadOnlySpan<byte> yInvPowers,
        int n,
        Span<byte> delta,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        using IMemoryOwner<byte> powersYOwner = pool.Rent(n * ScalarSize);
        Span<byte> powersY = powersYOwner.Memory.Span[..(n * ScalarSize)];
        BulletproofRangeComputation.BuildPowers(y, powersY, n, multiply, curve);

        Span<byte> sumY = stackalloc byte[ScalarSize];
        Span<byte> sumTwo = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.SumEntries(powersY, n, sumY, add, curve);
        BulletproofRangeComputation.SumEntries(powersTwo, n, sumTwo, add, curve);

        Span<byte> zCubed = stackalloc byte[ScalarSize];
        multiply(zSquared, z, zCubed, curve);

        Span<byte> term = stackalloc byte[ScalarSize];
        subtract(z, zSquared, delta, curve);
        multiply(delta, sumY, delta, curve);
        multiply(zCubed, sumTwo, term, curve);
        subtract(delta, term, delta, curve);
    }


    //scalars[index] += weight · value.
    private static void AccumulateScalar(
        Span<byte> scalars,
        int index,
        ReadOnlySpan<byte> weight,
        ReadOnlySpan<byte> value,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        multiply(weight, value, product, curve);
        Span<byte> slot = scalars.Slice(index * ScalarSize, ScalarSize);
        add(slot, product, slot, curve);
    }


    //scalars[index] = weight · value.
    private static void SetScalar(
        Span<byte> scalars,
        int index,
        ReadOnlySpan<byte> weight,
        ReadOnlySpan<byte> value,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        multiply(weight, value, scalars.Slice(index * ScalarSize, ScalarSize), curve);
    }


    //The encoded group identity: 0·g via the MSM backend, so the canonical
    //infinity encoding matches whatever the batch MSM emits for the identity.
    private static void EncodeIdentity(RangeProofKey key, Span<byte> destination, G1MultiScalarMultiplyDelegate g1Msm, CurveParameterSet curve, SensitiveMemoryPool<byte> pool)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        using IMemoryOwner<byte> pointOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> scalarOwner = pool.Rent(ScalarSize);
        key.GetValueGenerator().CopyTo(pointOwner.Memory.Span[..g1Size]);
        scalarOwner.Memory.Span[..ScalarSize].Clear();
        g1Msm(pointOwner.Memory.Span[..g1Size], scalarOwner.Memory.Span[..ScalarSize], 1, destination, curve);
    }
}
