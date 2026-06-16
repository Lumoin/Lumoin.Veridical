using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Batch verification of independent <em>aggregated</em> Bulletproofs range
/// proofs that share one <see cref="RangeProofKey"/> and the same
/// <c>(bitWidth, valueCount)</c> shape — the aggregated counterpart of
/// <see cref="BatchBulletproofRangeVerifier"/>, which batches single-value
/// proofs. Each aggregated proof already proves <c>m</c> values in one
/// logarithmic argument (<see cref="AggregatedBulletproofRangeVerifier"/>);
/// this batches <c>p</c> such proofs into one multiexponentiation, so a wall
/// of transactions each proving the same number of outputs verifies in a
/// single MSM.
/// </summary>
/// <remarks>
/// <para>
/// The technique is RG.5's: every proof's <c>t̂</c> consistency check and its
/// inner-product check collapse to single-multiexponentiation identities
/// (the IPA fold replaced by the closed-form s-vector
/// <c>s_i = ∏_j w_j^{±1}</c> over the <c>log₂(n·m)</c> round challenges), and
/// the identities combine under two fresh random weights per proof. What the
/// aggregation adds is the per-value structure carried over from §4.3: the
/// <c>t̂</c> right-hand side sums <c>z^{2+j}·V_j</c> over the proof's <c>m</c>
/// value commitments, the constant is the aggregated
/// <c>δ = (z−z²)⟨1,y^{nm}⟩ − Σ_j z^{3+j}⟨1,2^n⟩</c>, and the
/// <c>H</c>-generator weight at global index <c>i = j·n + b</c> carries
/// <c>z^{2+j}·2^b·y^{−i}</c>. The shared generators (<c>g, h, U</c> and the
/// <c>2·n·m</c> bit generators) appear once with accumulated coefficients and
/// decode once through the caching MSM.
/// </para>
/// </remarks>
public static class BatchAggregatedBulletproofRangeVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;

    //Label for the per-proof batch weights, distinct from the single-value
    //batch label so the two batch flavours never collide on a transcript.
    private const string BatchWeightLabelPrefix = "veridical.bulletproofs.range.aggbatch.weight";


    /// <summary>
    /// Verifies that every proof in <paramref name="proofs"/> attests its
    /// <c>valueCount</c> committed values (from
    /// <paramref name="valueCommitmentsConcatenated"/>) lie in
    /// <c>[0, 2^bitWidth)</c>. All proofs share <paramref name="key"/> and the
    /// <c>(bitWidth, valueCount)</c> shape.
    /// </summary>
    /// <param name="key">The shared key; its vector length must equal <c>bitWidth · valueCount</c>.</param>
    /// <param name="bitWidth">The per-value range width.</param>
    /// <param name="valueCount">The number of values each proof aggregates.</param>
    /// <param name="valueCommitmentsConcatenated">All proofs' value commitments back to back: proof 0's <c>valueCount</c> points, then proof 1's, and so on.</param>
    /// <param name="proofs">The aggregated proofs, each of vector length <c>bitWidth · valueCount</c>.</param>
    /// <param name="batchTranscript">The transcript the per-proof batch weights are squeezed from; bound to the batch's statement context by the caller.</param>
    /// <param name="newTranscript">Factory for each proof's verification transcript (the caller binds the statement context inside).</param>
    /// <returns><see langword="true"/> iff every proof verifies.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the shapes or counts do not line up.</exception>
    public static bool Verify(
        RangeProofKey key,
        int bitWidth,
        int valueCount,
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
        BaseMemoryPool pool)
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

        int proofCount = proofs.Count;
        if(proofCount == 0)
        {
            return true;
        }

        AggregatedBulletproofRangeProver.ValidateShape(key, bitWidth, valueCount);

        int total = bitWidth * valueCount;
        CurveParameterSet curve = key.Curve;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int rounds = BitOperations.Log2((uint)total);
        if(valueCommitmentsConcatenated.Length != proofCount * valueCount * g1Size)
        {
            throw new ArgumentException(
                $"The commitments must be {proofCount * valueCount} compressed G1 points ({proofCount * valueCount * g1Size} bytes); received {valueCommitmentsConcatenated.Length}.",
                nameof(valueCommitmentsConcatenated));
        }

        for(int p = 0; p < proofCount; p++)
        {
            if(proofs[p].BitWidth != total || proofs[p].Curve.Code != curve.Code)
            {
                throw new ArgumentException($"Proof {p} (vector length {proofs[p].BitWidth}, curve {proofs[p].Curve}) does not match bitWidth · valueCount = {total} over {curve}.", nameof(proofs));
            }
        }

        try
        {
            return VerifyCore(key, bitWidth, valueCount, valueCommitmentsConcatenated, proofs, batchTranscript, newTranscript, hash, squeeze, reduce, add, subtract, multiply, invert, g1Msm, pool, proofCount, total, g1Size, rounds);
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
        int bitWidth,
        int valueCount,
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
        BaseMemoryPool pool,
        int proofCount,
        int total,
        int g1Size,
        int rounds)
    {
        int n = bitWidth;
        int m = valueCount;
        CurveParameterSet curve = key.Curve;

        //One MSM: 3 shared (g, h, U) + 2·total shared (G_i, H_i) + per proof
        //(m value commitments, T1, T2, A, S) and its 2·rounds (L, R) points.
        int sharedCount = 3 + (2 * total);
        int perProofCount = m + 4 + (2 * rounds);
        int operandCount = sharedCount + (proofCount * perProofCount);

        using IMemoryOwner<byte> pointsOwner = pool.Rent(operandCount * g1Size);
        using IMemoryOwner<byte> scalarsOwner = pool.Rent(operandCount * ScalarSize);
        Span<byte> points = pointsOwner.Memory.Span[..(operandCount * g1Size)];
        Span<byte> scalars = scalarsOwner.Memory.Span[..(operandCount * ScalarSize)];
        scalars.Clear();

        const int IndexG = 0;
        const int IndexH = 1;
        const int IndexU = 2;
        int indexGFamily = 3;
        int indexHFamily = 3 + total;
        key.GetValueGenerator().CopyTo(points.Slice(IndexG * g1Size, g1Size));
        key.GetBlindingGenerator().CopyTo(points.Slice(IndexH * g1Size, g1Size));
        key.GetInnerProductGenerator().CopyTo(points.Slice(IndexU * g1Size, g1Size));
        for(int i = 0; i < total; i++)
        {
            key.GetGeneratorG(i).CopyTo(points.Slice((indexGFamily + i) * g1Size, g1Size));
            key.GetGeneratorH(i).CopyTo(points.Slice((indexHFamily + i) * g1Size, g1Size));
        }

        using IMemoryOwner<byte> challengeOwner = pool.Rent(rounds * ScalarSize);
        using IMemoryOwner<byte> sVectorOwner = pool.Rent(total * ScalarSize);
        using IMemoryOwner<byte> powersTwoOwner = pool.Rent(n * ScalarSize);
        using IMemoryOwner<byte> yInvPowersOwner = pool.Rent(total * ScalarSize);
        using IMemoryOwner<byte> zPowersOwner = pool.Rent(m * ScalarSize);
        Span<byte> roundChallenges = challengeOwner.Memory.Span[..(rounds * ScalarSize)];
        Span<byte> sVector = sVectorOwner.Memory.Span[..(total * ScalarSize)];
        Span<byte> powersTwo = powersTwoOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> yInvPowers = yInvPowersOwner.Memory.Span[..(total * ScalarSize)];
        Span<byte> zPowers = zPowersOwner.Memory.Span[..(m * ScalarSize)];

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
        Span<byte> delta = stackalloc byte[ScalarSize];
        Span<byte> xSquared = stackalloc byte[ScalarSize];
        Span<byte> sInv = stackalloc byte[ScalarSize];
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        Span<byte> countBytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(countBytes, m);

        int commitmentsPerProof = m * g1Size;
        int perProofBase = sharedCount;
        for(int p = 0; p < proofCount; p++)
        {
            RangeProof proof = proofs[p];
            ReadOnlySpan<byte> proofCommitments = valueCommitmentsConcatenated.Slice(p * commitmentsPerProof, commitmentsPerProof);

            using FiatShamirTranscript transcript = newTranscript();

            //Replay the §4.3 schedule: aggregation count, every value
            //commitment, then the §4.2 spine.
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.AggregationCount), countBytes, hash);
            for(int j = 0; j < m; j++)
            {
                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ValueCommitment), proofCommitments.Slice(j * g1Size, g1Size), hash);
            }

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

            for(int round = 0; round < rounds; round++)
            {
                string roundIndex = round.ToString(CultureInfo.InvariantCulture);
                transcript.AbsorbBytes(new FiatShamirOperationLabel($"{WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix}.{roundIndex}.l"), proof.GetIpaRoundPairBytes().Slice(round * 2 * g1Size, g1Size), hash);
                transcript.AbsorbBytes(new FiatShamirOperationLabel($"{WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix}.{roundIndex}.r"), proof.GetIpaRoundPairBytes().Slice((round * 2 * g1Size) + g1Size, g1Size), hash);
                using Scalar w = transcript.SqueezeScalar(new FiatShamirOperationLabel($"{WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix}.{roundIndex}.challenge"), squeeze, hash, reduce, curve, pool);
                w.AsReadOnlySpan().CopyTo(roundChallenges.Slice(round * ScalarSize, ScalarSize));
            }

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
            BulletproofRangeComputation.BuildPowers(yInverse, yInvPowers, total, multiply, curve);

            //z^{2+j}: zPowers[j] = z²·z^j.
            zSquared.CopyTo(zPowers[..ScalarSize]);
            for(int j = 1; j < m; j++)
            {
                multiply(zPowers.Slice((j - 1) * ScalarSize, ScalarSize), zBytes, zPowers.Slice(j * ScalarSize, ScalarSize), curve);
            }

            BatchBulletproofRangeVerifier.ComputeSVector(roundChallenges, rounds, total, sVector, multiply, invert, curve);

            //--- The t̂ equation, weighted by α_p ---
            //(t̂ − δ)·g + τ_x·h − Σ_j z^{2+j}·V_j − x·T1 − x²·T2 == 0.
            ComputeAggregatedDelta(yBytes, zBytes, zSquared, zPowers, powersTwo, n, m, total, delta, add, subtract, multiply, curve, pool);

            subtract(proof.GetTHatBytes(), delta, term, curve);
            AccumulateScalar(scalars, IndexG, tWeight, term, add, multiply, curve);
            AccumulateScalar(scalars, IndexH, tWeight, proof.GetTauXBytes(), add, multiply, curve);

            int proofBase = perProofBase + (p * perProofCount);
            //Value commitments V_j: coefficient α_p·(−z^{2+j}).
            for(int j = 0; j < m; j++)
            {
                proofCommitments.Slice(j * g1Size, g1Size).CopyTo(points.Slice((proofBase + j) * g1Size, g1Size));
                subtract(zero, zPowers.Slice(j * ScalarSize, ScalarSize), term, curve);
                SetScalar(scalars, proofBase + j, tWeight, term, multiply, curve);
            }

            int afterCommitments = proofBase + m;
            //T1: α_p·(−x).
            proof.GetT1Bytes().CopyTo(points.Slice(afterCommitments * g1Size, g1Size));
            subtract(zero, xBytes, term, curve);
            SetScalar(scalars, afterCommitments, tWeight, term, multiply, curve);
            //T2: α_p·(−x²).
            multiply(xBytes, xBytes, xSquared, curve);
            proof.GetT2Bytes().CopyTo(points.Slice((afterCommitments + 1) * g1Size, g1Size));
            subtract(zero, xSquared, term, curve);
            SetScalar(scalars, afterCommitments + 1, tWeight, term, multiply, curve);

            //--- The IPA equation, weighted by β_p ---
            int aIndex = afterCommitments + 2;
            int sIndex = aIndex + 1;
            //A: +β_p.
            proof.GetABytes().CopyTo(points.Slice(aIndex * g1Size, g1Size));
            weight.CopyTo(scalars.Slice(aIndex * ScalarSize, ScalarSize));
            //S: +β_p·x.
            proof.GetSBytes().CopyTo(points.Slice(sIndex * g1Size, g1Size));
            multiply(weight, xBytes, term, curve);
            term.CopyTo(scalars.Slice(sIndex * ScalarSize, ScalarSize));

            //h += β_p·(−μ).
            subtract(zero, proof.GetMuBytes(), term, curve);
            AccumulateScalar(scalars, IndexH, weight, term, add, multiply, curve);
            //U += β_p·(t̂ − a·b).
            ReadOnlySpan<byte> finalA = proof.GetIpaFinalABytes();
            ReadOnlySpan<byte> finalB = proof.GetIpaFinalBBytes();
            multiply(finalA, finalB, term, curve);
            subtract(proof.GetTHatBytes(), term, term, curve);
            AccumulateScalar(scalars, IndexU, weight, term, add, multiply, curve);

            //G_i += β_p·(−z − a·s_i).
            for(int i = 0; i < total; i++)
            {
                multiply(finalA, sVector.Slice(i * ScalarSize, ScalarSize), term, curve);
                add(term, zBytes, term, curve);
                subtract(zero, term, term, curve);
                AccumulateScalar(scalars, indexGFamily + i, weight, term, add, multiply, curve);
            }

            //H_i += β_p·((z + z^{2+j}·2^b·y^{−i}) − b·s_i^{−1}·y^{−i}),
            //with j = i / n, b = i % n.
            for(int i = 0; i < total; i++)
            {
                int valueIndex = i / n;
                int bitIndex = i % n;
                multiply(zPowers.Slice(valueIndex * ScalarSize, ScalarSize), powersTwo.Slice(bitIndex * ScalarSize, ScalarSize), term, curve);
                multiply(term, yInvPowers.Slice(i * ScalarSize, ScalarSize), term, curve);
                add(term, zBytes, term, curve);

                invert(sVector.Slice(i * ScalarSize, ScalarSize), sInv, curve);
                multiply(finalB, sInv, term2, curve);
                multiply(term2, yInvPowers.Slice(i * ScalarSize, ScalarSize), term2, curve);
                subtract(term, term2, term, curve);
                AccumulateScalar(scalars, indexHFamily + i, weight, term, add, multiply, curve);
            }

            //L_j: β_p·w_j² ; R_j: β_p·w_j^{−2}.
            ReadOnlySpan<byte> roundPairs = proof.GetIpaRoundPairBytes();
            int roundBase = sIndex + 1;
            for(int round = 0; round < rounds; round++)
            {
                ReadOnlySpan<byte> w = roundChallenges.Slice(round * ScalarSize, ScalarSize);
                int lIndex = roundBase + (2 * round);
                int rIndex = lIndex + 1;
                roundPairs.Slice(round * 2 * g1Size, g1Size).CopyTo(points.Slice(lIndex * g1Size, g1Size));
                roundPairs.Slice((round * 2 * g1Size) + g1Size, g1Size).CopyTo(points.Slice(rIndex * g1Size, g1Size));

                multiply(w, w, term, curve);
                SetScalar(scalars, lIndex, weight, term, multiply, curve);
                invert(term, term2, curve);
                SetScalar(scalars, rIndex, weight, term2, multiply, curve);
            }
        }

        Span<byte> resultBytes = stackalloc byte[64];
        Span<byte> result = resultBytes[..g1Size];
        g1Msm(points, scalars, operandCount, result, curve);

        Span<byte> identityBytes = stackalloc byte[64];
        Span<byte> identity = identityBytes[..g1Size];
        EncodeIdentity(key, identity, g1Msm, curve, pool);

        return result.SequenceEqual(identity);
    }


    //δ(y, z) = (z − z²)·⟨1, y^{nm}⟩ − Σ_j z^{3+j}·⟨1, 2^n⟩ — the aggregated
    //constant: the two-power sum runs over one value's width, weighted per
    //value by z^{3+j}.
    private static void ComputeAggregatedDelta(
        ReadOnlySpan<byte> y,
        ReadOnlySpan<byte> z,
        ReadOnlySpan<byte> zSquared,
        ReadOnlySpan<byte> zPowers,
        ReadOnlySpan<byte> powersTwo,
        int n,
        int m,
        int total,
        Span<byte> delta,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> powersYOwner = pool.Rent(total * ScalarSize);
        Span<byte> powersY = powersYOwner.Memory.Span[..(total * ScalarSize)];
        BulletproofRangeComputation.BuildPowers(y, powersY, total, multiply, curve);

        Span<byte> sumY = stackalloc byte[ScalarSize];
        Span<byte> sumTwo = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.SumEntries(powersY, total, sumY, add, curve);
        BulletproofRangeComputation.SumEntries(powersTwo, n, sumTwo, add, curve);

        Span<byte> term = stackalloc byte[ScalarSize];
        subtract(z, zSquared, delta, curve);
        multiply(delta, sumY, delta, curve);
        for(int j = 0; j < m; j++)
        {
            //z^{3+j} = z·z^{2+j}.
            multiply(zPowers.Slice(j * ScalarSize, ScalarSize), z, term, curve);
            multiply(term, sumTwo, term, curve);
            subtract(delta, term, delta, curve);
        }
    }


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


    private static void EncodeIdentity(RangeProofKey key, Span<byte> destination, G1MultiScalarMultiplyDelegate g1Msm, CurveParameterSet curve, BaseMemoryPool pool)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        using IMemoryOwner<byte> pointOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> scalarOwner = pool.Rent(ScalarSize);
        key.GetValueGenerator().CopyTo(pointOwner.Memory.Span[..g1Size]);
        scalarOwner.Memory.Span[..ScalarSize].Clear();
        g1Msm(pointOwner.Memory.Span[..g1Size], scalarOwner.Memory.Span[..ScalarSize], 1, destination, curve);
    }
}
