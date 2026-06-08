using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Verifies an aggregated Bulletproofs range proof
/// (<see cref="AggregatedBulletproofRangeProver"/>) against the <c>m</c>
/// Pedersen value commitments: replays the prover's transcript schedule
/// (aggregation count, every commitment, the §4.2 spine), checks the
/// aggregated <c>t̂</c> consistency equation
/// <c>t̂·g + τ_x·h == Σ_j z^{2+j}·V_j + δ(y,z)·g + x·T₁ + x²·T₂</c> with the
/// aggregated <c>δ(y,z) = (z−z²)·⟨1, y^{nm}⟩ − Σ_j z^{3+j}·⟨1, 2^n⟩</c>, and
/// runs the two-vector inner-product verification over the <c>n·m</c>-length
/// generator families. Exception-safe against malformed proof bytes.
/// </summary>
public static class AggregatedBulletproofRangeVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Verifies that every commitment in
    /// <paramref name="valueCommitmentsConcatenated"/> commits a value in
    /// <c>[0, 2^bitWidth)</c> under the aggregated <paramref name="proof"/>.
    /// The caller binds the transcript to the same statement context the
    /// prover used.
    /// </summary>
    /// <returns><see langword="true"/> iff every algebraic check passes.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the proof's shape does not match the key and counts, or the commitments span has the wrong length.</exception>
    public static bool Verify(
        RangeProofKey key,
        int bitWidth,
        int valueCount,
        ReadOnlySpan<byte> valueCommitmentsConcatenated,
        RangeProof proof,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        G1MultiScalarMultiplyDelegate g1Msm,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(g1ScalarMul);
        ArgumentNullException.ThrowIfNull(g1Msm);
        ArgumentNullException.ThrowIfNull(pool);

        AggregatedBulletproofRangeProver.ValidateShape(key, bitWidth, valueCount);

        int total = bitWidth * valueCount;
        CurveParameterSet curve = key.Curve;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        if(proof.BitWidth != total || proof.Curve.Code != curve.Code)
        {
            throw new ArgumentException(
                $"The proof's shape (vector length {proof.BitWidth}, curve {proof.Curve}) does not match bitWidth · valueCount = {total} over {curve}.",
                nameof(proof));
        }

        if(valueCommitmentsConcatenated.Length != valueCount * g1Size)
        {
            throw new ArgumentException(
                $"The commitments must be exactly {valueCount} compressed G1 points ({valueCount * g1Size} bytes); received {valueCommitmentsConcatenated.Length}.",
                nameof(valueCommitmentsConcatenated));
        }

        //Adversarial proof bytes can fail point decoding or other backend
        //invariants anywhere below; every such failure is a rejection.
        try
        {
            return VerifyCore(key, bitWidth, valueCount, valueCommitmentsConcatenated, proof, transcript, hash, squeeze, reduce, add, subtract, multiply, invert, g1Add, g1ScalarMul, g1Msm, pool);
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
        RangeProof proof,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        G1MultiScalarMultiplyDelegate g1Msm,
        SensitiveMemoryPool<byte> pool)
    {
        int n = bitWidth;
        int m = valueCount;
        int total = n * m;
        CurveParameterSet curve = key.Curve;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);

        //Replay the prover's absorb/squeeze schedule.
        Span<byte> countBytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(countBytes, m);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.AggregationCount), countBytes, hash);
        for(int j = 0; j < m; j++)
        {
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ValueCommitment), valueCommitmentsConcatenated.Slice(j * g1Size, g1Size), hash);
        }

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.BitCommitment), proof.GetABytes(), hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.BlindingCommitment), proof.GetSBytes(), hash);

        using Scalar y = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ChallengeY), squeeze, hash, reduce, curve, pool);
        using Scalar z = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ChallengeZ), squeeze, hash, reduce, curve, pool);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.PolynomialCommitmentT1), proof.GetT1Bytes(), hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.PolynomialCommitmentT2), proof.GetT2Bytes(), hash);

        using Scalar x = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ChallengeX), squeeze, hash, reduce, curve, pool);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.TauX), proof.GetTauXBytes(), hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.Mu), proof.GetMuBytes(), hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.THat), proof.GetTHatBytes(), hash);

        //Challenge-derived vectors over the aggregate length, plus the
        //per-block two-powers and the per-value z powers.
        using IMemoryOwner<byte> vectorsOwner = pool.Rent((2 * total * ScalarSize) + (n * ScalarSize) + (m * ScalarSize));
        Span<byte> vectors = vectorsOwner.Memory.Span[..((2 * total * ScalarSize) + (n * ScalarSize) + (m * ScalarSize))];
        Span<byte> powersY = vectors.Slice(0 * total * ScalarSize, total * ScalarSize);
        Span<byte> yInvPowers = vectors.Slice(1 * total * ScalarSize, total * ScalarSize);
        Span<byte> powersTwo = vectors.Slice(2 * total * ScalarSize, n * ScalarSize);
        Span<byte> zPowers = vectors.Slice((2 * total * ScalarSize) + (n * ScalarSize), m * ScalarSize);

        BulletproofRangeComputation.BuildPowers(y.AsReadOnlySpan(), powersY, total, multiply, curve);
        Span<byte> two = stackalloc byte[ScalarSize];
        two.Clear();
        two[^1] = 0x02;
        BulletproofRangeComputation.BuildPowers(two, powersTwo, n, multiply, curve);
        Span<byte> yInverse = stackalloc byte[ScalarSize];
        invert(y.AsReadOnlySpan(), yInverse, curve);
        BulletproofRangeComputation.BuildPowers(yInverse, yInvPowers, total, multiply, curve);

        Span<byte> zSquared = stackalloc byte[ScalarSize];
        multiply(z.AsReadOnlySpan(), z.AsReadOnlySpan(), zSquared, curve);
        zSquared.CopyTo(zPowers[..ScalarSize]);
        for(int j = 1; j < m; j++)
        {
            multiply(zPowers.Slice((j - 1) * ScalarSize, ScalarSize), z.AsReadOnlySpan(), zPowers.Slice(j * ScalarSize, ScalarSize), curve);
        }

        //δ(y, z) = (z − z²)·⟨1, y^{nm}⟩ − Σ_j z^{3+j}·⟨1, 2^n⟩.
        Span<byte> sumY = stackalloc byte[ScalarSize];
        Span<byte> sumTwo = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.SumEntries(powersY, total, sumY, add, curve);
        BulletproofRangeComputation.SumEntries(powersTwo, n, sumTwo, add, curve);

        Span<byte> delta = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        subtract(z.AsReadOnlySpan(), zSquared, delta, curve);
        multiply(delta, sumY, delta, curve);
        for(int j = 0; j < m; j++)
        {
            //z^{3+j} = z·z^{2+j}.
            multiply(zPowers.Slice(j * ScalarSize, ScalarSize), z.AsReadOnlySpan(), term, curve);
            multiply(term, sumTwo, term, curve);
            subtract(delta, term, delta, curve);
        }

        //Check 1: t̂·g + τ_x·h == Σ_j z^{2+j}·V_j + δ·g + x·T₁ + x²·T₂.
        Span<byte> xSquared = stackalloc byte[ScalarSize];
        multiply(x.AsReadOnlySpan(), x.AsReadOnlySpan(), xSquared, curve);

        Span<byte> lhsBytes = stackalloc byte[64];
        Span<byte> rhsBytes = stackalloc byte[64];
        Span<byte> lhs = lhsBytes[..g1Size];
        Span<byte> rhs = rhsBytes[..g1Size];
        {
            const int LhsOperandCount = 2;
            using IMemoryOwner<byte> pointsOwner = pool.Rent(LhsOperandCount * g1Size);
            using IMemoryOwner<byte> scalarsOwner = pool.Rent(LhsOperandCount * ScalarSize);
            Span<byte> points = pointsOwner.Memory.Span[..(LhsOperandCount * g1Size)];
            Span<byte> scalars = scalarsOwner.Memory.Span[..(LhsOperandCount * ScalarSize)];
            key.GetValueGenerator().CopyTo(points[..g1Size]);
            key.GetBlindingGenerator().CopyTo(points.Slice(g1Size, g1Size));
            proof.GetTHatBytes().CopyTo(scalars[..ScalarSize]);
            proof.GetTauXBytes().CopyTo(scalars.Slice(ScalarSize, ScalarSize));
            g1Msm(points, scalars, LhsOperandCount, lhs, curve);
        }

        {
            int rhsOperandCount = m + 3;
            using IMemoryOwner<byte> pointsOwner = pool.Rent(rhsOperandCount * g1Size);
            using IMemoryOwner<byte> scalarsOwner = pool.Rent(rhsOperandCount * ScalarSize);
            Span<byte> points = pointsOwner.Memory.Span[..(rhsOperandCount * g1Size)];
            Span<byte> scalars = scalarsOwner.Memory.Span[..(rhsOperandCount * ScalarSize)];
            for(int j = 0; j < m; j++)
            {
                valueCommitmentsConcatenated.Slice(j * g1Size, g1Size).CopyTo(points.Slice(j * g1Size, g1Size));
                zPowers.Slice(j * ScalarSize, ScalarSize).CopyTo(scalars.Slice(j * ScalarSize, ScalarSize));
            }

            key.GetValueGenerator().CopyTo(points.Slice(m * g1Size, g1Size));
            proof.GetT1Bytes().CopyTo(points.Slice((m + 1) * g1Size, g1Size));
            proof.GetT2Bytes().CopyTo(points.Slice((m + 2) * g1Size, g1Size));
            delta.CopyTo(scalars.Slice(m * ScalarSize, ScalarSize));
            x.AsReadOnlySpan().CopyTo(scalars.Slice((m + 1) * ScalarSize, ScalarSize));
            xSquared.CopyTo(scalars.Slice((m + 2) * ScalarSize, ScalarSize));
            g1Msm(points, scalars, rhsOperandCount, rhs, curve);
        }

        if(!lhs.SequenceEqual(rhs))
        {
            return false;
        }

        //The reduced commitment the IPA verifies against:
        //P = A + x·S − z·⟨1, G⟩ + Σ_k (z + z^{2+j}·2^i·y^{−k})·H_k − μ·h,
        //with k = j·n + i.
        Span<byte> pCommitmentBytes = stackalloc byte[64];
        Span<byte> pCommitment = pCommitmentBytes[..g1Size];
        {
            int operandCount = (2 * total) + 3;
            using IMemoryOwner<byte> pointsOwner = pool.Rent(operandCount * g1Size);
            using IMemoryOwner<byte> scalarsOwner = pool.Rent(operandCount * ScalarSize);
            Span<byte> points = pointsOwner.Memory.Span[..(operandCount * g1Size)];
            Span<byte> scalars = scalarsOwner.Memory.Span[..(operandCount * ScalarSize)];

            Span<byte> negZ = stackalloc byte[ScalarSize];
            Span<byte> negMu = stackalloc byte[ScalarSize];
            Span<byte> zero = stackalloc byte[ScalarSize];
            zero.Clear();
            subtract(zero, z.AsReadOnlySpan(), negZ, curve);
            subtract(zero, proof.GetMuBytes(), negMu, curve);

            proof.GetABytes().CopyTo(points[..g1Size]);
            BulletproofRangeComputation.WriteOne(scalars[..ScalarSize]);

            proof.GetSBytes().CopyTo(points.Slice(g1Size, g1Size));
            x.AsReadOnlySpan().CopyTo(scalars.Slice(ScalarSize, ScalarSize));

            for(int k = 0; k < total; k++)
            {
                key.GetGeneratorG(k).CopyTo(points.Slice((2 + k) * g1Size, g1Size));
                negZ.CopyTo(scalars.Slice((2 + k) * ScalarSize, ScalarSize));
            }

            //w_k = (z·y^k + z^{2+j}·2^i)·y^{−k} = z + z^{2+j}·2^i·y^{−k} — the
            //H'-basis weight expressed directly on H_k.
            for(int j = 0; j < m; j++)
            {
                for(int i = 0; i < n; i++)
                {
                    int k = (j * n) + i;
                    key.GetGeneratorH(k).CopyTo(points.Slice((2 + total + k) * g1Size, g1Size));
                    Span<byte> weight = scalars.Slice((2 + total + k) * ScalarSize, ScalarSize);
                    multiply(zPowers.Slice(j * ScalarSize, ScalarSize), powersTwo.Slice(i * ScalarSize, ScalarSize), weight, curve);
                    multiply(weight, yInvPowers.Slice(k * ScalarSize, ScalarSize), weight, curve);
                    add(weight, z.AsReadOnlySpan(), weight, curve);
                }
            }

            key.GetBlindingGenerator().CopyTo(points.Slice((2 + (2 * total)) * g1Size, g1Size));
            negMu.CopyTo(scalars.Slice((2 + (2 * total)) * ScalarSize, ScalarSize));

            g1Msm(points, scalars, operandCount, pCommitment, curve);
        }

        //The two-vector IPA over (G, H' = y^{−k}·H) against claim t̂.
        using IMemoryOwner<byte> generatorsOwner = pool.Rent(2 * total * g1Size);
        Span<byte> gWorking = generatorsOwner.Memory.Span[..(total * g1Size)];
        Span<byte> hPrime = generatorsOwner.Memory.Span.Slice(total * g1Size, total * g1Size);
        BulletproofRangeComputation.LoadGFamily(key, gWorking, curve);
        BulletproofRangeComputation.BuildScaledHFamily(key, yInvPowers, hPrime, g1ScalarMul, curve);

        return TwoVectorInnerProductArgument.Verify(
            pCommitment, proof.GetTHatBytes(), proof.GetIpaFinalABytes(), proof.GetIpaFinalBBytes(),
            proof.GetIpaRoundPairBytes(), key.GetInnerProductGenerator(),
            gWorking, hPrime, total, WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix, transcript,
            add, multiply, invert, reduce, g1Add, g1ScalarMul, hash, squeeze, curve, pool);
    }
}
