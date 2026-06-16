using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Verifies a Bulletproofs range proof against the Pedersen value commitment
/// and a <see cref="RangeProofKey"/>: replays the prover's transcript
/// schedule, checks the <c>t̂</c> consistency equation
/// <c>t̂·g + τ_x·h == z²·V + δ(y,z)·g + x·T₁ + x²·T₂</c>, and runs the
/// two-vector inner-product verification against the reduced commitment.
/// Exception-safe against malformed proof bytes — decode and backend
/// failures translate to a <see langword="false"/> return.
/// </summary>
public static class BulletproofRangeVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Verifies that <paramref name="valueCommitment"/> commits a value in
    /// <c>[0, 2^BitWidth)</c> under <paramref name="proof"/>. The caller
    /// binds the transcript to the same statement context the prover used.
    /// </summary>
    /// <returns><see langword="true"/> iff every algebraic check passes.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the proof's shape does not match the key or the commitment has the wrong length.</exception>
    public static bool Verify(
        RangeProofKey key,
        ReadOnlySpan<byte> valueCommitment,
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
        BaseMemoryPool pool)
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

        int n = key.BitWidth;
        CurveParameterSet curve = key.Curve;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        if(proof.BitWidth != n || proof.Curve.Code != curve.Code)
        {
            throw new ArgumentException(
                $"The proof's shape (bit width {proof.BitWidth}, curve {proof.Curve}) does not match the key (bit width {n}, curve {curve}).",
                nameof(proof));
        }

        if(valueCommitment.Length != g1Size)
        {
            throw new ArgumentException(
                $"The value commitment must be exactly {g1Size} bytes (one compressed G1 point); received {valueCommitment.Length}.",
                nameof(valueCommitment));
        }

        //Adversarial proof bytes can fail point decoding or other backend
        //invariants anywhere below; every such failure is a rejection.
        try
        {
            return VerifyCore(key, valueCommitment, proof, transcript, hash, squeeze, reduce, add, subtract, multiply, invert, g1Add, g1ScalarMul, g1Msm, pool);
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
        ReadOnlySpan<byte> valueCommitment,
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
        BaseMemoryPool pool)
    {
        int n = key.BitWidth;
        CurveParameterSet curve = key.Curve;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);

        //Replay the prover's absorb/squeeze schedule.
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ValueCommitment), valueCommitment, hash);
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

        //Challenge-derived vectors.
        const int VectorCount = 3;
        using IMemoryOwner<byte> vectorsOwner = pool.Rent(VectorCount * n * ScalarSize);
        Span<byte> vectors = vectorsOwner.Memory.Span[..(VectorCount * n * ScalarSize)];
        Span<byte> powersY = vectors.Slice(0 * n * ScalarSize, n * ScalarSize);
        Span<byte> powersTwo = vectors.Slice(1 * n * ScalarSize, n * ScalarSize);
        Span<byte> yInvPowers = vectors.Slice(2 * n * ScalarSize, n * ScalarSize);

        BulletproofRangeComputation.BuildPowers(y.AsReadOnlySpan(), powersY, n, multiply, curve);
        Span<byte> two = stackalloc byte[ScalarSize];
        two.Clear();
        two[^1] = 0x02;
        BulletproofRangeComputation.BuildPowers(two, powersTwo, n, multiply, curve);
        Span<byte> yInverse = stackalloc byte[ScalarSize];
        invert(y.AsReadOnlySpan(), yInverse, curve);
        BulletproofRangeComputation.BuildPowers(yInverse, yInvPowers, n, multiply, curve);

        Span<byte> zSquared = stackalloc byte[ScalarSize];
        Span<byte> zCubed = stackalloc byte[ScalarSize];
        multiply(z.AsReadOnlySpan(), z.AsReadOnlySpan(), zSquared, curve);
        multiply(zSquared, z.AsReadOnlySpan(), zCubed, curve);

        //δ(y, z) = (z − z²)·⟨1, y^n⟩ − z³·⟨1, 2^n⟩.
        Span<byte> sumY = stackalloc byte[ScalarSize];
        Span<byte> sumTwo = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.SumEntries(powersY, n, sumY, add, curve);
        BulletproofRangeComputation.SumEntries(powersTwo, n, sumTwo, add, curve);

        Span<byte> delta = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        subtract(z.AsReadOnlySpan(), zSquared, delta, curve);
        multiply(delta, sumY, delta, curve);
        multiply(zCubed, sumTwo, term, curve);
        subtract(delta, term, delta, curve);

        //Check 1: t̂·g + τ_x·h == z²·V + δ·g + x·T₁ + x²·T₂.
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
            const int RhsOperandCount = 4;
            using IMemoryOwner<byte> pointsOwner = pool.Rent(RhsOperandCount * g1Size);
            using IMemoryOwner<byte> scalarsOwner = pool.Rent(RhsOperandCount * ScalarSize);
            Span<byte> points = pointsOwner.Memory.Span[..(RhsOperandCount * g1Size)];
            Span<byte> scalars = scalarsOwner.Memory.Span[..(RhsOperandCount * ScalarSize)];
            valueCommitment.CopyTo(points[..g1Size]);
            key.GetValueGenerator().CopyTo(points.Slice(g1Size, g1Size));
            proof.GetT1Bytes().CopyTo(points.Slice(2 * g1Size, g1Size));
            proof.GetT2Bytes().CopyTo(points.Slice(3 * g1Size, g1Size));
            zSquared.CopyTo(scalars[..ScalarSize]);
            delta.CopyTo(scalars.Slice(ScalarSize, ScalarSize));
            x.AsReadOnlySpan().CopyTo(scalars.Slice(2 * ScalarSize, ScalarSize));
            xSquared.CopyTo(scalars.Slice(3 * ScalarSize, ScalarSize));
            g1Msm(points, scalars, RhsOperandCount, rhs, curve);
        }

        if(!lhs.SequenceEqual(rhs))
        {
            return false;
        }

        //The reduced commitment the IPA verifies against:
        //P = A + x·S − z·⟨1, G⟩ + Σ_i (z + z²·2^i·y^{−i})·H_i − μ·h.
        Span<byte> pCommitmentBytes = stackalloc byte[64];
        Span<byte> pCommitment = pCommitmentBytes[..g1Size];
        {
            int operandCount = (2 * n) + 3;
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

            for(int i = 0; i < n; i++)
            {
                key.GetGeneratorG(i).CopyTo(points.Slice((2 + i) * g1Size, g1Size));
                negZ.CopyTo(scalars.Slice((2 + i) * ScalarSize, ScalarSize));
            }

            //w_i = (z·y^i + z²·2^i)·y^{−i} = z + z²·2^i·y^{−i} — the H'-basis
            //weight expressed directly on H_i.
            for(int i = 0; i < n; i++)
            {
                key.GetGeneratorH(i).CopyTo(points.Slice((2 + n + i) * g1Size, g1Size));
                Span<byte> weight = scalars.Slice((2 + n + i) * ScalarSize, ScalarSize);
                multiply(zSquared, powersTwo.Slice(i * ScalarSize, ScalarSize), weight, curve);
                multiply(weight, yInvPowers.Slice(i * ScalarSize, ScalarSize), weight, curve);
                add(weight, z.AsReadOnlySpan(), weight, curve);
            }

            key.GetBlindingGenerator().CopyTo(points.Slice((2 + (2 * n)) * g1Size, g1Size));
            negMu.CopyTo(scalars.Slice((2 + (2 * n)) * ScalarSize, ScalarSize));

            g1Msm(points, scalars, operandCount, pCommitment, curve);
        }

        //The two-vector IPA over (G, H' = y^{−i}·H) against claim t̂.
        using IMemoryOwner<byte> generatorsOwner = pool.Rent(2 * n * g1Size);
        Span<byte> gWorking = generatorsOwner.Memory.Span[..(n * g1Size)];
        Span<byte> hPrime = generatorsOwner.Memory.Span.Slice(n * g1Size, n * g1Size);
        BulletproofRangeComputation.LoadGFamily(key, gWorking, curve);
        BulletproofRangeComputation.BuildScaledHFamily(key, yInvPowers, hPrime, g1ScalarMul, curve);

        return TwoVectorInnerProductArgument.Verify(
            pCommitment, proof.GetTHatBytes(), proof.GetIpaFinalABytes(), proof.GetIpaFinalBBytes(),
            proof.GetIpaRoundPairBytes(), key.GetInnerProductGenerator(),
            gWorking, hPrime, n, WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix, transcript,
            add, multiply, invert, reduce, g1Add, g1ScalarMul, hash, squeeze, curve, pool);
    }
}
