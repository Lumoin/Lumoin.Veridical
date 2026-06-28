using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Produces an aggregated Bulletproofs range proof (Bünz et al, IEEE S&amp;P
/// 2018, §4.3): <c>m</c> values, each in <c>[0, 2^n)</c>, proven in one
/// argument of size <c>2·log₂(n·m)</c> round pairs plus the constant header —
/// logarithmic in the aggregate, against <c>m</c> separate proofs' linear
/// growth. The bit decompositions concatenate into one <c>n·m</c>-length
/// vector pair; the per-value terms enter through ascending powers of
/// <c>z</c> (value <c>j</c> carries <c>z^{2+j}</c> where the single-value
/// protocol carries <c>z²</c>), and one shared blinding polynomial covers
/// all values.
/// </summary>
/// <remarks>
/// <para>
/// The wire container is <see cref="RangeProof"/> itself — the aggregated
/// proof's layout is exactly the single-value layout at vector length
/// <c>n·m</c>, so <see cref="RangeProof.BitWidth"/> reads the IPA vector
/// length, not the per-value width; the verifier checks the
/// <c>(bitWidth, valueCount)</c> factorisation explicitly. The transcript
/// schedule prepends the aggregation count and absorbs every value
/// commitment, so single and aggregated proofs can never be confused for
/// one another even over the same statement context.
/// </para>
/// </remarks>
public static class AggregatedBulletproofRangeProver
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Proves <c>values[j] ∈ [0, 2^bitWidth)</c> for every <c>j</c>, against
    /// the commitments <c>V_j = values[j]·g + blindings[j]·h</c> (computed
    /// internally and written to
    /// <paramref name="valueCommitmentsDestination"/>).
    /// </summary>
    /// <param name="key">The range-proof key; its <see cref="RangeProofKey.BitWidth"/> must equal <c>bitWidth · values.Length</c> (the aggregate vector length).</param>
    /// <param name="bitWidth">The per-value range width <c>n</c>; a power of two in <c>[2, 64]</c>.</param>
    /// <param name="values">The committed values; a power-of-two count of at least two (a single value takes the plain <see cref="BulletproofRangeProver"/>).</param>
    /// <param name="blindingsConcatenated">The commitment blindings, <c>values.Length</c> canonical scalars back to back.</param>
    /// <param name="valueCommitmentsDestination">Receives the compressed commitments, one G1 point per value.</param>
    /// <param name="transcript">The live Fiat-Shamir transcript; the caller binds it to the statement context beforehand.</param>
    /// <param name="hash">The Fiat-Shamir hash.</param>
    /// <param name="squeeze">The Fiat-Shamir squeeze.</param>
    /// <param name="reduce">Backend scalar reduction.</param>
    /// <param name="add">Backend scalar addition.</param>
    /// <param name="subtract">Backend scalar subtraction.</param>
    /// <param name="multiply">Backend scalar multiplication.</param>
    /// <param name="invert">Backend scalar inversion.</param>
    /// <param name="random">Backend random scalar generation.</param>
    /// <param name="g1Add">Backend G1 addition.</param>
    /// <param name="g1ScalarMul">Backend G1 scalar multiplication.</param>
    /// <param name="g1Msm">Backend G1 multi-scalar multiplication.</param>
    /// <param name="pool">The pool to rent the working buffers from.</param>
    /// <returns>The aggregated proof; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a value does not fit the bit width, or a count is out of shape.</exception>
    /// <exception cref="ArgumentException">When a span argument has the wrong length or the key does not match the aggregate shape.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented proof buffer transfers ownership to the returned RangeProof.")]
    public static RangeProof Prove(
        RangeProofKey key,
        int bitWidth,
        ReadOnlySpan<ulong> values,
        ReadOnlySpan<byte> blindingsConcatenated,
        Span<byte> valueCommitmentsDestination,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarRandomDelegate random,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        G1MultiScalarMultiplyDelegate g1Msm,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(g1ScalarMul);
        ArgumentNullException.ThrowIfNull(g1Msm);
        ArgumentNullException.ThrowIfNull(pool);

        int m = values.Length;
        ValidateShape(key, bitWidth, m);
        for(int j = 0; j < m; j++)
        {
            ThrowIfValueOutOfRange(values[j], bitWidth);
        }

        int n = bitWidth;
        int total = n * m;
        CurveParameterSet curve = key.Curve;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        if(blindingsConcatenated.Length != m * ScalarSize)
        {
            throw new ArgumentException($"The blindings must be exactly {m} scalars ({m * ScalarSize} bytes); received {blindingsConcatenated.Length}.", nameof(blindingsConcatenated));
        }

        if(valueCommitmentsDestination.Length != m * g1Size)
        {
            throw new ArgumentException($"The commitments destination must be exactly {m} G1 points ({m * g1Size} bytes); received {valueCommitmentsDestination.Length}.", nameof(valueCommitmentsDestination));
        }

        Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);

        //All aggregate-length scratch in one rented block: aL, aR, sL, sR, l0,
        //r0, r1, l, r, powersY, yInvPowers (11 vectors of n·m scalars) plus
        //the per-block powersTwo (n) and the per-value z powers (m).
        const int VectorCount = 11;
        using IMemoryOwner<byte> vectorsOwner = pool.Rent((VectorCount * total * ScalarSize) + (n * ScalarSize) + (m * ScalarSize));
        Span<byte> vectors = vectorsOwner.Memory.Span[..((VectorCount * total * ScalarSize) + (n * ScalarSize) + (m * ScalarSize))];
        Span<byte> aL = vectors.Slice(0 * total * ScalarSize, total * ScalarSize);
        Span<byte> aR = vectors.Slice(1 * total * ScalarSize, total * ScalarSize);
        Span<byte> sL = vectors.Slice(2 * total * ScalarSize, total * ScalarSize);
        Span<byte> sR = vectors.Slice(3 * total * ScalarSize, total * ScalarSize);
        Span<byte> l0 = vectors.Slice(4 * total * ScalarSize, total * ScalarSize);
        Span<byte> r0 = vectors.Slice(5 * total * ScalarSize, total * ScalarSize);
        Span<byte> r1 = vectors.Slice(6 * total * ScalarSize, total * ScalarSize);
        Span<byte> l = vectors.Slice(7 * total * ScalarSize, total * ScalarSize);
        Span<byte> r = vectors.Slice(8 * total * ScalarSize, total * ScalarSize);
        Span<byte> powersY = vectors.Slice(9 * total * ScalarSize, total * ScalarSize);
        Span<byte> yInvPowers = vectors.Slice(10 * total * ScalarSize, total * ScalarSize);
        Span<byte> powersTwo = vectors.Slice(VectorCount * total * ScalarSize, n * ScalarSize);
        Span<byte> zPowers = vectors.Slice((VectorCount * total * ScalarSize) + (n * ScalarSize), m * ScalarSize);

        //The aggregation count, then every V_j — the count keeps single and
        //aggregated transcripts apart, the commitments bind every statement.
        Span<byte> countBytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(countBytes, m);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.AggregationCount), countBytes, hash);
        for(int j = 0; j < m; j++)
        {
            Span<byte> commitment = valueCommitmentsDestination.Slice(j * g1Size, g1Size);
            key.CommitValue(values[j], blindingsConcatenated.Slice(j * ScalarSize, ScalarSize), commitment, g1Msm, pool);
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ValueCommitment), commitment, hash);
        }

        //Concatenated bit decompositions: slot j·n + i is bit i of value j.
        Span<byte> one = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.WriteOne(one);
        for(int j = 0; j < m; j++)
        {
            for(int i = 0; i < n; i++)
            {
                int k = (j * n) + i;
                Span<byte> aLSlot = aL.Slice(k * ScalarSize, ScalarSize);
                aLSlot.Clear();
                if(((values[j] >> i) & 1UL) != 0UL)
                {
                    aLSlot[^1] = 0x01;
                }

                subtract(aLSlot, one, aR.Slice(k * ScalarSize, ScalarSize), curve);
            }
        }

        //A = α·h + ⟨aL, G⟩ + ⟨aR, H⟩; S = ρ·h + ⟨sL, G⟩ + ⟨sR, H⟩ over n·m.
        Span<byte> alpha = stackalloc byte[ScalarSize];
        Span<byte> rho = stackalloc byte[ScalarSize];
        _ = random(alpha, curve, scalarTag);
        _ = random(rho, curve, scalarTag);
        for(int k = 0; k < total; k++)
        {
            _ = random(sL.Slice(k * ScalarSize, ScalarSize), curve, scalarTag);
            _ = random(sR.Slice(k * ScalarSize, ScalarSize), curve, scalarTag);
        }

        Span<byte> aPoint = stackalloc byte[64];
        Span<byte> sPoint = stackalloc byte[64];
        Span<byte> commitmentA = aPoint[..g1Size];
        Span<byte> commitmentS = sPoint[..g1Size];
        ComputeVectorCommitment(key, aL, aR, alpha, commitmentA, g1Msm, curve, pool);
        ComputeVectorCommitment(key, sL, sR, rho, commitmentS, g1Msm, curve, pool);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.BitCommitment), commitmentA, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.BlindingCommitment), commitmentS, hash);

        using Scalar y = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ChallengeY), squeeze, hash, reduce, curve, pool);
        using Scalar z = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ChallengeZ), squeeze, hash, reduce, curve, pool);

        BulletproofRangeComputation.BuildPowers(y.AsReadOnlySpan(), powersY, total, multiply, curve);
        Span<byte> two = stackalloc byte[ScalarSize];
        two.Clear();
        two[^1] = 0x02;
        BulletproofRangeComputation.BuildPowers(two, powersTwo, n, multiply, curve);
        Span<byte> yInverse = stackalloc byte[ScalarSize];
        invert(y.AsReadOnlySpan(), yInverse, curve);
        BulletproofRangeComputation.BuildPowers(yInverse, yInvPowers, total, multiply, curve);

        //z^{2+j} per value: zPowers[j] = z²·z^j.
        Span<byte> zSquared = stackalloc byte[ScalarSize];
        multiply(z.AsReadOnlySpan(), z.AsReadOnlySpan(), zSquared, curve);
        zSquared.CopyTo(zPowers[..ScalarSize]);
        for(int j = 1; j < m; j++)
        {
            multiply(zPowers.Slice((j - 1) * ScalarSize, ScalarSize), z.AsReadOnlySpan(), zPowers.Slice(j * ScalarSize, ScalarSize), curve);
        }

        //l0 = aL − z·1; r0[k] = y^k·(aR[k] + z) + z^{2+j}·2^i; r1 = y^k ∘ sR.
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int j = 0; j < m; j++)
        {
            for(int i = 0; i < n; i++)
            {
                int k = (j * n) + i;
                subtract(aL.Slice(k * ScalarSize, ScalarSize), z.AsReadOnlySpan(), l0.Slice(k * ScalarSize, ScalarSize), curve);

                Span<byte> r0Slot = r0.Slice(k * ScalarSize, ScalarSize);
                add(aR.Slice(k * ScalarSize, ScalarSize), z.AsReadOnlySpan(), r0Slot, curve);
                multiply(r0Slot, powersY.Slice(k * ScalarSize, ScalarSize), r0Slot, curve);
                multiply(zPowers.Slice(j * ScalarSize, ScalarSize), powersTwo.Slice(i * ScalarSize, ScalarSize), term, curve);
                add(r0Slot, term, r0Slot, curve);

                multiply(powersY.Slice(k * ScalarSize, ScalarSize), sR.Slice(k * ScalarSize, ScalarSize), r1.Slice(k * ScalarSize, ScalarSize), curve);
            }
        }

        //t1 = ⟨l0, r1⟩ + ⟨sL, r0⟩; t2 = ⟨sL, r1⟩.
        Span<byte> t1 = stackalloc byte[ScalarSize];
        Span<byte> t2 = stackalloc byte[ScalarSize];
        Span<byte> innerProduct = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.InnerProduct(l0, r1, total, t1, add, multiply, curve);
        BulletproofRangeComputation.InnerProduct(sL, r0, total, innerProduct, add, multiply, curve);
        add(t1, innerProduct, t1, curve);
        BulletproofRangeComputation.InnerProduct(sL, r1, total, t2, add, multiply, curve);

        //T1 = t1·g + τ1·h; T2 = t2·g + τ2·h.
        Span<byte> tau1 = stackalloc byte[ScalarSize];
        Span<byte> tau2 = stackalloc byte[ScalarSize];
        _ = random(tau1, curve, scalarTag);
        _ = random(tau2, curve, scalarTag);

        Span<byte> t1Point = stackalloc byte[64];
        Span<byte> t2Point = stackalloc byte[64];
        Span<byte> commitmentT1 = t1Point[..g1Size];
        Span<byte> commitmentT2 = t2Point[..g1Size];
        ComputeTwoTermCommitment(key, t1, tau1, commitmentT1, g1Msm, curve, pool);
        ComputeTwoTermCommitment(key, t2, tau2, commitmentT2, g1Msm, curve, pool);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.PolynomialCommitmentT1), commitmentT1, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.PolynomialCommitmentT2), commitmentT2, hash);

        using Scalar x = transcript.SqueezeScalar(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ChallengeX), squeeze, hash, reduce, curve, pool);

        //l = l0 + x·sL; r = r0 + x·r1; t̂ = ⟨l, r⟩.
        for(int k = 0; k < total; k++)
        {
            multiply(x.AsReadOnlySpan(), sL.Slice(k * ScalarSize, ScalarSize), term, curve);
            add(l0.Slice(k * ScalarSize, ScalarSize), term, l.Slice(k * ScalarSize, ScalarSize), curve);

            multiply(x.AsReadOnlySpan(), r1.Slice(k * ScalarSize, ScalarSize), term, curve);
            add(r0.Slice(k * ScalarSize, ScalarSize), term, r.Slice(k * ScalarSize, ScalarSize), curve);
        }

        Span<byte> tHat = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.InnerProduct(l, r, total, tHat, add, multiply, curve);

        //τ_x = τ2·x² + τ1·x + Σ_j z^{2+j}·γ_j; μ = α + ρ·x.
        Span<byte> xSquared = stackalloc byte[ScalarSize];
        multiply(x.AsReadOnlySpan(), x.AsReadOnlySpan(), xSquared, curve);
        Span<byte> tauX = stackalloc byte[ScalarSize];
        multiply(tau2, xSquared, tauX, curve);
        multiply(tau1, x.AsReadOnlySpan(), term, curve);
        add(tauX, term, tauX, curve);
        for(int j = 0; j < m; j++)
        {
            multiply(zPowers.Slice(j * ScalarSize, ScalarSize), blindingsConcatenated.Slice(j * ScalarSize, ScalarSize), term, curve);
            add(tauX, term, tauX, curve);
        }

        Span<byte> mu = stackalloc byte[ScalarSize];
        multiply(rho, x.AsReadOnlySpan(), mu, curve);
        add(alpha, mu, mu, curve);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.TauX), tauX, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.Mu), mu, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.THat), tHat, hash);

        //The two-vector IPA over (G, H' = y^{−k}·H) proving ⟨l, r⟩ = t̂.
        using IMemoryOwner<byte> generatorsOwner = pool.Rent(2 * total * g1Size);
        Span<byte> gWorking = generatorsOwner.Memory.Span[..(total * g1Size)];
        Span<byte> hPrime = generatorsOwner.Memory.Span.Slice(total * g1Size, total * g1Size);
        BulletproofRangeComputation.LoadGFamily(key, gWorking, curve);
        BulletproofRangeComputation.BuildScaledHFamily(key, yInvPowers, hPrime, g1ScalarMul, curve);

        int proofSize = RangeProof.GetBufferSizeBytes(total, curve);
        IMemoryOwner<byte> proofOwner = pool.Rent(proofSize);
        Span<byte> proofBuffer = proofOwner.Memory.Span[..proofSize];

        int offset = 0;
        commitmentA.CopyTo(proofBuffer.Slice(offset, g1Size));
        offset += g1Size;
        commitmentS.CopyTo(proofBuffer.Slice(offset, g1Size));
        offset += g1Size;
        commitmentT1.CopyTo(proofBuffer.Slice(offset, g1Size));
        offset += g1Size;
        commitmentT2.CopyTo(proofBuffer.Slice(offset, g1Size));
        offset += g1Size;
        tauX.CopyTo(proofBuffer.Slice(offset, ScalarSize));
        offset += ScalarSize;
        mu.CopyTo(proofBuffer.Slice(offset, ScalarSize));
        offset += ScalarSize;
        tHat.CopyTo(proofBuffer.Slice(offset, ScalarSize));
        offset += ScalarSize;

        int ipaRoundCount = TwoVectorInnerProductArgument.GetRoundCount(total);
        int pairBytes = ipaRoundCount * 2 * g1Size;
        TwoVectorInnerProductArgument.Prove(
            l, r, gWorking, hPrime, key.GetInnerProductGenerator(),
            proofBuffer.Slice(offset, pairBytes),
            proofBuffer.Slice(offset + pairBytes, ScalarSize),
            proofBuffer.Slice(offset + pairBytes + ScalarSize, ScalarSize),
            total, WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix, transcript,
            add, multiply, invert, reduce, g1Add, g1ScalarMul, g1Msm, hash, squeeze, curve, pool);

        return new RangeProof(proofOwner, total, curve, RangeProof.ComposeProofTag(curve));
    }


    internal static void ValidateShape(RangeProofKey key, int bitWidth, int valueCount)
    {
        if(bitWidth < 2 || bitWidth > 64 || !BitOperations.IsPow2(bitWidth))
        {
            throw new ArgumentOutOfRangeException(nameof(bitWidth), bitWidth, "The per-value bit width must be a power of two in [2, 64].");
        }

        if(valueCount < 2 || !BitOperations.IsPow2(valueCount))
        {
            throw new ArgumentOutOfRangeException(nameof(valueCount), valueCount, "Aggregation needs a power-of-two count of at least two values; a single value takes the plain range proof.");
        }

        if(key.BitWidth != bitWidth * valueCount)
        {
            throw new ArgumentException(
                $"The key's vector length ({key.BitWidth}) must equal bitWidth · valueCount ({bitWidth} · {valueCount} = {bitWidth * valueCount}).",
                nameof(key));
        }
    }


    internal static void ThrowIfValueOutOfRange(ulong value, int bitWidth)
    {
        if(bitWidth < 64 && (value >> bitWidth) != 0UL)
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, $"The value does not fit in {bitWidth} bits.");
        }
    }


    //⟨first, G⟩ + ⟨second, H⟩ + blind·h in one MSM over the key's full length.
    private static void ComputeVectorCommitment(
        RangeProofKey key,
        ReadOnlySpan<byte> firstVector,
        ReadOnlySpan<byte> secondVector,
        ReadOnlySpan<byte> blind,
        Span<byte> destination,
        G1MultiScalarMultiplyDelegate g1Msm,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int total = key.BitWidth;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int operandCount = (2 * total) + 1;

        using IMemoryOwner<byte> pointsOwner = pool.Rent(operandCount * g1Size);
        using IMemoryOwner<byte> scalarsOwner = pool.Rent(operandCount * ScalarSize);
        Span<byte> points = pointsOwner.Memory.Span[..(operandCount * g1Size)];
        Span<byte> scalars = scalarsOwner.Memory.Span[..(operandCount * ScalarSize)];

        for(int i = 0; i < total; i++)
        {
            key.GetGeneratorG(i).CopyTo(points.Slice(i * g1Size, g1Size));
            key.GetGeneratorH(i).CopyTo(points.Slice((total + i) * g1Size, g1Size));
        }

        key.GetBlindingGenerator().CopyTo(points.Slice(2 * total * g1Size, g1Size));
        firstVector.CopyTo(scalars[..(total * ScalarSize)]);
        secondVector.CopyTo(scalars.Slice(total * ScalarSize, total * ScalarSize));
        blind.CopyTo(scalars.Slice(2 * total * ScalarSize, ScalarSize));

        g1Msm(points, scalars, operandCount, destination, curve);
    }


    //coefficient·g + blind·h in one MSM.
    private static void ComputeTwoTermCommitment(
        RangeProofKey key,
        ReadOnlySpan<byte> coefficient,
        ReadOnlySpan<byte> blind,
        Span<byte> destination,
        G1MultiScalarMultiplyDelegate g1Msm,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        const int OperandCount = 2;

        using IMemoryOwner<byte> pointsOwner = pool.Rent(OperandCount * g1Size);
        using IMemoryOwner<byte> scalarsOwner = pool.Rent(OperandCount * ScalarSize);
        Span<byte> points = pointsOwner.Memory.Span[..(OperandCount * g1Size)];
        Span<byte> scalars = scalarsOwner.Memory.Span[..(OperandCount * ScalarSize)];

        key.GetValueGenerator().CopyTo(points[..g1Size]);
        key.GetBlindingGenerator().CopyTo(points.Slice(g1Size, g1Size));
        coefficient.CopyTo(scalars[..ScalarSize]);
        blind.CopyTo(scalars.Slice(ScalarSize, ScalarSize));

        g1Msm(points, scalars, OperandCount, destination, curve);
    }
}
