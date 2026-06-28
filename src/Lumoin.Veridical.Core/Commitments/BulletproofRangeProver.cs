using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Produces a Bulletproofs range proof (Bünz et al, IEEE S&amp;P 2018, §4.2):
/// given a value <c>v ∈ [0, 2^n)</c> and the blinding <c>γ</c> of its
/// Pedersen commitment <c>V = v·g + γ·h</c>, proves the range membership
/// without revealing <c>v</c>. The logarithmic-size argument reduces the bit
/// decomposition's constraints to one inner product, proven by
/// <see cref="TwoVectorInnerProductArgument"/> over the generator families
/// of a <see cref="RangeProofKey"/>.
/// </summary>
/// <remarks>
/// <para>
/// The protocol, in transcript order: absorb <c>V</c>; commit the bit
/// vectors (<c>A</c>) and their blinding vectors (<c>S</c>); squeeze
/// <c>y, z</c>; commit the <c>t(X)</c> coefficients (<c>T₁, T₂</c>); squeeze
/// <c>x</c>; reveal the blinding aggregates <c>τ_x, μ</c> and the inner
/// product <c>t̂ = ⟨l, r⟩</c>; then run the two-vector IPA on
/// <c>(l, r)</c> over <c>(G, H')</c> with <c>H'_i = y^{−i}·H_i</c>. The
/// caller binds the transcript to its statement context before calling, and
/// must use the same transcript construction on the verifier side.
/// </para>
/// <para>
/// The prover refuses an out-of-range value loudly
/// (<see cref="RangeProofKey.ThrowIfValueOutOfRange"/>) — an honest prover
/// cannot accidentally produce an unsound proof, and a dishonest one is
/// caught by the verifier's algebra.
/// </para>
/// </remarks>
public static class BulletproofRangeProver
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Proves <c>value ∈ [0, 2^BitWidth)</c> for the commitment
    /// <c>V = value·g + blinding·h</c>, which is computed internally,
    /// absorbed onto the transcript, and written to
    /// <paramref name="valueCommitmentDestination"/> for the caller to store
    /// or publish.
    /// </summary>
    /// <param name="key">The range-proof key (generator families and width).</param>
    /// <param name="value">The committed value; must fit the key's bit width.</param>
    /// <param name="blinding">The commitment blinding <c>γ</c>, canonical scalar bytes.</param>
    /// <param name="valueCommitmentDestination">Receives the compressed commitment <c>V</c>; one G1 point wide.</param>
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
    /// <returns>The range proof; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the value does not fit the bit width.</exception>
    /// <exception cref="ArgumentException">When a span argument has the wrong length.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented proof buffer transfers ownership to the returned RangeProof.")]
    public static RangeProof Prove(
        RangeProofKey key,
        ulong value,
        ReadOnlySpan<byte> blinding,
        Span<byte> valueCommitmentDestination,
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
        key.ThrowIfValueOutOfRange(value);
        if(key.BitWidth > 64)
        {
            throw new ArgumentException(
                $"A single-value range proof needs a key of at most 64 generators (the ulong value width); a {key.BitWidth}-length key belongs to the aggregated prover.",
                nameof(key));
        }

        int n = key.BitWidth;
        CurveParameterSet curve = key.Curve;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        if(blinding.Length != ScalarSize)
        {
            throw new ArgumentException($"The blinding must be exactly {ScalarSize} bytes; received {blinding.Length}.", nameof(blinding));
        }

        if(valueCommitmentDestination.Length != g1Size)
        {
            throw new ArgumentException($"The value-commitment destination must be exactly {g1Size} bytes; received {valueCommitmentDestination.Length}.", nameof(valueCommitmentDestination));
        }

        Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);

        //All n-vector scratch in one rented block: aL, aR, sL, sR, l0, r0, r1,
        //l, r, powersY, powersTwo, yInvPowers (12 vectors of n scalars).
        const int VectorCount = 12;
        using IMemoryOwner<byte> vectorsOwner = pool.Rent(VectorCount * n * ScalarSize);
        Span<byte> vectors = vectorsOwner.Memory.Span[..(VectorCount * n * ScalarSize)];
        Span<byte> aL = vectors.Slice(0 * n * ScalarSize, n * ScalarSize);
        Span<byte> aR = vectors.Slice(1 * n * ScalarSize, n * ScalarSize);
        Span<byte> sL = vectors.Slice(2 * n * ScalarSize, n * ScalarSize);
        Span<byte> sR = vectors.Slice(3 * n * ScalarSize, n * ScalarSize);
        Span<byte> l0 = vectors.Slice(4 * n * ScalarSize, n * ScalarSize);
        Span<byte> r0 = vectors.Slice(5 * n * ScalarSize, n * ScalarSize);
        Span<byte> r1 = vectors.Slice(6 * n * ScalarSize, n * ScalarSize);
        Span<byte> l = vectors.Slice(7 * n * ScalarSize, n * ScalarSize);
        Span<byte> r = vectors.Slice(8 * n * ScalarSize, n * ScalarSize);
        Span<byte> powersY = vectors.Slice(9 * n * ScalarSize, n * ScalarSize);
        Span<byte> powersTwo = vectors.Slice(10 * n * ScalarSize, n * ScalarSize);
        Span<byte> yInvPowers = vectors.Slice(11 * n * ScalarSize, n * ScalarSize);

        //V = value·g + blinding·h, absorbed first so every challenge binds it.
        key.CommitValue(value, blinding, valueCommitmentDestination, g1Msm, pool);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.ValueCommitment), valueCommitmentDestination, hash);

        //The bit decomposition: aL[i] = bit i of value, aR = aL − 1.
        Span<byte> one = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.WriteOne(one);
        for(int i = 0; i < n; i++)
        {
            Span<byte> aLSlot = aL.Slice(i * ScalarSize, ScalarSize);
            aLSlot.Clear();
            if(((value >> i) & 1UL) != 0UL)
            {
                aLSlot[^1] = 0x01;
            }

            subtract(aLSlot, one, aR.Slice(i * ScalarSize, ScalarSize), curve);
        }

        //A = α·h + ⟨aL, G⟩ + ⟨aR, H⟩; S = ρ·h + ⟨sL, G⟩ + ⟨sR, H⟩.
        Span<byte> alpha = stackalloc byte[ScalarSize];
        Span<byte> rho = stackalloc byte[ScalarSize];
        _ = random(alpha, curve, scalarTag);
        _ = random(rho, curve, scalarTag);
        for(int i = 0; i < n; i++)
        {
            _ = random(sL.Slice(i * ScalarSize, ScalarSize), curve, scalarTag);
            _ = random(sR.Slice(i * ScalarSize, ScalarSize), curve, scalarTag);
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

        BulletproofRangeComputation.BuildPowers(y.AsReadOnlySpan(), powersY, n, multiply, curve);
        Span<byte> two = stackalloc byte[ScalarSize];
        two.Clear();
        two[^1] = 0x02;
        BulletproofRangeComputation.BuildPowers(two, powersTwo, n, multiply, curve);
        Span<byte> yInverse = stackalloc byte[ScalarSize];
        invert(y.AsReadOnlySpan(), yInverse, curve);
        BulletproofRangeComputation.BuildPowers(yInverse, yInvPowers, n, multiply, curve);

        Span<byte> zSquared = stackalloc byte[ScalarSize];
        multiply(z.AsReadOnlySpan(), z.AsReadOnlySpan(), zSquared, curve);

        //l0 = aL − z·1; r0 = y^n ∘ (aR + z·1) + z²·2^n; r1 = y^n ∘ sR.
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int i = 0; i < n; i++)
        {
            subtract(aL.Slice(i * ScalarSize, ScalarSize), z.AsReadOnlySpan(), l0.Slice(i * ScalarSize, ScalarSize), curve);

            Span<byte> r0Slot = r0.Slice(i * ScalarSize, ScalarSize);
            add(aR.Slice(i * ScalarSize, ScalarSize), z.AsReadOnlySpan(), r0Slot, curve);
            multiply(r0Slot, powersY.Slice(i * ScalarSize, ScalarSize), r0Slot, curve);
            multiply(zSquared, powersTwo.Slice(i * ScalarSize, ScalarSize), term, curve);
            add(r0Slot, term, r0Slot, curve);

            multiply(powersY.Slice(i * ScalarSize, ScalarSize), sR.Slice(i * ScalarSize, ScalarSize), r1.Slice(i * ScalarSize, ScalarSize), curve);
        }

        //t1 = ⟨l0, r1⟩ + ⟨sL, r0⟩; t2 = ⟨sL, r1⟩.
        Span<byte> t1 = stackalloc byte[ScalarSize];
        Span<byte> t2 = stackalloc byte[ScalarSize];
        Span<byte> innerProduct = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.InnerProduct(l0, r1, n, t1, add, multiply, curve);
        BulletproofRangeComputation.InnerProduct(sL, r0, n, innerProduct, add, multiply, curve);
        add(t1, innerProduct, t1, curve);
        BulletproofRangeComputation.InnerProduct(sL, r1, n, t2, add, multiply, curve);

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
        for(int i = 0; i < n; i++)
        {
            multiply(x.AsReadOnlySpan(), sL.Slice(i * ScalarSize, ScalarSize), term, curve);
            add(l0.Slice(i * ScalarSize, ScalarSize), term, l.Slice(i * ScalarSize, ScalarSize), curve);

            multiply(x.AsReadOnlySpan(), r1.Slice(i * ScalarSize, ScalarSize), term, curve);
            add(r0.Slice(i * ScalarSize, ScalarSize), term, r.Slice(i * ScalarSize, ScalarSize), curve);
        }

        Span<byte> tHat = stackalloc byte[ScalarSize];
        BulletproofRangeComputation.InnerProduct(l, r, n, tHat, add, multiply, curve);

        //τ_x = τ2·x² + τ1·x + z²·γ; μ = α + ρ·x.
        Span<byte> xSquared = stackalloc byte[ScalarSize];
        multiply(x.AsReadOnlySpan(), x.AsReadOnlySpan(), xSquared, curve);
        Span<byte> tauX = stackalloc byte[ScalarSize];
        multiply(tau2, xSquared, tauX, curve);
        multiply(tau1, x.AsReadOnlySpan(), term, curve);
        add(tauX, term, tauX, curve);
        multiply(zSquared, blinding, term, curve);
        add(tauX, term, tauX, curve);

        Span<byte> mu = stackalloc byte[ScalarSize];
        multiply(rho, x.AsReadOnlySpan(), mu, curve);
        add(alpha, mu, mu, curve);

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.TauX), tauX, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.Mu), mu, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownBulletproofRangeLabels.THat), tHat, hash);

        //The two-vector IPA over (G, H' = y^{−i}·H) proving ⟨l, r⟩ = t̂.
        using IMemoryOwner<byte> generatorsOwner = pool.Rent(2 * n * g1Size);
        Span<byte> gWorking = generatorsOwner.Memory.Span[..(n * g1Size)];
        Span<byte> hPrime = generatorsOwner.Memory.Span.Slice(n * g1Size, n * g1Size);
        BulletproofRangeComputation.LoadGFamily(key, gWorking, curve);
        BulletproofRangeComputation.BuildScaledHFamily(key, yInvPowers, hPrime, g1ScalarMul, curve);

        int proofSize = RangeProof.GetBufferSizeBytes(n, curve);
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

        int ipaRoundCount = TwoVectorInnerProductArgument.GetRoundCount(n);
        int pairBytes = ipaRoundCount * 2 * g1Size;
        TwoVectorInnerProductArgument.Prove(
            l, r, gWorking, hPrime, key.GetInnerProductGenerator(),
            proofBuffer.Slice(offset, pairBytes),
            proofBuffer.Slice(offset + pairBytes, ScalarSize),
            proofBuffer.Slice(offset + pairBytes + ScalarSize, ScalarSize),
            n, WellKnownBulletproofRangeLabels.IpaRoundLabelPrefix, transcript,
            add, multiply, invert, reduce, g1Add, g1ScalarMul, g1Msm, hash, squeeze, curve, pool);

        return new RangeProof(proofOwner, n, curve, RangeProof.ComposeProofTag(curve));
    }


    //⟨first, G⟩ + ⟨second, H⟩ + blind·h in one MSM (2n + 1 operands).
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
        int n = key.BitWidth;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int operandCount = (2 * n) + 1;

        using IMemoryOwner<byte> pointsOwner = pool.Rent(operandCount * g1Size);
        using IMemoryOwner<byte> scalarsOwner = pool.Rent(operandCount * ScalarSize);
        Span<byte> points = pointsOwner.Memory.Span[..(operandCount * g1Size)];
        Span<byte> scalars = scalarsOwner.Memory.Span[..(operandCount * ScalarSize)];

        for(int i = 0; i < n; i++)
        {
            key.GetGeneratorG(i).CopyTo(points.Slice(i * g1Size, g1Size));
            key.GetGeneratorH(i).CopyTo(points.Slice((n + i) * g1Size, g1Size));
        }

        key.GetBlindingGenerator().CopyTo(points.Slice(2 * n * g1Size, g1Size));
        firstVector.CopyTo(scalars[..(n * ScalarSize)]);
        secondVector.CopyTo(scalars.Slice(n * ScalarSize, n * ScalarSize));
        blind.CopyTo(scalars.Slice(2 * n * ScalarSize, ScalarSize));

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
