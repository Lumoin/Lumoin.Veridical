using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Globalization;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The Bulletproofs-style inner-product argument the Hyrax opening
/// protocol consumes. Proves that a committed scalar vector
/// <c>f</c> has a specific inner product <c>c</c> with a public scalar
/// vector <c>R</c>, given the augmented Pedersen commitment
/// <c>P = ⟨f, G⟩ + r · H + c · U</c>.
/// </summary>
/// <remarks>
/// <para>
/// Fold conventions are the standard Bulletproofs ones, chosen so the
/// folded commitment satisfies
/// <c>P' = P + x² · L_round + x²_inv · R_round</c>:
/// </para>
/// <list type="bullet">
///   <item><description><c>f' = x · f_L + x_inv · f_R</c></description></item>
///   <item><description><c>G' = x_inv · G_L + x · G_R</c></description></item>
///   <item><description><c>R' = x_inv · R_L + x · R_R</c></description></item>
/// </list>
/// <para>
/// Where <c>L_round = ⟨f_L, G_R⟩ + ⟨f_L, R_R⟩ · U</c> and
/// <c>R_round = ⟨f_R, G_L⟩ + ⟨f_R, R_L⟩ · U</c>. After
/// <c>t = log_2(k)</c> rounds the vectors collapse to single scalars
/// and the prover sends the final folded <c>f</c> scalar; the verifier
/// reconstructs the final folded <c>G</c> and <c>R</c> by re-applying
/// the same fold sequence with the transcript-derived challenges.
/// </para>
/// <para>
/// Buffer ownership: <see cref="Prove"/> consumes mutable
/// <c>f / G / R</c> buffers (folded in place) and writes the round
/// <c>(L_round, R_round)</c> pairs and the final scalar into
/// caller-provided destination spans. <see cref="Verify"/> consumes
/// the same public inputs plus the proof bytes and returns true iff
/// the final algebraic check holds.
/// </para>
/// </remarks>
internal static class InnerProductArgument
{
    /// <summary>The expected number of IPA rounds for a vector of the given length. Equivalent to <c>log_2(initialLength)</c>; throws when not a power of two.</summary>
    public static int GetRoundCount(int initialLength)
    {
        if(initialLength <= 0 || (initialLength & (initialLength - 1)) != 0)
        {
            throw new ArgumentException(
                $"IPA requires the initial vector length to be a positive power of two; received {initialLength}.",
                nameof(initialLength));
        }

        int log = 0;
        int v = initialLength;
        while(v > 1)
        {
            v >>= 1;
            log++;
        }


        return log;
    }


    /// <summary>
    /// Runs the IPA prover.
    /// </summary>
    /// <param name="f">The private scalar vector, folded in place. Length <c>initialLength</c>. On exit, <c>f[0..ScalarSize)</c> holds the final folded scalar; the rest is stale.</param>
    /// <param name="g">The public generator vector (G1 points), folded in place. Length <c>initialLength</c> points.</param>
    /// <param name="r">The public scalar vector, folded in place. Length <c>initialLength</c> scalars.</param>
    /// <param name="hPoint">The Pedersen blinding generator <c>H</c> bytes (single G1 point, 48 bytes).</param>
    /// <param name="uPoint">The IPA value generator <c>U</c> bytes (single G1 point, 48 bytes).</param>
    /// <param name="roundPairsDestination">Destination for the <c>(L_round, R_round)</c> pairs. Length <c>roundCount * 2 * 48</c>.</param>
    /// <param name="finalScalarDestination">Destination for the final folded <c>f</c> scalar. Length 32.</param>
    /// <param name="initialLength">The starting vector length. Must be a positive power of two.</param>
    /// <param name="ipaRoundLabelPrefix">The transcript label prefix for IPA rounds, typically <c>"hyrax.ipa.round"</c>. Each round absorbs L and R under labels <c>{prefix}.{i}.l</c> and <c>{prefix}.{i}.r</c>, and squeezes the challenge under <c>{prefix}.{i}.challenge</c>.</param>
    public static void Prove(
        Span<byte> f,
        Span<byte> g,
        Span<byte> r,
        ReadOnlySpan<byte> hPoint,
        ReadOnlySpan<byte> uPoint,
        Span<byte> roundPairsDestination,
        Span<byte> finalScalarDestination,
        int initialLength,
        string ipaRoundLabelPrefix,
        FiatShamirTranscript transcript,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMul,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        G1MultiScalarMultiplyDelegate g1Msm,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int roundCount = GetRoundCount(initialLength);
        int scalarSize = Scalar.SizeBytes;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int pairSize = 2 * g1Size;

        ValidatePlanShape(f, g, r, roundPairsDestination, finalScalarDestination, initialLength, roundCount, scalarSize, g1Size);

        int currentLength = initialLength;
        for(int round = 0; round < roundCount; round++)
        {
            int half = currentLength / 2;
            int halfFBytes = half * scalarSize;
            int halfGBytes = half * g1Size;

            Span<byte> fLeft = f[..halfFBytes];
            Span<byte> fRight = f.Slice(halfFBytes, halfFBytes);
            Span<byte> gLeft = g[..halfGBytes];
            Span<byte> gRight = g.Slice(halfGBytes, halfGBytes);
            Span<byte> rLeft = r[..halfFBytes];
            Span<byte> rRight = r.Slice(halfFBytes, halfFBytes);

            Span<byte> lDest = roundPairsDestination.Slice(round * pairSize, g1Size);
            Span<byte> rDest = roundPairsDestination.Slice(round * pairSize + g1Size, g1Size);

            ComputeCrossPoint(fLeft, gRight, rRight, uPoint, lDest, half, scalarSize, g1Size, scalarAdd, scalarMul, g1Add, g1ScalarMul, g1Msm, curve, pool);
            ComputeCrossPoint(fRight, gLeft, rLeft, uPoint, rDest, half, scalarSize, g1Size, scalarAdd, scalarMul, g1Add, g1ScalarMul, g1Msm, curve, pool);

            string roundIdx = round.ToString(CultureInfo.InvariantCulture);
            FiatShamirOperationLabel lLabel = new($"{ipaRoundLabelPrefix}.{roundIdx}.l");
            FiatShamirOperationLabel rLabel = new($"{ipaRoundLabelPrefix}.{roundIdx}.r");
            FiatShamirOperationLabel cLabel = new($"{ipaRoundLabelPrefix}.{roundIdx}.challenge");

            transcript.AbsorbBytes(lLabel, lDest, hash);
            transcript.AbsorbBytes(rLabel, rDest, hash);

            using IMemoryOwner<byte> xOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> xInvOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> wideOwner = pool.Rent(64);
            Span<byte> wide = wideOwner.Memory.Span[..64];
            transcript.SqueezeBytes(cLabel, wide, squeeze, hash);
            Span<byte> challenge = xOwner.Memory.Span[..scalarSize];
            scalarReduce(wide, challenge, curve);
            Span<byte> challengeInv = xInvOwner.Memory.Span[..scalarSize];
            scalarInvert(challenge, challengeInv, curve);

            FoldScalarVector(fLeft, fRight, challenge, challengeInv, half, scalarSize, scalarAdd, scalarMul, curve, pool);
            FoldGeneratorVector(gLeft, gRight, challenge, challengeInv, half, g1Size, g1Add, g1ScalarMul, curve, pool);
            FoldScalarVectorWithSwappedChallenge(rLeft, rRight, challenge, challengeInv, half, scalarSize, scalarAdd, scalarMul, curve, pool);

            currentLength = half;
        }

        f[..scalarSize].CopyTo(finalScalarDestination);
        CryptographicOperationCounters.Increment(CryptographicOperationKind.IpaProve, curve);
    }


    /// <summary>
    /// Runs the IPA verifier.
    /// </summary>
    /// <returns>True iff the IPA's final algebraic check holds.</returns>
    public static bool Verify(
        ReadOnlySpan<byte> initialCommitment,
        ReadOnlySpan<byte> claimedValueBytes,
        ReadOnlySpan<byte> rBlindingBytes,
        ReadOnlySpan<byte> finalScalarBytes,
        ReadOnlySpan<byte> roundPairs,
        ReadOnlySpan<byte> hPoint,
        ReadOnlySpan<byte> uPoint,
        Span<byte> gWorking,
        Span<byte> rWorking,
        int initialLength,
        string ipaRoundLabelPrefix,
        FiatShamirTranscript transcript,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMul,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int roundCount = GetRoundCount(initialLength);
        int scalarSize = Scalar.SizeBytes;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int pairSize = 2 * g1Size;

        if(gWorking.Length != initialLength * g1Size)
        {
            throw new ArgumentException(
                $"gWorking must be {initialLength * g1Size} bytes; received {gWorking.Length}.", nameof(gWorking));
        }

        if(rWorking.Length != initialLength * scalarSize)
        {
            throw new ArgumentException(
                $"rWorking must be {initialLength * scalarSize} bytes; received {rWorking.Length}.", nameof(rWorking));
        }

        if(roundPairs.Length != roundCount * pairSize)
        {
            throw new ArgumentException(
                $"roundPairs must be {roundCount * pairSize} bytes; received {roundPairs.Length}.", nameof(roundPairs));
        }

        //An adversarial prover can feed proof bytes that fail to decode as
        //G1 points or that violate other backend invariants. The verifier
        //must treat any such failure as "reject", not propagate the
        //exception — otherwise the verifier can be DoSed by a malformed
        //proof. Catch backend-level invariant violations here.
        try
        {
            return VerifyCore(initialCommitment, claimedValueBytes, rBlindingBytes, finalScalarBytes, roundPairs,
                hPoint, uPoint, gWorking, rWorking, initialLength, ipaRoundLabelPrefix, transcript,
                scalarAdd, scalarMul, scalarInvert, scalarReduce, g1Add, g1ScalarMul, hash, squeeze, curve, pool,
                roundCount, scalarSize, g1Size, pairSize);
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
        ReadOnlySpan<byte> initialCommitment,
        ReadOnlySpan<byte> claimedValueBytes,
        ReadOnlySpan<byte> rBlindingBytes,
        ReadOnlySpan<byte> finalScalarBytes,
        ReadOnlySpan<byte> roundPairs,
        ReadOnlySpan<byte> hPoint,
        ReadOnlySpan<byte> uPoint,
        Span<byte> gWorking,
        Span<byte> rWorking,
        int initialLength,
        string ipaRoundLabelPrefix,
        FiatShamirTranscript transcript,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMul,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        int roundCount,
        int scalarSize,
        int g1Size,
        int pairSize)
    {
        //P_current starts as initialCommitment + claimedValue·U.
        using IMemoryOwner<byte> pOwner = pool.Rent(g1Size);
        Span<byte> pCurrent = pOwner.Memory.Span[..g1Size];
        ComputeAugmentedCommitment(initialCommitment, claimedValueBytes, uPoint, pCurrent, g1Add, g1ScalarMul, curve);

        int currentLength = initialLength;
        for(int round = 0; round < roundCount; round++)
        {
            ReadOnlySpan<byte> lPoint = roundPairs.Slice(round * pairSize, g1Size);
            ReadOnlySpan<byte> rPoint = roundPairs.Slice(round * pairSize + g1Size, g1Size);

            string roundIdx = round.ToString(CultureInfo.InvariantCulture);
            FiatShamirOperationLabel lLabel = new($"{ipaRoundLabelPrefix}.{roundIdx}.l");
            FiatShamirOperationLabel rLabel = new($"{ipaRoundLabelPrefix}.{roundIdx}.r");
            FiatShamirOperationLabel cLabel = new($"{ipaRoundLabelPrefix}.{roundIdx}.challenge");

            transcript.AbsorbBytes(lLabel, lPoint, hash);
            transcript.AbsorbBytes(rLabel, rPoint, hash);

            using IMemoryOwner<byte> wideOwner = pool.Rent(64);
            using IMemoryOwner<byte> challengeOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> challengeInvOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> challengeSquaredOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> challengeSquaredInvOwner = pool.Rent(scalarSize);
            Span<byte> wide = wideOwner.Memory.Span[..64];
            transcript.SqueezeBytes(cLabel, wide, squeeze, hash);
            Span<byte> challenge = challengeOwner.Memory.Span[..scalarSize];
            scalarReduce(wide, challenge, curve);
            Span<byte> challengeInv = challengeInvOwner.Memory.Span[..scalarSize];
            scalarInvert(challenge, challengeInv, curve);
            Span<byte> challengeSquared = challengeSquaredOwner.Memory.Span[..scalarSize];
            scalarMul(challenge, challenge, challengeSquared, curve);
            Span<byte> challengeSquaredInv = challengeSquaredInvOwner.Memory.Span[..scalarSize];
            scalarMul(challengeInv, challengeInv, challengeSquaredInv, curve);

            //P' = P + x² · L + x²_inv · R.
            using IMemoryOwner<byte> termOwner = pool.Rent(g1Size);
            using IMemoryOwner<byte> nextPOwner = pool.Rent(g1Size);
            Span<byte> term = termOwner.Memory.Span[..g1Size];
            Span<byte> nextP = nextPOwner.Memory.Span[..g1Size];

            g1ScalarMul(lPoint, challengeSquared, term, curve);
            g1Add(pCurrent, term, nextP, curve);
            g1ScalarMul(rPoint, challengeSquaredInv, term, curve);
            g1Add(nextP, term, pCurrent, curve);

            //Fold gWorking and rWorking in place (verifier-side fold).
            int half = currentLength / 2;
            int halfFBytes = half * scalarSize;
            int halfGBytes = half * g1Size;

            FoldGeneratorVector(
                gWorking[..halfGBytes], gWorking.Slice(halfGBytes, halfGBytes),
                challenge, challengeInv, half, g1Size, g1Add, g1ScalarMul, curve, pool);
            FoldScalarVectorWithSwappedChallenge(
                rWorking[..halfFBytes], rWorking.Slice(halfFBytes, halfFBytes),
                challenge, challengeInv, half, scalarSize, scalarAdd, scalarMul, curve, pool);

            currentLength = half;
        }

        //Final check: P_final == a'·G_final + r·H + a'·R_final·U.
        using IMemoryOwner<byte> aTimesGOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> aTimesRTimesUOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> rTimesHOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> sumOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> productOwner = pool.Rent(scalarSize);
        Span<byte> aTimesG = aTimesGOwner.Memory.Span[..g1Size];
        Span<byte> aTimesRTimesU = aTimesRTimesUOwner.Memory.Span[..g1Size];
        Span<byte> rTimesH = rTimesHOwner.Memory.Span[..g1Size];
        Span<byte> sum = sumOwner.Memory.Span[..g1Size];
        Span<byte> aTimesRfinal = productOwner.Memory.Span[..scalarSize];

        g1ScalarMul(gWorking[..g1Size], finalScalarBytes, aTimesG, curve);
        g1ScalarMul(hPoint, rBlindingBytes, rTimesH, curve);

        scalarMul(finalScalarBytes, rWorking[..scalarSize], aTimesRfinal, curve);
        g1ScalarMul(uPoint, aTimesRfinal, aTimesRTimesU, curve);

        g1Add(aTimesG, rTimesH, sum, curve);
        g1Add(sum, aTimesRTimesU, sum, curve);

        CryptographicOperationCounters.Increment(CryptographicOperationKind.IpaVerify, curve);

        return pCurrent.SequenceEqual(sum);
    }


    private static void ValidatePlanShape(
        ReadOnlySpan<byte> f,
        ReadOnlySpan<byte> g,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> roundPairsDestination,
        ReadOnlySpan<byte> finalScalarDestination,
        int initialLength,
        int roundCount,
        int scalarSize,
        int g1Size)
    {
        if(f.Length != initialLength * scalarSize)
        {
            throw new ArgumentException($"f must be {initialLength * scalarSize} bytes; received {f.Length}.", nameof(f));
        }

        if(g.Length != initialLength * g1Size)
        {
            throw new ArgumentException($"g must be {initialLength * g1Size} bytes; received {g.Length}.", nameof(g));
        }

        if(r.Length != initialLength * scalarSize)
        {
            throw new ArgumentException($"r must be {initialLength * scalarSize} bytes; received {r.Length}.", nameof(r));
        }

        if(roundPairsDestination.Length != roundCount * 2 * g1Size)
        {
            throw new ArgumentException($"roundPairsDestination must be {roundCount * 2 * g1Size} bytes; received {roundPairsDestination.Length}.", nameof(roundPairsDestination));
        }

        if(finalScalarDestination.Length != scalarSize)
        {
            throw new ArgumentException($"finalScalarDestination must be {scalarSize} bytes; received {finalScalarDestination.Length}.", nameof(finalScalarDestination));
        }
    }


    /// <summary>Computes <c>⟨fSlice, gSlice⟩ + ⟨fSlice, rSlice⟩ · U</c> via one MSM plus one scalar-mul-add.</summary>
    private static void ComputeCrossPoint(
        ReadOnlySpan<byte> fSlice,
        ReadOnlySpan<byte> gSlice,
        ReadOnlySpan<byte> rSlice,
        ReadOnlySpan<byte> uPoint,
        Span<byte> destination,
        int sliceCount,
        int scalarSize,
        int g1Size,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMul,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        G1MultiScalarMultiplyDelegate g1Msm,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> msmOwner = pool.Rent(g1Size);
        Span<byte> msmResult = msmOwner.Memory.Span[..g1Size];
        g1Msm(gSlice, fSlice, sliceCount, msmResult, curve);

        //Inner product <fSlice, rSlice>.
        using IMemoryOwner<byte> ipOwner = pool.Rent(scalarSize);
        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> ip = ipOwner.Memory.Span[..scalarSize];
        Span<byte> term = termOwner.Memory.Span[..scalarSize];
        ip.Clear();
        for(int i = 0; i < sliceCount; i++)
        {
            scalarMul(
                fSlice.Slice(i * scalarSize, scalarSize),
                rSlice.Slice(i * scalarSize, scalarSize),
                term,
                curve);
            scalarAdd(ip, term, ip, curve);
        }

        //ip * U then add to msmResult.
        using IMemoryOwner<byte> ipTimesUOwner = pool.Rent(g1Size);
        Span<byte> ipTimesU = ipTimesUOwner.Memory.Span[..g1Size];
        g1ScalarMul(uPoint, ip, ipTimesU, curve);
        g1Add(msmResult, ipTimesU, destination, curve);
    }


    /// <summary>Computes the augmented commitment <c>P = baseCommitment + claimedValue · U</c>.</summary>
    private static void ComputeAugmentedCommitment(
        ReadOnlySpan<byte> baseCommitment,
        ReadOnlySpan<byte> claimedValueBytes,
        ReadOnlySpan<byte> uPoint,
        Span<byte> destination,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        CurveParameterSet curve)
    {
        Span<byte> termU = stackalloc byte[WellKnownCurves.GetG1CompressedSizeBytes(curve)];
        g1ScalarMul(uPoint, claimedValueBytes, termU, curve);
        g1Add(baseCommitment, termU, destination, curve);
    }


    /// <summary>Folds the scalar vector <c>f</c> with <c>f' = x · f_L + x_inv · f_R</c>. Writes the folded half-length vector into <c>fLeft</c> in place.</summary>
    private static void FoldScalarVector(
        Span<byte> fLeft,
        Span<byte> fRight,
        ReadOnlySpan<byte> challenge,
        ReadOnlySpan<byte> challengeInv,
        int sliceCount,
        int scalarSize,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMul,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> leftTermOwner = pool.Rent(scalarSize);
        using IMemoryOwner<byte> rightTermOwner = pool.Rent(scalarSize);
        Span<byte> leftTerm = leftTermOwner.Memory.Span[..scalarSize];
        Span<byte> rightTerm = rightTermOwner.Memory.Span[..scalarSize];

        for(int i = 0; i < sliceCount; i++)
        {
            Span<byte> fLeftSlot = fLeft.Slice(i * scalarSize, scalarSize);
            ReadOnlySpan<byte> fRightSlot = fRight.Slice(i * scalarSize, scalarSize);
            scalarMul(challenge, fLeftSlot, leftTerm, curve);
            scalarMul(challengeInv, fRightSlot, rightTerm, curve);
            scalarAdd(leftTerm, rightTerm, fLeftSlot, curve);
        }
    }


    /// <summary>Folds the public scalar vector <c>R</c> with <c>R' = x_inv · R_L + x · R_R</c> (swapped challenge convention vs <see cref="FoldScalarVector"/>).</summary>
    private static void FoldScalarVectorWithSwappedChallenge(
        Span<byte> rLeft,
        Span<byte> rRight,
        ReadOnlySpan<byte> challenge,
        ReadOnlySpan<byte> challengeInv,
        int sliceCount,
        int scalarSize,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMul,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> leftTermOwner = pool.Rent(scalarSize);
        using IMemoryOwner<byte> rightTermOwner = pool.Rent(scalarSize);
        Span<byte> leftTerm = leftTermOwner.Memory.Span[..scalarSize];
        Span<byte> rightTerm = rightTermOwner.Memory.Span[..scalarSize];

        for(int i = 0; i < sliceCount; i++)
        {
            Span<byte> rLeftSlot = rLeft.Slice(i * scalarSize, scalarSize);
            ReadOnlySpan<byte> rRightSlot = rRight.Slice(i * scalarSize, scalarSize);
            scalarMul(challengeInv, rLeftSlot, leftTerm, curve);
            scalarMul(challenge, rRightSlot, rightTerm, curve);
            scalarAdd(leftTerm, rightTerm, rLeftSlot, curve);
        }
    }


    /// <summary>Folds the generator vector <c>G</c> with <c>G' = x_inv · G_L + x · G_R</c>.</summary>
    private static void FoldGeneratorVector(
        Span<byte> gLeft,
        Span<byte> gRight,
        ReadOnlySpan<byte> challenge,
        ReadOnlySpan<byte> challengeInv,
        int sliceCount,
        int g1Size,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> leftTermOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> rightTermOwner = pool.Rent(g1Size);
        Span<byte> leftTerm = leftTermOwner.Memory.Span[..g1Size];
        Span<byte> rightTerm = rightTermOwner.Memory.Span[..g1Size];

        for(int i = 0; i < sliceCount; i++)
        {
            Span<byte> gLeftSlot = gLeft.Slice(i * g1Size, g1Size);
            ReadOnlySpan<byte> gRightSlot = gRight.Slice(i * g1Size, g1Size);
            g1ScalarMul(gLeftSlot, challengeInv, leftTerm, curve);
            g1ScalarMul(gRightSlot, challenge, rightTerm, curve);
            g1Add(leftTerm, rightTerm, gLeftSlot, curve);
        }
    }
}