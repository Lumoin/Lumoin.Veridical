using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Globalization;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The two-secret-vector Bulletproofs inner-product argument (Bünz et al,
/// "Bulletproofs: Short Proofs for Confidential Transactions and More",
/// IEEE S&amp;P 2018, Protocol 2). Proves that two committed scalar vectors
/// <c>a</c> and <c>b</c> have a specific inner product <c>c = ⟨a, b⟩</c>,
/// given the augmented commitment
/// <c>P = ⟨a, G⟩ + ⟨b, H⟩ + c · U</c> over two independent generator
/// families.
/// </summary>
/// <remarks>
/// <para>
/// The sibling of <see cref="InnerProductArgument"/>, which proves
/// <c>⟨f, R⟩</c> for a <em>public</em> vector <c>R</c> (the Hyrax opening's
/// shape). Here both vectors are secret, so each round sends cross terms
/// covering both:
/// <c>L = ⟨a_L, G_R⟩ + ⟨b_R, H_L⟩ + ⟨a_L, b_R⟩·U</c> and
/// <c>R = ⟨a_R, G_L⟩ + ⟨b_L, H_R⟩ + ⟨a_R, b_L⟩·U</c>, and the folds run
/// with mirrored challenge orientation:
/// </para>
/// <list type="bullet">
///   <item><description><c>a' = x · a_L + x_inv · a_R</c></description></item>
///   <item><description><c>b' = x_inv · b_L + x · b_R</c></description></item>
///   <item><description><c>G' = x_inv · G_L + x · G_R</c></description></item>
///   <item><description><c>H' = x · H_L + x_inv · H_R</c></description></item>
/// </list>
/// <para>
/// so the folded commitment satisfies <c>P' = x² · L + P + x_inv² · R</c>.
/// After <c>log₂(n)</c> rounds the vectors collapse and the prover sends the
/// final scalar pair <c>(a, b)</c>; the verifier reconstructs the folded
/// <c>G</c> and <c>H</c> and checks
/// <c>P_final == a·G_final + b·H_final + (a·b)·U</c>.
/// </para>
/// <para>
/// The argument carries no blinding of its own: the consumer (the
/// Bulletproofs range proof) removes the blinding term <c>μ·h</c> from
/// <c>P</c> before invoking it, exactly as the paper's Protocol 1 reduces to
/// Protocol 2.
/// </para>
/// </remarks>
internal static class TwoVectorInnerProductArgument
{
    /// <summary>The expected number of rounds for vectors of the given length. Equivalent to <c>log₂(initialLength)</c>; throws when not a power of two.</summary>
    public static int GetRoundCount(int initialLength) => InnerProductArgument.GetRoundCount(initialLength);


    /// <summary>
    /// Runs the two-vector IPA prover.
    /// </summary>
    /// <param name="a">The first secret scalar vector, folded in place. Length <c>initialLength</c> scalars. On exit, the leading scalar holds the final folded value; the rest is stale.</param>
    /// <param name="b">The second secret scalar vector, folded in place.</param>
    /// <param name="g">The first generator family (G1 points), folded in place.</param>
    /// <param name="h">The second generator family (G1 points), folded in place.</param>
    /// <param name="uPoint">The inner-product value generator <c>U</c> (single compressed G1 point).</param>
    /// <param name="roundPairsDestination">Destination for the <c>(L, R)</c> pairs. Length <c>roundCount · 2 · g1Size</c>.</param>
    /// <param name="finalADestination">Destination for the final folded <c>a</c> scalar.</param>
    /// <param name="finalBDestination">Destination for the final folded <c>b</c> scalar.</param>
    /// <param name="initialLength">The starting vector length. Must be a positive power of two.</param>
    /// <param name="roundLabelPrefix">The transcript label prefix; each round absorbs L and R under <c>{prefix}.{i}.l</c> / <c>{prefix}.{i}.r</c> and squeezes the challenge under <c>{prefix}.{i}.challenge</c>.</param>
    public static void Prove(
        Span<byte> a,
        Span<byte> b,
        Span<byte> g,
        Span<byte> h,
        ReadOnlySpan<byte> uPoint,
        Span<byte> roundPairsDestination,
        Span<byte> finalADestination,
        Span<byte> finalBDestination,
        int initialLength,
        string roundLabelPrefix,
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

        ValidateProveShape(a, b, g, h, roundPairsDestination, finalADestination, finalBDestination, initialLength, roundCount, scalarSize, g1Size);

        int currentLength = initialLength;
        for(int round = 0; round < roundCount; round++)
        {
            int half = currentLength / 2;
            int halfScalarBytes = half * scalarSize;
            int halfG1Bytes = half * g1Size;

            Span<byte> aLeft = a[..halfScalarBytes];
            Span<byte> aRight = a.Slice(halfScalarBytes, halfScalarBytes);
            Span<byte> bLeft = b[..halfScalarBytes];
            Span<byte> bRight = b.Slice(halfScalarBytes, halfScalarBytes);
            Span<byte> gLeft = g[..halfG1Bytes];
            Span<byte> gRight = g.Slice(halfG1Bytes, halfG1Bytes);
            Span<byte> hLeft = h[..halfG1Bytes];
            Span<byte> hRight = h.Slice(halfG1Bytes, halfG1Bytes);

            Span<byte> lDest = roundPairsDestination.Slice(round * pairSize, g1Size);
            Span<byte> rDest = roundPairsDestination.Slice(round * pairSize + g1Size, g1Size);

            //L = ⟨a_L, G_R⟩ + ⟨b_R, H_L⟩ + ⟨a_L, b_R⟩·U;
            //R = ⟨a_R, G_L⟩ + ⟨b_L, H_R⟩ + ⟨a_R, b_L⟩·U.
            ComputeCrossPoint(aLeft, gRight, bRight, hLeft, uPoint, lDest, half, scalarSize, g1Size, scalarAdd, scalarMul, g1Add, g1ScalarMul, g1Msm, curve, pool);
            ComputeCrossPoint(aRight, gLeft, bLeft, hRight, uPoint, rDest, half, scalarSize, g1Size, scalarAdd, scalarMul, g1Add, g1ScalarMul, g1Msm, curve, pool);

            string roundIndex = round.ToString(CultureInfo.InvariantCulture);
            FiatShamirOperationLabel lLabel = new($"{roundLabelPrefix}.{roundIndex}.l");
            FiatShamirOperationLabel rLabel = new($"{roundLabelPrefix}.{roundIndex}.r");
            FiatShamirOperationLabel cLabel = new($"{roundLabelPrefix}.{roundIndex}.challenge");

            transcript.AbsorbBytes(lLabel, lDest, hash);
            transcript.AbsorbBytes(rLabel, rDest, hash);

            using IMemoryOwner<byte> challengeOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> challengeInvOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> wideOwner = pool.Rent(64);
            Span<byte> wide = wideOwner.Memory.Span[..64];
            transcript.SqueezeBytes(cLabel, wide, squeeze, hash);
            Span<byte> challenge = challengeOwner.Memory.Span[..scalarSize];
            scalarReduce(wide, challenge, curve);
            Span<byte> challengeInv = challengeInvOwner.Memory.Span[..scalarSize];
            scalarInvert(challenge, challengeInv, curve);

            //a folds challenge-first, b and G inverse-first, H challenge-first —
            //the mirrored orientation that closes the P' identity.
            FoldScalarVector(aLeft, aRight, challenge, challengeInv, half, scalarSize, scalarAdd, scalarMul, curve, pool);
            FoldScalarVector(bLeft, bRight, challengeInv, challenge, half, scalarSize, scalarAdd, scalarMul, curve, pool);
            FoldGeneratorVector(gLeft, gRight, challengeInv, challenge, half, g1Size, g1Add, g1ScalarMul, curve, pool);
            FoldGeneratorVector(hLeft, hRight, challenge, challengeInv, half, g1Size, g1Add, g1ScalarMul, curve, pool);

            currentLength = half;
        }

        a[..scalarSize].CopyTo(finalADestination);
        b[..scalarSize].CopyTo(finalBDestination);
        CryptographicOperationCounters.Increment(CryptographicOperationKind.IpaProve, curve);
    }


    /// <summary>
    /// Runs the two-vector IPA verifier.
    /// </summary>
    /// <param name="pCommitment">The commitment <c>P − c·U</c> side: the caller's <c>⟨a,G⟩ + ⟨b,H⟩</c> aggregate (the claimed value is supplied separately and folded in here).</param>
    /// <param name="claimedInnerProductBytes">The claimed inner product <c>c</c>, canonical scalar bytes.</param>
    /// <param name="finalABytes">The prover's final folded <c>a</c> scalar.</param>
    /// <param name="finalBBytes">The prover's final folded <c>b</c> scalar.</param>
    /// <param name="roundPairs">The <c>(L, R)</c> pairs, <c>roundCount · 2 · g1Size</c> bytes.</param>
    /// <param name="uPoint">The inner-product value generator <c>U</c>.</param>
    /// <param name="gWorking">The first generator family, folded in place.</param>
    /// <param name="hWorking">The second generator family, folded in place.</param>
    /// <param name="initialLength">The starting vector length.</param>
    /// <param name="roundLabelPrefix">The transcript label prefix the prover used.</param>
    /// <returns>True iff the final algebraic check holds.</returns>
    public static bool Verify(
        ReadOnlySpan<byte> pCommitment,
        ReadOnlySpan<byte> claimedInnerProductBytes,
        ReadOnlySpan<byte> finalABytes,
        ReadOnlySpan<byte> finalBBytes,
        ReadOnlySpan<byte> roundPairs,
        ReadOnlySpan<byte> uPoint,
        Span<byte> gWorking,
        Span<byte> hWorking,
        int initialLength,
        string roundLabelPrefix,
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

        if(gWorking.Length != initialLength * g1Size || hWorking.Length != initialLength * g1Size)
        {
            throw new ArgumentException(
                $"Generator working buffers must each be {initialLength * g1Size} bytes.");
        }

        if(roundPairs.Length != roundCount * pairSize)
        {
            throw new ArgumentException(
                $"roundPairs must be {roundCount * pairSize} bytes; received {roundPairs.Length}.", nameof(roundPairs));
        }

        //An adversarial prover can feed bytes that fail to decode as G1 points
        //or violate other backend invariants; any such failure is a rejection,
        //not a fault to propagate.
        try
        {
            return VerifyCore(
                pCommitment, claimedInnerProductBytes, finalABytes, finalBBytes, roundPairs, uPoint,
                gWorking, hWorking, initialLength, roundLabelPrefix, transcript,
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
        ReadOnlySpan<byte> pCommitment,
        ReadOnlySpan<byte> claimedInnerProductBytes,
        ReadOnlySpan<byte> finalABytes,
        ReadOnlySpan<byte> finalBBytes,
        ReadOnlySpan<byte> roundPairs,
        ReadOnlySpan<byte> uPoint,
        Span<byte> gWorking,
        Span<byte> hWorking,
        int initialLength,
        string roundLabelPrefix,
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
        //P_current = pCommitment + c·U.
        using IMemoryOwner<byte> pOwner = pool.Rent(g1Size);
        Span<byte> pCurrent = pOwner.Memory.Span[..g1Size];
        Span<byte> termU = stackalloc byte[64];
        Span<byte> uTerm = termU[..g1Size];
        g1ScalarMul(uPoint, claimedInnerProductBytes, uTerm, curve);
        g1Add(pCommitment, uTerm, pCurrent, curve);

        int currentLength = initialLength;
        for(int round = 0; round < roundCount; round++)
        {
            ReadOnlySpan<byte> lPoint = roundPairs.Slice(round * pairSize, g1Size);
            ReadOnlySpan<byte> rPoint = roundPairs.Slice(round * pairSize + g1Size, g1Size);

            string roundIndex = round.ToString(CultureInfo.InvariantCulture);
            FiatShamirOperationLabel lLabel = new($"{roundLabelPrefix}.{roundIndex}.l");
            FiatShamirOperationLabel rLabel = new($"{roundLabelPrefix}.{roundIndex}.r");
            FiatShamirOperationLabel cLabel = new($"{roundLabelPrefix}.{roundIndex}.challenge");

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

            //P' = x²·L + P + x_inv²·R.
            using IMemoryOwner<byte> foldTermOwner = pool.Rent(g1Size);
            using IMemoryOwner<byte> nextPOwner = pool.Rent(g1Size);
            Span<byte> foldTerm = foldTermOwner.Memory.Span[..g1Size];
            Span<byte> nextP = nextPOwner.Memory.Span[..g1Size];

            g1ScalarMul(lPoint, challengeSquared, foldTerm, curve);
            g1Add(pCurrent, foldTerm, nextP, curve);
            g1ScalarMul(rPoint, challengeSquaredInv, foldTerm, curve);
            g1Add(nextP, foldTerm, pCurrent, curve);

            int half = currentLength / 2;
            int halfG1Bytes = half * g1Size;

            FoldGeneratorVector(
                gWorking[..halfG1Bytes], gWorking.Slice(halfG1Bytes, halfG1Bytes),
                challengeInv, challenge, half, g1Size, g1Add, g1ScalarMul, curve, pool);
            FoldGeneratorVector(
                hWorking[..halfG1Bytes], hWorking.Slice(halfG1Bytes, halfG1Bytes),
                challenge, challengeInv, half, g1Size, g1Add, g1ScalarMul, curve, pool);

            currentLength = half;
        }

        //Final check: P_final == a·G_final + b·H_final + (a·b)·U.
        using IMemoryOwner<byte> aTimesGOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> bTimesHOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> abTimesUOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> sumOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> productOwner = pool.Rent(scalarSize);
        Span<byte> aTimesG = aTimesGOwner.Memory.Span[..g1Size];
        Span<byte> bTimesH = bTimesHOwner.Memory.Span[..g1Size];
        Span<byte> abTimesU = abTimesUOwner.Memory.Span[..g1Size];
        Span<byte> sum = sumOwner.Memory.Span[..g1Size];
        Span<byte> abProduct = productOwner.Memory.Span[..scalarSize];

        g1ScalarMul(gWorking[..g1Size], finalABytes, aTimesG, curve);
        g1ScalarMul(hWorking[..g1Size], finalBBytes, bTimesH, curve);
        scalarMul(finalABytes, finalBBytes, abProduct, curve);
        g1ScalarMul(uPoint, abProduct, abTimesU, curve);

        g1Add(aTimesG, bTimesH, sum, curve);
        g1Add(sum, abTimesU, sum, curve);

        CryptographicOperationCounters.Increment(CryptographicOperationKind.IpaVerify, curve);

        return pCurrent.SequenceEqual(sum);
    }


    private static void ValidateProveShape(
        ReadOnlySpan<byte> a,
        ReadOnlySpan<byte> b,
        ReadOnlySpan<byte> g,
        ReadOnlySpan<byte> h,
        ReadOnlySpan<byte> roundPairsDestination,
        ReadOnlySpan<byte> finalADestination,
        ReadOnlySpan<byte> finalBDestination,
        int initialLength,
        int roundCount,
        int scalarSize,
        int g1Size)
    {
        if(a.Length != initialLength * scalarSize || b.Length != initialLength * scalarSize)
        {
            throw new ArgumentException(
                $"Both scalar vectors must be {initialLength * scalarSize} bytes; received {a.Length} and {b.Length}.");
        }

        if(g.Length != initialLength * g1Size || h.Length != initialLength * g1Size)
        {
            throw new ArgumentException(
                $"Both generator families must be {initialLength * g1Size} bytes; received {g.Length} and {h.Length}.");
        }

        if(roundPairsDestination.Length != roundCount * 2 * g1Size)
        {
            throw new ArgumentException(
                $"roundPairsDestination must be {roundCount * 2 * g1Size} bytes; received {roundPairsDestination.Length}.");
        }

        if(finalADestination.Length != scalarSize || finalBDestination.Length != scalarSize)
        {
            throw new ArgumentException(
                $"Final scalar destinations must each be {scalarSize} bytes.");
        }
    }


    /// <summary>Computes <c>⟨xSlice, gSlice⟩ + ⟨ySlice, hSlice⟩ + ⟨xSlice, ySlice⟩·U</c>: two MSMs, one inner product, one scalar-mul-add.</summary>
    private static void ComputeCrossPoint(
        ReadOnlySpan<byte> xSlice,
        ReadOnlySpan<byte> gSlice,
        ReadOnlySpan<byte> ySlice,
        ReadOnlySpan<byte> hSlice,
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
        using IMemoryOwner<byte> xgOwner = pool.Rent(g1Size);
        using IMemoryOwner<byte> yhOwner = pool.Rent(g1Size);
        Span<byte> xgResult = xgOwner.Memory.Span[..g1Size];
        Span<byte> yhResult = yhOwner.Memory.Span[..g1Size];
        g1Msm(gSlice, xSlice, sliceCount, xgResult, curve);
        g1Msm(hSlice, ySlice, sliceCount, yhResult, curve);

        //⟨x, y⟩, then its U term.
        using IMemoryOwner<byte> ipOwner = pool.Rent(scalarSize);
        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> innerProduct = ipOwner.Memory.Span[..scalarSize];
        Span<byte> term = termOwner.Memory.Span[..scalarSize];
        innerProduct.Clear();
        for(int i = 0; i < sliceCount; i++)
        {
            scalarMul(
                xSlice.Slice(i * scalarSize, scalarSize),
                ySlice.Slice(i * scalarSize, scalarSize),
                term,
                curve);
            scalarAdd(innerProduct, term, innerProduct, curve);
        }

        using IMemoryOwner<byte> ipTimesUOwner = pool.Rent(g1Size);
        Span<byte> ipTimesU = ipTimesUOwner.Memory.Span[..g1Size];
        g1ScalarMul(uPoint, innerProduct, ipTimesU, curve);

        g1Add(xgResult, yhResult, destination, curve);
        g1Add(destination, ipTimesU, destination, curve);
    }


    /// <summary>Folds a scalar vector with <c>v' = leftFactor · v_L + rightFactor · v_R</c>, written into the left half in place.</summary>
    private static void FoldScalarVector(
        Span<byte> left,
        Span<byte> right,
        ReadOnlySpan<byte> leftFactor,
        ReadOnlySpan<byte> rightFactor,
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
            Span<byte> leftSlot = left.Slice(i * scalarSize, scalarSize);
            ReadOnlySpan<byte> rightSlot = right.Slice(i * scalarSize, scalarSize);
            scalarMul(leftFactor, leftSlot, leftTerm, curve);
            scalarMul(rightFactor, rightSlot, rightTerm, curve);
            scalarAdd(leftTerm, rightTerm, leftSlot, curve);
        }
    }


    /// <summary>Folds a generator vector with <c>P' = leftFactor · P_L + rightFactor · P_R</c>, written into the left half in place.</summary>
    private static void FoldGeneratorVector(
        Span<byte> left,
        Span<byte> right,
        ReadOnlySpan<byte> leftFactor,
        ReadOnlySpan<byte> rightFactor,
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
            Span<byte> leftSlot = left.Slice(i * g1Size, g1Size);
            ReadOnlySpan<byte> rightSlot = right.Slice(i * g1Size, g1Size);
            g1ScalarMul(leftSlot, leftFactor, leftTerm, curve);
            g1ScalarMul(rightSlot, rightFactor, rightTerm, curve);
            g1Add(leftTerm, rightTerm, leftSlot, curve);
        }
    }
}
