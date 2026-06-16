using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The multilinear sumcheck protocol over a field supplied as add / subtract / multiply / reduce
/// delegates, so it runs over the P-256 base field Fp256 (<see cref="CurveParameterSet.None"/> +
/// the <c>P256BaseFieldReference</c> delegates) — the field Longfellow's sumcheck operates in. It
/// proves <c>H = Σ_{x∈{0,1}^v} f(x)</c> for a multilinear <c>f</c> given by its 2^v hypercube
/// evaluations, reducing that claim to a single evaluation <c>f(r)</c> at a Fiat-Shamir-random
/// point <c>r</c>. Linear time: each round folds the evaluation table in half.
/// </summary>
/// <remarks>
/// This is the foundational round-by-round binding the layered GKR prover composes (the GKR layer
/// sumcheck is the same skeleton over a degree-2/3 product, plus the data-parallel copy variable).
/// The caller absorbs the claimed sum and any commitment into the transcript before invoking, so
/// prover and verifier draw identical challenges; the verifier returns the reduced claim and the
/// caller checks <c>f(r)</c> against it (via an oracle, the next layer, or a commitment opening).
/// It is delegate-based on purpose — the existing <see cref="MultilinearExtension"/> /
/// <c>SpartanProver</c> sumcheck are keyed to BLS12-381, whereas Longfellow needs the EC base field.
/// </remarks>
public static class MultilinearSumcheck
{
    private const int ScalarSize = Scalar.SizeBytes;

    //64-byte wide squeeze keeps the modular-reduction bias below 2^-256 (RFC 9380 L = 64), the
    //same width the Ligero challenge squeeze uses.
    private const int SqueezeWideBytes = 64;

    private static readonly FiatShamirOperationLabel RoundPolynomialLabel = new("veridical.gkr.sumcheck.round");
    private static readonly FiatShamirOperationLabel ChallengeLabel = new("veridical.gkr.sumcheck.challenge");


    public static MultilinearSumcheckProof Prove(
        ReadOnlySpan<byte> evaluations,
        int variableCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);

        int size = 1 << variableCount;
        if(evaluations.Length != size * ScalarSize)
        {
            throw new ArgumentException($"A {variableCount}-variable multilinear table must be {size * ScalarSize} bytes; received {evaluations.Length}.", nameof(evaluations));
        }

        using IMemoryOwner<byte> tableOwner = pool.Rent(size * ScalarSize);
        Span<byte> table = tableOwner.Memory.Span[..(size * ScalarSize)];
        evaluations.CopyTo(table);

        //The proof owns this buffer: [round polynomials | final value].
        IMemoryOwner<byte> proofBuffer = pool.Rent(MultilinearSumcheckProof.GetBufferSizeBytes(variableCount));
        Span<byte> roundPolynomials = proofBuffer.Memory.Span[..(variableCount * 2 * ScalarSize)];

        Span<byte> one = stackalloc byte[ScalarSize];
        EncodeOne(one);
        Span<byte> challenge = stackalloc byte[ScalarSize];
        Span<byte> oneMinusChallenge = stackalloc byte[ScalarSize];
        Span<byte> productLow = stackalloc byte[ScalarSize];
        Span<byte> productHigh = stackalloc byte[ScalarSize];

        //Each round binds the most-significant remaining variable: the lower half of the table is
        //its value at that bit = 0, the upper half at bit = 1; the round polynomial is their two
        //partial sums, and the fold is the line through them at the squeezed challenge.
        int half = size;
        for(int round = 0; round < variableCount; round++)
        {
            half >>= 1;
            Span<byte> roundPair = roundPolynomials.Slice(round * 2 * ScalarSize, 2 * ScalarSize);
            SumRange(table, 0, half, roundPair[..ScalarSize], add, curve);
            SumRange(table, half, half, roundPair[ScalarSize..], add, curve);

            transcript.AbsorbBytes(RoundPolynomialLabel, roundPair, hash);
            SqueezeChallenge(transcript, challenge, squeeze, hash, reduce, curve);
            subtract(one, challenge, oneMinusChallenge, curve);

            for(int j = 0; j < half; j++)
            {
                Span<byte> low = table.Slice(j * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> high = table.Slice((j + half) * ScalarSize, ScalarSize);
                multiply(low, oneMinusChallenge, productLow, curve);
                multiply(high, challenge, productHigh, curve);
                add(productLow, productHigh, low, curve);
            }
        }

        table[..ScalarSize].CopyTo(proofBuffer.Memory.Span[(variableCount * 2 * ScalarSize)..]);

        return new MultilinearSumcheckProof(proofBuffer, variableCount);
    }


    public static MultilinearSumcheckVerification Verify(
        ReadOnlySpan<byte> claimedSum,
        MultilinearSumcheckProof proof,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(pool);

        int variableCount = proof.VariableCount;
        ReadOnlySpan<byte> roundPolynomials = proof.RoundPolynomials.Span;
        if(claimedSum.Length != ScalarSize)
        {
            throw new ArgumentException($"The claimed sum must be {ScalarSize} bytes; received {claimedSum.Length}.", nameof(claimedSum));
        }

        if(roundPolynomials.Length != variableCount * 2 * ScalarSize)
        {
            throw new ArgumentException($"A {variableCount}-round proof must carry {variableCount * 2 * ScalarSize} round-polynomial bytes; received {roundPolynomials.Length}.", nameof(proof));
        }

        Span<byte> claim = stackalloc byte[ScalarSize];
        claimedSum.CopyTo(claim);

        //The verification owns this buffer: [challenge point | reduced claim].
        IMemoryOwner<byte> verificationBuffer = pool.Rent(MultilinearSumcheckVerification.GetBufferSizeBytes(variableCount));
        Span<byte> challenges = verificationBuffer.Memory.Span[..(variableCount * ScalarSize)];

        Span<byte> one = stackalloc byte[ScalarSize];
        EncodeOne(one);
        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> challenge = stackalloc byte[ScalarSize];
        Span<byte> oneMinusChallenge = stackalloc byte[ScalarSize];
        Span<byte> termLow = stackalloc byte[ScalarSize];
        Span<byte> termHigh = stackalloc byte[ScalarSize];

        bool accepted = true;
        for(int round = 0; round < variableCount; round++)
        {
            ReadOnlySpan<byte> roundPair = roundPolynomials.Slice(round * 2 * ScalarSize, 2 * ScalarSize);
            ReadOnlySpan<byte> s0 = roundPair[..ScalarSize];
            ReadOnlySpan<byte> s1 = roundPair[ScalarSize..];

            //Round consistency: s(0) + s(1) must equal the running claim.
            add(s0, s1, sum, curve);
            if(!sum.SequenceEqual(claim))
            {
                accepted = false;
            }

            transcript.AbsorbBytes(RoundPolynomialLabel, roundPair, hash);
            SqueezeChallenge(transcript, challenge, squeeze, hash, reduce, curve);
            challenge.CopyTo(challenges.Slice(round * ScalarSize, ScalarSize));

            //Reduce the claim to s(r) = s(0)·(1−r) + s(1)·r along the round line.
            subtract(one, challenge, oneMinusChallenge, curve);
            multiply(s0, oneMinusChallenge, termLow, curve);
            multiply(s1, challenge, termHigh, curve);
            add(termLow, termHigh, claim, curve);
        }

        claim.CopyTo(verificationBuffer.Memory.Span[(variableCount * ScalarSize)..]);

        return new MultilinearSumcheckVerification(verificationBuffer, accepted, variableCount);
    }


    //destination = Σ table[start .. start+count) (count ≥ 1), without aliasing the add output.
    private static void SumRange(ReadOnlySpan<byte> table, int start, int count, Span<byte> destination, ScalarAddDelegate add, CurveParameterSet curve)
    {
        table.Slice(start * ScalarSize, ScalarSize).CopyTo(destination);
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        for(int k = 1; k < count; k++)
        {
            add(destination, table.Slice((start + k) * ScalarSize, ScalarSize), accumulator, curve);
            accumulator.CopyTo(destination);
        }
    }


    private static void SqueezeChallenge(FiatShamirTranscript transcript, Span<byte> destination, FiatShamirSqueezeDelegate squeeze, FiatShamirHashDelegate hash, ScalarReduceDelegate reduce, CurveParameterSet curve)
    {
        Span<byte> wide = stackalloc byte[SqueezeWideBytes];
        transcript.SqueezeBytes(ChallengeLabel, wide, squeeze, hash);
        reduce(wide, destination, curve);
    }


    private static void EncodeOne(Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 1] = 1;
    }
}
