using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The product sumcheck over a delegate-supplied field: proves <c>H = Σ_{x∈{0,1}^v} Π_k f_k(x)</c>
/// for <c>d</c> multilinear factors, reducing it to the single product <c>Π_k f_k(r)</c> at a
/// Fiat-Shamir point <c>r</c>. Each round polynomial has degree <c>d</c> (one per factor), sent as
/// its <c>d + 1</c> evaluations at the integer points <c>0..d</c>; the verifier Lagrange-interpolates
/// the running claim at the squeezed challenge. This is the GKR layer shape — degree 2 for a
/// <c>V_left·V_right</c> product, degree 3 once the <c>eq</c> selector multiplies in — over the
/// P-256 base field Fp256 (<see cref="CurveParameterSet.None"/> + the P256BaseFieldReference
/// delegates). Linear time: each round folds every factor table in half.
/// </summary>
public static class ProductSumcheck
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    /// <summary>
    /// Proves <c>H = Σ_{x∈{0,1}^v} Π_k f_k(x)</c> for the <paramref name="factorCount"/> multilinear
    /// factors given by their hypercube <paramref name="factorTables"/>, folding every factor table in
    /// half each round and emitting the degree-<c>d</c> round polynomials; returns the proof together
    /// with the Fiat-Shamir challenge point the prover needs to continue a larger protocol.
    /// </summary>
    public static ProductSumcheckProverResult Prove(
        ReadOnlySpan<byte> factorTables,
        int factorCount,
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
        ArgumentOutOfRangeException.ThrowIfLessThan(factorCount, 1);

        int size = 1 << variableCount;
        if(factorTables.Length != factorCount * size * ScalarSize)
        {
            throw new ArgumentException($"{factorCount} factors of {variableCount} variables need {factorCount * size * ScalarSize} bytes; received {factorTables.Length}.", nameof(factorTables));
        }

        int evaluationCount = factorCount + 1;

        using IMemoryOwner<byte> tableOwner = pool.Rent(factorCount * size * ScalarSize);
        Span<byte> tables = tableOwner.Memory.Span[..(factorCount * size * ScalarSize)];
        factorTables.CopyTo(tables);

        //The integer evaluation points 0, 1, …, d as field elements.
        using IMemoryOwner<byte> pointOwner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> points = pointOwner.Memory.Span[..(evaluationCount * ScalarSize)];
        for(int t = 0; t < evaluationCount; t++)
        {
            SumcheckChallenge.EncodeConstant((uint)t, points.Slice(t * ScalarSize, ScalarSize));
        }

        //The proof owns the [round polynomials | final values] buffer; the prover result owns the point.
        IMemoryOwner<byte> proofBuffer = pool.Rent(ProductSumcheckProof.GetBufferSizeBytes(variableCount, factorCount));
        Span<byte> roundPolynomials = proofBuffer.Memory.Span[..(variableCount * evaluationCount * ScalarSize)];
        Span<byte> finalValues = proofBuffer.Memory.Span.Slice(variableCount * evaluationCount * ScalarSize, factorCount * ScalarSize);
        IMemoryOwner<byte> pointBuffer = pool.Rent(variableCount * ScalarSize);
        Span<byte> challenges = pointBuffer.Memory.Span[..(variableCount * ScalarSize)];

        Span<byte> one = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(one);
        Span<byte> challenge = stackalloc byte[ScalarSize];
        Span<byte> oneMinusChallenge = stackalloc byte[ScalarSize];
        Span<byte> delta = stackalloc byte[ScalarSize];
        Span<byte> value = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        Span<byte> low = stackalloc byte[ScalarSize];
        Span<byte> high = stackalloc byte[ScalarSize];

        int half = size;
        for(int round = 0; round < variableCount; round++)
        {
            half >>= 1;
            Span<byte> roundEvaluations = roundPolynomials.Slice(round * evaluationCount * ScalarSize, evaluationCount * ScalarSize);
            roundEvaluations.Clear();

            //s(t) = Σ_j Π_k (f_k[j] + t·(f_k[j+half] − f_k[j])) for t = 0..d.
            for(int j = 0; j < half; j++)
            {
                for(int t = 0; t < evaluationCount; t++)
                {
                    ReadOnlySpan<byte> point = points.Slice(t * ScalarSize, ScalarSize);
                    one.CopyTo(product);
                    for(int k = 0; k < factorCount; k++)
                    {
                        ReadOnlySpan<byte> factorLow = tables.Slice(((k * size) + j) * ScalarSize, ScalarSize);
                        ReadOnlySpan<byte> factorHigh = tables.Slice((((k * size) + j + half)) * ScalarSize, ScalarSize);
                        subtract(factorHigh, factorLow, delta, curve);
                        multiply(point, delta, scratch, curve);
                        add(factorLow, scratch, value, curve);
                        multiply(product, value, scratch, curve);
                        scratch.CopyTo(product);
                    }

                    Span<byte> evaluation = roundEvaluations.Slice(t * ScalarSize, ScalarSize);
                    add(evaluation, product, scratch, curve);
                    scratch.CopyTo(evaluation);
                }
            }

            SumcheckChallenge.AbsorbAndSqueeze(transcript, roundEvaluations, challenge, squeeze, hash, reduce, curve);
            challenge.CopyTo(challenges.Slice(round * ScalarSize, ScalarSize));
            subtract(one, challenge, oneMinusChallenge, curve);

            for(int k = 0; k < factorCount; k++)
            {
                for(int j = 0; j < half; j++)
                {
                    Span<byte> folded = tables.Slice(((k * size) + j) * ScalarSize, ScalarSize);
                    ReadOnlySpan<byte> factorHigh = tables.Slice((((k * size) + j + half)) * ScalarSize, ScalarSize);
                    multiply(folded, oneMinusChallenge, low, curve);
                    multiply(factorHigh, challenge, high, curve);
                    add(low, high, folded, curve);
                }
            }
        }

        for(int k = 0; k < factorCount; k++)
        {
            tables.Slice(k * size * ScalarSize, ScalarSize).CopyTo(finalValues.Slice(k * ScalarSize, ScalarSize));
        }

        return new ProductSumcheckProverResult(
            new ProductSumcheckProof(proofBuffer, variableCount, factorCount),
            pointBuffer);
    }


    /// <summary>
    /// Verifies a product sumcheck proof against <paramref name="claimedSum"/>, Lagrange-interpolating
    /// each round's degree-<c>d</c> polynomial at the squeezed challenge and reducing the claim to the
    /// single product <c>Π_k f_k(r)</c> the caller checks the real factors against at the challenge point.
    /// </summary>
    public static MultilinearSumcheckVerification Verify(
        ReadOnlySpan<byte> claimedSum,
        ProductSumcheckProof proof,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
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
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(pool);

        int variableCount = proof.VariableCount;
        int factorCount = proof.FactorCount;
        int evaluationCount = factorCount + 1;
        ReadOnlySpan<byte> roundPolynomials = proof.RoundPolynomials.Span;
        if(claimedSum.Length != ScalarSize)
        {
            throw new ArgumentException($"The claimed sum must be {ScalarSize} bytes; received {claimedSum.Length}.", nameof(claimedSum));
        }

        if(roundPolynomials.Length != variableCount * evaluationCount * ScalarSize)
        {
            throw new ArgumentException($"A {variableCount}-round, degree-{factorCount} proof needs {variableCount * evaluationCount * ScalarSize} round bytes; received {roundPolynomials.Length}.", nameof(proof));
        }

        using IMemoryOwner<byte> inverseDenominatorOwner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> inverseDenominators = inverseDenominatorOwner.Memory.Span[..(evaluationCount * ScalarSize)];
        SumcheckInterpolation.ComputeInverseDenominators(inverseDenominators, evaluationCount, subtract, multiply, invert, curve);

        Span<byte> claim = stackalloc byte[ScalarSize];
        claimedSum.CopyTo(claim);

        //The verification owns this buffer: [challenge point | reduced claim].
        IMemoryOwner<byte> verificationBuffer = pool.Rent(MultilinearSumcheckVerification.GetBufferSizeBytes(variableCount));
        Span<byte> challenges = verificationBuffer.Memory.Span[..(variableCount * ScalarSize)];

        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> challenge = stackalloc byte[ScalarSize];

        bool accepted = true;
        for(int round = 0; round < variableCount; round++)
        {
            ReadOnlySpan<byte> evaluations = roundPolynomials.Slice(round * evaluationCount * ScalarSize, evaluationCount * ScalarSize);

            //Round consistency: s(0) + s(1) must equal the running claim.
            add(evaluations[..ScalarSize], evaluations.Slice(ScalarSize, ScalarSize), sum, curve);
            if(!sum.SequenceEqual(claim))
            {
                accepted = false;
            }

            SumcheckChallenge.AbsorbAndSqueeze(transcript, evaluations, challenge, squeeze, hash, reduce, curve);
            challenge.CopyTo(challenges.Slice(round * ScalarSize, ScalarSize));

            SumcheckInterpolation.Interpolate(evaluations, evaluationCount, challenge, inverseDenominators, claim, add, subtract, multiply, curve);
        }

        //The protocol reduced the sum to Π_k f_k(r); the proof's final factor values must match it.
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(product);
        ReadOnlySpan<byte> finalValues = proof.FinalValues.Span;
        for(int k = 0; k < factorCount; k++)
        {
            multiply(product, finalValues.Slice(k * ScalarSize, ScalarSize), scratch, curve);
            scratch.CopyTo(product);
        }

        if(!product.SequenceEqual(claim))
        {
            accepted = false;
        }

        claim.CopyTo(verificationBuffer.Memory.Span[(variableCount * ScalarSize)..]);

        return new MultilinearSumcheckVerification(verificationBuffer, accepted, variableCount);
    }


}
