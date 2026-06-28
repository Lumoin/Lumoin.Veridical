using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Drives the outer (degree-3) sumcheck verification phase: replays
/// the transcript, decompresses each round polynomial against the
/// running claim, and re-derives the verifier challenges. Returns the
/// challenge vector <c>r_x</c> and the final running claim, which the
/// caller checks against the outer terminating identity.
/// </summary>
/// <remarks>
/// <para>
/// Compression in <see cref="CompressedRoundPolynomial"/> reconstructs
/// the linear term from the running claim by construction, so the
/// per-round identity <c>g_i(0) + g_i(1) == previous_claim</c> always
/// holds for any decompressed polynomial. Detection of a tampered or
/// malformed proof happens at the outer or inner terminating-identity
/// check at the end of <see cref="SpartanVerifierExtensions.Verify(SpartanVerifier, SpartanProof, Lumoin.Veridical.Core.ConstraintSystems.RelaxedR1csInstance, FiatShamirTranscript, ScalarAddDelegate, ScalarMultiplyDelegate, ScalarSubtractDelegate, ScalarInvertDelegate, ScalarReduceDelegate, G1AddDelegate, G1ScalarMultiplyDelegate, G1MultiScalarMultiplyDelegate, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, Lumoin.Base.BaseMemoryPool)"/>.
/// </para>
/// </remarks>
internal static class OuterSumcheckVerifier
{
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of per-round challenge scalars and the final claim transfers to the returned SumcheckVerifierResult, which owns their disposal.")]
    internal static SumcheckVerifierResult Run(
        SpartanSumcheckProofPart part,
        int roundCount,
        Scalar initialClaim,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate scalarReduce,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(part);
        ArgumentNullException.ThrowIfNull(initialClaim);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarSubtract);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        return SumcheckVerifierCore.Run(
            roundCount,
            expectedDegree: 3,
            i => part.GetOuterRoundCompressedBytes(i),
            initialClaim,
            transcript,
            hash, squeeze, scalarReduce,
            scalarAdd, scalarSubtract, scalarMultiply,
            pool);
    }
}


/// <summary>
/// The shared result type for outer / inner sumcheck verification:
/// the per-round challenges and the final running claim after the
/// last round.
/// </summary>
internal sealed class SumcheckVerifierResult: IDisposable
{
    /// <summary>The challenge vector, in round order.</summary>
    public IReadOnlyList<Scalar> Challenges { get; }

    /// <summary>The running claim after the final round.</summary>
    public Scalar FinalClaim { get; }


    internal SumcheckVerifierResult(IReadOnlyList<Scalar> challenges, Scalar finalClaim)
    {
        Challenges = challenges;
        FinalClaim = finalClaim;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        foreach(Scalar challenge in Challenges)
        {
            challenge.Dispose();
        }
        FinalClaim.Dispose();
    }
}


/// <summary>
/// Internal shared core for the outer and inner sumcheck verifier
/// drivers. Both protocols share the same per-round structure
/// (decompress against running claim, absorb, squeeze, Horner-evaluate
/// at the challenge); they differ only in the degree bound and the
/// proof-side byte-slice accessor.
/// </summary>
internal static class SumcheckVerifierCore
{
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of per-round challenge scalars and the final claim transfers to the returned SumcheckVerifierResult, which owns their disposal. Exceptional paths are handled by the try/catch wrapping the loop.")]
    internal static SumcheckVerifierResult Run(
        int roundCount,
        int expectedDegree,
        CompressedRoundBytesAccessor getCompressedBytes,
        Scalar initialClaim,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate scalarReduce,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        BaseMemoryPool pool)
    {
        CurveParameterSet curve = initialClaim.Curve;

        Scalar runningClaim = Scalar.FromCanonical(initialClaim.AsReadOnlySpan(), curve, pool);
        List<Scalar> challenges = new(roundCount);

        try
        {
            for(int round = 0; round < roundCount; round++)
            {
                ReadOnlySpan<byte> compressedBytes = getCompressedBytes(round);

                using CompressedRoundPolynomial compressed = CompressedRoundPolynomial.FromCompressedBytes(
                    compressedBytes, expectedDegree, curve, pool);
                using Polynomial decompressed = compressed.Decompress(runningClaim, scalarSubtract, pool);

                transcript.AbsorbCompressedRoundPolynomial(compressed, hash);
                Scalar challenge = transcript.SqueezeScalar(
                    new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.SumcheckRoundChallenge),
                    squeeze, hash, scalarReduce, curve, pool);
                challenges.Add(challenge);

                CryptographicOperationCounters.Increment(CryptographicOperationKind.SumcheckRoundVerify, curve);

                //New running claim = g_round(challenge) via Horner.
                Scalar nextClaim = HornerEvaluatePolynomial(
                    decompressed, challenge, scalarAdd, scalarMultiply, pool);
                runningClaim.Dispose();
                runningClaim = nextClaim;
            }


            return new SumcheckVerifierResult(challenges, runningClaim);
        }
        catch
        {
            runningClaim.Dispose();
            foreach(Scalar c in challenges)
            {
                c.Dispose();
            }
            throw;
        }
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The returned scalar is the caller's responsibility to dispose; transfer-of-ownership pattern.")]
    private static Scalar HornerEvaluatePolynomial(
        Polynomial polynomial,
        Scalar at,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        CurveParameterSet curve = polynomial.Curve;
        ReadOnlySpan<byte> coefficients = polynomial.AsReadOnlySpan();
        int degree = polynomial.Degree;

        IMemoryOwner<byte> resultOwner = pool.Rent(scalarSize);
        Span<byte> result = resultOwner.Memory.Span[..scalarSize];

        //Start Horner from the highest-degree coefficient.
        coefficients.Slice(degree * scalarSize, scalarSize).CopyTo(result);

        ReadOnlySpan<byte> atBytes = at.AsReadOnlySpan();
        for(int k = degree - 1; k >= 0; k--)
        {
            scalarMultiply(result, atBytes, result, curve);
            scalarAdd(result, coefficients.Slice(k * scalarSize, scalarSize), result, curve);
        }


        return new Scalar(resultOwner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }
}


/// <summary>
/// Delegate-typed alias for the per-round byte-slice accessor on a
/// <see cref="SpartanSumcheckProofPart"/>. Used by
/// <see cref="SumcheckVerifierCore"/> to remain bound to
/// <c>SpartanSumcheckProofPart.GetOuterRoundCompressedBytes</c> or
/// <c>GetInnerRoundCompressedBytes</c> as appropriate for the phase. The
/// delegate's return type is <see cref="ReadOnlySpan{T}"/> rather than
/// <see cref="byte"/>[] so the call site avoids copying.
/// </summary>
internal delegate ReadOnlySpan<byte> CompressedRoundBytesAccessor(int roundIndex);