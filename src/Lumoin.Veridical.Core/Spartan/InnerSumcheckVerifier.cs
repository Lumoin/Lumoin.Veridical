using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Drives the inner (degree-2) sumcheck verification phase. Mirrors
/// <see cref="OuterSumcheckVerifier"/> but selects the inner round
/// polynomials and the degree-2 bound.
/// </summary>
internal static class InnerSumcheckVerifier
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
        SensitiveMemoryPool<byte> pool)
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
            expectedDegree: 2,
            i => part.GetInnerRoundCompressedBytes(i),
            initialClaim,
            transcript,
            hash, squeeze, scalarReduce,
            scalarAdd, scalarSubtract, scalarMultiply,
            pool);
    }
}