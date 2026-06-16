using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Builds a software <see cref="SecdsaRawEcdsaSign"/> — the in-process counterpart of a TPM/HSM raw signer —
/// that holds the hardware key <c>u</c> in memory and raw-ECDSA-signs the blinded hash under it with the
/// injected nonce source (RFC 6979 in production). A hardware deployment supplies its own
/// <see cref="SecdsaRawEcdsaSign"/> closing over a TPM key handle instead; this is the code-only fallback,
/// and the proof that the split-sign seam is implementation-agnostic — the same
/// <see cref="SecdsaAlgorithm.SplitSign(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte}, SecdsaRawEcdsaSign, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarReduceDelegate, System.Span{byte}, System.Span{byte})"/>
/// drives both.
/// </summary>
public static class SecdsaSoftwareRawSigner
{
    /// <summary>
    /// Returns a software raw signer over <paramref name="hardwareKey"/>: each call derives the nonce
    /// <c>k = nonceSource(P256, u, e')</c> and computes <c>(r, s₀)</c> via <see cref="SecdsaAlgorithm.Sign"/>.
    /// The key is held in the returned delegate's closure (the software case keeps <c>u</c> in memory by
    /// nature); it is taken as <see cref="ReadOnlyMemory{T}"/> because a closure cannot capture a span.
    /// </summary>
    /// <param name="hardwareKey">The hardware-key scalar <c>u</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="nonceSource">The nonce source, invoked as <c>(P256, u, e')</c>; production binds RFC 6979.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for <c>k·G</c>).</param>
    /// <returns>A <see cref="SecdsaRawEcdsaSign"/> that raw-signs under <c>u</c>.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    public static SecdsaRawEcdsaSign Create(
        ReadOnlyMemory<byte> hardwareKey,
        SecdsaNonceSource nonceSource,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply)
    {
        ArgumentNullException.ThrowIfNull(nonceSource);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);

        return (messageRepresentative, r, s0) =>
        {
            Span<byte> nonce = stackalloc byte[SecdsaAlgorithm.ScalarSizeBytes];
            try
            {
                nonceSource(CurveParameterSet.P256, hardwareKey.Span, messageRepresentative, nonce);
                SecdsaAlgorithm.Sign(
                    hardwareKey.Span, messageRepresentative, nonce,
                    scalarMultiply, scalarAdd, scalarInvert, scalarReduce, g1ScalarMultiply,
                    r, s0);
            }
            finally
            {
                nonce.Clear();
            }
        };
    }
}
