using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Derives the per-signature ECDSA nonce <c>k ∈ [1, n−1]</c> from a signing key and a message
/// representative, writing it into <paramref name="nonce"/>. This is the seam SECDSA's split sign draws its
/// nonce through: production binds it to RFC 6979 deterministic generation
/// (<see cref="Rfc6979SecdsaNonceSource"/>); a test or a hardware source can bind it to anything that
/// produces a 32-byte big-endian scalar in range.
/// </summary>
/// <param name="curve">The curve whose order <c>n</c> bounds the nonce (P-256 for SECDSA).</param>
/// <param name="privateKey">The signing key the raw ECDSA step uses — the hardware key <c>u</c> in split sign — as a 32-byte big-endian scalar.</param>
/// <param name="messageHash">The 32-byte message representative the raw ECDSA step signs — the blinded hash <c>e' = P⁻¹·e</c> in split sign.</param>
/// <param name="nonce">Receives the 32-byte big-endian nonce <c>k ∈ [1, n−1]</c>.</param>
/// <remarks>
/// <para>
/// The nonce binds to the exact <c>(key, message)</c> pair the raw ECDSA step consumes. In split sign that
/// pair is <c>(u, e')</c>, NOT <c>(P·u, e)</c>: the raw signature is computed under the hardware key <c>u</c>
/// over the blinded hash <c>e'</c>, and the produced <c>(r, s)</c> is mathematically a standard ECDSA
/// signature under <c>P·u</c> over <c>e</c> only after the output mask <c>s = P·s₀</c>. A deterministic nonce
/// over <c>(u, e')</c> is therefore correct and reproducible, but it is a different <c>k</c> than a direct
/// ECDSA signer under <c>P·u</c> over <c>e</c> would pick; the two signatures are both valid yet not
/// byte-identical (see <see cref="SecdsaAlgorithm.SplitSign(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte}, SecdsaNonceSource, Lumoin.Veridical.Core.Algebraic.ScalarMultiplyDelegate, Lumoin.Veridical.Core.Algebraic.ScalarAddDelegate, Lumoin.Veridical.Core.Algebraic.ScalarInvertDelegate, Lumoin.Veridical.Core.Algebraic.ScalarReduceDelegate, Lumoin.Veridical.Core.Algebraic.G1ScalarMultiplyDelegate, System.Span{byte}, System.Span{byte})"/>).
/// </para>
/// </remarks>
public delegate void SecdsaNonceSource(
    CurveParameterSet curve,
    ReadOnlySpan<byte> privateKey,
    ReadOnlySpan<byte> messageHash,
    Span<byte> nonce);
