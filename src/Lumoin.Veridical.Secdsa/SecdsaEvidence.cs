using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Convenience instantiations of the <see cref="DlEqualityNizk"/> for the two equal-discrete-log relations SECDSA
/// proves, so callers pass the named protocol points instead of assembling raw two-pair concatenations:
/// <list type="bullet">
/// <item>the <b>blind-signing relation</b> (Verheul Algorithm 3 Steps 6–7, verified in Algorithm 4 Step 10) — that the
/// blinded instruction components <c>G''</c> and <c>Y''</c> are correctly formed as <c>s⁻¹·G</c> and <c>s⁻¹·Y'</c>,
/// where <c>G</c> is the standard base point and <c>Y'</c> comes from the internal certificate, i.e. the proof
/// <c>ZKP[(G,G''),(Y',Y''), ∅]</c> with witness <c>d = s⁻¹</c>; and</item>
/// <item>the <b>control relation</b> (Verheul Equation (7), the evidence of Algorithms 9/10) — that the wallet
/// provider applied its blinding key <c>aU</c> consistently, <c>H' = aU·H</c> and <c>W' = aU·W</c>, where <c>H</c> is
/// the wallet-specific base point and <c>H'</c> its image held in the internal certificate, <c>W = R − e·G''</c>, and
/// <c>W' = r·Y''</c>; i.e. the proof <c>ZKP[(H,H'),(W,W'), H(T_I)]</c> with witness <c>d = aU</c> bound to the
/// transaction-record context.</item>
/// </list>
/// </summary>
/// <remarks>
/// <para>
/// These are thin, pure compositions over <see cref="DlEqualityNizk"/>; all arithmetic and hashing still enter as
/// injected delegates and no key material is retained.
/// </para>
/// <para>
/// <b>Deployment note for the control relation.</b> When the blinding key <c>aU</c> lives in a PKCS#11 HSM that
/// cannot produce a Schnorr NIZK, the control relation is instead proven with the ECIES-based Protocol 2, in which
/// the verifier ECIES-encrypts ephemeral keys towards <c>E = Σ eᵢ·Gᵢ</c> and the prover decrypts with <c>aU</c>
/// inside the HSM and answers with the primary hash <c>H1</c>, or with its transferable variant (Verheul
/// Algorithms 22–24), in which a trusted party issues the challenge, the prover returns a signed response and a
/// third party verifies it. The method here is the software-prover / verifier form of the same statement. The
/// orchestration of those interactive protocols, the signed transaction record, the transparency log, and PID
/// issuance belong to the application layer built on top of this library.
/// </para>
/// </remarks>
public static class SecdsaEvidence
{
    /// <summary>The byte length of one SEC1-compressed P-256 point.</summary>
    private const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;
    /// <summary>The number of points in a DL-equality pair: the generator and its image.</summary>
    private const int PairCount = 2;
    /// <summary>The byte length of two concatenated compressed points, the shape <see cref="DlEqualityNizk"/> takes for a generators or public-keys argument.</summary>
    private const int ConcatSizeBytes = PairCount * CompressedPointSizeBytes;


    /// <summary>
    /// Proves the blind-signing relation (Verheul Algorithm 3 Steps 6–7): that <c>G'' = s⁻¹·G</c> and
    /// <c>Y'' = s⁻¹·Y'</c> share the witness <c>s⁻¹</c>, as <c>ZKP[(G,G''),(Y',Y''), ∅]</c>.
    /// </summary>
    /// <param name="g">The standard base point <c>G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="gDoublePrime">The blinded component <c>G'' = s⁻¹·G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="yPrime">The internal-certificate point <c>Y'</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="yDoublePrime">The blinded component <c>Y'' = s⁻¹·Y'</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="blindingWitness">The inverse signature scalar <c>s⁻¹</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="nonceSource">The commitment-nonce source; production binds RFC 6979.</param>
    /// <param name="hash">The Fiat–Shamir hash.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="pool">The pool to rent the proof buffer from.</param>
    /// <returns>The proof of the blind-signing relation.</returns>
    /// <exception cref="ArgumentNullException">When a delegate or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a point has the wrong length or the witness is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When the nonce yields a degenerate proof (retry; probability ~<c>1/n</c>).</exception>
    public static DlEqualityProof ProveBlindingRelation(
        ReadOnlySpan<byte> g,
        ReadOnlySpan<byte> gDoublePrime,
        ReadOnlySpan<byte> yPrime,
        ReadOnlySpan<byte> yDoublePrime,
        ReadOnlySpan<byte> blindingWitness,
        SecdsaNonceSource nonceSource,
        FiatShamirHashDelegate hash,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool)
    {
        Span<byte> generators = stackalloc byte[ConcatSizeBytes];
        Span<byte> publicKeys = stackalloc byte[ConcatSizeBytes];
        AssemblePair(g, yPrime, generators);
        AssemblePair(gDoublePrime, yDoublePrime, publicKeys);

        return DlEqualityNizk.Prove(
            blindingWitness, generators, publicKeys, ReadOnlySpan<byte>.Empty,
            nonceSource, hash, scalarMultiply, scalarAdd, scalarReduce, g1ScalarMultiply, pool);
    }


    /// <summary>
    /// Verifies the blind-signing relation proof produced by
    /// <see cref="ProveBlindingRelation"/> (Verheul Algorithm 4 Step 10, which applies Algorithm 21).
    /// </summary>
    /// <param name="g">The standard base point <c>G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="gDoublePrime">The blinded component <c>G''</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="yPrime">The internal-certificate point <c>Y'</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="yDoublePrime">The blinded component <c>Y''</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="r">The full-width Fiat–Shamir value <c>r</c>, 32-byte big-endian.</param>
    /// <param name="s">The response scalar <c>s</c>, 32-byte big-endian.</param>
    /// <param name="hash">The Fiat–Shamir hash.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="g1Negate">G1 negation.</param>
    /// <returns><see langword="true"/> iff the relation proof is valid.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    public static bool VerifyBlindingRelation(
        ReadOnlySpan<byte> g,
        ReadOnlySpan<byte> gDoublePrime,
        ReadOnlySpan<byte> yPrime,
        ReadOnlySpan<byte> yDoublePrime,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        G1NegateDelegate g1Negate)
    {
        if(!TryAssemblePair(g, yPrime, out byte[] generators) || !TryAssemblePair(gDoublePrime, yDoublePrime, out byte[] publicKeys))
        {
            return false;
        }

        return DlEqualityNizk.Verify(
            generators, publicKeys, ReadOnlySpan<byte>.Empty, r, s,
            hash, scalarReduce, g1ScalarMultiply, g1Add, g1Negate);
    }


    /// <summary>
    /// Proves the control relation (Verheul Equation (7), Algorithm 9 Step 6): that <c>H' = aU·H</c> and
    /// <c>W' = aU·W</c> share the wallet-provider blinding key <c>aU</c>, as <c>ZKP[(H,H'),(W,W'), N]</c>, with the
    /// challenge bound to the transaction-record context <paramref name="recordContext"/> (<c>N = H(T_I)</c>).
    /// Here <c>W = R − e·G''</c> and <c>W' = r·Y''</c> are recomputed from the signed instruction.
    /// </summary>
    /// <param name="h">The wallet-specific base point <c>H</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="w">The point <c>W = R − e·G''</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="hPrime">The blinded base <c>H' = aU·H</c> from the internal certificate, SEC1 compressed (33 bytes).</param>
    /// <param name="wPrime">The blinded point <c>W' = r·Y'' = aU·W</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="controlWitness">The wallet-provider blinding key <c>aU</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="recordContext">The transaction-record context <c>N = H(T_I)</c> bound into the proof (may be empty).</param>
    /// <param name="nonceSource">The commitment-nonce source; production binds RFC 6979.</param>
    /// <param name="hash">The Fiat–Shamir hash.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="pool">The pool to rent the proof buffer from.</param>
    /// <returns>The proof of the control relation.</returns>
    /// <exception cref="ArgumentNullException">When a delegate or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a point has the wrong length or the witness is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When the nonce yields a degenerate proof (retry; probability ~<c>1/n</c>).</exception>
    public static DlEqualityProof ProveControlRelation(
        ReadOnlySpan<byte> h,
        ReadOnlySpan<byte> w,
        ReadOnlySpan<byte> hPrime,
        ReadOnlySpan<byte> wPrime,
        ReadOnlySpan<byte> controlWitness,
        ReadOnlySpan<byte> recordContext,
        SecdsaNonceSource nonceSource,
        FiatShamirHashDelegate hash,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool)
    {
        Span<byte> generators = stackalloc byte[ConcatSizeBytes];
        Span<byte> publicKeys = stackalloc byte[ConcatSizeBytes];
        AssemblePair(h, w, generators);
        AssemblePair(hPrime, wPrime, publicKeys);

        return DlEqualityNizk.Prove(
            controlWitness, generators, publicKeys, recordContext,
            nonceSource, hash, scalarMultiply, scalarAdd, scalarReduce, g1ScalarMultiply, pool);
    }


    /// <summary>
    /// Verifies the control relation proof produced by <see cref="ProveControlRelation"/> — that <c>W' = aU·W</c>
    /// for the same <c>aU</c> as <c>H' = aU·H</c>, bound to <paramref name="recordContext"/> (Verheul Algorithm 10
    /// Step 6, which applies Algorithm 21; the non-interactive form of Equation (7)).
    /// </summary>
    /// <param name="h">The wallet-specific base point <c>H</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="w">The point <c>W = R − e·G''</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="hPrime">The blinded base <c>H'</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="wPrime">The blinded point <c>W'</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="recordContext">The transaction-record context <c>N</c> the proof was bound to (may be empty).</param>
    /// <param name="r">The full-width Fiat–Shamir value <c>r</c>, 32-byte big-endian.</param>
    /// <param name="s">The response scalar <c>s</c>, 32-byte big-endian.</param>
    /// <param name="hash">The Fiat–Shamir hash.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="g1Negate">G1 negation.</param>
    /// <returns><see langword="true"/> iff the relation proof is valid.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    public static bool VerifyControlRelation(
        ReadOnlySpan<byte> h,
        ReadOnlySpan<byte> w,
        ReadOnlySpan<byte> hPrime,
        ReadOnlySpan<byte> wPrime,
        ReadOnlySpan<byte> recordContext,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        G1NegateDelegate g1Negate)
    {
        if(!TryAssemblePair(h, w, out byte[] generators) || !TryAssemblePair(hPrime, wPrime, out byte[] publicKeys))
        {
            return false;
        }

        return DlEqualityNizk.Verify(
            generators, publicKeys, recordContext, r, s,
            hash, scalarReduce, g1ScalarMultiply, g1Add, g1Negate);
    }


    /// <summary>Prove-side assembly: concatenates two compressed points. A wrong-length point is a programmer error and throws, consistent with <c>DlEqualityNizk.Prove</c>.</summary>
    private static void AssemblePair(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, Span<byte> destination)
    {
        RequirePoint(first, nameof(first));
        RequirePoint(second, nameof(second));
        first.CopyTo(destination);
        second.CopyTo(destination[CompressedPointSizeBytes..]);
    }


    /// <summary>Verify-side assembly: concatenates two compressed points. A wrong-length point is adversarial wire input and rejects (returns <see langword="false"/>) rather than throwing.</summary>
    private static bool TryAssemblePair(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, out byte[] destination)
    {
        if(first.Length != CompressedPointSizeBytes || second.Length != CompressedPointSizeBytes)
        {
            destination = [];

            return false;
        }

        destination = new byte[ConcatSizeBytes];
        first.CopyTo(destination);
        second.CopyTo(destination.AsSpan(CompressedPointSizeBytes));

        return true;
    }


    /// <summary>Throws when a point is not exactly <see cref="CompressedPointSizeBytes"/> bytes.</summary>
    private static void RequirePoint(ReadOnlySpan<byte> point, string name)
    {
        if(point.Length != CompressedPointSizeBytes)
        {
            throw new ArgumentException($"A compressed point must be exactly {CompressedPointSizeBytes} bytes; received {point.Length}.", name);
        }
    }
}
