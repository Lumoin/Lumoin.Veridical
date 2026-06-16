using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Convenience instantiations of the <see cref="DlEqualityNizk"/> for the two equal-discrete-log relations SECDSA
/// proves, so callers pass the named protocol points instead of assembling raw two-pair concatenations:
/// <list type="bullet">
/// <item>the <b>blind-signing relation</b> (Verheul Algorithm 3, verified in Algorithm 4) — that the blinded
/// instruction components <c>G''</c> and <c>Y''</c> are correctly formed as <c>s⁻¹·G'</c> and <c>s⁻¹·Y'</c>, i.e.
/// the proof <c>ZKP[(G',G''),(Y',Y''), ∅]</c> with witness <c>d = s⁻¹</c>; and</item>
/// <item>the <b>control relation</b> (Verheul Equation (7), the evidence of Algorithms 9/10) — that the wallet
/// provider applied its blinding key <c>aU</c> consistently, <c>G' = aU·G</c> and <c>R' = aU·R</c>, i.e. the proof
/// <c>ZKP[(G,G'),(R,R'), H(T_I)]</c> with witness <c>d = aU</c> bound to the transaction-record context.</item>
/// </list>
/// </summary>
/// <remarks>
/// <para>
/// These are thin, pure compositions over <see cref="DlEqualityNizk"/>; all arithmetic and hashing still enter as
/// injected delegates and no key material is retained.
/// </para>
/// <para>
/// <b>Deployment note for the control relation.</b> When the blinding key <c>aU</c> lives in a PKCS#11 HSM that
/// cannot produce a Schnorr NIZK, the control relation is instead proven with the ECDH-MAC interactive Protocol 2
/// or its transferable variant (Verheul Algorithms 21–23) — that orchestration, together with the signed
/// transaction record, the transparency log, and PID issuance, belongs to the application layer (VerifableSystem).
/// The method here is the software-prover / verifier form of the same statement.
/// </para>
/// </remarks>
public static class SecdsaEvidence
{
    private const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;
    private const int PairCount = 2;
    private const int ConcatSizeBytes = PairCount * CompressedPointSizeBytes;


    /// <summary>
    /// Proves the blind-signing relation (Verheul Algorithm 3): that <c>G'' = s⁻¹·G'</c> and <c>Y'' = s⁻¹·Y'</c>
    /// share the witness <c>s⁻¹</c>, as <c>ZKP[(G',G''),(Y',Y''), ∅]</c>.
    /// </summary>
    /// <param name="gPrime">The certificate generator <c>G'</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="gDoublePrime">The blinded component <c>G'' = s⁻¹·G'</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="yPrime">The certificate generator <c>Y'</c>, SEC1 compressed (33 bytes).</param>
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
        ReadOnlySpan<byte> gPrime,
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
        AssemblePair(gPrime, yPrime, generators);
        AssemblePair(gDoublePrime, yDoublePrime, publicKeys);

        return DlEqualityNizk.Prove(
            blindingWitness, generators, publicKeys, ReadOnlySpan<byte>.Empty,
            nonceSource, hash, scalarMultiply, scalarAdd, scalarReduce, g1ScalarMultiply, pool);
    }


    /// <summary>
    /// Verifies the blind-signing relation proof produced by
    /// <see cref="ProveBlindingRelation"/> (Verheul Algorithm 4's ZKP check).
    /// </summary>
    /// <param name="gPrime">The certificate generator <c>G'</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="gDoublePrime">The blinded component <c>G''</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="yPrime">The certificate generator <c>Y'</c>, SEC1 compressed (33 bytes).</param>
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
        ReadOnlySpan<byte> gPrime,
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
        if(!TryAssemblePair(gPrime, yPrime, out byte[] generators) || !TryAssemblePair(gDoublePrime, yDoublePrime, out byte[] publicKeys))
        {
            return false;
        }

        return DlEqualityNizk.Verify(
            generators, publicKeys, ReadOnlySpan<byte>.Empty, r, s,
            hash, scalarReduce, g1ScalarMultiply, g1Add, g1Negate);
    }


    /// <summary>
    /// Proves the control relation (Verheul Equation (7), the evidence of Algorithm 9): that <c>G' = aU·G</c> and
    /// <c>R' = aU·R</c> share the wallet-provider blinding key <c>aU</c>, as <c>ZKP[(G,G'),(R,R'), N]</c>, with the
    /// challenge bound to the transaction-record context <paramref name="recordContext"/> (<c>H(T_I)</c>).
    /// </summary>
    /// <param name="generator">The base point <c>G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="noncePoint">The signature nonce point <c>R</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="blindedGenerator">The blinded base <c>G' = aU·G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="blindedNoncePoint">The blinded nonce point <c>R' = aU·R</c>, SEC1 compressed (33 bytes).</param>
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
        ReadOnlySpan<byte> generator,
        ReadOnlySpan<byte> noncePoint,
        ReadOnlySpan<byte> blindedGenerator,
        ReadOnlySpan<byte> blindedNoncePoint,
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
        AssemblePair(generator, noncePoint, generators);
        AssemblePair(blindedGenerator, blindedNoncePoint, publicKeys);

        return DlEqualityNizk.Prove(
            controlWitness, generators, publicKeys, recordContext,
            nonceSource, hash, scalarMultiply, scalarAdd, scalarReduce, g1ScalarMultiply, pool);
    }


    /// <summary>
    /// Verifies the control relation proof produced by <see cref="ProveControlRelation"/> — that <c>R' = aU·R</c>
    /// for the same <c>aU</c> as <c>G' = aU·G</c>, bound to <paramref name="recordContext"/> (Verheul Algorithm 10's
    /// ZKP check; the non-HSM form of Equation (7)).
    /// </summary>
    /// <param name="generator">The base point <c>G</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="noncePoint">The signature nonce point <c>R</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="blindedGenerator">The blinded base <c>G'</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="blindedNoncePoint">The blinded nonce point <c>R'</c>, SEC1 compressed (33 bytes).</param>
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
        ReadOnlySpan<byte> generator,
        ReadOnlySpan<byte> noncePoint,
        ReadOnlySpan<byte> blindedGenerator,
        ReadOnlySpan<byte> blindedNoncePoint,
        ReadOnlySpan<byte> recordContext,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        G1NegateDelegate g1Negate)
    {
        if(!TryAssemblePair(generator, noncePoint, out byte[] generators) || !TryAssemblePair(blindedGenerator, blindedNoncePoint, out byte[] publicKeys))
        {
            return false;
        }

        return DlEqualityNizk.Verify(
            generators, publicKeys, recordContext, r, s,
            hash, scalarReduce, g1ScalarMultiply, g1Add, g1Negate);
    }


    //Prove-side assembly: a wrong-length point is a programmer error and throws (consistent with DlEqualityNizk.Prove).
    private static void AssemblePair(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, Span<byte> destination)
    {
        RequirePoint(first, nameof(first));
        RequirePoint(second, nameof(second));
        first.CopyTo(destination);
        second.CopyTo(destination[CompressedPointSizeBytes..]);
    }


    //Verify-side assembly: a wrong-length point is adversarial wire input and rejects (returns false) rather than throwing.
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


    private static void RequirePoint(ReadOnlySpan<byte> point, string name)
    {
        if(point.Length != CompressedPointSizeBytes)
        {
            throw new ArgumentException($"A compressed point must be exactly {CompressedPointSizeBytes} bytes; received {point.Length}.", name);
        }
    }
}
