using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.Cryptography;

/// <summary>
/// Deterministic ECDSA nonce generation per RFC 6979 §3.2, the SHA-256 ciphersuite (HMAC-SHA256), for curves
/// whose order is a 256-bit prime — i.e. NIST P-256, the curve SECDSA uses. The nonce <c>k</c> is derived
/// solely from the private key and the message hash through an <c>HMAC_DRBG</c>, so signing needs no random
/// source and is reproducible: two signatures over the same message with the same key produce the same
/// <c>(r, s)</c>. This removes the catastrophic nonce-reuse / weak-RNG failure modes of randomized ECDSA.
/// </summary>
/// <remarks>
/// <para>
/// Scoped to a 256-bit order (<c>qlen = 256</c>, <c>rolen = hlen = 32</c>): the RFC's <c>bits2int</c> never
/// shifts (the bit length of every HMAC output and of the message hash equals <c>qlen</c>), <c>int2octets</c>
/// is the identity on a 32-byte big-endian scalar, and the <c>T</c> accumulation needs exactly one HMAC per
/// attempt. Orders that are not 256-bit (e.g. P-521's 521-bit order) would need the general <c>bits2int</c>
/// shift and the multi-output <c>T</c> loop; this implementation rejects them. The HMAC is injected
/// (<see cref="HmacSha256Delegate"/>) so Core carries no concrete hash dependency.
/// </para>
/// <para>
/// The private key and the running <c>HMAC_DRBG</c> state (<c>V</c>, <c>K</c>) plus the work buffers are
/// cleared before return. The reject loop's iteration count is message/key-dependent (RFC 6979's inherent
/// shape), but for a 256-bit order whose value is within <c>2⁻³²</c> of <c>2²⁵⁶</c> (P-256) a candidate is
/// accepted on the first attempt with overwhelming probability. The candidate range check is NOT yet a
/// constant-time comparison — the constant-time secret-scalar hardening is a separate, later step.
/// </para>
/// </remarks>
public static class Rfc6979DeterministicNonce
{
    /// <summary>The SHA-256 / HMAC-SHA256 output length and, for a 256-bit order, the scalar octet length.</summary>
    private const int HashLength = 32;


    /// <summary>
    /// Derives the deterministic nonce <c>k ∈ [1, q−1]</c> for an ECDSA signature over <paramref name="curve"/>.
    /// </summary>
    /// <param name="curve">The curve whose order <c>q</c> bounds the nonce; must have a 256-bit order (P-256).</param>
    /// <param name="privateKey">The signing private key <c>d</c>, a 32-byte big-endian scalar in <c>[1, q−1]</c> (the RFC's <c>int2octets(x)</c>).</param>
    /// <param name="messageHash">The message hash <c>h1 = H(m)</c>, the 32-byte SHA-256 digest.</param>
    /// <param name="hmac">HMAC-SHA256.</param>
    /// <param name="nonce">Receives the 32-byte big-endian nonce <c>k ∈ [1, q−1]</c>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="hmac"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the order is not 256-bit, or a span has the wrong length.</exception>
    public static void GenerateNonce(
        CurveParameterSet curve,
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> messageHash,
        HmacSha256Delegate hmac,
        Span<byte> nonce)
    {
        ArgumentNullException.ThrowIfNull(hmac);

        if(privateKey.Length != HashLength)
        {
            throw new ArgumentException($"The private key must be {HashLength} big-endian bytes.", nameof(privateKey));
        }

        if(messageHash.Length != HashLength)
        {
            throw new ArgumentException($"The message hash must be the {HashLength}-byte SHA-256 digest.", nameof(messageHash));
        }

        if(nonce.Length != HashLength)
        {
            throw new ArgumentException($"The nonce destination must be {HashLength} bytes.", nameof(nonce));
        }

        //The order q as a 32-byte big-endian scalar (q is public — no constant-time concern).
        Span<byte> order = stackalloc byte[HashLength];
        WriteOrder(curve, order);

        //bits2octets(h1): for a 256-bit order, h1 (256 bits) reduced mod q by one conditional subtraction
        //(h1 < 2²⁵⁶ < 2q, so a single subtract suffices).
        Span<byte> hashReduced = stackalloc byte[HashLength];
        messageHash.CopyTo(hashReduced);
        if(!IsLess(hashReduced, order))
        {
            SubtractInPlace(hashReduced, order);
        }

        //HMAC_DRBG state. V = 0x01·hlen, K = 0x00·hlen (steps b, c).
        Span<byte> v = stackalloc byte[HashLength];
        Span<byte> k = stackalloc byte[HashLength];
        v.Fill(0x01);
        k.Clear();

        //Work buffers, hoisted out of the reject loop (CA2014): the next-V/next-K HMAC outputs, the seed
        //message V‖tag‖int2octets(x)‖bits2octets(h1) (97 bytes), and the retry message V‖0x00 (33 bytes).
        Span<byte> vNext = stackalloc byte[HashLength];
        Span<byte> kNext = stackalloc byte[HashLength];
        Span<byte> seed = stackalloc byte[HashLength + 1 + HashLength + HashLength];
        Span<byte> retry = stackalloc byte[HashLength + 1];

        //Step d: K = HMAC_K(V ‖ 0x00 ‖ int2octets(x) ‖ bits2octets(h1)).
        BuildSeed(seed, v, 0x00, privateKey, hashReduced);
        hmac(k, seed, kNext);
        kNext.CopyTo(k);

        //Step e: V = HMAC_K(V).
        hmac(k, v, vNext);
        vNext.CopyTo(v);

        //Step f: K = HMAC_K(V ‖ 0x01 ‖ int2octets(x) ‖ bits2octets(h1)).
        BuildSeed(seed, v, 0x01, privateKey, hashReduced);
        hmac(k, seed, kNext);
        kNext.CopyTo(k);

        //Step g: V = HMAC_K(V).
        hmac(k, v, vNext);
        vNext.CopyTo(v);

        //Step h: until k ∈ [1, q−1]. For a 256-bit order, T = one HMAC output (tlen = qlen) and
        //k = bits2int(T) = V with no shift.
        while(true)
        {
            hmac(k, v, vNext);
            vNext.CopyTo(v);

            if(!IsZero(v) && IsLess(v, order))
            {
                v.CopyTo(nonce);
                break;
            }

            //Reject: K = HMAC_K(V ‖ 0x00); V = HMAC_K(V).
            v.CopyTo(retry[..HashLength]);
            retry[HashLength] = 0x00;
            hmac(k, retry, kNext);
            kNext.CopyTo(k);
            hmac(k, v, vNext);
            vNext.CopyTo(v);
        }

        order.Clear();
        hashReduced.Clear();
        v.Clear();
        k.Clear();
        vNext.Clear();
        kNext.Clear();
        seed.Clear();
        retry.Clear();
    }


    //Assembles the HMAC_DRBG seed message V ‖ tag ‖ int2octets(x) ‖ bits2octets(h1) into `seed` (97 bytes).
    private static void BuildSeed(Span<byte> seed, ReadOnlySpan<byte> v, byte tag, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> hashReduced)
    {
        v.CopyTo(seed[..HashLength]);
        seed[HashLength] = tag;
        privateKey.CopyTo(seed.Slice(HashLength + 1, HashLength));
        hashReduced.CopyTo(seed.Slice((2 * HashLength) + 1, HashLength));
    }


    //Writes the curve's order q as a 32-byte big-endian scalar; rejects orders that are not 256-bit.
    private static void WriteOrder(CurveParameterSet curve, Span<byte> order)
    {
        BigInteger q = WellKnownCurves.GetScalarFieldOrder(curve);
        byte[] qBytes = q.ToByteArray(isUnsigned: true, isBigEndian: true);
        if(qBytes.Length > HashLength)
        {
            throw new ArgumentException($"RFC 6979 nonce generation here supports a 256-bit order (P-256); curve {curve} has a {qBytes.Length * 8}-bit order.", nameof(curve));
        }

        order.Clear();
        qBytes.CopyTo(order[(HashLength - qBytes.Length)..]);
    }


    //Big-endian unsigned comparison: a < b.
    private static bool IsLess(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for(int i = 0; i < a.Length; i++)
        {
            if(a[i] != b[i])
            {
                return a[i] < b[i];
            }
        }

        return false;
    }


    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;


    //Big-endian in-place subtraction a -= b, assuming a >= b (the caller's conditional guards this).
    private static void SubtractInPlace(Span<byte> a, ReadOnlySpan<byte> b)
    {
        int borrow = 0;
        for(int i = a.Length - 1; i >= 0; i--)
        {
            int difference = a[i] - b[i] - borrow;
            borrow = (difference >> 8) & 1;
            a[i] = (byte)difference;
        }
    }
}
