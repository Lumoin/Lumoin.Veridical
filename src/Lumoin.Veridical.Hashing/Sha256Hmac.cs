using System;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// HMAC-SHA256 (RFC 2104 / FIPS 198-1) built on <see cref="Sha256Hasher"/>: the keyed message authentication
/// code <c>H((K0 ⊕ opad) ‖ H((K0 ⊕ ipad) ‖ message))</c>, where <c>K0</c> is the key zero-padded to the 64-byte
/// SHA-256 block, or — when the key is longer than a block — its SHA-256 digest zero-padded to a block. The
/// building block for RFC 6979 deterministic ECDSA nonces (the <c>HMAC_DRBG</c> the standard specifies).
/// </summary>
/// <remarks>
/// Byte-identical to <c>System.Security.Cryptography.HMACSHA256</c>. The padded key, the pad blocks and the inner
/// digest carry key-derived material and are cleared before return.
/// </remarks>
public static class Sha256Hmac
{
    /// <summary>The SHA-256 block size in bytes (the HMAC key-padding width).</summary>
    public const int BlockSizeBytes = 64;

    /// <summary>The HMAC-SHA256 output size in bytes.</summary>
    public const int MacSizeBytes = Sha256Hasher.DigestSizeBytes;

    private const byte InnerPad = 0x36;
    private const byte OuterPad = 0x5C;


    /// <summary>
    /// Computes HMAC-SHA256 of <paramref name="message"/> under <paramref name="key"/> into
    /// <paramref name="mac"/>, which must be exactly <see cref="MacSizeBytes"/> bytes.
    /// </summary>
    /// <param name="key">The MAC key (any length).</param>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="mac">The destination, exactly <see cref="MacSizeBytes"/> bytes.</param>
    /// <exception cref="ArgumentException">When <paramref name="mac"/> is not <see cref="MacSizeBytes"/> bytes.</exception>
    public static void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
    {
        if(mac.Length != MacSizeBytes)
        {
            throw new ArgumentException($"The MAC destination must be exactly {MacSizeBytes} bytes.", nameof(mac));
        }

        //K0: the key reduced to one block — zero-padded when shorter than a block, SHA-256-then-zero-padded when
        //longer (RFC 2104 §2). stackalloc is not guaranteed zeroed, so clear before the partial copy. All four
        //scratch buffers carry key-derived material, so they are cleared in a finally: a throw partway through
        //the hashing must not leave them live on the stack.
        Span<byte> paddedKey = stackalloc byte[BlockSizeBytes];
        Span<byte> innerPadBlock = stackalloc byte[BlockSizeBytes];
        Span<byte> outerPadBlock = stackalloc byte[BlockSizeBytes];
        Span<byte> inner = stackalloc byte[MacSizeBytes];
        try
        {
            paddedKey.Clear();
            if(key.Length > BlockSizeBytes)
            {
                Sha256Hasher keyHasher = Sha256Hasher.CreateAutoSelected();
                keyHasher.Update(key);
                keyHasher.Finalize(paddedKey[..MacSizeBytes]);
            }
            else
            {
                key.CopyTo(paddedKey);
            }

            for(int i = 0; i < BlockSizeBytes; i++)
            {
                innerPadBlock[i] = (byte)(paddedKey[i] ^ InnerPad);
                outerPadBlock[i] = (byte)(paddedKey[i] ^ OuterPad);
            }

            //inner = H((K0 ⊕ ipad) ‖ message).
            Sha256Hasher innerHasher = Sha256Hasher.CreateAutoSelected();
            innerHasher.Update(innerPadBlock);
            innerHasher.Update(message);
            innerHasher.Finalize(inner);

            //mac = H((K0 ⊕ opad) ‖ inner).
            Sha256Hasher outerHasher = Sha256Hasher.CreateAutoSelected();
            outerHasher.Update(outerPadBlock);
            outerHasher.Update(inner);
            outerHasher.Finalize(mac);
        }
        finally
        {
            paddedKey.Clear();
            innerPadBlock.Clear();
            outerPadBlock.Clear();
            inner.Clear();
        }
    }
}
