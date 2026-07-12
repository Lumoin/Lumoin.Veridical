using System;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// HKDF-SHA256 (RFC 5869) built on <see cref="Sha256Hmac.Compute"/>: the two-stage extract-then-expand key
/// derivation function <c>PRK = HMAC-Hash(salt, IKM)</c> followed by <c>OKM = T(1) ‖ T(2) ‖ … ‖ T(N)</c>, where
/// <c>T(i) = HMAC-Hash(PRK, T(i-1) ‖ info ‖ i)</c> and <c>T(0)</c> is the empty string. This is the KDF ISO
/// 18013-5 stipulates for <c>EMacKey</c> derivation in its ECDH-MAC device binding; the generic
/// <c>K = HKDF(Z_AB, SharedInfo)</c> step it instantiates is the SECDSA paper's Annex A.3 (the ISO-specific
/// salt/info/length parameterization is the consumer's wiring).
/// </summary>
/// <remarks>
/// Byte-identical to <c>System.Security.Cryptography.HKDF</c> with <c>HashAlgorithmName.SHA256</c>. The
/// pseudorandom key and the running <c>T(i)</c> block carry key-derived material and are cleared before return.
/// </remarks>
public static class Sha256Hkdf
{
    /// <summary>The HKDF-SHA256 pseudorandom key size in bytes (RFC 5869 §2.2's <c>HashLen</c>).</summary>
    public const int PseudoRandomKeySizeBytes = Sha256Hasher.DigestSizeBytes;

    /// <summary>
    /// The largest output <see cref="Expand"/> and <see cref="DeriveKey"/> can produce: RFC 5869 §2.3 bounds
    /// <c>L</c> to <c>255·HashLen</c>, since the block counter is a single octet running <c>1..255</c>.
    /// </summary>
    public const int MaxOutputSizeBytes = 255 * Sha256Hasher.DigestSizeBytes;

    /// <summary>
    /// The largest <c>info</c> <see cref="Expand"/> and <see cref="DeriveKey"/> accept. RFC 5869 §3.2 frames
    /// <c>info</c> as a short context/application string, not a data channel; bounding it keeps the expand
    /// step's HMAC message assembly in a fixed-size stack allocation with no caller-length-driven stack
    /// growth. One kibibyte accommodates every profiled consumer (ISO 18013-5's <c>EMacKey</c> uses the
    /// 7-byte string <c>"EMacKey"</c>; X9.63-style <c>SharedInfo</c> strings are similarly small).
    /// </summary>
    public const int MaxInfoSizeBytes = 1024;


    /// <summary>
    /// The RFC 5869 §2.2 extract step: <c>PRK = HMAC-Hash(salt, IKM)</c>, concentrating the (possibly
    /// non-uniform) input keying material into a fixed-length pseudorandom key.
    /// </summary>
    /// <param name="salt">
    /// The extraction salt (optional per the RFC; not secret). An empty span selects HKDF's default.
    /// </param>
    /// <param name="inputKeyingMaterial">
    /// The input keying material (for ECDH-MAC, the shared-point x-coordinate <c>Z_AB</c>).
    /// </param>
    /// <param name="pseudoRandomKey">The destination, exactly <see cref="PseudoRandomKeySizeBytes"/> bytes.</param>
    /// <exception cref="ArgumentException">
    /// When <paramref name="pseudoRandomKey"/> is not <see cref="PseudoRandomKeySizeBytes"/> bytes.
    /// </exception>
    /// <remarks>
    /// RFC 5869 §2.2 gives the default salt — used when the caller has none — as "a string of HashLen zeros".
    /// That default needs no special casing here: HMAC zero-pads a key shorter than the 64-byte block
    /// (<see cref="Sha256Hmac"/>'s <c>K0</c> construction), so an empty <paramref name="salt"/> is already
    /// byte-identical to 32 zero bytes.
    /// </remarks>
    public static void Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyingMaterial, Span<byte> pseudoRandomKey)
    {
        if(pseudoRandomKey.Length != PseudoRandomKeySizeBytes)
        {
            throw new ArgumentException($"The pseudorandom key destination must be exactly {PseudoRandomKeySizeBytes} bytes.", nameof(pseudoRandomKey));
        }

        Sha256Hmac.Compute(salt, inputKeyingMaterial, pseudoRandomKey);
    }


    /// <summary>
    /// The RFC 5869 §2.3 expand step: <c>OKM = T(1) ‖ T(2) ‖ … ‖ T(N)</c>, truncated to
    /// <paramref name="outputKeyingMaterial"/>'s length, where <c>T(0)</c> is the empty string and
    /// <c>T(i) = HMAC-Hash(PRK, T(i-1) ‖ info ‖ i)</c> for the one-based counter octet <c>i</c>.
    /// </summary>
    /// <param name="pseudoRandomKey">
    /// The pseudorandom key, at least <see cref="PseudoRandomKeySizeBytes"/> bytes (RFC 5869 §2.3's
    /// <c>HashLen</c> minimum; typically <see cref="Extract"/>'s output).
    /// </param>
    /// <param name="info">
    /// The context/application information string (may be empty; at most <see cref="MaxInfoSizeBytes"/> bytes).
    /// </param>
    /// <param name="outputKeyingMaterial">
    /// The destination; its length is the RFC's <c>L</c> and selects how much keying material is derived,
    /// from 1 up to <see cref="MaxOutputSizeBytes"/> bytes.
    /// </param>
    /// <exception cref="ArgumentException">
    /// When <paramref name="pseudoRandomKey"/> is shorter than <see cref="PseudoRandomKeySizeBytes"/>,
    /// <paramref name="info"/> is longer than <see cref="MaxInfoSizeBytes"/>, or
    /// <paramref name="outputKeyingMaterial"/>'s length is not between 1 and <see cref="MaxOutputSizeBytes"/>.
    /// </exception>
    public static void Expand(ReadOnlySpan<byte> pseudoRandomKey, ReadOnlySpan<byte> info, Span<byte> outputKeyingMaterial)
    {
        if(pseudoRandomKey.Length < PseudoRandomKeySizeBytes)
        {
            throw new ArgumentException($"The pseudorandom key must be at least {PseudoRandomKeySizeBytes} bytes.", nameof(pseudoRandomKey));
        }

        if(info.Length > MaxInfoSizeBytes)
        {
            throw new ArgumentException($"The info string must be at most {MaxInfoSizeBytes} bytes.", nameof(info));
        }

        if(outputKeyingMaterial.Length is < 1 or > MaxOutputSizeBytes)
        {
            throw new ArgumentException($"The output length must be between 1 and {MaxOutputSizeBytes} bytes.", nameof(outputKeyingMaterial));
        }

        //T(i-1) ‖ info ‖ counter, the running HMAC message (RFC 5869 §2.3). T(i-1) occupies the first
        //`previousBlockLength` bytes of `hmacInput` — zero on the first iteration, since T(0) is the empty
        //string — followed by `info` and the trailing one-based counter octet.
        Span<byte> hmacInput = stackalloc byte[PseudoRandomKeySizeBytes + info.Length + 1];
        Span<byte> previousBlock = stackalloc byte[PseudoRandomKeySizeBytes];

        try
        {
            int previousBlockLength = 0;
            int written = 0;
            byte counter = 1;

            while(written < outputKeyingMaterial.Length)
            {
                int messageLength = previousBlockLength + info.Length + 1;
                previousBlock[..previousBlockLength].CopyTo(hmacInput);
                info.CopyTo(hmacInput.Slice(previousBlockLength, info.Length));
                hmacInput[messageLength - 1] = counter;

                Sha256Hmac.Compute(pseudoRandomKey, hmacInput[..messageLength], previousBlock);
                previousBlockLength = PseudoRandomKeySizeBytes;

                int chunkLength = Math.Min(PseudoRandomKeySizeBytes, outputKeyingMaterial.Length - written);
                previousBlock[..chunkLength].CopyTo(outputKeyingMaterial.Slice(written, chunkLength));
                written += chunkLength;
                counter++;
            }
        }
        finally
        {
            hmacInput.Clear();
            previousBlock.Clear();
        }
    }


    /// <summary>
    /// The full RFC 5869 derivation: <see cref="Extract"/> then <see cref="Expand"/>. Matches
    /// <see cref="Lumoin.Veridical.Core.Cryptography.HkdfSha256Delegate"/>'s signature, so it is directly
    /// assignable wherever that delegate is injected (e.g. ECDH-MAC <c>EMacKey</c> derivation).
    /// </summary>
    /// <param name="salt">The extraction salt; empty selects the RFC 5869 default (32 zero bytes).</param>
    /// <param name="inputKeyingMaterial">
    /// The input keying material (for ECDH-MAC, the shared-point x-coordinate <c>Z_AB</c>).
    /// </param>
    /// <param name="info">
    /// The context/application information string (may be empty; at most <see cref="MaxInfoSizeBytes"/> bytes).
    /// </param>
    /// <param name="outputKeyingMaterial">The destination; its length selects how much keying material is derived.</param>
    /// <exception cref="ArgumentException">
    /// When <paramref name="info"/> is longer than <see cref="MaxInfoSizeBytes"/>, or
    /// <paramref name="outputKeyingMaterial"/>'s length is not between 1 and <see cref="MaxOutputSizeBytes"/>.
    /// </exception>
    public static void DeriveKey(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> info, Span<byte> outputKeyingMaterial)
    {
        Span<byte> pseudoRandomKey = stackalloc byte[PseudoRandomKeySizeBytes];

        try
        {
            Extract(salt, inputKeyingMaterial, pseudoRandomKey);
            Expand(pseudoRandomKey, info, outputKeyingMaterial);
        }
        finally
        {
            pseudoRandomKey.Clear();
        }
    }
}
