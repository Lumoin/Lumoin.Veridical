using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The ANSI X9.63 key derivation function over SHA-256 (SEC 1 version 2, section 3.6.1), the derivation the PKCS#11
/// mechanism <c>CKD_SHA256_KDF</c> applies in <c>CKM_ECDH1_DERIVE</c>: the output is
/// <c>Hash(Z ‖ Counter ‖ SharedInfo)</c> for a 4-byte big-endian counter that starts at 1, the blocks
/// concatenated and truncated to the requested length. In ECIES (Verheul Annex A.4) the additional authenticated
/// data <c>A</c> takes the role of <c>SharedInfo</c>, which on a PKCS#11 HSM is the <c>pSharedData</c> field.
/// </summary>
/// <remarks>
/// <para>
/// <b>Delegate-injected hash.</b> The hash enters as a <see cref="FiatShamirHashDelegate"/> invoked with
/// <see cref="WellKnownHashAlgorithms.Sha256"/>, so the library carries no hash backend. The scratch buffer that
/// holds <c>Z ‖ Counter ‖ SharedInfo</c> is rented from the supplied pool and cleared before it returns, as is the
/// digest block, because <c>Z</c> is secret.
/// </para>
/// <para>
/// <b>Bound.</b> SEC 1 bounds the output by <c>2³²−1</c> blocks; this implementation bounds it by
/// <see cref="MaxOutputSizeBytes"/>, far above any key material ECIES derives.
/// </para>
/// </remarks>
public static class X963KeyDerivation
{
    /// <summary>The SHA-256 digest length in bytes, the size of one derivation block.</summary>
    public const int DigestSizeBytes = 32;

    /// <summary>The length of the big-endian block counter in bytes.</summary>
    public const int CounterSizeBytes = sizeof(uint);

    /// <summary>The largest output the derivation produces.</summary>
    public const int MaxOutputSizeBytes = 1024;

    //SEC 1 section 3.6.1 starts the counter at one.
    private const uint FirstCounter = 1;


    /// <summary>Binds the X9.63 SHA-256 derivation to a hash and a pool, producing an ECIES key-derivation delegate.</summary>
    /// <param name="hash">The hash delegate; invoked with SHA-256 and a 32-byte output.</param>
    /// <param name="pool">The pool the secret scratch buffer is rented from.</param>
    /// <returns>A delegate computing <c>K = KDF(Z_AB, SharedInfo)</c>.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hash"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static EciesKeyDerivationDelegate Create(FiatShamirHashDelegate hash, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(pool);

        return (sharedSecret, sharedData, keyMaterial) => Derive(hash, pool, sharedSecret, sharedData, keyMaterial);
    }


    /// <summary>Derives key material with the X9.63 KDF over SHA-256.</summary>
    /// <param name="hash">The hash delegate; invoked with SHA-256 and a 32-byte output.</param>
    /// <param name="pool">The pool the secret scratch buffer is rented from.</param>
    /// <param name="sharedSecret">The shared secret <c>Z</c>; secret.</param>
    /// <param name="sharedInfo">The <c>SharedInfo</c>; may be empty.</param>
    /// <param name="output">Receives <c>output.Length</c> bytes of key material, at least one and at most <see cref="MaxOutputSizeBytes"/>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="hash"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="sharedSecret"/> is empty or <paramref name="output"/> is empty or longer than <see cref="MaxOutputSizeBytes"/>.</exception>
    public static void Derive(
        FiatShamirHashDelegate hash,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> sharedInfo,
        Span<byte> output)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(pool);
        if(sharedSecret.IsEmpty)
        {
            throw new ArgumentException("The shared secret must not be empty.", nameof(sharedSecret));
        }

        if(output.IsEmpty || output.Length > MaxOutputSizeBytes)
        {
            throw new ArgumentException($"The output must be between 1 and {MaxOutputSizeBytes} bytes.", nameof(output));
        }

        int inputLength = sharedSecret.Length + CounterSizeBytes + sharedInfo.Length;
        using IMemoryOwner<byte> scratch = pool.Rent(inputLength);
        Span<byte> input = scratch.Memory.Span[..inputLength];
        Span<byte> block = stackalloc byte[DigestSizeBytes];
        try
        {
            sharedSecret.CopyTo(input);
            sharedInfo.CopyTo(input[(sharedSecret.Length + CounterSizeBytes)..]);
            Span<byte> counter = input.Slice(sharedSecret.Length, CounterSizeBytes);

            uint index = FirstCounter;
            int written = 0;
            while(written < output.Length)
            {
                BinaryPrimitives.WriteUInt32BigEndian(counter, index);
                hash(input, block, WellKnownHashAlgorithms.Sha256);

                int take = Math.Min(DigestSizeBytes, output.Length - written);
                block[..take].CopyTo(output[written..]);
                written += take;
                index++;
            }
        }
        finally
        {
            input.Clear();
            block.Clear();
        }
    }
}
