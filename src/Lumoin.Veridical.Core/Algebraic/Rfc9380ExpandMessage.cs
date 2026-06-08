using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Core.Algebraic;

//Rfc9380ExpandMessage hosts both expand_message_xmd (SHA-256) and
//expand_message_xof (SHAKE-256). Both are RFC 9380 §5.3 primitives
//and form the building block that hash-to-curve and hash-to-scalar
//consume. The XMD variant predates the XOF variant in this codebase;
//the BBS+ ciphersuite tier picks one or the other per ciphersuite_id.

/// <summary>
/// RFC 9380 <c>expand_message_xmd</c> implementations. The expand-message
/// primitive is the deterministic-uniform-bytes building block underneath
/// every hash-to-curve and hash-to-scalar operation in the curves the
/// library supports.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9380 §5.3.1 fixes <c>expand_message_xmd(msg, DST, len_in_bytes)</c>
/// to produce <c>len_in_bytes</c> uniform pseudo-random bytes from a
/// message and a domain-separation tag, using an underlying Merkle-Damgård
/// hash. The construction is structured so that distinct DSTs always
/// produce independent uniform streams, even on identical messages.
/// </para>
/// <para>
/// Hash-to-curve and hash-to-scalar consume the output of this function
/// and reduce it into the appropriate field. This helper is curve-agnostic
/// and the only thing that varies across curves is the choice of the
/// underlying hash and the DST.
/// </para>
/// <para>
/// Constraints enforced by the implementation (all per RFC 9380):
/// </para>
/// <list type="bullet">
///   <item><c>0 &lt; len_in_bytes ≤ 65535</c>.</item>
///   <item><c>len(DST) ≤ 255</c> bytes (the short-DST path; RFC 9380
///     §5.3.3's long-DST hashing is not implemented).</item>
///   <item>Number of output blocks <c>ell = ceil(len_in_bytes / hash_len) ≤ 255</c>.</item>
/// </list>
/// </remarks>
public static class Rfc9380ExpandMessage
{
    private const int Sha256OutputBytes = 32;
    private const int Sha256MessageBlockBytes = 64;
    private const int MaximumMessageBytes = 2048;


    /// <summary>
    /// Computes <c>expand_message_xmd</c> per RFC 9380 §5.3.1 with the
    /// SHA-256 hash, writing exactly <paramref name="output"/>.Length
    /// uniform bytes into <paramref name="output"/>.
    /// </summary>
    /// <param name="message">The application message bytes (the inner-hash input).</param>
    /// <param name="domainSeparationTag">The DST bytes (≤ 255 bytes; longer DSTs are not supported by this reference).</param>
    /// <param name="output">Destination buffer sized to the desired uniform-output length.</param>
    /// <exception cref="ArgumentException">When any of the size constraints listed in the class remarks is violated.</exception>
    public static void ExpandMessageXmdSha256(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> domainSeparationTag,
        Span<byte> output)
    {
        int lenInBytes = output.Length;
        if(lenInBytes <= 0 || lenInBytes > 65535)
        {
            throw new ArgumentException("expand_message_xmd output length must satisfy 0 < lenInBytes <= 65535.", nameof(output));
        }

        if(domainSeparationTag.Length > 255)
        {
            throw new ArgumentException("expand_message_xmd reference does not support DST longer than 255 bytes.", nameof(domainSeparationTag));
        }

        int ell = (lenInBytes + Sha256OutputBytes - 1) / Sha256OutputBytes;
        if(ell > 255)
        {
            throw new ArgumentException("expand_message_xmd output requires more than 255 blocks; not supported by this reference.", nameof(output));
        }

        if(message.Length > MaximumMessageBytes)
        {
            throw new ArgumentException($"expand_message_xmd reference caps message length at {MaximumMessageBytes} bytes.", nameof(message));
        }

        //DST_prime = DST || I2OSP(len(DST), 1)
        Span<byte> dstPrime = stackalloc byte[256];
        domainSeparationTag.CopyTo(dstPrime);
        dstPrime[domainSeparationTag.Length] = (byte)domainSeparationTag.Length;
        int dstPrimeLength = domainSeparationTag.Length + 1;

        //msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
        int msgPrimeLength = Sha256MessageBlockBytes + message.Length + 2 + 1 + dstPrimeLength;
        Span<byte> msgPrime = stackalloc byte[Sha256MessageBlockBytes + MaximumMessageBytes + 2 + 1 + 256];
        msgPrime.Clear();
        int offset = Sha256MessageBlockBytes; //Z_pad bytes are zero.
        message.CopyTo(msgPrime[offset..]);
        offset += message.Length;
        msgPrime[offset++] = (byte)(lenInBytes >> 8);
        msgPrime[offset++] = (byte)(lenInBytes & 0xff);
        msgPrime[offset++] = 0;
        dstPrime[..dstPrimeLength].CopyTo(msgPrime[offset..]);

        Span<byte> b0 = stackalloc byte[Sha256OutputBytes];
        SHA256.HashData(msgPrime[..msgPrimeLength], b0);

        Span<byte> followInputBuffer = stackalloc byte[Sha256OutputBytes + 1 + 256];
        int followInputLength = Sha256OutputBytes + 1 + dstPrimeLength;

        //b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        b0.CopyTo(followInputBuffer);
        followInputBuffer[Sha256OutputBytes] = 1;
        dstPrime[..dstPrimeLength].CopyTo(followInputBuffer[(Sha256OutputBytes + 1)..]);

        Span<byte> bi = stackalloc byte[Sha256OutputBytes];
        SHA256.HashData(followInputBuffer[..followInputLength], bi);

        int writeOffset = 0;
        int firstBlockBytes = Math.Min(Sha256OutputBytes, lenInBytes - writeOffset);
        bi[..firstBlockBytes].CopyTo(output[writeOffset..]);
        writeOffset += firstBlockBytes;

        Span<byte> biPrev = stackalloc byte[Sha256OutputBytes];
        bi.CopyTo(biPrev);

        for(int i = 2; i <= ell; i++)
        {
            //strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime
            for(int j = 0; j < Sha256OutputBytes; j++)
            {
                followInputBuffer[j] = (byte)(b0[j] ^ biPrev[j]);
            }

            followInputBuffer[Sha256OutputBytes] = (byte)i;
            dstPrime[..dstPrimeLength].CopyTo(followInputBuffer[(Sha256OutputBytes + 1)..]);

            SHA256.HashData(followInputBuffer[..followInputLength], bi);

            int blockBytes = Math.Min(Sha256OutputBytes, lenInBytes - writeOffset);
            bi[..blockBytes].CopyTo(output[writeOffset..]);
            writeOffset += blockBytes;

            bi.CopyTo(biPrev);
        }
    }


    /// <summary>
    /// Computes <c>expand_message_xof</c> per RFC 9380 §5.3.2 with the
    /// SHAKE-256 extendable-output function, writing exactly
    /// <paramref name="output"/>.Length uniform bytes into
    /// <paramref name="output"/>.
    /// </summary>
    /// <param name="message">The application message bytes (the inner-XOF input).</param>
    /// <param name="domainSeparationTag">The DST bytes (≤ 255 bytes; longer DSTs are not supported by this reference per RFC 9380 §5.3.3's short-DST path).</param>
    /// <param name="output">Destination buffer sized to the desired uniform-output length.</param>
    /// <exception cref="ArgumentException">When <c>len_in_bytes &gt; 65535</c> or <c>len(DST) &gt; 255</c> per RFC 9380 §5.3.2 step 1.</exception>
    /// <remarks>
    /// <para>
    /// expand_message_xof is the XOF-based companion to
    /// <see cref="ExpandMessageXmdSha256"/>. It is simpler because the
    /// XOF emits the requested output length in one shot — no
    /// block-iteration with strxor is needed. The construction:
    /// </para>
    /// <code>
    /// DST_prime = DST || I2OSP(len(DST), 1)
    /// msg_prime = msg || I2OSP(len_in_bytes, 2) || DST_prime
    /// uniform_bytes = SHAKE256(msg_prime, len_in_bytes)
    /// </code>
    /// <para>
    /// The 65535-byte output ceiling matches expand_message_xmd's; the
    /// k = 256 security level the SHAKE-256 XOF provides is more than
    /// sufficient for the BLS12-381 BBS+ ciphersuite (k = 128).
    /// </para>
    /// </remarks>
    public static void ExpandMessageXofShake256(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> domainSeparationTag,
        Span<byte> output)
    {
        int lenInBytes = output.Length;
        if(lenInBytes <= 0 || lenInBytes > 65535)
        {
            throw new ArgumentException("expand_message_xof output length must satisfy 0 < lenInBytes <= 65535.", nameof(output));
        }

        if(domainSeparationTag.Length > 255)
        {
            throw new ArgumentException("expand_message_xof reference does not support DST longer than 255 bytes.", nameof(domainSeparationTag));
        }

        if(message.Length > MaximumMessageBytes)
        {
            throw new ArgumentException($"expand_message_xof reference caps message length at {MaximumMessageBytes} bytes.", nameof(message));
        }

        //msg_prime = msg || I2OSP(len_in_bytes, 2) || DST || I2OSP(len(DST), 1).
        //SHAKE absorbs the whole input before squeezing, so a single
        //concatenated buffer is byte-identical to incremental appends. The
        //buffer is bounded (message + 2 + DST + 1), so it stays on the stack.
        Span<byte> messagePrime = stackalloc byte[MaximumMessageBytes + 2 + 256 + 1];
        int written = 0;
        message.CopyTo(messagePrime[written..]);
        written += message.Length;
        messagePrime[written++] = (byte)(lenInBytes >> 8);
        messagePrime[written++] = (byte)(lenInBytes & 0xff);
        domainSeparationTag.CopyTo(messagePrime[written..]);
        written += domainSeparationTag.Length;
        messagePrime[written++] = (byte)domainSeparationTag.Length;
        ReadOnlySpan<byte> absorbed = messagePrime[..written];

        //Prefer the OS XOF where the platform provides SHA-3 (Linux, recent
        //Windows); fall back to the managed Keccak on hosts that do not
        //(notably macOS, where Shake256.IsSupported is false). Both paths are
        //byte-identical — an agreement test pins that on hosts where both run.
        if(Shake256.IsSupported)
        {
            Shake256.HashData(absorbed, output);
        }
        else
        {
            ManagedShake256.HashData(absorbed, output);
        }
    }
}