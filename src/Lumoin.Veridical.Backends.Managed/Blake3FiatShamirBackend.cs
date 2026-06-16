using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The production BLAKE3 backend for the Fiat-Shamir transcript's hash and
/// squeeze delegates, wrapping the library's own managed
/// <see cref="Lumoin.Veridical.Hashing.Blake3"/> implementation. Promoted
/// from the test-only reference so consumers of the proof systems have a
/// shipped implementation of the transcript delegates rather than writing
/// their own.
/// </summary>
/// <remarks>
/// <para>
/// Both delegates dispatch to the same
/// <see cref="Lumoin.Veridical.Hashing.Blake3.Hash(System.ReadOnlySpan{byte}, System.Span{byte})"/>
/// overload. When the destination is exactly 32 bytes that overload computes
/// the standard fixed-output BLAKE3 hash; for any other length it switches
/// to the XOF mode internally. The transcript treats the two as a logical
/// hash and squeeze pair, but the API does not distinguish them — a 32-byte
/// squeeze and a 32-byte hash of the same input return the same bytes,
/// exactly as the BLAKE3 spec requires.
/// </para>
/// <para>
/// Backends for other hash functions land as parallel implementations; this
/// one fails fast with <see cref="NotSupportedException"/> for anything
/// other than BLAKE3 so a mis-wired consumer surfaces the misconfiguration
/// immediately.
/// </para>
/// </remarks>
public static class Blake3FiatShamirBackend
{
    /// <summary>Returns the fixed-output hash delegate.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static FiatShamirHashDelegate GetHash() => Hash;

    /// <summary>Returns the XOF-mode squeeze delegate.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static FiatShamirSqueezeDelegate GetSqueeze() => Squeeze;


    private static void Hash(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        EnsureBlake3(hashFunction);
        Lumoin.Veridical.Hashing.Blake3.Hash(input, output);
    }


    private static void Squeeze(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        EnsureBlake3(hashFunction);

        //Hash(input, output) switches to XOF mode automatically when
        //output.Length != 32. For the 32-byte squeeze path this is the same
        //byte sequence as the fixed-output hash by BLAKE3's own definition;
        //for any other length the XOF mode fills the destination with the
        //requested prefix of the infinite output.
        Lumoin.Veridical.Hashing.Blake3.Hash(input, output);
    }


    private static void EnsureBlake3(string hashFunction)
    {
        if(!WellKnownHashAlgorithms.IsBlake3(hashFunction))
        {
            throw new NotSupportedException(
                $"Blake3FiatShamirBackend does not implement '{hashFunction}'; only BLAKE3 is supported by this backend.");
        }
    }
}
