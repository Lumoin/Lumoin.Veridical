using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The plaintext <c>P</c> of an ECIES encryption, or the plaintext an authenticated decryption released (Verheul
/// Annex A.4): caller-defined bytes of any length, zero included.
/// </summary>
/// <remarks>
/// <b>Secret.</b> The plaintext is confidential for as long as it exists. The authenticated decryption releases it
/// only when the tag is valid, and the caller disposes it, which clears its memory.
/// </remarks>
public sealed class EciesPlaintext: SensitiveMemory
{
    /// <summary>The length of the plaintext in bytes.</summary>
    public int Length => AsReadOnlySpan().Length;


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> and the algorithms construct a plaintext.</summary>
    internal EciesPlaintext(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies caller-supplied plaintext bytes into a pool-rented buffer and returns a plaintext wrapping it.</summary>
    /// <param name="canonicalBytes">The plaintext; may be empty.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>A plaintext wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static EciesPlaintext FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new EciesPlaintext(SecdsaMemory.CopyOf(canonicalBytes, pool), tag ?? Tag.Empty);
    }


    /// <summary>Returns the plaintext bytes.</summary>
    public ReadOnlySpan<byte> GetBytes() => AsReadOnlySpan();
}
