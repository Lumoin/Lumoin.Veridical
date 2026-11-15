using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The role additional data plays in an ECIES envelope or a transferable proof.
/// </summary>
/// <param name="Identifier">The stable name of the role.</param>
[DebuggerDisplay("{Identifier,nq}")]
public readonly record struct AdditionalDataRole(string Identifier)
{
    /// <summary>Additional authenticated data <c>A</c> or <c>AAD</c>: authenticated and bound into the key derivation and signatures, never encrypted, and carried in plaintext.</summary>
    public static AdditionalDataRole Authenticated { get; } = new("authenticated");

    /// <summary>Additional secret data <c>ASD</c>: encrypted next to the seed in the ECIES envelope of a transferable challenge, so only the prover that decrypts it recovers it.</summary>
    public static AdditionalDataRole Secret { get; } = new("secret");
}


/// <summary>
/// Caller-defined data of any length, zero included, that rides along with an ECIES operation or a transferable
/// proof: the additional authenticated data <c>A</c> / <c>AAD</c> (Verheul Algorithms 18 to 24), or the additional
/// secret data <c>ASD</c> (Algorithms 22 and 23). The role is recorded in the tag.
/// </summary>
/// <remarks>
/// <para>
/// <b>Authenticated data is public and bound.</b> It is authenticated by the AEAD tag and by the signatures of a
/// transferable proof, so a change to it is detected, but it is not encrypted; the caller authenticates its meaning.
/// </para>
/// <para>
/// <b>Secret data is confidential.</b> The additional secret data recovered by a prover is disposed by the caller,
/// which clears its memory.
/// </para>
/// </remarks>
public sealed class AdditionalData: SensitiveMemory
{
    /// <summary>The role of this data, from its tag.</summary>
    public AdditionalDataRole Role => Tag.Get<AdditionalDataRole>();

    /// <summary>The length of the data in bytes.</summary>
    public int Length => AsReadOnlySpan().Length;


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> and the algorithms construct additional data.</summary>
    internal AdditionalData(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies caller-supplied bytes into a pool-rented buffer and returns additional data wrapping it.</summary>
    /// <param name="canonicalBytes">The data; may be empty.</param>
    /// <param name="role">The role the data plays.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the role entry.</param>
    /// <returns>Additional data wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static AdditionalData FromCanonical(ReadOnlySpan<byte> canonicalBytes, AdditionalDataRole role, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tag baseTag = tag ?? Tag.Empty;

        return new AdditionalData(
            SecdsaMemory.CopyOf(canonicalBytes, pool),
            baseTag.With(SecdsaStructureKind.AdditionalData).With(role));
    }


    /// <summary>Returns the data bytes.</summary>
    public ReadOnlySpan<byte> GetBytes() => AsReadOnlySpan();
}
