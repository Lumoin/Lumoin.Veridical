using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The root digest of a binary Merkle tree over a codeword — the succinct
/// commitment to the whole codeword. A verifier checks a claimed leaf value
/// against this root via a <see cref="MerkleAuthenticationPath"/>.
/// </summary>
/// <remarks>
/// <para>
/// The root is a single node digest (32 bytes under the default BLAKE3
/// parameter set, see <see cref="WellKnownMerkleHashParameters"/>). It is the
/// commitment BaseFold sends on the wire for a committed polynomial's
/// codeword; the bytes are not secret, but the pool-backed
/// <see cref="SensitiveMemory"/> base gives every cryptographic value a
/// uniform lifecycle.
/// </para>
/// <para>
/// The tag carries the <see cref="AlgebraicRole.Commitment"/> role. The
/// construction is field-agnostic (a hash digest belongs to no curve), so the
/// tag carries no curve dimension; the digest size travels as the value's
/// length.
/// </para>
/// </remarks>
public sealed class MerkleRoot: SensitiveMemory
{
    internal MerkleRoot(IMemoryOwner<byte> owner, int length, Tag tag)
        : base(owner, tag)
    {
    }


    /// <summary>Builds the identifying tag for a Merkle root.</summary>
    internal static Tag CreateTag()
    {
        return Tag.Create(AlgebraicRole.Commitment);
    }


    /// <summary>Wraps a pool-rented buffer that holds a root digest; takes ownership of <paramref name="owner"/>.</summary>
    internal static MerkleRoot Create(IMemoryOwner<byte> owner, int length)
    {
        return new MerkleRoot(owner, length, CreateTag());
    }


    /// <summary>
    /// Reconstructs a Merkle root from its canonical digest bytes (verifier
    /// side). Copies the bytes into a fresh pool-rented buffer; the caller
    /// retains ownership of <paramref name="rootBytes"/>.
    /// </summary>
    /// <param name="rootBytes">The root digest bytes; must be non-empty.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A root wrapping a fresh copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="rootBytes"/> is empty.</exception>
    public static MerkleRoot FromBytes(ReadOnlySpan<byte> rootBytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(rootBytes.IsEmpty)
        {
            throw new ArgumentException("Merkle root bytes must be non-empty.", nameof(rootBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(rootBytes.Length);
        rootBytes.CopyTo(owner.Memory.Span[..rootBytes.Length]);

        return Create(owner, rootBytes.Length);
    }
}
