using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// A canonical Merkle commitment to a key-value <em>set</em> with
/// membership proofs — the cryptographic shadow-root primitive a
/// content-addressed store (the Veritas hypertrie being the intended
/// consumer) publishes alongside its fast non-cryptographic identifiers.
/// Hash-agnostic via <see cref="MerkleHashDelegate"/>: the same convention
/// realises a BLAKE3 shadow root today and a Poseidon shadow root (cheap
/// in-circuit) when a native Poseidon permutation lands — only the delegate
/// changes.
/// </summary>
/// <remarks>
/// <para>
/// <b>The pinned convention.</b> An entry is a <c>(key, value)</c> pair of
/// digest-sized chunks (the consumer pre-hashes or pads its native key and
/// value forms to the digest size deterministically). Entries are supplied
/// in strictly ascending key order (byte-lexicographic, unique keys) — the
/// canonical set order, validated and refused loudly — so the same set
/// always produces the same root. Leaf <c>i</c> is
/// <c>hash(key_i, value_i)</c> through the same two-to-one compression that
/// builds the tree; the leaf layer is padded to the next power of two with
/// all-zero digests (a real leaf colliding with the zero digest would be a
/// preimage of zero under the compression). The tree above the leaves is
/// the standard <see cref="MerkleTree"/>.
/// </para>
/// <para>
/// A membership proof is the entry's <see cref="MerkleAuthenticationPath"/>
/// plus its index; verification recomputes the leaf from the claimed
/// <c>(key, value)</c> and authenticates it against the committed root.
/// The proof binds key <em>and</em> value: a different value under the same
/// key produces a different leaf. Non-membership proofs (via adjacent-entry
/// range arguments over the sorted order) are a recorded follow-on, not
/// built.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class MerkleSetCommitment
{
    /// <summary>
    /// Commits a key-value set: builds the canonical Merkle tree over the
    /// leaf digests <c>hash(key_i, value_i)</c>, zero-padded to the next
    /// power of two. The returned tree's <see cref="MerkleTree.Root"/> is
    /// the set commitment; keep the tree to produce membership proofs.
    /// </summary>
    /// <param name="entries">The concatenated entries, each <c>2 × digestSizeBytes</c> wide (<c>key ‖ value</c>), in strictly ascending byte-lexicographic key order.</param>
    /// <param name="entryCount">The number of entries; positive.</param>
    /// <param name="digestSizeBytes">The digest size of <paramref name="hash"/>.</param>
    /// <param name="hash">The two-to-one compression, used for the leaves and the tree alike.</param>
    /// <param name="pool">The pool to rent the working buffers from.</param>
    /// <returns>The committed tree; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is non-positive.</exception>
    /// <exception cref="ArgumentException">When the entry bytes do not match the shape, or the keys are not strictly ascending and unique.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The returned tree owns its layer buffer; the leaf scratch is disposed here.")]
    public static MerkleTree Commit(
        ReadOnlySpan<byte> entries,
        int entryCount,
        int digestSizeBytes,
        MerkleHashDelegate hash,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(entryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        int entrySize = 2 * digestSizeBytes;
        if(entries.Length != entryCount * entrySize)
        {
            throw new ArgumentException(
                $"Entries must be exactly {entryCount} × {entrySize} bytes (key ‖ value, each digest-wide); received {entries.Length}.",
                nameof(entries));
        }

        ThrowIfKeysNotStrictlyAscending(entries, entryCount, digestSizeBytes);

        //Leaf layer: hash(key_i, value_i), zero-padded to the next power of two.
        int leafCount = (int)BitOperations.RoundUpToPowerOf2((uint)entryCount);
        using IMemoryOwner<byte> leavesOwner = pool.Rent(leafCount * digestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(leafCount * digestSizeBytes)];
        leaves.Clear();
        for(int i = 0; i < entryCount; i++)
        {
            ReadOnlySpan<byte> key = entries.Slice(i * entrySize, digestSizeBytes);
            ReadOnlySpan<byte> value = entries.Slice((i * entrySize) + digestSizeBytes, digestSizeBytes);
            hash(key, value, leaves.Slice(i * digestSizeBytes, digestSizeBytes));
        }

        return MerkleTree.Build(leaves, leafCount, hash, pool);
    }


    /// <summary>
    /// Produces the membership proof of the entry at
    /// <paramref name="entryIndex"/>: its authentication path in the
    /// committed tree. The verifier additionally needs the entry's
    /// <c>(key, value)</c> and the index.
    /// </summary>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the index is outside the tree's leaf range.</exception>
    public static MerkleAuthenticationPath ProveMembership(
        MerkleTree tree,
        int entryIndex,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(tree);
        ArgumentNullException.ThrowIfNull(pool);

        return tree.BuildPath(entryIndex, pool);
    }


    /// <summary>
    /// Verifies that <c>(key, value)</c> is a member of the set committed by
    /// <paramref name="root"/>: recomputes the leaf <c>hash(key, value)</c>
    /// and authenticates it at <paramref name="entryIndex"/> under
    /// <paramref name="path"/>. Exception-safe against malformed inputs —
    /// shape mismatches report as a non-match.
    /// </summary>
    /// <returns><see langword="true"/> iff the membership proof checks out.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    public static bool VerifyMembership(
        MerkleRoot root,
        int entryIndex,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> value,
        MerkleAuthenticationPath path,
        MerkleHashDelegate hash)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(hash);

        int digestSize = root.Length;
        if(entryIndex < 0 || key.Length != digestSize || value.Length != digestSize
            || digestSize > WellKnownMerkleHashParameters.MaximumDigestSizeBytes)
        {
            return false;
        }

        Span<byte> leaf = stackalloc byte[WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
        leaf = leaf[..digestSize];
        hash(key, value, leaf);

        return path.Verify(root, entryIndex, leaf, hash);
    }


    //The canonical set order: strictly ascending byte-lexicographic keys —
    //the determinism guarantee that makes equal sets commit identically.
    private static void ThrowIfKeysNotStrictlyAscending(ReadOnlySpan<byte> entries, int entryCount, int digestSizeBytes)
    {
        int entrySize = 2 * digestSizeBytes;
        for(int i = 1; i < entryCount; i++)
        {
            ReadOnlySpan<byte> previous = entries.Slice((i - 1) * entrySize, digestSizeBytes);
            ReadOnlySpan<byte> current = entries.Slice(i * entrySize, digestSizeBytes);
            if(previous.SequenceCompareTo(current) >= 0)
            {
                throw new ArgumentException(
                    $"Entry keys must be strictly ascending (byte-lexicographic, unique); violated at entry {i}.",
                    nameof(entries));
            }
        }
    }
}
